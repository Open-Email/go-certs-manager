package certmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"bytes"

	"github.com/Open-Email/go-certs-manager/internal/safego"
	"github.com/Open-Email/go-certs-manager/storage"
)

// OnDemandConfig turns the manager's fixed domain whitelist into a DYNAMIC
// allow-set fetched from an external authority — the shape a multi-tenant
// platform needs, where customers add vanity hostnames continuously and no
// config file can enumerate them.
//
// The design constraint that shapes everything here: a certificate authority's
// rate limits are a SHARED, ACCOUNT-WIDE resource. One misconfigured (or
// malicious) hostname must not be able to spend it. Three mechanisms enforce
// that, and they are layered so each catches what the previous cannot:
//
//  1. The allow-set is PUSHED, never queried per handshake. An SNI outside it
//     is refused from memory with no I/O at all, so a flood of invented names
//     costs nothing — no lookup, no order, no amplification against the
//     authority that publishes the set.
//  2. A DNS PRE-FLIGHT runs before any on-demand order: the hostname must
//     actually resolve to us. A name that is allowed but not pointed here
//     (a customer who has not published the CNAME yet, or removed it) is
//     skipped without contacting the CA, so the overwhelmingly common failure
//     costs zero CA budget rather than a failed validation.
//  3. A NEW-ORDER TOKEN BUCKET bounds first issuances per hour regardless of
//     how many hostnames appear at once, so a thousand-hostname import drains
//     over hours instead of exhausting the account's new-order limit in
//     minutes and blocking RENEWALS for existing customers.
//
// Renewals are deliberately scheduled ahead of first issuances for that last
// reason: a renewal keeps a working service working, a first issuance starts
// one, and when the budget is scarce the former must win.
type OnDemandConfig struct {
	// Enumerate returns the full set of hostnames that may be served. Called on
	// the LEADER only, every Interval. An error keeps the last good set — a
	// control-plane blip must never retract certificates that are already
	// serving traffic.
	//
	// The caller is expected to make this cheap (a conditional request against
	// its own authority); the manager compares the returned set against what it
	// last published and only writes storage when it actually changed.
	Enumerate func(ctx context.Context) ([]string, error)

	// Interval between enumerations (leader) and allow-set refreshes
	// (followers). Default 60s.
	Interval time.Duration

	// ExpectedTarget is the platform hostname customers CNAME at. The DNS
	// pre-flight requires an on-demand hostname to resolve to it — by CNAME
	// chain, or by sharing an address with it. Empty disables the pre-flight,
	// which is NOT recommended: it is the only thing standing between an
	// unpointed hostname and a failed CA order.
	ExpectedTarget string

	// HandshakeWait, when > 0, lets a handshake for an allowed-but-not-yet-issued
	// hostname WAIT for issuance instead of failing immediately. It exists for
	// interactive clients (an IMAP user typing their new hostname sees a
	// connection error, not a retry), and is bounded because the alternative —
	// blocking indefinitely on a slow CA — is exactly the autocert behaviour
	// this module was written to avoid. Static domains are unaffected. 0 keeps
	// the original asynchronous behaviour.
	HandshakeWait time.Duration

	// MaxNewOrdersPerHour bounds FIRST issuances per node per hour (renewals are
	// exempt: they are bounded by the certificate lifetime and must not be
	// starved by an import). Default 40 — sized so that even two believed-leaders
	// in a split-brain stay under Let's Encrypt's 300-new-orders-per-account per
	// 3 hours.
	MaxNewOrdersPerHour int

	// MaxConcurrentOrders bounds in-flight issuances. Default 4.
	MaxConcurrentOrders int

	// Resolver used for the DNS pre-flight. nil = net.DefaultResolver.
	Resolver *net.Resolver
}

// onDemandStateKey is the published allow-set: the leader writes it, followers
// read it. Sharing it through storage rather than having every node call the
// authority keeps credentials on one node, makes the fleet's view consistent,
// and means a follower needs no network path to the control plane at all.
const onDemandStateKey = "ondemand/hosts.json"

// certIndexKey maps hostname -> leaf NotAfter for every on-demand certificate
// in storage. Followers diff it once per tick and refresh only what changed,
// instead of issuing one storage read per hostname per tick — the difference
// between O(1) and O(N) steady-state load at tens of thousands of hostnames.
const certIndexKey = "ondemand/certs-index.json"

// preflightBackoff is how long a hostname that failed the DNS pre-flight is
// skipped. Long, deliberately: the failure means a human has not finished (or
// has undone) a DNS change, which is not a condition that resolves in minutes,
// and re-checking it every tick would put a needless query per unpointed
// hostname on the resolver forever.
const preflightBackoff = 24 * time.Hour

type onDemandState struct {
	GeneratedAt int64    `json:"generated_at"`
	Hosts       []string `json:"hosts"`
}

// onDemand holds the runtime half of OnDemandConfig.
type onDemand struct {
	cfg      OnDemandConfig
	backend  storage.Backend
	prefix   string
	resolver *net.Resolver

	// allow is swapped atomically so the handshake path reads it with no lock.
	allow atomic.Pointer[map[string]struct{}]

	orders *tokenBucket

	// indexMu serializes the cert index's read-modify-write-put. Separate from
	// `mu` because it is held across I/O and `mu` must never be.
	indexMu sync.Mutex

	// resolveFn is the pre-flight's resolution decision, injectable for tests
	// (it returns "" when the hostname points at the target, else why not).
	resolveFn func(ctx context.Context, hostname, target string) string

	mu           sync.Mutex
	published    string               // last set the leader wrote, joined — change detection
	hasPublished bool                 // false until the first write, so an EMPTY set still lands
	preflight    map[string]time.Time // hostname -> when its pre-flight may be retried
	index        map[string]int64     // hostname -> leaf NotAfter (unix), follower diffing
}

func newOnDemand(cfg OnDemandConfig, backend storage.Backend, prefix string) *onDemand {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	if cfg.MaxNewOrdersPerHour <= 0 {
		cfg.MaxNewOrdersPerHour = 40
	}
	if cfg.MaxConcurrentOrders <= 0 {
		cfg.MaxConcurrentOrders = 4
	}
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	od := &onDemand{
		cfg:       cfg,
		backend:   backend,
		prefix:    prefix,
		resolver:  resolver,
		orders:    newTokenBucket(cfg.MaxNewOrdersPerHour, time.Hour),
		preflight: make(map[string]time.Time),
	}
	od.resolveFn = od.resolvesTo
	empty := make(map[string]struct{})
	od.allow.Store(&empty)
	return od
}

func (o *onDemand) key(name string) string { return o.prefix + name }

// allowed reports whether serverName is in the current allow-set. Pure memory:
// this is on the handshake path.
func (o *onDemand) allows(serverName string) bool {
	set := o.allow.Load()
	if set == nil {
		return false
	}
	_, ok := (*set)[serverName]
	return ok
}

// hosts returns the current allow-set as a sorted slice (maintenance ordering).
func (o *onDemand) hosts() []string {
	set := o.allow.Load()
	if set == nil {
		return nil
	}
	out := make([]string, 0, len(*set))
	for h := range *set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func (o *onDemand) store(hosts []string) {
	set := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
		if h != "" {
			set[h] = struct{}{}
		}
	}
	o.allow.Store(&set)

	// Forget bookkeeping for hostnames that have left the allow-set. Both maps
	// are keyed by a value CUSTOMERS choose, so without this a long-running node
	// accumulates an entry for every hostname ever claimed and released.
	o.mu.Lock()
	for h := range o.preflight {
		if _, ok := set[h]; !ok {
			delete(o.preflight, h)
		}
	}
	for h := range o.index {
		if _, ok := set[h]; !ok {
			delete(o.index, h)
		}
	}
	o.mu.Unlock()
}

// refreshLeader enumerates from the authority and publishes the result for the
// followers. An enumeration error is logged and the previous set kept.
func (o *onDemand) refreshLeader(ctx context.Context, logger interface{ Warn(string, ...any) }) {
	if o.cfg.Enumerate == nil {
		return
	}
	hosts, err := o.cfg.Enumerate(ctx)
	if err != nil {
		logger.Warn("TLS: on-demand enumeration failed — keeping the previous allow-set", "error", err)
		return
	}
	normalized := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
		if h != "" {
			normalized = append(normalized, h)
		}
	}
	sort.Strings(normalized)
	o.store(normalized)

	joined := strings.Join(normalized, "\n")
	o.mu.Lock()
	// `hasPublished` exists because the empty set and the never-written state
	// have the same string. Without it a fleet whose last vanity hostname was
	// released never publishes the emptying, and a follower (or a leader that
	// restarts) keeps serving TLS for retired hostnames from a stale object,
	// indefinitely.
	unchanged := o.hasPublished && joined == o.published
	o.published, o.hasPublished = joined, true
	o.mu.Unlock()
	if unchanged {
		return
	}
	body, err := json.Marshal(onDemandState{GeneratedAt: time.Now().Unix(), Hosts: normalized})
	if err != nil {
		return
	}
	if err := o.backend.PutObject(ctx, o.key(onDemandStateKey), bytes.NewReader(body),
		int64(len(body)), storage.PutOptions{ContentType: "application/json"}); err != nil {
		logger.Warn("TLS: publishing the on-demand allow-set failed", "error", err)
	}
}

// refreshFollower reads the allow-set the leader published. Cheap by
// construction: one conditional-ish read of one small object per tick, whatever
// the fleet's hostname count.
func (o *onDemand) refreshFollower(ctx context.Context) error {
	body, err := readObject(ctx, o.backend, o.key(onDemandStateKey))
	if err != nil {
		return err
	}
	var state onDemandState
	if err := json.Unmarshal(body, &state); err != nil {
		return err
	}
	o.store(state.Hosts)
	return nil
}

// noteIssued records a hostname's expiry in the shared index (leader side).
func (o *onDemand) noteIssued(ctx context.Context, hostname string, notAfter time.Time) {
	// The write lock is held across the marshal AND the put, not just the map
	// update. With MaxConcurrentOrders issuances in flight, two goroutines that
	// snapshotted independently would race their puts, and the later-landing
	// (older) snapshot would erase the other's entry — a hostname the followers
	// would then never refresh, because their diff sees it unchanged at zero.
	// Issuance is minutes of work; serializing one small object write is free.
	o.indexMu.Lock()
	defer o.indexMu.Unlock()

	o.mu.Lock()
	if o.index == nil {
		o.index = make(map[string]int64)
	}
	// The FULL map, never a single entry: a follower diffing an index that held
	// only the last write would read every other hostname as missing and fall
	// back to the per-host storage reads this exists to avoid.
	o.index[strings.ToLower(hostname)] = notAfter.Unix()
	snapshot := make(map[string]int64, len(o.index))
	for k, v := range o.index {
		snapshot[k] = v
	}
	o.mu.Unlock()

	body, err := json.Marshal(snapshot)
	if err != nil {
		return
	}
	_ = o.backend.PutObject(ctx, o.key(certIndexKey), bytes.NewReader(body),
		int64(len(body)), storage.PutOptions{ContentType: "application/json"})
}

// hydrateIndex seeds the in-memory expiry map from the published one.
//
// Without it, a leader that restarts starts with an empty map and its first
// noteIssued publishes an index containing ONE hostname — which every follower
// then reads as "everything else changed" and falls back to a full per-host
// refresh. Worse, the index would no longer describe storage, so nothing could
// be inferred from it. One read at startup keeps it truthful.
func (o *onDemand) hydrateIndex(ctx context.Context) {
	body, err := readObject(ctx, o.backend, o.key(certIndexKey))
	if err != nil {
		return
	}
	var published map[string]int64
	if err := json.Unmarshal(body, &published); err != nil {
		return
	}
	o.mu.Lock()
	o.index = published
	o.mu.Unlock()
}

// indexNotAfter reports the expiry the shared index records for a hostname.
func (o *onDemand) indexNotAfter(hostname string) (time.Time, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	ts, ok := o.index[strings.ToLower(hostname)]
	if !ok || ts == 0 {
		return time.Time{}, false
	}
	return time.Unix(ts, 0), true
}

// changedSince reads the published index and returns the hostnames whose
// expiry differs from what this node last saw — the follower's refresh list.
func (o *onDemand) changedSince(ctx context.Context, hosts []string) []string {
	body, err := readObject(ctx, o.backend, o.key(certIndexKey))
	if err != nil {
		// No index yet (or unreadable): fall back to refreshing everything, which
		// is what the pre-index behaviour did.
		return hosts
	}
	var published map[string]int64
	if err := json.Unmarshal(body, &published); err != nil {
		return hosts
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.index == nil {
		o.index = make(map[string]int64)
	}
	var changed []string
	for _, h := range hosts {
		h = strings.ToLower(h)
		if published[h] != o.index[h] {
			changed = append(changed, h)
		}
	}
	// Deliberately NOT adopted here. The caller adopts each hostname only after
	// its refresh actually succeeded (noteRefreshed): a failed storage read that
	// had already been remembered as done would never be retried, and the
	// handshake path cannot heal it either — it serves the stale-but-present
	// certificate from memory until that certificate expires.
	return changed
}

// noteRefreshed records that this node now holds what the published index says
// for `hostname`. Called only after a successful refresh.
func (o *onDemand) noteRefreshed(ctx context.Context, hostname string) {
	body, err := readObject(ctx, o.backend, o.key(certIndexKey))
	if err != nil {
		return
	}
	var published map[string]int64
	if err := json.Unmarshal(body, &published); err != nil {
		return
	}
	h := strings.ToLower(hostname)
	o.mu.Lock()
	if o.index == nil {
		o.index = make(map[string]int64)
	}
	o.index[h] = published[h]
	o.mu.Unlock()
}

// preflightOK reports whether hostname currently resolves to ExpectedTarget,
// with a long backoff on failure.
//
// This is the mechanism that makes an allow-set safe to hand to a CA. A
// hostname can be legitimately allowed and still not point here — the customer
// has not published the CNAME, or has removed it — and ordering for it burns a
// failed validation against a shared account limit every time. One DNS lookup
// per DUE issuance replaces that with nothing.
func (o *onDemand) preflightOK(ctx context.Context, hostname string) (bool, string) {
	if o.cfg.ExpectedTarget == "" {
		return true, ""
	}
	o.mu.Lock()
	until, backing := o.preflight[hostname]
	o.mu.Unlock()
	if backing && time.Now().Before(until) {
		return false, "recent DNS pre-flight failure"
	}

	target := strings.TrimSuffix(strings.ToLower(o.cfg.ExpectedTarget), ".")
	reason := o.resolveFn(ctx, hostname, target)
	if reason == "" {
		o.mu.Lock()
		delete(o.preflight, hostname)
		o.mu.Unlock()
		return true, ""
	}
	o.mu.Lock()
	o.preflight[hostname] = time.Now().Add(preflightBackoff)
	o.mu.Unlock()
	return false, reason
}

// resolvesTo returns "" when hostname resolves to target, else why not.
// Two ways to satisfy it, because DNS providers expose the same configuration
// differently: the canonical name after following CNAMEs, or a shared address
// set (a provider that flattens a CNAME at an apex, or an ALIAS record).
func (o *onDemand) resolvesTo(ctx context.Context, hostname, target string) string {
	lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cname, err := o.resolver.LookupCNAME(lookupCtx, hostname)
	if err == nil {
		if strings.TrimSuffix(strings.ToLower(cname), ".") == target {
			return ""
		}
	}
	ours, err := o.resolver.LookupHost(lookupCtx, target)
	if err != nil {
		// We cannot tell — do NOT record a failure. Failing open here is safe
		// because the CA still validates; failing closed on our own resolver
		// trouble would stop issuing for correctly configured customers.
		return ""
	}
	theirs, err := o.resolver.LookupHost(lookupCtx, hostname)
	if err != nil {
		// FAIL OPEN, exactly as a failure on the target side does. A lookup error
		// is "we cannot tell", not "the customer unpointed it" — and treating it
		// as the latter locked a demonstrably-working hostname out of issuance
		// for a full backoff window over one SERVFAIL. The CA validates
		// independently, so the cost of being wrong in this direction is one
		// failed order rather than a day of outage.
		return ""
	}
	ourSet := make(map[string]struct{}, len(ours))
	for _, a := range ours {
		ourSet[a] = struct{}{}
	}
	for _, a := range theirs {
		if _, ok := ourSet[a]; ok {
			return ""
		}
	}
	return fmt.Sprintf("resolves to %v, not to %s", theirs, target)
}

// tokenBucket is a simple sliding-window counter: at most `max` events per
// `window`. Used for new orders, where the point is not smoothness but a hard
// ceiling below the CA's own.
type tokenBucket struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	events []time.Time
	now    func() time.Time
}

func newTokenBucket(max int, window time.Duration) *tokenBucket {
	return &tokenBucket{max: max, window: window, now: time.Now}
}

// take consumes one token, reporting whether one was available.
func (b *tokenBucket) take() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := b.now().Add(-b.window)
	kept := b.events[:0]
	for _, t := range b.events {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	b.events = kept
	if len(b.events) >= b.max {
		return false
	}
	b.events = append(b.events, b.now())
	return true
}

// startOnDemand runs the allow-set refresh loop. Separate from the maintenance
// loop and faster than it: the set must track the control plane closely (a
// customer who just verified a hostname should be served promptly), while
// issuance runs at the slower certificate cadence.
func (m *Manager) startOnDemand() {
	if m.onDemand == nil {
		return
	}
	safego.Go(m.logger, "tls-ondemand", func() {
		m.refreshAllowSet()
		ticker := time.NewTicker(m.onDemand.cfg.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.refreshAllowSet()
			case <-m.stopCh:
				return
			}
		}
	})
}

func (m *Manager) refreshAllowSet() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if m.isLeader() {
		m.onDemand.refreshLeader(ctx, m.logger)
		return
	}
	if err := m.onDemand.refreshFollower(ctx); err != nil {
		m.logger.Debug("TLS: on-demand allow-set not readable yet", "error", err)
	}
}

// readObject is a small helper around Backend.GetObject.
func readObject(ctx context.Context, backend storage.Backend, key string) ([]byte, error) {
	rc, err := backend.GetObject(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}
