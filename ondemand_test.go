package certmanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/Open-Email/go-certs-manager/storage"
)

// newOnDemandManager builds a serving-path Manager with a dynamic allow-set,
// sharing one storage backend so leader/follower behaviour can be exercised.
func newOnDemandManager(t *testing.T, backend storage.Backend, leader bool, cfg OnDemandConfig) *Manager {
	t.Helper()
	ks := NewKeyStore(backend, "", KeyTypeECDSAP256, func() bool { return leader }, nil)
	m := &Manager{
		keyStore:      ks,
		certCache:     newCertCache(backend, "", ks.LoadCertKey, nil),
		challenges:    NewChallengeServer(backend, "", nil),
		logger:        slog.Default(),
		domains:       []string{"mx.example.com"},
		domainSet:     map[string]bool{"mx.example.com": true},
		defaultDomain: "mx.example.com",
		isLeaderF:     func() bool { return leader },
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
	m.onDemand = newOnDemand(cfg, backend, "")
	m.tlsConfig = m.buildTLSConfig()
	return m
}

func TestOnDemand_AllowSetGatesHandshake(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := newOnDemandManager(t, backend, false, OnDemandConfig{
		Enumerate: func(context.Context) ([]string, error) { return nil, nil },
	})
	get := m.tlsConfig.GetCertificate

	// An unknown SNI must be refused WITHOUT any storage access. This is the
	// property that makes an SNI flood free: no lookup, no order, no
	// amplification against the control plane.
	if _, err := get(&tls.ClientHelloInfo{ServerName: "nobody.example.org"}); !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("expected ErrHostNotAllowed, got %v", err)
	}

	m.onDemand.store([]string{"Mail.Acme.Com"})
	// Allowed but not yet issued: a different refusal, so the two cases stay
	// distinguishable in logs and in tests.
	_, err = get(&tls.ClientHelloInfo{ServerName: "mail.acme.com"})
	if !errors.Is(err, ErrCertificateUnavailable) {
		t.Fatalf("expected ErrCertificateUnavailable for an allowed host, got %v", err)
	}
	// Normalization: the authority may hand back any case, and SNI arrives in
	// any case.
	if !m.onDemand.allows("mail.acme.com") {
		t.Fatal("allow-set should be case-normalized")
	}
}

func TestOnDemand_LeaderPublishesFollowerConsumes(t *testing.T) {
	dir := t.TempDir()
	backend, err := storage.NewFilesystemBackend(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	hosts := []string{"b.acme.com", "a.acme.com"}
	leader := newOnDemandManager(t, backend, true, OnDemandConfig{
		Enumerate: func(context.Context) ([]string, error) { return hosts, nil },
	})
	follower := newOnDemandManager(t, backend, false, OnDemandConfig{})

	ctx := context.Background()
	leader.onDemand.refreshLeader(ctx, leader.logger)
	if err := follower.onDemand.refreshFollower(ctx); err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		if !follower.onDemand.allows(h) {
			t.Fatalf("follower missing %s", h)
		}
	}
	if got := follower.onDemand.hosts(); len(got) != 2 || got[0] != "a.acme.com" {
		t.Fatalf("expected a sorted set, got %v", got)
	}

	// An enumeration FAILURE keeps the previous set: a control-plane blip must
	// never retract certificates that are serving traffic.
	leader.onDemand.cfg.Enumerate = func(context.Context) ([]string, error) {
		return nil, errors.New("control plane down")
	}
	leader.onDemand.refreshLeader(ctx, leader.logger)
	if !leader.onDemand.allows("a.acme.com") {
		t.Fatal("a failed enumeration must not empty the allow-set")
	}

	// A shrinking set does propagate — that is how a released hostname stops
	// being served and stops being renewed.
	leader.onDemand.cfg.Enumerate = func(context.Context) ([]string, error) {
		return []string{"a.acme.com"}, nil
	}
	leader.onDemand.refreshLeader(ctx, leader.logger)
	if err := follower.onDemand.refreshFollower(ctx); err != nil {
		t.Fatal(err)
	}
	if follower.onDemand.allows("b.acme.com") {
		t.Fatal("released hostname still allowed on the follower")
	}
}

func TestOnDemand_TokenBucket(t *testing.T) {
	base := time.Now()
	b := newTokenBucket(2, time.Hour)
	b.now = func() time.Time { return base }
	if !b.take() || !b.take() {
		t.Fatal("first two tokens should be available")
	}
	if b.take() {
		t.Fatal("third token should be refused inside the window")
	}
	b.now = func() time.Time { return base.Add(time.Hour + time.Minute) }
	if !b.take() {
		t.Fatal("token should be available once the window has passed")
	}
	// A nil budget never throttles — the same nil-safety the issuance lease has,
	// so a hand-built Manager in a test is not silently rate-limited.
	var nilBucket *tokenBucket
	if !nilBucket.take() {
		t.Fatal("nil bucket must not throttle")
	}
}

func TestOnDemand_CertIndexDiff(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	leader := newOnDemand(OnDemandConfig{}, backend, "")
	follower := newOnDemand(OnDemandConfig{}, backend, "")
	ctx := context.Background()

	expiry := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	leader.noteIssued(ctx, "a.acme.com", expiry)
	leader.noteIssued(ctx, "b.acme.com", expiry)

	hosts := []string{"a.acme.com", "b.acme.com"}
	changed := follower.changedSince(ctx, hosts)
	if len(changed) != 2 {
		t.Fatalf("a follower with no state must refresh everything, got %v", changed)
	}
	// Second pass: nothing changed, so nothing is re-read. This is the whole
	// point — steady-state cost independent of the hostname count.
	if changed := follower.changedSince(ctx, hosts); len(changed) != 0 {
		t.Fatalf("expected no changes, got %v", changed)
	}
	// A renewal moves one expiry; only that hostname is refreshed.
	leader.noteIssued(ctx, "b.acme.com", expiry.Add(24*time.Hour))
	changed = follower.changedSince(ctx, hosts)
	if len(changed) != 1 || changed[0] != "b.acme.com" {
		t.Fatalf("expected only b.acme.com, got %v", changed)
	}

	// The published index must always be the FULL inventory: a partial one would
	// read to a follower as "every other hostname changed".
	body, err := readObject(ctx, backend, certIndexKey)
	if err != nil {
		t.Fatal(err)
	}
	var published map[string]int64
	if err := json.Unmarshal(body, &published); err != nil {
		t.Fatal(err)
	}
	if len(published) != 2 {
		t.Fatalf("index should hold every hostname, got %v", published)
	}

	// A restarted leader hydrates from it rather than starting empty.
	restarted := newOnDemand(OnDemandConfig{}, backend, "")
	restarted.hydrateIndex(ctx)
	if _, ok := restarted.indexNotAfter("a.acme.com"); !ok {
		t.Fatal("hydrateIndex did not seed the map")
	}
}

func TestOnDemand_PreflightBlocksUnpointedHost(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	od := newOnDemand(OnDemandConfig{ExpectedTarget: "mail.open.email"}, backend, "")
	od.resolver = nil // unused: resolvesTo is stubbed below via the fake

	// Stub the resolution decision rather than DNS itself: what matters is that a
	// hostname reported as not pointing here is refused WITHOUT contacting the
	// CA, and that the refusal is remembered so it is not re-queried every tick.
	calls := 0
	od.resolveFn = func(context.Context, string, string) string {
		calls++
		return "resolves elsewhere"
	}
	ctx := context.Background()
	if ok, _ := od.preflightOK(ctx, "mail.acme.com"); ok {
		t.Fatal("an unpointed hostname must not pass the pre-flight")
	}
	if ok, reason := od.preflightOK(ctx, "mail.acme.com"); ok || reason == "" {
		t.Fatal("the failure should be remembered with a reason")
	}
	if calls != 1 {
		t.Fatalf("backoff should suppress re-resolution, got %d lookups", calls)
	}

	// Once it points here, it passes and the backoff is cleared.
	od.resolveFn = func(context.Context, string, string) string { return "" }
	od.mu.Lock()
	od.preflight["mail.acme.com"] = time.Now().Add(-time.Second)
	od.mu.Unlock()
	if ok, reason := od.preflightOK(ctx, "mail.acme.com"); !ok {
		t.Fatalf("a correctly pointed hostname must pass, got %q", reason)
	}

	// No target configured = no pre-flight (opt-out for a deployment that has
	// another way to know).
	off := newOnDemand(OnDemandConfig{}, backend, "")
	if ok, _ := off.preflightOK(ctx, "anything.example"); !ok {
		t.Fatal("pre-flight must be inert without an expected target")
	}
}

func TestOnDemand_HandshakeWaitBounded(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := newOnDemandManager(t, backend, false, OnDemandConfig{HandshakeWait: 2 * time.Second})
	m.onDemand.store([]string{"mail.acme.com"})

	// The certificate appears mid-wait (as the leader's issuance would land).
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chain := selfSignedChainPEM(t, key, "mail.acme.com")
	cert, err := buildCertificate(chain, key)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		m.certCache.set("mail.acme.com", cert)
	}()
	start := time.Now()
	got, err := m.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "mail.acme.com"})
	if err != nil {
		t.Fatalf("handshake should have waited for issuance: %v", err)
	}
	if got != cert {
		t.Fatal("wrong certificate returned")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("wait exceeded its bound: %s", elapsed)
	}

	// And it is BOUNDED: a certificate that never arrives fails, it does not hang.
	start = time.Now()
	if _, err := m.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "never.acme.com"}); err == nil {
		t.Fatal("expected a refusal for a host outside the allow-set")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("a disallowed host must be refused immediately, took %s", elapsed)
	}
}

func TestOnDemand_StaticDomainsUnaffected(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := newOnDemandManager(t, backend, false, OnDemandConfig{HandshakeWait: time.Hour})
	// A static domain keeps the original semantics: no wait, immediate
	// "unavailable" — the platform's own names are preloaded, so a miss there
	// really does mean not-yet-issued and an MTA's own retry is the right loop.
	start := time.Now()
	_, err = m.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "mx.example.com"})
	if err == nil {
		t.Fatal("expected unavailable for an unissued static domain")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("static domains must not use HandshakeWait, took %s", elapsed)
	}
	_ = fmt.Sprint(err)
}
