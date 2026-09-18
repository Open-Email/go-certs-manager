package certmanager

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Open-Email/go-certs-manager/storage"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// flakyBackend fails the next failPuts writes to keys containing failFor, and
// counts every write, so a test can say "storage is down" and then "storage is
// back" without a second implementation of a backend.
type flakyBackend struct {
	storage.Backend
	failFor  string
	failPuts int
	puts     int
}

func (b *flakyBackend) PutObject(ctx context.Context, key string, r io.Reader, size int64, opts storage.PutOptions) error {
	if strings.Contains(key, b.failFor) {
		b.puts++
		if b.failPuts > 0 {
			b.failPuts--
			return errors.New("storage unavailable")
		}
	}
	return b.Backend.PutObject(ctx, key, r, size, opts)
}

// newFlakyManager is a leader with no certificate yet, whose chain writes fail
// the first failPuts times.
func newFlakyManager(t *testing.T, failPuts int) (*Manager, *countingCA, *flakyBackend) {
	t.Helper()
	fs, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	backend := &flakyBackend{Backend: fs, failFor: "certs/", failPuts: failPuts}
	leader := func() bool { return true }
	ks := NewKeyStore(backend, "", KeyTypeECDSAP256, leader, nil)
	ca := &countingCA{}
	m := &Manager{
		keyStore:    ks,
		certCache:   newCertCache(backend, "", ks.LoadCertKey, nil),
		issuer:      ca,
		logger:      testLogger(),
		domains:     []string{"mx.example.com"},
		domainSet:   map[string]bool{"mx.example.com": true},
		isLeaderF:   leader,
		renewBefore: 30 * 24 * time.Hour,
		retries:     newRetryBudget(3),
		leaser:      newLeaser(t, backend, "node-self", time.Minute),
	}
	if _, err := ks.LoadOrCreateCertKey(context.Background(), "mx.example.com"); err != nil {
		t.Fatal(err)
	}
	return m, ca, backend
}

// A write that fails once must not cost an order: persist retries in place.
func TestStore_RetriesATransientWriteFailure(t *testing.T) {
	m, ca, backend := newFlakyManager(t, 1)
	ctx := context.Background()

	if err := m.renewIfNeeded(ctx, "mx.example.com"); err != nil {
		t.Fatalf("renewIfNeeded: %v", err)
	}
	if ca.orders != 1 {
		t.Fatalf("CA saw %d order(s), want 1", ca.orders)
	}
	if backend.puts != 2 {
		t.Fatalf("%d chain write(s), want 2 (one failed, one retried)", backend.puts)
	}
	if got := m.certCache.pendingDomains(); len(got) != 0 {
		t.Fatalf("held %v after the retry succeeded, want nothing", got)
	}
	if _, err := m.certCache.loadChain(ctx, "mx.example.com"); err != nil {
		t.Fatalf("chain not in storage: %v", err)
	}
}

// Storage down for the whole issuance: the order is spent, so the certificate
// must be served rather than dropped, the caller must be told not to retry, and
// the write must be re-attempted on the next maintenance tick.
func TestIssuance_HoldsAndLaterStoresAnOrderStorageRefused(t *testing.T) {
	m, ca, backend := newFlakyManager(t, persistAttempts)
	ctx := context.Background()

	err := m.renewIfNeeded(ctx, "mx.example.com")
	if err == nil || !errors.Is(err, ErrOrderNotPersisted) {
		t.Fatalf("err = %v, want ErrOrderNotPersisted", err)
	}
	if ca.orders != 1 {
		t.Fatalf("CA saw %d order(s), want 1", ca.orders)
	}
	// Paid for, so served.
	cert, ok := m.certCache.Get("mx.example.com")
	if !ok || cert.Leaf.SerialNumber.Int64() != 101 {
		t.Fatalf("the issued certificate is not being served (ok=%v)", ok)
	}
	if got := m.certCache.pendingDomains(); len(got) != 1 || got[0] != "mx.example.com" {
		t.Fatalf("held %v, want [mx.example.com]", got)
	}
	if _, err := m.certCache.loadChain(ctx, "mx.example.com"); err == nil {
		t.Fatal("storage has the chain, but the test made every write fail")
	}

	// Storage recovers; the next tick writes what we already paid for and does
	// not order again.
	backend.failPuts = 0
	m.maintainOnce()

	if ca.orders != 1 {
		t.Fatalf("CA saw %d order(s) after recovery, want still 1 — the held chain must not be re-ordered", ca.orders)
	}
	if got := m.certCache.pendingDomains(); len(got) != 0 {
		t.Fatalf("still holding %v after storage recovered", got)
	}
	stored, err := m.certCache.loadChain(ctx, "mx.example.com")
	if err != nil {
		t.Fatalf("chain still not in storage: %v", err)
	}
	if na, err := leafNotAfterPEM(stored); err != nil || !na.Equal(cert.Leaf.NotAfter) {
		t.Fatalf("storage holds a different chain (notAfter=%v, err=%v)", na, err)
	}
}

// The held copy must never land on top of a newer one. A node that could not
// write may have lost leadership; the new leader's certificate is in storage,
// and putting ours back would walk the fleet onto the older expiry — the shape
// of the incident this whole area exists to prevent.
func TestFlushPending_NeverOverwritesANewerChain(t *testing.T) {
	m, _, backend := newFlakyManager(t, persistAttempts)
	ctx := context.Background()

	if err := m.renewIfNeeded(ctx, "mx.example.com"); !errors.Is(err, ErrOrderNotPersisted) {
		t.Fatalf("setup: err = %v, want ErrOrderNotPersisted", err)
	}
	held, _ := m.certCache.Get("mx.example.com")

	// A peer issues a longer-lived certificate for the same name.
	backend.failPuts = 0
	key, err := m.keyStore.LoadCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	peerChain, err := chainWithSerialNotAfter(key, "mx.example.com", 42, held.Leaf.NotAfter.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.certCache.persist(ctx, "mx.example.com", peerChain, 1); err != nil {
		t.Fatalf("peer write: %v", err)
	}

	m.flushHeldChains(ctx)

	stored, err := m.certCache.loadChain(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseFirstLeaf(t, stored)
	if leaf.SerialNumber.Int64() != 42 {
		t.Fatalf("storage holds serial %d, want the peer's 42 — the held copy overwrote it", leaf.SerialNumber.Int64())
	}
	if got := m.certCache.pendingDomains(); len(got) != 0 {
		t.Fatalf("still holding %v, want it dropped once storage moved ahead", got)
	}
}

// A chain that does not build is not an order worth keeping: nothing is served
// and nothing is held.
func TestIssuance_DoesNotHoldAnUnusableChain(t *testing.T) {
	m, _, _ := newFlakyManager(t, 0)
	m.issuer = &countingCA{chain: []byte("not a certificate")}

	err := m.renewIfNeeded(context.Background(), "mx.example.com")
	if err == nil || errors.Is(err, ErrOrderNotPersisted) {
		t.Fatalf("err = %v, want a plain build failure", err)
	}
	if _, ok := m.certCache.Get("mx.example.com"); ok {
		t.Fatal("an unusable chain is being served")
	}
	if got := m.certCache.pendingDomains(); len(got) != 0 {
		t.Fatalf("held %v, want nothing", got)
	}
}

func parseFirstLeaf(t *testing.T, chainPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(chainPEM)
	if block == nil {
		t.Fatal("no PEM block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// readErrorBackend fails reads of the chain for one domain while leaving writes
// working, so a test can say "storage did not answer" rather than "storage is
// empty" — the two the flush must never confuse.
type readErrorBackend struct {
	storage.Backend
	failGetFor string
	puts       int
}

func (b *readErrorBackend) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	if strings.Contains(key, b.failGetFor) {
		return nil, errors.New("storage read timed out")
	}
	return b.Backend.GetObject(ctx, key)
}

func (b *readErrorBackend) PutObject(ctx context.Context, key string, r io.Reader, size int64, opts storage.PutOptions) error {
	if strings.Contains(key, "certs/") {
		b.puts++
	}
	return b.Backend.PutObject(ctx, key, r, size, opts)
}

// "I could not look" is not "nothing is there". A flush that wrote on a failed
// read would put an older chain over a newer one whenever storage is degraded
// in both directions at once — the way it usually is.
func TestFlushHeldChains_DoesNotWriteWhenStorageCannotBeRead(t *testing.T) {
	m, _, flaky := newFlakyManager(t, persistAttempts)
	ctx := context.Background()

	if err := m.renewIfNeeded(ctx, "mx.example.com"); !errors.Is(err, ErrOrderNotPersisted) {
		t.Fatalf("setup: err = %v, want ErrOrderNotPersisted", err)
	}
	flaky.failPuts = 0

	blind := &readErrorBackend{Backend: flaky.Backend, failGetFor: "certs/mx.example.com"}
	m.certCache.backend = blind

	if stored := m.flushHeldChains(ctx); len(stored) != 0 {
		t.Fatalf("flush reported %v stored, want none while the read fails", stored)
	}
	if blind.puts != 0 {
		t.Fatalf("%d chain write(s) on an unreadable storage, want 0", blind.puts)
	}
	if got := m.certCache.pendingDomains(); len(got) != 1 {
		t.Fatalf("held %v, want the chain kept for a later tick", got)
	}
}

// The tick is the retry. A flush that slept through the in-line backoff would
// spend the maintenance budget on a domain whose next chance is minutes away.
func TestFlushHeldChains_WritesOncePerTick(t *testing.T) {
	m, _, flaky := newFlakyManager(t, persistAttempts)
	ctx := context.Background()

	if err := m.renewIfNeeded(ctx, "mx.example.com"); !errors.Is(err, ErrOrderNotPersisted) {
		t.Fatalf("setup: err = %v, want ErrOrderNotPersisted", err)
	}

	flaky.failPuts = 1 // this tick's single attempt fails
	flaky.puts = 0
	start := time.Now()
	if stored := m.flushHeldChains(ctx); len(stored) != 0 {
		t.Fatalf("flush reported %v stored, want none", stored)
	}
	if flaky.puts != 1 {
		t.Fatalf("%d write attempt(s) in one tick, want exactly 1", flaky.puts)
	}
	if elapsed := time.Since(start); elapsed > persistBackoff {
		t.Fatalf("flush slept %v; it must not run the in-line backoff", elapsed)
	}

	// The next tick gets its own attempt.
	if stored := m.flushHeldChains(ctx); len(stored) != 1 {
		t.Fatalf("second tick stored %v, want [mx.example.com]", stored)
	}
}

// Dropping the held copy is only half of it: a node that keeps serving the
// superseded chain is serving a retired SPKI, which after a peer's key
// replacement is a DANE failure, not a stale certificate.
func TestFlushHeldChains_AdoptsTheNewerChainItDefersTo(t *testing.T) {
	m, _, flaky := newFlakyManager(t, persistAttempts)
	ctx := context.Background()

	if err := m.renewIfNeeded(ctx, "mx.example.com"); !errors.Is(err, ErrOrderNotPersisted) {
		t.Fatalf("setup: err = %v, want ErrOrderNotPersisted", err)
	}
	held, _ := m.certCache.Get("mx.example.com")
	flaky.failPuts = 0

	key, err := m.keyStore.LoadCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	peerChain, err := chainWithSerialNotAfter(key, "mx.example.com", 42, held.Leaf.NotAfter.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.certCache.persist(ctx, "mx.example.com", peerChain, 1); err != nil {
		t.Fatal(err)
	}

	m.flushHeldChains(ctx)

	serving, ok := m.certCache.Get("mx.example.com")
	if !ok {
		t.Fatal("nothing served after the flush")
	}
	if got := serving.Leaf.SerialNumber.Int64(); got != 42 {
		t.Fatalf("still serving serial %d after deferring to storage; want the peer's 42", got)
	}
}

// A peer flushing or issuing the same domain must not race us: two nodes each
// holding a chain could otherwise land in either order, and the older last.
func TestFlushHeldChains_WaitsForTheIssuanceLease(t *testing.T) {
	m, _, flaky := newFlakyManager(t, persistAttempts)
	ctx := context.Background()

	if err := m.renewIfNeeded(ctx, "mx.example.com"); !errors.Is(err, ErrOrderNotPersisted) {
		t.Fatalf("setup: err = %v, want ErrOrderNotPersisted", err)
	}
	flaky.failPuts = 0

	peer := newLeaser(t, flaky, "node-peer", time.Minute)
	rel, ok := peer.acquire(ctx, "mx.example.com")
	if !ok {
		t.Fatal("peer should acquire")
	}

	if stored := m.flushHeldChains(ctx); len(stored) != 0 {
		t.Fatalf("flush stored %v while a peer held the lease", stored)
	}
	if got := m.certCache.pendingDomains(); len(got) != 1 {
		t.Fatalf("held %v, want the chain kept until the lease frees", got)
	}

	rel()
	if stored := m.flushHeldChains(ctx); len(stored) != 1 {
		t.Fatalf("flush stored %v once the lease was free, want [mx.example.com]", stored)
	}
}

// A chain stored late must be announced, or the followers that read the index
// to decide what to refresh never learn it exists.
func TestAnnounceStoredChains_PublishesALateOnDemandWrite(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	m := newOnDemandManager(t, backend, true, OnDemandConfig{})

	cert := holdChain(t, m, "vanity.example.com", 7)

	if _, known := m.onDemand.indexNotAfter("vanity.example.com"); known {
		t.Fatal("index already knows the hostname before the announcement")
	}

	m.announceStoredChains(ctx, true, []string{"vanity.example.com"})

	notAfter, known := m.onDemand.indexNotAfter("vanity.example.com")
	if !known {
		t.Fatal("a late write was not published to the on-demand index; no follower will ever refresh it")
	}
	if !notAfter.Equal(cert.Leaf.NotAfter) {
		t.Fatalf("index says %v, certificate says %v", notAfter, cert.Leaf.NotAfter)
	}
}

// Only the leader publishes, and only for hostnames the index is for.
func TestAnnounceStoredChains_LeaderOnlyAndDynamicOnly(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Both managers must actually HOLD the certificate, or the announcement
	// would be skipped for want of one and the guards under test never reached.
	follower := newOnDemandManager(t, backend, false, OnDemandConfig{})
	holdChain(t, follower, "vanity.example.com", 11)
	follower.announceStoredChains(ctx, false, []string{"vanity.example.com"})
	if _, known := follower.onDemand.indexNotAfter("vanity.example.com"); known {
		t.Error("a follower published to the shared on-demand index")
	}

	leader := newOnDemandManager(t, backend, true, OnDemandConfig{})
	holdChain(t, leader, "mx.example.com", 12)
	leader.announceStoredChains(ctx, true, []string{"mx.example.com"}) // static
	if _, known := leader.onDemand.indexNotAfter("mx.example.com"); known {
		t.Error("a static domain was written into the on-demand index")
	}
}

// The key-replacement ceremony spends an order like any other, so a storage
// failure must not throw it away. The key must stay STAGED while it does:
// promoting against a chain storage does not have leaves every follower pairing
// the new live key with the old chain, which is ErrKeyCertMismatch and no TLS
// at all. reconcileCeremony finishes the job once the flush lands the chain.
func TestActivateCertificateKey_HoldsItsOrderAndCompletesLater(t *testing.T) {
	m, ca, flaky := newFlakyManager(t, persistAttempts)
	ctx := context.Background()

	liveBefore, err := m.keyStore.LoadCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.keyStore.GenerateNextCertKey(ctx, "mx.example.com"); err != nil {
		t.Fatal(err)
	}

	err = m.ActivateCertificateKey("mx.example.com", true)
	if err == nil || !errors.Is(err, ErrOrderNotPersisted) {
		t.Fatalf("err = %v, want ErrOrderNotPersisted", err)
	}
	if ca.orders != 1 {
		t.Fatalf("CA saw %d order(s), want 1", ca.orders)
	}
	if got := m.certCache.pendingDomains(); len(got) != 1 {
		t.Fatalf("held %v, want the ceremony's chain kept", got)
	}
	// Not promoted: storage still has no chain to pair a new live key with.
	liveNow, err := m.keyStore.LoadCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !liveNow.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(liveBefore.Public()) {
		t.Fatal("the staged key was promoted while its chain was still unstored")
	}

	// Storage recovers: the flush lands the chain, and the next maintenance
	// pass rolls the ceremony forward without another order.
	flaky.failPuts = 0
	if stored := m.flushHeldChains(ctx); len(stored) != 1 {
		t.Fatalf("flush stored %v, want [mx.example.com]", stored)
	}
	m.reconcileCeremony(ctx, "mx.example.com")

	liveAfter, err := m.keyStore.LoadCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if liveAfter.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(liveBefore.Public()) {
		t.Fatal("the ceremony never completed once its chain reached storage")
	}
	if ca.orders != 1 {
		t.Fatalf("CA saw %d order(s) in total, want 1 — completing the ceremony must not re-order", ca.orders)
	}
}

// holdChain puts a certificate for host into m's cache as a held, unwritten
// chain, and returns it.
func holdChain(t *testing.T, m *Manager, host string, serial int64) *tls.Certificate {
	t.Helper()
	ctx := context.Background()
	// Minted through a leader-backed KeyStore on the same backend: a follower's
	// own store refuses to create keys, which is the property keystore_test
	// covers and not the one under test here.
	ks := NewKeyStore(m.certCache.backend, "", KeyTypeECDSAP256, func() bool { return true }, nil)
	key, err := ks.LoadOrCreateCertKey(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := chainWithSerial(key, host, serial)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := buildCertificate(chain, key)
	if err != nil {
		t.Fatal(err)
	}
	m.certCache.hold(host, cert, chain)
	return cert
}

// The wiring, not just the step: a maintenance tick must flush a held chain AND
// announce it. Either half missing leaves an on-demand hostname that no
// follower is ever told to read.
func TestMaintainOnce_FlushesAndAnnouncesAHeldChain(t *testing.T) {
	m, _, flaky := newFlakyManager(t, 0)
	m.domains = nil // the static loop is not what this exercises
	m.onDemand = newOnDemand(OnDemandConfig{}, flaky, "")
	m.stopCh = make(chan struct{})

	cert := holdChain(t, m, "vanity.example.com", 21)

	m.maintainOnce()

	if _, err := m.certCache.loadChain(context.Background(), "vanity.example.com"); err != nil {
		t.Fatalf("the tick did not store the held chain: %v", err)
	}
	notAfter, known := m.onDemand.indexNotAfter("vanity.example.com")
	if !known {
		t.Fatal("the tick stored the chain but never announced it; followers will not refresh it")
	}
	if !notAfter.Equal(cert.Leaf.NotAfter) {
		t.Fatalf("index says %v, certificate says %v", notAfter, cert.Leaf.NotAfter)
	}
}
