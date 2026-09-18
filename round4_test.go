package certmanager

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Open-Email/go-certs-manager/dane"
	"github.com/Open-Email/go-certs-manager/storage"
)

// onDemandLeader builds a leader with a dynamic allow-set over one backend.
func onDemandLeader(t *testing.T, backend storage.Backend, ca *countingCA, hosts ...string) *Manager {
	t.Helper()
	m := newOnDemandManager(t, backend, true, OnDemandConfig{MaxConcurrentOrders: 2})
	m.issuer = ca
	m.renewBefore = 30 * 24 * time.Hour
	m.retries = newRetryBudget(3)
	m.onDemand.store(hosts)
	return m
}

// A write that failed on our side but landed on the server's is the ordinary
// shape of a dropped connection. The next flush finds the chain already there
// and lets go of its copy — and that path announced nothing, so the hostname
// stayed invisible to every follower until it expired.
func TestFlushHeldChains_AnnouncesAChainItFindsAlreadyStored(t *testing.T) {
	fs, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := onDemandLeader(t, fs, &countingCA{}, "vanity.example.com")

	cert := holdChain(t, m, "vanity.example.com", 61)
	// The PUT the node believes failed actually committed: storage has exactly
	// the chain still being held.
	storeHeldChain(t, m, "vanity.example.com")

	m.maintainOnce()

	if got := m.certCache.pendingDomains(); len(got) != 0 {
		t.Fatalf("still holding %v after storage turned out to have it", got)
	}
	notAfter, known := m.onDemand.indexNotAfter("vanity.example.com")
	if !known {
		t.Fatal("a chain found already stored was never announced; no follower will refresh it")
	}
	if !notAfter.Equal(cert.Leaf.NotAfter) {
		t.Fatalf("index says %v, certificate says %v", notAfter, cert.Leaf.NotAfter)
	}
}

// A handshake loads the certificate into memory. That alone used to be enough
// to hide the hostname from maintenance for good: in memory means it is neither
// a first issuance nor a renewal, so nothing ever looked at it again — and
// nothing announced it.
func TestMaintainOnDemand_AnnouncesWhatMemoryHoldsAndTheIndexDoesNot(t *testing.T) {
	fs, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ca := &countingCA{}
	m := onDemandLeader(t, fs, ca, "vanity.example.com")

	// In memory and in storage, but never announced — a handshake got there
	// first, or a demoted node stored it.
	cert := holdChain(t, m, "vanity.example.com", 62)
	storeHeldChain(t, m, "vanity.example.com")
	m.certCache.dropPending("vanity.example.com")
	if _, known := m.onDemand.indexNotAfter("vanity.example.com"); known {
		t.Fatal("setup: the index should not know this hostname")
	}

	m.maintainOnDemand(true)

	if ca.orders != 0 {
		t.Fatalf("CA saw %d order(s) for a hostname already held, want 0", ca.orders)
	}
	notAfter, known := m.onDemand.indexNotAfter("vanity.example.com")
	if !known {
		t.Fatal("the leader holds a certificate the index does not name and never published it")
	}
	if !notAfter.Equal(cert.Leaf.NotAfter) {
		t.Fatalf("index says %v, certificate says %v", notAfter, cert.Leaf.NotAfter)
	}
}

// One dropped PUT on the index must not cost days of follower blindness. The
// publication is owed, and the next tick pays it.
func TestOnDemandIndex_RepublishesAfterAFailedWrite(t *testing.T) {
	fs, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	backend := &flakyBackend{Backend: fs, failFor: certIndexKey, failPuts: 1}
	m := onDemandLeader(t, backend, &countingCA{}, "vanity.example.com")

	holdChain(t, m, "vanity.example.com", 63)
	if err := m.onDemand.noteIssued(ctx, "vanity.example.com", time.Now().Add(48*time.Hour)); err == nil {
		t.Fatal("setup: the index write should have failed")
	}
	if _, err := readObject(ctx, backend, m.onDemand.key(certIndexKey)); err == nil {
		t.Fatal("setup: nothing should be published yet")
	}

	// A later tick, with no other hostname to carry it along.
	m.maintainOnDemand(true)

	body, err := readObject(ctx, backend, m.onDemand.key(certIndexKey))
	if err != nil {
		t.Fatalf("the index was never republished: %v", err)
	}
	if !strings.Contains(string(body), "vanity.example.com") {
		t.Fatalf("republished index does not name the hostname: %s", body)
	}
}

// The soak record says which TLSA record the operator must keep published. The
// storage failure that interrupts a ceremony takes that write with it just as
// readily as the chain's, and after the promotion there is no live old key left
// to reconstruct it from.
func TestReconcileCeremony_RecordsTheRetiringDigestTheInterruptionLost(t *testing.T) {
	fs, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_ = fs
	m, ca, flaky := newFlakyManager(t, persistAttempts)
	// A real outage takes the DANE write with the chain write. Only the lease
	// keeps working, which is what lets the order happen at all.
	outage := &flakyBackend{Backend: flaky.Backend, failFor: "dane/retiring/", failPuts: persistAttempts}
	m.dane = newDANEController(m.keyStore, outage, "", []string{"mx.example.com"}, 3600, 24*time.Hour, testLogger())

	liveBefore, err := m.keyStore.LoadCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	oldDigest, err := dane.SPKISHA256(liveBefore.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.keyStore.GenerateNextCertKey(ctx, "mx.example.com"); err != nil {
		t.Fatal(err)
	}

	// Storage is down: the chain is held, and the soak record never lands.
	if err := m.ActivateCertificateKey("mx.example.com", true); !errors.Is(err, ErrOrderNotPersisted) {
		t.Fatalf("err = %v, want ErrOrderNotPersisted", err)
	}
	if _, ok := m.dane.getRetiring(ctx, "mx.example.com"); ok {
		t.Fatal("setup: the retiring record should not have survived the outage")
	}

	// Storage recovers and the ceremony rolls forward.
	flaky.failPuts = 0
	outage.failPuts = 0
	if stored := m.flushHeldChains(ctx); len(stored) != 1 {
		t.Fatalf("flush stored %v, want the ceremony's chain", stored)
	}
	m.reconcileCeremony(ctx, "mx.example.com")

	rec, ok := m.dane.getRetiring(ctx, "mx.example.com")
	if !ok {
		t.Fatal("no retiring digest recorded; the old TLSA record gets dropped with no soak")
	}
	if rec.Digest != oldDigest {
		t.Fatalf("retiring digest = %s, want the outgoing key's %s", rec.Digest, oldDigest)
	}
	if ca.orders != 1 {
		t.Fatalf("CA saw %d order(s), want 1", ca.orders)
	}
}

// Re-running an activation after a storage failure must not buy the same
// certificate twice: the first attempt's order is held, bound to the staged key.
func TestActivateCertificateKey_ReusesTheOrderItAlreadyPlaced(t *testing.T) {
	ctx := context.Background()
	m, ca, flaky := newFlakyManager(t, 100) // down for both attempts

	if _, err := m.keyStore.GenerateNextCertKey(ctx, "mx.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := m.ActivateCertificateKey("mx.example.com", true); !errors.Is(err, ErrOrderNotPersisted) {
		t.Fatalf("first attempt: err = %v, want ErrOrderNotPersisted", err)
	}
	if ca.orders != 1 {
		t.Fatalf("CA saw %d order(s) on the first attempt, want 1", ca.orders)
	}

	// The operator re-runs it while storage is still down.
	if err := m.ActivateCertificateKey("mx.example.com", true); !errors.Is(err, ErrOrderNotPersisted) {
		t.Fatalf("second attempt: err = %v, want ErrOrderNotPersisted", err)
	}
	if ca.orders != 1 {
		t.Fatalf("CA saw %d order(s) after a retry, want still 1 — the held order must be reused", ca.orders)
	}

	// And once storage recovers it completes, still on that one order.
	flaky.failPuts = 0
	if err := m.ActivateCertificateKey("mx.example.com", true); err != nil {
		t.Fatalf("third attempt: %v", err)
	}
	if ca.orders != 1 {
		t.Fatalf("CA saw %d order(s) in total, want 1", ca.orders)
	}
}

// The failures charged while storage was down stop mattering the moment the
// chain is stored; leaving the domain throttled punishes it for a problem that
// is over.
func TestFlushHeldChains_ClearsTheRetryBudgetItCharged(t *testing.T) {
	m, _, flaky := newFlakyManager(t, 100) // down throughout

	// Three forced renewals, each reaching the CA and failing to store: exactly
	// the budget, so the fourth attempt would be refused.
	for i := 0; i < 3; i++ {
		if _, err := m.RenewCertificate("mx.example.com"); !errors.Is(err, ErrOrderNotPersisted) {
			t.Fatalf("attempt %d: err = %v, want ErrOrderNotPersisted", i+1, err)
		}
	}
	if _, ok := m.retries.allow("mx.example.com"); ok {
		t.Fatal("setup: the budget should be exhausted after three failures")
	}

	ctx := context.Background()
	flaky.failPuts = 0
	if stored := m.flushHeldChains(ctx); len(stored) != 1 {
		t.Fatalf("flush stored %v, want [mx.example.com]", stored)
	}

	if _, ok := m.retries.allow("mx.example.com"); !ok {
		t.Error("the domain is still throttled after its chain was stored")
	}
}

// storeHeldChain writes the chain currently held for domain into storage,
// standing in for a PUT that landed on the server after the client gave up.
func storeHeldChain(t *testing.T, m *Manager, domain string) {
	t.Helper()
	held := m.certCache.pendingSnapshot()
	p, ok := held[strings.ToLower(domain)]
	if !ok {
		t.Fatalf("nothing held for %s", domain)
	}
	if err := m.certCache.persist(context.Background(), domain, p.chainPEM, 1); err != nil {
		t.Fatal(err)
	}
}
