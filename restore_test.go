package certmanager

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/Open-Email/go-certs-manager/storage"
)

// issuedLeader is a leader that has issued and stored mx.example.com, the
// ordinary state a deleted chain is taken from.
func issuedLeader(t *testing.T) (*Manager, *countingCA, *flakyBackend) {
	t.Helper()
	m, ca, backend := newFlakyManager(t, 0)
	m.stopCh = make(chan struct{})
	if err := m.renewIfNeeded(context.Background(), "mx.example.com"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	return m, ca, backend
}

func deleteChain(t *testing.T, b storage.Backend, domain string) {
	t.Helper()
	if err := b.RemoveObject(context.Background(), "certs/"+domain); err != nil {
		t.Fatal(err)
	}
}

// storedSerial is the serial of the leaf storage holds, or 0 for none.
func storedSerial(t *testing.T, m *Manager, domain string) int64 {
	t.Helper()
	chain, err := m.certCache.loadChain(context.Background(), domain)
	if err != nil {
		return 0
	}
	return parseFirstLeaf(t, chain).SerialNumber.Int64()
}

// The reported failure: a chain deleted from storage while the leader serves
// it. The leader never noticed, so a node restarting before the renewal window
// came up with no certificate. One tick must put it back — the same chain,
// without an order — so a node starting afterwards can load it.
func TestMaintainOnce_RestoresAChainDeletedFromStorage(t *testing.T) {
	m, ca, backend := issuedLeader(t)
	served := servedSerial(t, m)
	deleteChain(t, backend, "mx.example.com")

	m.maintainOnce()

	if got := storedSerial(t, m, "mx.example.com"); got != served {
		t.Fatalf("storage holds serial %d after the tick, want the served %d", got, served)
	}
	if ca.orders != 1 {
		t.Fatalf("CA saw %d orders, want 1: restoring must not re-order", ca.orders)
	}
	restarted := newCertCache(backend, "", m.keyStore.LoadCertKey, nil)
	if _, err := restarted.Refresh(context.Background(), "mx.example.com"); err != nil {
		t.Fatalf("a node starting after the tick still cannot load the certificate: %v", err)
	}
}

// Followers read storage; they do not write what they read back into it.
func TestMaintainOnce_OnlyTheLeaderRestores(t *testing.T) {
	m, _, backend := issuedLeader(t)
	m.isLeaderF = func() bool { return false }
	deleteChain(t, backend, "mx.example.com")

	m.maintainOnce()

	if got := storedSerial(t, m, "mx.example.com"); got != 0 {
		t.Fatalf("a follower wrote serial %d back to storage", got)
	}
}

type listErrorBackend struct{ storage.Backend }

func (listErrorBackend) ListObjects(context.Context, string, bool) ([]storage.ObjectInfo, error) {
	return nil, errors.New("list timed out")
}

// A listing that failed says nothing about what is missing.
func TestRestoreMissingChains_WritesNothingWhenItCannotList(t *testing.T) {
	m, _, backend := issuedLeader(t)
	deleteChain(t, backend, "mx.example.com")
	backend.puts = 0
	m.certCache.backend = listErrorBackend{backend}

	if got := m.restoreMissingChains(context.Background()); len(got) != 0 {
		t.Fatalf("restored %v without a listing", got)
	}
	if backend.puts != 0 {
		t.Fatalf("%d chain writes without a listing, want 0", backend.puts)
	}
}

// emptyListBackend lists nothing, whatever storage holds: the filesystem
// backend does this for a path it cannot read.
type emptyListBackend struct{ storage.Backend }

func (emptyListBackend) ListObjects(context.Context, string, bool) ([]storage.ObjectInfo, error) {
	return nil, nil
}

// The listing nominates; the read decides. A chain a listing missed, newer
// than the one in memory, must be adopted, not overwritten with the older.
func TestRestoreMissingChains_TheReadDecidesNotTheListing(t *testing.T) {
	m, _, backend := issuedLeader(t)
	ctx := context.Background()
	key, err := m.keyStore.LoadCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	newer, err := chainWithSerialNotAfter(key, "mx.example.com", 999, time.Now().Add(120*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.certCache.persist(ctx, "mx.example.com", newer, 1); err != nil {
		t.Fatal(err)
	}
	backend.puts = 0
	m.certCache.backend = emptyListBackend{backend}

	if got := m.restoreMissingChains(ctx); len(got) != 0 {
		t.Fatalf("restored %v over a newer chain", got)
	}
	if backend.puts != 0 {
		t.Fatalf("%d chain writes, want 0: storage held a newer chain", backend.puts)
	}
	if got := servedSerial(t, m); got != 999 {
		t.Fatalf("serving serial %d, want the newer 999 storage holds", got)
	}
}

// An expired chain is not worth putting back, and a name no longer served is
// not ours to put back: an operator deleting a departed customer's hostname
// must not see it reappear. The served, unexpired case is restored, so the
// test cannot pass by restoring nothing.
func TestRestoreMissingChains_OnlyServedNamesWithUnexpiredChains(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := onDemandLeader(t, backend, &countingCA{}, "kept.example.com", "gone.example.com", "stale.example.com")
	ctx := context.Background()
	storedChain(t, m, "kept.example.com", 1)
	storedChain(t, m, "gone.example.com", 2)

	key, err := m.keyStore.LoadOrCreateCertKey(ctx, "stale.example.com")
	if err != nil {
		t.Fatal(err)
	}
	expired, err := chainWithSerialNotAfter(key, "stale.example.com", 3, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := buildCertificate(expired, key)
	if err != nil {
		t.Fatal(err)
	}
	m.certCache.set("stale.example.com", cert)

	m.onDemand.store([]string{"kept.example.com", "stale.example.com"})
	deleteChain(t, backend, "kept.example.com")
	deleteChain(t, backend, "gone.example.com")

	got := m.restoreMissingChains(ctx)
	if len(got) != 1 || got[0] != "kept.example.com" {
		t.Fatalf("restored %v, want only [kept.example.com]", got)
	}
	for _, name := range []string{"gone.example.com", "stale.example.com"} {
		if s := storedSerial(t, m, name); s != 0 {
			t.Errorf("%s was written back (serial %d)", name, s)
		}
	}
}

// After a key replacement the chain in memory belongs to the retired key.
// Written back, every node reading it would pair it with the new key and
// refuse it — a worse state than nothing, because nothing re-issues it.
func TestRestoreMissingChains_WillNotWriteAChainForAReplacedKey(t *testing.T) {
	m, _, backend := issuedLeader(t)
	ctx := context.Background()
	if _, err := m.keyStore.GenerateNextCertKey(ctx, "mx.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := m.keyStore.PromoteNextCertKey(ctx, "mx.example.com"); err != nil {
		t.Fatal(err)
	}
	deleteChain(t, backend, "mx.example.com")
	logs := &capturingHandler{}
	m.logger = slog.New(logs)

	if got := m.restoreMissingChains(ctx); len(got) != 0 {
		t.Fatalf("restored %v for a key storage no longer holds", got)
	}
	if s := storedSerial(t, m, "mx.example.com"); s != 0 {
		t.Fatalf("wrote back serial %d against the replaced key", s)
	}
	if !logs.warnedAbout("not for the stored key") {
		t.Fatal("skipped without saying why; the leader is serving a certificate nothing will renew early")
	}
}

// A held chain is the flush's, which writes once per tick. Restoring it too
// would make that two writes into a storage that is already failing.
func TestMaintainOnce_WritesAHeldChainOncePerTick(t *testing.T) {
	m, _, flaky := newFlakyManager(t, persistAttempts)
	m.stopCh = make(chan struct{})
	if err := m.renewIfNeeded(context.Background(), "mx.example.com"); !errors.Is(err, ErrOrderNotPersisted) {
		t.Fatalf("setup: err = %v, want ErrOrderNotPersisted", err)
	}
	flaky.failPuts = 100
	flaky.puts = 0

	m.maintainOnce()

	if flaky.puts != 1 {
		t.Fatalf("%d writes of the held chain in one tick, want 1", flaky.puts)
	}
}

// The retry budget is cleared when a HELD chain lands, because its failures
// were storage's. A restore says nothing about why renewals were failing, so it
// must leave the budget as it found it.
func TestRestoreMissingChains_LeavesTheRetryBudgetAlone(t *testing.T) {
	m, _, backend := issuedLeader(t)
	for i := 0; i < 3; i++ {
		m.retries.recordFailure("mx.example.com")
	}
	deleteChain(t, backend, "mx.example.com")

	if got := m.restoreMissingChains(context.Background()); len(got) != 1 {
		t.Fatalf("restored %v, want [mx.example.com]", got)
	}
	if _, ok := m.retries.allow("mx.example.com"); ok {
		t.Fatal("the restore cleared a retry budget it had not charged")
	}
}
