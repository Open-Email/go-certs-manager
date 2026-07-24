package certmanager

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/Open-Email/go-certs-manager/storage"
)

func newLeaser(t *testing.T, backend storage.Backend, node string, ttl time.Duration) *issueLeaser {
	t.Helper()
	return &issueLeaser{backend: backend, prefix: "", nodeID: node, ttl: ttl, logger: slog.Default()}
}

func TestIssueLease_MutualExclusionAndRelease(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	a := newLeaser(t, backend, "node-a", time.Minute)
	b := newLeaser(t, backend, "node-b", time.Minute)

	relA, ok := a.acquire(ctx, "mx.example.com")
	if !ok {
		t.Fatal("A should acquire a free lease")
	}
	if _, ok := b.acquire(ctx, "mx.example.com"); ok {
		t.Fatal("B must not acquire while A holds the lease")
	}
	relA()

	relB, ok := b.acquire(ctx, "mx.example.com")
	if !ok {
		t.Fatal("B should acquire after A releases")
	}
	relB()

	// Different domains never contend.
	r1, ok1 := a.acquire(ctx, "a.example.com")
	r2, ok2 := b.acquire(ctx, "b.example.com")
	if !ok1 || !ok2 {
		t.Fatal("distinct domains must not contend")
	}
	r1()
	r2()
}

func TestIssueLease_ExpiredTakeover(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// A acquires with a tiny TTL and never releases (simulating a crash).
	crashed := newLeaser(t, backend, "node-a", time.Millisecond)
	if _, ok := crashed.acquire(ctx, "mx.example.com"); !ok {
		t.Fatal("A should acquire")
	}
	time.Sleep(10 * time.Millisecond) // let it expire

	b := newLeaser(t, backend, "node-b", time.Minute)
	relB, ok := b.acquire(ctx, "mx.example.com")
	if !ok {
		t.Fatal("B should take over the expired lease")
	}

	// While B holds a fresh lease, a third node must not steal it.
	c := newLeaser(t, backend, "node-c", time.Minute)
	if _, ok := c.acquire(ctx, "mx.example.com"); ok {
		t.Fatal("C must not take over a still-valid lease")
	}
	relB()
}

func TestIssueLease_ReleaseOnlyOwnLease(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// A acquires (tiny TTL, no release), B takes over after expiry.
	a := newLeaser(t, backend, "node-a", time.Millisecond)
	relA, _ := a.acquire(ctx, "mx.example.com")
	time.Sleep(10 * time.Millisecond)
	b := newLeaser(t, backend, "node-b", time.Minute)
	if _, ok := b.acquire(ctx, "mx.example.com"); !ok {
		t.Fatal("B should take over")
	}

	// A's late release must NOT delete B's lease.
	relA()
	c := newLeaser(t, backend, "node-c", time.Minute)
	if _, ok := c.acquire(ctx, "mx.example.com"); ok {
		t.Fatal("A's stale release deleted B's lease — C wrongly acquired")
	}
}

// When a peer holds the issuance lease, issueWithKey must NOT drive an ACME order;
// it serves the peer's already-stored certificate instead.
func TestIssueWithKey_DefersToStorageWhenLeaseHeld(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	leader := func() bool { return true }
	ks := NewKeyStore(backend, "", KeyTypeECDSAP256, leader, nil)
	key, err := ks.LoadOrCreateCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	cc := newCertCache(backend, "", ks.LoadCertKey, nil)
	if _, err := cc.Store(ctx, "mx.example.com", selfSignedChainPEM(t, key, "mx.example.com"), key); err != nil {
		t.Fatal(err)
	}

	m := &Manager{
		keyStore:    ks,
		certCache:   cc,
		logger:      slog.Default(),
		isLeaderF:   leader,
		renewBefore: 30 * 24 * time.Hour,
		leaser:      newLeaser(t, backend, "node-self", time.Minute),
	}

	// A peer takes the lease first.
	peer := newLeaser(t, backend, "node-peer", time.Minute)
	rel, ok := peer.acquire(ctx, "mx.example.com")
	if !ok {
		t.Fatal("peer should acquire")
	}
	defer rel()

	// issueWithKey would call the CA if it tried to issue (no CA here) — it must
	// instead defer and return the stored cert.
	cert, err := m.issueWithKey(ctx, "mx.example.com", key)
	if err != nil {
		t.Fatalf("expected defer-to-storage, got error: %v", err)
	}
	if cert == nil || cert.Leaf == nil {
		t.Fatal("expected the peer's stored certificate from the defer path")
	}
}

// nil backend (single-node / tests) is a no-op that always "acquires".
func TestIssueLease_NilBackendNoop(t *testing.T) {
	l := &issueLeaser{backend: nil, logger: slog.Default()}
	rel, ok := l.acquire(context.Background(), "mx.example.com")
	if !ok {
		t.Fatal("nil backend should always acquire")
	}
	rel()
}
