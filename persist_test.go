package certmanager

import (
	"context"
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
	if err := m.certCache.persist(ctx, "mx.example.com", peerChain); err != nil {
		t.Fatalf("peer write: %v", err)
	}

	m.certCache.flushPending(ctx)

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
