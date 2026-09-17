package certmanager

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Open-Email/go-certs-manager/storage"
)

// countingCA stands in for the CA: it counts orders and answers each with a
// chain whose serial is the order number, so a test can tell WHICH certificate
// ended up being served.
type countingCA struct {
	orders int
	err    error
}

func (ca *countingCA) Issue(_ context.Context, domain string, certKey crypto.Signer) ([]byte, error) {
	ca.orders++
	if ca.err != nil {
		return nil, ca.err
	}
	return chainWithSerial(certKey, domain, int64(100+ca.orders))
}

func chainWithSerial(key crypto.Signer, cn string, serial int64) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// newRenewalManager is a leader holding a FRESH certificate (serial 1, 90 days
// left against a 30-day renewal window) for mx.example.com, with ca as its CA.
func newRenewalManager(t *testing.T, ca *countingCA) (*Manager, storage.Backend) {
	t.Helper()
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
	chain, err := chainWithSerial(key, "mx.example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cc.Store(ctx, "mx.example.com", chain, key); err != nil {
		t.Fatal(err)
	}
	return &Manager{
		keyStore:    ks,
		certCache:   cc,
		issuer:      ca,
		logger:      slog.Default(),
		domains:     []string{"mx.example.com"},
		domainSet:   map[string]bool{"mx.example.com": true},
		isLeaderF:   leader,
		renewBefore: 30 * 24 * time.Hour,
		retries:     newRetryBudget(3),
		leaser:      newLeaser(t, backend, "node-self", time.Minute),
	}, backend
}

func servedSerial(t *testing.T, m *Manager) int64 {
	t.Helper()
	cert, ok := m.certCache.Get("mx.example.com")
	if !ok || cert.Leaf == nil {
		t.Fatal("no certificate served for mx.example.com")
	}
	return cert.Leaf.SerialNumber.Int64()
}

// The manual renewal exists to replace a certificate that is still valid, so it
// must reach the CA however fresh the current one is — and what it reports as
// renewed must be what is then served, and what a follower reads from storage.
func TestRenewCertificate_OrdersEvenWhenFresh(t *testing.T) {
	ca := &countingCA{}
	m, backend := newRenewalManager(t, ca)

	got, err := m.RenewCertificate("mx.example.com")
	if err != nil {
		t.Fatalf("RenewCertificate: %v", err)
	}
	if len(got) != 1 || got[0] != "mx.example.com" {
		t.Fatalf("renewed = %v, want [mx.example.com]", got)
	}
	if ca.orders != 1 {
		t.Fatalf("CA saw %d order(s), want 1 — a manual renewal of a fresh certificate must still order", ca.orders)
	}
	if s := servedSerial(t, m); s != 101 {
		t.Fatalf("serving serial %d, want the newly ordered 101", s)
	}

	// A follower sees the replacement through storage.
	ks := NewKeyStore(backend, "", KeyTypeECDSAP256, func() bool { return false }, nil)
	follower := newCertCache(backend, "", ks.LoadCertKey, nil)
	cert, err := follower.Refresh(context.Background(), "mx.example.com")
	if err != nil {
		t.Fatalf("follower refresh: %v", err)
	}
	if s := cert.Leaf.SerialNumber.Int64(); s != 101 {
		t.Fatalf("storage holds serial %d, want 101", s)
	}
}

// The other half of the same switch: scheduled maintenance must NOT order for a
// fresh certificate. Without this, forcing everywhere would pass the test above.
func TestRenewIfNeeded_DoesNotOrderWhenFresh(t *testing.T) {
	ca := &countingCA{}
	m, _ := newRenewalManager(t, ca)
	ctx := context.Background()

	if err := m.renewIfNeeded(ctx, "mx.example.com"); err != nil {
		t.Fatalf("renewIfNeeded: %v", err)
	}
	// And past renewIfNeeded's own window check, at the lease re-check a second
	// believed-leader relies on.
	key, err := m.keyStore.LoadCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.issueWithKey(ctx, "mx.example.com", key, false); err != nil {
		t.Fatalf("issueWithKey: %v", err)
	}
	if ca.orders != 0 {
		t.Fatalf("CA saw %d order(s) for a fresh certificate, want 0", ca.orders)
	}
	if s := servedSerial(t, m); s != 1 {
		t.Fatalf("serving serial %d, want the untouched 1", s)
	}
}

// force skips the freshness check and nothing else: a peer driving an order for
// the same domain still holds the manual renewal off.
func TestRenewCertificate_StillHonoursIssuanceLease(t *testing.T) {
	ca := &countingCA{}
	m, backend := newRenewalManager(t, ca)

	peer := newLeaser(t, backend, "node-peer", time.Minute)
	rel, ok := peer.acquire(context.Background(), "mx.example.com")
	if !ok {
		t.Fatal("peer should acquire")
	}
	defer rel()

	// An error, not the stored certificate: answering with what is already there
	// would tell the operator a renewal happened.
	if _, err := m.RenewCertificate("mx.example.com"); err == nil || !strings.Contains(err.Error(), "in progress on another node") {
		t.Fatalf("err = %v, want issuance in progress on another node", err)
	}
	if ca.orders != 0 {
		t.Fatalf("CA saw %d order(s) while a peer held the lease, want 0", ca.orders)
	}
}

// A refused order must cost the operator nothing but the attempt: the working
// certificate stays served, and the failure is charged to the retry budget so
// repeating the command cannot run through the CA's failed-validation limit.
func TestRenewCertificate_FailedOrderKeepsCurrentCertificate(t *testing.T) {
	ca := &countingCA{err: errors.New("429 too many certificates")}
	m, _ := newRenewalManager(t, ca)

	for i := 0; i < 3; i++ {
		if _, err := m.RenewCertificate("mx.example.com"); err == nil || !strings.Contains(err.Error(), "429") {
			t.Fatalf("attempt %d: err = %v, want the CA's 429", i+1, err)
		}
	}
	if _, err := m.RenewCertificate("mx.example.com"); err == nil || !strings.Contains(err.Error(), "retry budget exhausted") {
		t.Fatalf("4th attempt: err = %v, want retry budget exhausted", err)
	}
	if ca.orders != 3 {
		t.Fatalf("CA saw %d order(s), want 3 (the budget)", ca.orders)
	}
	if s := servedSerial(t, m); s != 1 {
		t.Fatalf("serving serial %d after failed renewals, want the untouched 1", s)
	}
}

// The split-brain case the lease re-check exists for: this node still holds the
// expiring certificate in memory, while a peer that also believed itself leader
// has already renewed into storage. Scheduled maintenance must adopt the peer's
// certificate rather than spend a second order on the same name.
func TestRenewIfNeeded_AdoptsPeerRenewalInsteadOfOrdering(t *testing.T) {
	ca := &countingCA{}
	m, _ := newRenewalManager(t, ca) // storage: serial 1, 90 days left
	ctx := context.Background()

	key, err := m.keyStore.LoadCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	expiring := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "mx.example.com"},
		NotBefore:    time.Now().Add(-80 * 24 * time.Hour),
		NotAfter:     time.Now().Add(10 * 24 * time.Hour),
		DNSNames:     []string{"mx.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, expiring, expiring, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := buildCertificate(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key)
	if err != nil {
		t.Fatal(err)
	}
	m.certCache.set("mx.example.com", stale)

	if err := m.renewIfNeeded(ctx, "mx.example.com"); err != nil {
		t.Fatalf("renewIfNeeded: %v", err)
	}
	if ca.orders != 0 {
		t.Fatalf("CA saw %d order(s), want 0 — the peer's renewal was already in storage", ca.orders)
	}
	if s := servedSerial(t, m); s != 1 {
		t.Fatalf("serving serial %d, want the peer's 1", s)
	}
}
