package certmanager

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Open-Email/go-certs-manager/dane"
	"github.com/Open-Email/go-certs-manager/storage"
)

// Simulates a key-replacement ceremony interrupted after Store (new cert issued and
// persisted, bound to the next key) but before PromoteNextCertKey. A new/recovered
// leader must roll the promotion forward so the new cert becomes servable, rather
// than being stuck on the cert/key mismatch.
func TestReconcileCeremony_CompletesInterruptedActivation(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	leader := func() bool { return true }
	ks := NewKeyStore(backend, "", KeyTypeECDSAP256, leader, nil)
	ctx := context.Background()

	oldKey, err := ks.LoadOrCreateCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	nextKey, err := ks.GenerateNextCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	oldSPKI, _ := dane.SPKISHA256(oldKey.Public())
	nextSPKI, _ := dane.SPKISHA256(nextKey.Public())
	if oldSPKI == nextSPKI {
		t.Fatal("test keys collided")
	}

	// Interrupted state: chain bound to the NEXT key is stored, but the live key was
	// never promoted (still the old key).
	cc := newCertCache(backend, "", ks.LoadCertKey, nil)
	chain := selfSignedChainPEM(t, nextKey, "mx.example.com")
	if _, err := cc.Store(ctx, "mx.example.com", chain, nextKey); err != nil {
		t.Fatal(err)
	}

	// A fresh node cannot serve it: new chain + old live key mismatch.
	fresh := newCertCache(backend, "", ks.LoadCertKey, nil)
	if _, err := fresh.Refresh(ctx, "mx.example.com"); !errors.Is(err, ErrKeyCertMismatch) {
		t.Fatalf("expected ErrKeyCertMismatch before reconcile, got %v", err)
	}

	m := &Manager{keyStore: ks, certCache: fresh, logger: slog.Default(), isLeaderF: leader}
	m.reconcileCeremony(ctx, "mx.example.com")

	// Live key promoted to next, staged key removed, new cert now servable.
	live, _ := ks.LoadCertKey(ctx, "mx.example.com")
	if liveSPKI, _ := dane.SPKISHA256(live.Public()); liveSPKI != nextSPKI {
		t.Fatalf("live key not promoted: got %s want %s", liveSPKI, nextSPKI)
	}
	if _, err := ks.LoadNextCertKey(ctx, "mx.example.com"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged next key not cleaned up: %v", err)
	}
	cert, ok := fresh.Get("mx.example.com")
	if !ok || cert.Leaf == nil {
		t.Fatal("cert not servable after reconcile")
	}
	if leafSPKI, _ := dane.SPKISHA256(cert.Leaf.PublicKey); leafSPKI != nextSPKI {
		t.Fatalf("served leaf SPKI %s != promoted key %s", leafSPKI, nextSPKI)
	}
}

// A no-op when no ceremony is staged.
func TestReconcileCeremony_NoopWithoutStagedKey(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	leader := func() bool { return true }
	ks := NewKeyStore(backend, "", KeyTypeECDSAP256, leader, nil)
	ctx := context.Background()
	key, _ := ks.LoadOrCreateCertKey(ctx, "mx.example.com")
	cc := newCertCache(backend, "", ks.LoadCertKey, nil)
	if _, err := cc.Store(ctx, "mx.example.com", selfSignedChainPEM(t, key, "mx.example.com"), key); err != nil {
		t.Fatal(err)
	}
	m := &Manager{keyStore: ks, certCache: cc, logger: slog.Default(), isLeaderF: leader}
	m.reconcileCeremony(ctx, "mx.example.com") // must not panic or change anything
	if _, err := ks.LoadNextCertKey(ctx, "mx.example.com"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected staged key: %v", err)
	}
}

// A DANE MX host whose persistent key is missing while usage-3 TLSA records are
// still published must not have a fresh key minted by automatic renewal.
func TestRenewIfNeeded_BlockedByDANEGateOnMissingKey(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	leader := func() bool { return true }
	ks := NewKeyStore(backend, "", KeyTypeECDSAP256, leader, nil)
	ctl := newDANEController(ks, backend, "", []string{"mx.example.com"}, 3600, time.Minute, nil)
	ctl.lookup = fakeLookup(publishedEE(strings.Repeat("ab", 32)), nil)

	m := &Manager{
		keyStore:    ks,
		certCache:   newCertCache(backend, "", ks.LoadCertKey, nil),
		dane:        ctl,
		logger:      slog.Default(),
		isLeaderF:   leader,
		renewBefore: 30 * 24 * time.Hour,
	}
	err = m.renewIfNeeded(context.Background(), "mx.example.com")
	if err == nil || !strings.Contains(err.Error(), "no live key exists") {
		t.Fatalf("expected the DANE gate to block issuance, got %v", err)
	}
	// The gate must have blocked BEFORE a key was minted.
	if _, kerr := ks.LoadCertKey(context.Background(), "mx.example.com"); !errors.Is(kerr, os.ErrNotExist) {
		t.Fatalf("no key must be created while blocked, got %v", kerr)
	}
}

// Activation must refuse to swap the served SPKI until DNS shows the staged
// key's TLSA record (fail-closed on indeterminate lookups too).
func TestActivateCertificateKey_GateRequiresPublishedStagedRecord(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	leader := func() bool { return true }
	ks := NewKeyStore(backend, "", KeyTypeECDSAP256, leader, nil)
	ctx := context.Background()

	liveKey, err := ks.LoadOrCreateCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	liveDigest, _ := dane.SPKISHA256(liveKey.Public())
	if _, err := ks.GenerateNextCertKey(ctx, "mx.example.com"); err != nil {
		t.Fatal(err)
	}

	ctl := newDANEController(ks, backend, "", []string{"mx.example.com"}, 3600, time.Minute, nil)
	m := &Manager{
		keyStore:  ks,
		certCache: newCertCache(backend, "", ks.LoadCertKey, nil),
		dane:      ctl,
		logger:    slog.Default(),
		isLeaderF: leader,
		domainSet: map[string]bool{"mx.example.com": true},
	}

	// Only the live digest is published — the staged record is missing.
	ctl.lookup = fakeLookup(publishedEE(liveDigest), nil)
	err = m.ActivateCertificateKey("mx.example.com", false)
	if err == nil || !strings.Contains(err.Error(), "not visible in DNS") {
		t.Fatalf("expected activation to be blocked, got %v", err)
	}

	// Indeterminate lookup is also fail-closed for activation.
	ctl.lookup = fakeLookup(dane.LookupResult{}, context.DeadlineExceeded)
	err = m.ActivateCertificateKey("mx.example.com", false)
	if err == nil || !strings.Contains(err.Error(), "cannot verify") {
		t.Fatalf("expected fail-closed activation on lookup failure, got %v", err)
	}

	// The staged key must still be staged (nothing promoted or issued).
	if _, err := ks.LoadNextCertKey(ctx, "mx.example.com"); err != nil {
		t.Fatalf("staged key must survive a blocked activation: %v", err)
	}
	live, _ := ks.LoadCertKey(ctx, "mx.example.com")
	if d, _ := dane.SPKISHA256(live.Public()); d != liveDigest {
		t.Fatal("live key must be unchanged after a blocked activation")
	}
}
