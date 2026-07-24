package certmanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Open-Email/go-certs-manager/storage"
)

func selfSignedChainPEM(t *testing.T, key crypto.Signer, cn string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestBuildCertificate_RejectsKeyMismatch(t *testing.T) {
	keyA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyB, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chainA := selfSignedChainPEM(t, keyA, "mx.example.com")

	if _, err := buildCertificate(chainA, keyA); err != nil {
		t.Fatalf("matching key/cert should build: %v", err)
	}
	if _, err := buildCertificate(chainA, keyB); !errors.Is(err, ErrKeyCertMismatch) {
		t.Fatalf("expected ErrKeyCertMismatch for mismatched key, got %v", err)
	}
}

// Simulates a follower refreshing during the leader's Store->PromoteNextCertKey
// window: storage holds the NEW chain but keyFor still returns the OLD key. Refresh
// must fail and leave the previously-served cert in memory untouched.
func TestCertCache_RefreshKeepsLastGoodOnMismatch(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	oldKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// keyFor returns the OLD (not-yet-promoted) key, as a lagging follower would see.
	cc := newCertCache(backend, "", func(context.Context, string) (crypto.Signer, error) {
		return oldKey, nil
	}, nil)

	// Seed the follower's last-good cert (old chain + old key).
	oldCert, err := buildCertificate(selfSignedChainPEM(t, oldKey, "mx.example.com"), oldKey)
	if err != nil {
		t.Fatal(err)
	}
	cc.set("mx.example.com", oldCert)

	// Leader has written the NEW chain to storage but not yet promoted the key.
	newChain := selfSignedChainPEM(t, newKey, "mx.example.com")
	if err := backend.PutObject(ctx, "certs/mx.example.com", strings.NewReader(string(newChain)), int64(len(newChain)), storage.PutOptions{}); err != nil {
		t.Fatal(err)
	}

	if _, err := cc.Refresh(ctx, "mx.example.com"); !errors.Is(err, ErrKeyCertMismatch) {
		t.Fatalf("expected refresh to reject mismatch, got %v", err)
	}
	if got, _ := cc.Get("mx.example.com"); got != oldCert {
		t.Fatal("Refresh clobbered the last-good cert on a key mismatch")
	}
}

func TestCertCache_StoreThenRefreshFromStorage(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyFor := func(context.Context, string) (crypto.Signer, error) { return key, nil }

	cc := newCertCache(backend, "", keyFor, nil)
	chain := selfSignedChainPEM(t, key, "mx.example.com")
	if _, err := cc.Store(ctx, "mx.example.com", chain, key); err != nil {
		t.Fatal(err)
	}
	if _, ok := cc.Get("mx.example.com"); !ok {
		t.Fatal("cert not in memory after Store")
	}

	// A fresh cache (simulating a follower / restart) must rebuild from storage.
	cc2 := newCertCache(backend, "", keyFor, nil)
	if _, ok := cc2.Get("MX.example.com"); ok {
		t.Fatal("fresh cache unexpectedly had cert in memory")
	}
	cert, err := cc2.Refresh(ctx, "mx.example.com")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if cert.Leaf == nil || cert.Leaf.Subject.CommonName != "mx.example.com" {
		t.Fatalf("unexpected leaf: %+v", cert.Leaf)
	}
	if _, ok := cert.PrivateKey.(crypto.Signer); !ok {
		t.Fatal("rebuilt cert missing private key")
	}
}
