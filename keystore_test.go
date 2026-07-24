package certmanager

import (
	"context"
	"testing"

	"github.com/Open-Email/go-certs-manager/dane"
	"github.com/Open-Email/go-certs-manager/storage"
)

func newTestKeyStore(t *testing.T, keyType string, isLeaderF func() bool) *KeyStore {
	t.Helper()
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return NewKeyStore(backend, "", keyType, isLeaderF, nil)
}

// The whole point of the design: a domain's key — and therefore its SPKI digest —
// must be identical across repeated loads. A second LoadOrCreate must NEVER mint a
// new key.
func TestKeyStore_ReusesKeyAndDigest(t *testing.T) {
	ks := newTestKeyStore(t, KeyTypeECDSAP256, nil)
	ctx := context.Background()

	k1, err := ks.LoadOrCreateCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	d1, err := dane.SPKISHA256(k1.Public())
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		k2, err := ks.LoadOrCreateCertKey(ctx, "mx.example.com")
		if err != nil {
			t.Fatal(err)
		}
		d2, err := dane.SPKISHA256(k2.Public())
		if err != nil {
			t.Fatal(err)
		}
		if d1 != d2 {
			t.Fatalf("SPKI digest changed on reload %d: %s != %s — key was regenerated", i, d1, d2)
		}
	}
}

func TestKeyStore_FollowerCannotCreate(t *testing.T) {
	follower := newTestKeyStore(t, KeyTypeECDSAP256, func() bool { return false })
	if _, err := follower.LoadOrCreateCertKey(context.Background(), "mx.example.com"); err == nil {
		t.Fatal("expected follower to be unable to create a key")
	}
}

func TestKeyStore_DomainsAreIndependent(t *testing.T) {
	ks := newTestKeyStore(t, KeyTypeECDSAP256, nil)
	ctx := context.Background()
	a, _ := ks.LoadOrCreateCertKey(ctx, "a.example.com")
	b, _ := ks.LoadOrCreateCertKey(ctx, "b.example.com")
	da, _ := dane.SPKISHA256(a.Public())
	db, _ := dane.SPKISHA256(b.Public())
	if da == db {
		t.Fatal("distinct domains shared a key")
	}
}
