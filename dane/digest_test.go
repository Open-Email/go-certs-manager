package dane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestSPKISHA256_StableAcrossCalls(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d1, err := SPKISHA256(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	d2, err := SPKISHA256(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("digest not deterministic: %s != %s", d1, d2)
	}
	if len(d1) != 64 {
		t.Fatalf("expected 64 hex chars for SHA-256, got %d (%q)", len(d1), d1)
	}
}

func TestSPKISHA256_DiffersPerKey(t *testing.T) {
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	d1, _ := SPKISHA256(k1.Public())
	d2, _ := SPKISHA256(k2.Public())
	if d1 == d2 {
		t.Fatal("distinct keys produced identical SPKI digest")
	}
}

func TestOwnerNameAndRData(t *testing.T) {
	r := NewSPKIRecord("MX.Example.com.", "ABCDEF", 3600)
	if r.Name != "_25._tcp.mx.example.com." {
		t.Fatalf("owner name = %q", r.Name)
	}
	if r.RData() != "3 1 1 abcdef" {
		t.Fatalf("rdata = %q", r.RData())
	}
	if r.MXHost != "mx.example.com" {
		t.Fatalf("mx host = %q", r.MXHost)
	}
}
