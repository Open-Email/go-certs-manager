package certmanager

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Open-Email/go-certs-manager/storage"
)

func tokenCert(t *testing.T, cn string) *tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// The CA's validation can reach any node, but only the leader stages the challenge.
// A second node (separate ChallengeServer, shared storage) must serve both the
// HTTP-01 and TLS-ALPN-01 tokens from storage.
func TestChallengeServer_StorageBackedCrossNode(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	leaderCS := NewChallengeServer(backend, "", nil)
	followerCS := NewChallengeServer(backend, "", nil) // different node, same storage

	// HTTP-01: follower serves the leader's token from storage.
	leaderCS.PutHTTP("tok-123", "tok-123.keyauth")
	rec := httptest.NewRecorder()
	followerCS.HTTPHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/acme-challenge/tok-123", nil))
	if rec.Code != 200 || rec.Body.String() != "tok-123.keyauth" {
		t.Fatalf("follower HTTP-01: code=%d body=%q", rec.Code, rec.Body.String())
	}

	// TLS-ALPN-01: follower returns the leader's token certificate from storage.
	cert := tokenCert(t, "mx.example.com")
	leaderCS.PutALPN("mx.example.com", cert)
	got, ok := followerCS.GetALPN("mx.example.com")
	if !ok {
		t.Fatal("follower could not serve tls-alpn-01 token from storage")
	}
	if !bytes.Equal(got.Certificate[0], cert.Certificate[0]) {
		t.Fatal("follower served a different token certificate")
	}

	// Cleanup removes the token cluster-wide.
	leaderCS.DeleteHTTP("tok-123")
	rec2 := httptest.NewRecorder()
	followerCS.HTTPHandler().ServeHTTP(rec2, httptest.NewRequest("GET", "/.well-known/acme-challenge/tok-123", nil))
	if rec2.Code != 404 {
		t.Fatalf("expected 404 after cleanup, got %d", rec2.Code)
	}
	leaderCS.DeleteALPN("mx.example.com")
	if _, ok := followerCS.GetALPN("mx.example.com"); ok {
		t.Fatal("tls-alpn-01 token still served after cleanup")
	}
}
