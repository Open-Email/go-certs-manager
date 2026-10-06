package certmanager

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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

// countingGetBackend counts reads, so a test can say how many storage reads a
// request was allowed to cause.
type countingGetBackend struct {
	storage.Backend
	gets int
}

func (b *countingGetBackend) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	b.gets++
	return b.Backend.GetObject(ctx, key)
}

// The token came straight from the URL path and became a storage key, so a
// request for ../../keys/<domain> read the domain's private key back out of
// the filesystem backend and served it over HTTP. An ACME token is base64url
// and nothing else; anything else is answered 404 without touching storage.
func TestHTTPHandler_RefusesATokenThatIsNotAToken(t *testing.T) {
	fs, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	secret := "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----\n"
	if err := fs.PutObject(ctx, "keys/mx.example.com", strings.NewReader(secret), int64(len(secret)), storage.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	backend := &countingGetBackend{Backend: fs}
	cs := NewChallengeServer(backend, "", nil)
	srv := httptest.NewServer(cs.HTTPHandler()) // mounted bare on :80, as the services do
	defer srv.Close()

	for _, path := range []string{
		"/.well-known/acme-challenge/../../keys/mx.example.com",
		"/.well-known/acme-challenge/..%2F..%2Fkeys%2Fmx.example.com",
		"/.well-known/acme-challenge/tok/../../keys/mx.example.com",
		"/.well-known/acme-challenge/" + strings.Repeat("a", 129),
		"/.well-known/acme-challenge/",
	} {
		// Raw request: a client's path cleaning would hide the problem.
		conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", path)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		conn.Close()
		if resp.StatusCode != 404 || bytes.Contains(body, []byte("PRIVATE KEY")) {
			t.Errorf("%s: status=%d body=%q, want 404 without the key", path, resp.StatusCode, body)
		}
	}
	if backend.gets != 0 {
		t.Errorf("%d storage read(s) for paths that cannot be tokens, want 0", backend.gets)
	}
}

// Anyone can send a well-formed token nobody issued. Each one cost a storage
// read, so a flood of them was a flood of reads against the bucket every node
// shares. A token found absent is remembered for a while.
func TestHTTPHandler_UnknownTokensDoNotEachCostAStorageRead(t *testing.T) {
	fs, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	backend := &countingGetBackend{Backend: fs}
	cs := NewChallengeServer(backend, "", nil)

	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		cs.HTTPHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/acme-challenge/nobody-issued-this-token-0123456789abcdef", nil))
		if rec.Code != 404 {
			t.Fatalf("unknown token answered %d", rec.Code)
		}
	}
	if backend.gets != 1 {
		t.Errorf("5 requests for one unknown token caused %d storage reads, want 1", backend.gets)
	}
}

// The ALPN token certificate was looked up in storage for ANY server name
// that negotiated acme-tls/1, before the allow-list. A validation can only be
// in progress for a name this node may serve, so other names are refused
// without a read.
func TestGetCertificate_ALPNLookupOnlyForAllowedNames(t *testing.T) {
	m := newServingManager(t)
	backend := &countingGetBackend{Backend: m.challenges.backend}
	m.challenges.backend = backend

	hello := &tls.ClientHelloInfo{ServerName: "nobody.example.net", SupportedProtos: []string{"acme-tls/1"}}
	if _, err := m.tlsConfig.GetCertificate(hello); err == nil {
		t.Fatal("served an ALPN token for a name outside the allow-list")
	}
	if backend.gets != 0 {
		t.Errorf("ALPN hello for a name outside the allow-list caused %d storage read(s), want 0", backend.gets)
	}

	allowed := &tls.ClientHelloInfo{ServerName: "mx.example.com", SupportedProtos: []string{"acme-tls/1"}}
	m.tlsConfig.GetCertificate(allowed)
	if backend.gets != 1 {
		t.Errorf("ALPN hello for an allowed name caused %d storage read(s), want 1", backend.gets)
	}
}
