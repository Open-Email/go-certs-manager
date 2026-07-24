package certmanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"log/slog"
	"testing"

	"github.com/Open-Email/go-certs-manager/storage"

	"golang.org/x/crypto/acme"
)

// newServingManager builds a Manager wired only for the serving path (no CA, no
// maintenance goroutine) so GetCertificate can be exercised in isolation.
func newServingManager(t *testing.T) *Manager {
	t.Helper()
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ks := NewKeyStore(backend, "", KeyTypeECDSAP256, func() bool { return false }, nil)
	m := &Manager{
		keyStore:      ks,
		certCache:     newCertCache(backend, "", ks.LoadCertKey, nil),
		challenges:    NewChallengeServer(backend, "", nil),
		logger:        slog.Default(),
		domains:       []string{"mx.example.com"},
		domainSet:     map[string]bool{"mx.example.com": true},
		defaultDomain: "mx.example.com",
		isLeaderF:     func() bool { return false },
	}
	m.tlsConfig = m.buildTLSConfig()
	return m
}

func TestGetCertificate_Serving(t *testing.T) {
	m := newServingManager(t)
	get := m.tlsConfig.GetCertificate

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chain := selfSignedChainPEM(t, key, "mx.example.com")
	cert, err := buildCertificate(chain, key)
	if err != nil {
		t.Fatal(err)
	}
	m.certCache.set("mx.example.com", cert)

	t.Run("cached hit (case-insensitive SNI)", func(t *testing.T) {
		got, err := get(&tls.ClientHelloInfo{ServerName: "MX.example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if got != cert {
			t.Fatal("did not return cached cert")
		}
	})

	t.Run("missing SNI falls back to default domain", func(t *testing.T) {
		got, err := get(&tls.ClientHelloInfo{ServerName: ""})
		if err != nil || got != cert {
			t.Fatalf("default-domain fallback failed: cert=%v err=%v", got != nil, err)
		}
	})

	t.Run("IP-literal SNI falls back to default domain", func(t *testing.T) {
		// RFC 6066 forbids IP SNI but some MTAs send it anyway; rejecting breaks
		// opportunistic inbound TLS.
		got, err := get(&tls.ClientHelloInfo{ServerName: "203.0.113.5"})
		if err != nil || got != cert {
			t.Fatalf("default-domain fallback failed: cert=%v err=%v", got != nil, err)
		}
	})

	t.Run("no usable SNI and no default domain", func(t *testing.T) {
		bare := newServingManager(t)
		bare.defaultDomain = ""
		for _, sni := range []string{"", "203.0.113.5"} {
			_, err := bare.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
			if !errors.Is(err, ErrMissingServerName) {
				t.Fatalf("sni=%q: expected ErrMissingServerName, got %v", sni, err)
			}
		}
	})

	t.Run("unconfigured domain rejected", func(t *testing.T) {
		_, err := get(&tls.ClientHelloInfo{ServerName: "evil.example.net"})
		if !errors.Is(err, ErrHostNotAllowed) {
			t.Fatalf("expected ErrHostNotAllowed, got %v", err)
		}
	})

	t.Run("follower cache miss is unavailable, not a crash", func(t *testing.T) {
		_, err := get(&tls.ClientHelloInfo{ServerName: "mx.example.com", SupportedProtos: []string{"http/1.1"}})
		// served from cache above; remove to force a miss
		m.certCache.mu.Lock()
		delete(m.certCache.mem, "mx.example.com")
		m.certCache.mu.Unlock()
		_, err = get(&tls.ClientHelloInfo{ServerName: "mx.example.com"})
		if !errors.Is(err, ErrCertificateUnavailable) {
			t.Fatalf("expected ErrCertificateUnavailable on follower miss, got %v", err)
		}
	})
}

func TestGetCertificate_ALPNChallenge(t *testing.T) {
	m := newServingManager(t)
	get := m.tlsConfig.GetCertificate

	// No challenge staged -> unavailable.
	if _, err := get(&tls.ClientHelloInfo{ServerName: "mx.example.com", SupportedProtos: []string{acme.ALPNProto}}); !errors.Is(err, ErrCertificateUnavailable) {
		t.Fatalf("expected unavailable without staged challenge, got %v", err)
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tokenChain := selfSignedChainPEM(t, key, "mx.example.com")
	tokenCert, _ := buildCertificate(tokenChain, key)
	m.challenges.PutALPN("mx.example.com", tokenCert)

	got, err := get(&tls.ClientHelloInfo{ServerName: "mx.example.com", SupportedProtos: []string{acme.ALPNProto}})
	if err != nil {
		t.Fatal(err)
	}
	if got != tokenCert {
		t.Fatal("ALPN branch did not return the staged token certificate")
	}
}
