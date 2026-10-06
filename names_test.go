package certmanager

import (
	"context"
	"crypto/tls"
	"io"
	"testing"
	"time"

	"github.com/Open-Email/go-certs-manager/storage"
)

// Names were only lower-cased, in six places. A Unicode domain in the
// configuration matched no SNI (clients send punycode) and was ordered as
// typed, which the CA refuses — three failed attempts an hour, forever.
func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"MX.Example.COM.":       "mx.example.com",
		" bücher.example ":      "xn--bcher-kva.example",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
		"straße.example":        "xn--strae-oqa.example",
	}
	for in, want := range cases {
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

// The configured list, the SNI and the admin command must all land on the
// same key.
func TestUnicodeDomain_IsServedAndRenewedUnderItsALabel(t *testing.T) {
	ca := &countingCA{}
	m, backend := newRenewalManager(t, ca)
	ctx := context.Background()

	// Configured in Unicode, as an operator would type it.
	m.domains = []string{"bücher.example"}
	m.domainSet = domainSetOf(m.domains)
	key, err := m.keyStore.LoadOrCreateCertKey(ctx, "xn--bcher-kva.example")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := chainWithSerial(key, "xn--bcher-kva.example", 9)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.certCache.Store(ctx, "xn--bcher-kva.example", chain, key); err != nil {
		t.Fatal(err)
	}
	m.tlsConfig = m.buildTLSConfig()
	_ = backend

	if _, err := m.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "xn--bcher-kva.example"}); err != nil {
		t.Fatalf("handshake with the A-label failed: %v", err)
	}
	if _, err := m.RenewCertificate("Bücher.example"); err != nil {
		t.Fatalf("RenewCertificate with the Unicode spelling: %v", err)
	}
	if ca.orders != 1 {
		t.Fatalf("CA saw %d order(s), want 1", ca.orders)
	}
	if _, ok := m.certCache.Get("xn--bcher-kva.example"); !ok {
		t.Fatal("renewed certificate is not filed under the A-label")
	}
}

// ignoringBackend accepts every put, conditions included — the S3-compatible
// gateway that silently drops If-None-Match.
type ignoringBackend struct{ storage.Backend }

func (b ignoringBackend) PutObject(ctx context.Context, key string, r io.Reader, size int64, opts storage.PutOptions) error {
	opts.IfNoneMatch, opts.IfMatch = "", ""
	return b.Backend.PutObject(ctx, key, r, size, opts)
}

// The lease and the key create-once are conditional writes, and nothing
// checked that the backend honoured them: on one that ignores If-None-Match
// every acquire succeeds and the lease does nothing. A cluster must refuse to
// start on such a backend; a single node, which needs no lease, carries on.
func TestVerifyConditionalWrites(t *testing.T) {
	fs, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if ok, err := verifyConditionalWrites(ctx, fs, "p/"); err != nil || !ok {
		t.Fatalf("filesystem backend: ok=%v err=%v, want supported", ok, err)
	}
	if ok, err := verifyConditionalWrites(ctx, ignoringBackend{fs}, "p/"); err != nil || ok {
		t.Fatalf("ignoring backend: ok=%v err=%v, want unsupported", ok, err)
	}
	if objs, _ := fs.ListObjects(ctx, "p/", true); len(objs) != 0 {
		t.Errorf("probe left %d object(s) behind", len(objs))
	}

	cfg := &Config{Enabled: true, Provider: "letsencrypt"}
	if _, err := NewManager(ctx, cfg, ignoringBackend{fs}, "p/", testLogger(), func() bool { return true }); err == nil {
		t.Fatal("a clustered manager started on a backend that ignores conditional writes")
	}
	m, err := NewManager(ctx, cfg, ignoringBackend{fs}, "p/", testLogger())
	if err != nil {
		t.Fatalf("single node refused to start: %v", err)
	}
	m.Stop()
}

// Every node reports the expiry of what IT serves, so a node left behind on a
// stale certificate is visible on its own series — the health check dials the
// hostname through DNS and may be describing another node.
func TestMaintainOnce_ReportsWhatThisNodeServes(t *testing.T) {
	fs, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	m := newOnDemandManager(t, fs, false, OnDemandConfig{})
	m.domains = []string{"mx.example.com", "mx2.example.com"}
	m.domainSet = domainSetOf(m.domains)
	m.renewBefore = 30 * 24 * time.Hour

	ks := NewKeyStore(fs, "", KeyTypeECDSAP256, func() bool { return true }, nil)
	key, err := ks.LoadOrCreateCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Now().Add(42 * 24 * time.Hour).Truncate(time.Second)
	chain, err := chainWithSerialNotAfter(key, "mx.example.com", 5, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.certCache.persist(ctx, "mx.example.com", chain, 1); err != nil {
		t.Fatal(err)
	}

	reported := map[string]time.Time{}
	m.onServedExpiry = func(domain string, expiry time.Time) { reported[domain] = expiry }
	m.maintainOnce()

	if got := reported["mx.example.com"]; !got.Equal(notAfter) {
		t.Errorf("mx.example.com reported %v, want %v", got, notAfter)
	}
	if got, ok := reported["mx2.example.com"]; !ok || !got.IsZero() {
		t.Errorf("mx2.example.com (no certificate) reported %v (present=%v), want the zero time", got, ok)
	}
}
