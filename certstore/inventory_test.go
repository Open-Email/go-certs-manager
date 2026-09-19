package certstore

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	certmanager "github.com/Open-Email/go-certs-manager"
	"github.com/Open-Email/go-certs-manager/internal/layout"
	"github.com/Open-Email/go-certs-manager/storage"
)

// fixture is a deployment's storage with certificates written where the
// manager writes them: keys through the manager's own KeyStore, chains and the
// allow-set at the layout's paths.
type fixture struct {
	t       *testing.T
	backend storage.Backend
	prefix  string
	keys    *certmanager.KeyStore
}

func newFixture(t *testing.T, prefix string) *fixture {
	t.Helper()
	b, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, backend: b, prefix: prefix,
		keys: certmanager.NewKeyStore(b, prefix, certmanager.KeyTypeECDSAP256, func() bool { return true }, slog.New(slog.NewTextHandler(io.Discard, nil)))}
}

// chain stores a certificate for domain expiring at notAfter, and returns it.
func (f *fixture) chain(domain string, notAfter time.Time) []byte {
	f.t.Helper()
	key, err := f.keys.LoadOrCreateCertKey(context.Background(), domain)
	if err != nil {
		f.t.Fatal(err)
	}
	pemBytes := selfSigned(f.t, key, domain, notAfter)
	f.put(layout.Chain(f.prefix, domain), pemBytes)
	return pemBytes
}

func (f *fixture) put(key string, data []byte) {
	f.t.Helper()
	if err := f.backend.PutObject(context.Background(), key, strings.NewReader(string(data)), int64(len(data)), storage.PutOptions{}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) onDemand(hosts ...string) {
	f.t.Helper()
	body, err := json.Marshal(layout.OnDemandState{GeneratedAt: time.Now().Unix(), Hosts: hosts})
	if err != nil {
		f.t.Fatal(err)
	}
	f.put(f.prefix+layout.OnDemandHosts, body)
}

func (f *fixture) stored(domain string) bool {
	f.t.Helper()
	_, err := f.backend.StatObject(context.Background(), layout.Chain(f.prefix, domain))
	return err == nil
}

func selfSigned(t *testing.T, key crypto.Signer, cn string, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: cn},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

var (
	fresh   = time.Now().Add(80 * 24 * time.Hour)
	expired = time.Now().Add(-24 * time.Hour)
)

func byDomain(list []Certificate) map[string]Certificate {
	out := map[string]Certificate{}
	for _, c := range list {
		out[c.Domain] = c
	}
	return out
}

func TestList_SaysWhyEachCertificateIsThereAndWhetherItCanBeServed(t *testing.T) {
	f := newFixture(t, "prod/")
	f.chain("mx.example.com", fresh)
	f.chain("mail.customer.example", fresh)
	f.chain("gone.example", fresh)
	f.chain("old.example.com", expired)
	f.put(layout.Chain(f.prefix, "garbage.example"), []byte("not a certificate"))
	f.onDemand("mail.customer.example")
	if _, err := f.keys.GenerateNextCertKey(context.Background(), "mx.example.com"); err != nil {
		t.Fatal(err)
	}
	// Under the chain directory, but not a chain the manager writes.
	f.put(f.prefix+layout.ChainDir+"nested/thing", []byte("x"))
	// Another deployment's prefix: not ours.
	f.put(layout.Chain("", "other.example"), []byte("x"))

	list, err := New(f.backend, f.prefix, []string{"MX.example.com.", "old.example.com"}, 0).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := byDomain(list)
	if len(got) != 5 {
		t.Fatalf("listed %d certificates, want 5: %+v", len(got), list)
	}
	want := map[string]struct {
		role       Role
		unservable string
		inUse      bool
	}{
		"mx.example.com":        {RoleConfigured, "", true},
		"mail.customer.example": {RoleOnDemand, "", true},
		"gone.example":          {RoleOrphan, "", false},
		"old.example.com":       {RoleConfigured, "expired", false},
		"garbage.example":       {RoleOrphan, "invalid (no certificate in the PEM)", false},
	}
	for domain, w := range want {
		c := got[domain]
		if c.Role != w.role || c.Unservable() != w.unservable || c.InUse() != w.inUse {
			t.Errorf("%s: role %q unservable %q in use %v, want %q %q %v", domain, c.Role, c.Unservable(), c.InUse(), w.role, w.unservable, w.inUse)
		}
	}
	mx := got["mx.example.com"]
	if !mx.HasKey || !mx.HasStagedKey {
		t.Errorf("mx.example.com: has key %v, staged %v; want both", mx.HasKey, mx.HasStagedKey)
	}
	if !mx.NotAfter.Equal(fresh.Truncate(time.Second)) || mx.Algorithm != "ECDSA" {
		t.Errorf("mx.example.com: expires %v alg %q", mx.NotAfter, mx.Algorithm)
	}
	if got["garbage.example"].HasKey {
		t.Error("garbage.example has no key, but the listing says it does")
	}
}

// errorReadBackend fails reads of keys containing failFor.
type errorReadBackend struct {
	storage.Backend
	failFor string
}

func (b errorReadBackend) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	if strings.Contains(key, b.failFor) {
		return nil, errors.New("read timed out")
	}
	return b.Backend.GetObject(ctx, key)
}

// An allow-set that could not be read is not an empty one. Read as empty,
// every on-demand name would list as an orphan, and an orphan is deletable
// without --force.
func TestInventory_FailsWhenItCannotReadTheAllowSet(t *testing.T) {
	f := newFixture(t, "")
	f.chain("mail.customer.example", fresh)
	f.onDemand("mail.customer.example")
	inv := New(errorReadBackend{f.backend, layout.OnDemandHosts}, "", nil, 0)

	if _, err := inv.List(context.Background()); err == nil {
		t.Error("List succeeded without the allow-set")
	}
	if _, err := inv.Delete(context.Background(), "mail.customer.example", false); err == nil {
		t.Error("Delete went ahead without knowing the name is on-demand")
	}
	if !f.stored("mail.customer.example") {
		t.Fatal("the on-demand certificate was deleted")
	}
}

// With the feature off there is no allow-set at all; that is not an error.
func TestList_NoAllowSetMeansNoOnDemandNames(t *testing.T) {
	f := newFixture(t, "")
	f.chain("gone.example", fresh)
	list, err := New(f.backend, "", nil, 0).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Role != RoleOrphan {
		t.Fatalf("got %+v, want one orphan", list)
	}
}

func TestDelete_RefusesACertificateInUseUnlessForced(t *testing.T) {
	for _, tc := range []struct {
		name, domain string
		role         Role
	}{
		{"configured", "mx.example.com", RoleConfigured},
		{"on-demand", "mail.customer.example", RoleOnDemand},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "")
			f.chain(tc.domain, fresh)
			f.onDemand("mail.customer.example")
			inv := New(f.backend, "", []string{"mx.example.com"}, 0)
			ctx := context.Background()

			c, err := inv.Delete(ctx, tc.domain, false)
			if !errors.Is(err, ErrInUse) {
				t.Fatalf("err = %v, want ErrInUse", err)
			}
			if c.Role != tc.role {
				t.Errorf("reported role %q, want %q", c.Role, tc.role)
			}
			if !f.stored(tc.domain) {
				t.Fatal("refused, but the chain is gone")
			}

			if _, err := inv.Delete(ctx, tc.domain, true); err != nil {
				t.Fatalf("forced delete: %v", err)
			}
			if f.stored(tc.domain) {
				t.Fatal("forced delete left the chain")
			}
			if _, err := f.keys.LoadCertKey(ctx, tc.domain); err != nil {
				t.Fatalf("the key went with the chain: %v", err)
			}
		})
	}
}

// What nothing serves, and what no node could serve, go without --force.
func TestDelete_RemovesOrphansAndUnservableChains(t *testing.T) {
	f := newFixture(t, "")
	f.chain("gone.example", fresh)
	f.chain("mx.example.com", expired)
	inv := New(f.backend, "", []string{"mx.example.com"}, 0)
	for _, d := range []string{"gone.example", "mx.example.com"} {
		if _, err := inv.Delete(context.Background(), d, false); err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		if f.stored(d) {
			t.Fatalf("%s is still stored", d)
		}
	}
}

func TestDelete_NoSuchCertificate(t *testing.T) {
	f := newFixture(t, "")
	if _, err := New(f.backend, "", nil, 0).Delete(context.Background(), "nothing.example", false); !errors.Is(err, ErrNotStored) {
		t.Fatalf("err = %v, want ErrNotStored", err)
	}
}
