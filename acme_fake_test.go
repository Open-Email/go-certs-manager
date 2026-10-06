package certmanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// fakeCA is an in-process ACME server: enough of RFC 8555 for Issuer to run
// an order end to end, with counters and failure switches so a test can say
// what the CA saw and make it misbehave at a chosen step.
type fakeCA struct {
	t   *testing.T
	srv *httptest.Server
	key *ecdsa.PrivateKey
	ca  *x509.Certificate

	mu         sync.Mutex
	newOrders  int // new-order requests: what Let's Encrypt counts
	accepts    int // challenge accepts
	certFetch  int // certificate downloads attempted
	failFetch  int // fail this many certificate downloads (500)
	challenges bool
	orders     map[string]*fakeOrder
	certs      map[string][]byte
	seq        int
}

type fakeOrder struct {
	status  string
	certURL string
	authz   string
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	f := &fakeCA{t: t, key: key, ca: ca, orders: map[string]*fakeOrder{}, certs: map[string][]byte{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCA) directoryURL() string { return f.srv.URL + "/directory" }

func (f *fakeCA) counts() (newOrders, accepts, certFetch int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.newOrders, f.accepts, f.certFetch
}

// jwsPayload decodes the payload of a JWS request body.
func jwsPayload(r *http.Request) []byte {
	var jws struct{ Payload string }
	_ = json.NewDecoder(r.Body).Decode(&jws)
	payload, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
	return payload
}

func (f *fakeCA) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
	base := f.srv.URL
	respond := func(status int, location string, v any) {
		if location != "" {
			w.Header().Set("Location", location)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if v != nil {
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	problem := func(status int, typ, detail string) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"type": typ, "detail": detail})
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	path := r.URL.Path
	switch {
	case path == "/directory":
		respond(200, "", map[string]string{
			"newNonce": base + "/new-nonce", "newAccount": base + "/new-account", "newOrder": base + "/new-order",
		})
	case path == "/new-nonce":
		w.WriteHeader(200)
	case path == "/new-account":
		respond(201, base+"/account/1", map[string]string{"status": "valid"})
	case path == "/new-order":
		f.newOrders++
		f.seq++
		id := fmt.Sprint(f.seq)
		o := &fakeOrder{status: "ready"}
		if f.challenges {
			o.status = "pending"
			o.authz = base + "/authz/" + id
		}
		f.orders[id] = o
		respond(201, base+"/order/"+id, f.orderJSON(id, o))
	case strings.HasPrefix(path, "/order/"):
		id := strings.TrimPrefix(path, "/order/")
		o, ok := f.orders[id]
		if !ok {
			problem(404, "urn:ietf:params:acme:error:malformed", "no such order")
			return
		}
		respond(200, "", f.orderJSON(id, o))
	case strings.HasPrefix(path, "/authz/"):
		id := strings.TrimPrefix(path, "/authz/")
		o := f.orders[id]
		status := "pending"
		if o.status != "pending" {
			status = "valid"
		}
		respond(200, "", map[string]any{
			"status":     status,
			"identifier": map[string]string{"type": "dns", "value": "mx.example.com"},
			"challenges": []map[string]string{{"type": "http-01", "url": base + "/chal/" + id, "token": "tok-" + id, "status": status}},
		})
	case strings.HasPrefix(path, "/chal/"):
		id := strings.TrimPrefix(path, "/chal/")
		f.accepts++
		f.orders[id].status = "ready"
		respond(200, "", map[string]string{"type": "http-01", "url": base + "/chal/" + id, "token": "tok-" + id, "status": "valid"})
	case strings.HasPrefix(path, "/finalize/"):
		id := strings.TrimPrefix(path, "/finalize/")
		o := f.orders[id]
		var fin struct{ CSR string }
		_ = json.Unmarshal(jwsPayload(r), &fin)
		csrDER, _ := base64.RawURLEncoding.DecodeString(fin.CSR)
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			problem(400, "urn:ietf:params:acme:error:badCSR", err.Error())
			return
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(100 + f.seq)),
			Subject:      pkix.Name{CommonName: csr.DNSNames[0]},
			DNSNames:     csr.DNSNames,
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca, csr.PublicKey, f.key)
		if err != nil {
			f.t.Errorf("fakeCA: signing: %v", err)
		}
		f.certs[id] = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw})...)
		o.status, o.certURL = "valid", base+"/cert/"+id
		respond(200, base+"/order/"+id, f.orderJSON(id, o))
	case strings.HasPrefix(path, "/cert/"):
		f.certFetch++
		if f.failFetch > 0 {
			f.failFetch--
			problem(500, "urn:ietf:params:acme:error:serverInternal", "try later")
			return
		}
		id := strings.TrimPrefix(path, "/cert/")
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(200)
		_, _ = w.Write(f.certs[id])
	default:
		problem(404, "urn:ietf:params:acme:error:malformed", "unknown path "+path)
	}
}

func (f *fakeCA) orderJSON(id string, o *fakeOrder) map[string]any {
	base := f.srv.URL
	m := map[string]any{
		"status":      o.status,
		"expires":     time.Now().Add(7 * 24 * time.Hour).Format(time.RFC3339),
		"identifiers": []map[string]string{{"type": "dns", "value": "mx.example.com"}},
		"finalize":    base + "/finalize/" + id,
	}
	if o.authz != "" {
		m["authorizations"] = []string{o.authz}
	} else {
		m["authorizations"] = []string{}
	}
	if o.certURL != "" {
		m["certificate"] = o.certURL
	}
	return m
}

// newIssuerAt is an Issuer talking to the fake CA, with its order journal on
// the given manager's storage.
func newIssuerAt(t *testing.T, ca *fakeCA, m *Manager) *Issuer {
	t.Helper()
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if m.challenges == nil {
		m.challenges = NewChallengeServer(m.certCache.backend, m.certCache.prefix, testLogger())
	}
	iss := NewIssuer(accountKey, "", false, m.challenges, testLogger())
	iss.client.DirectoryURL = ca.directoryURL()
	iss.journal = newOrderJournal(m.certCache.backend, m.certCache.prefix, testLogger())
	return iss
}

// ensure the fake speaks what x/crypto's client expects.
var _ = acme.ALPNProto

// Issue covered finalize, waiting and the download in one call, and any error
// after the finalize POST threw away a certificate the CA had already
// counted: a deploy restart mid-order was enough. The order is now written
// down before anything is sent, and the next attempt collects it instead of
// placing another.
func TestIssue_ResumesAnOrderWhoseCertificateWasNotCollected(t *testing.T) {
	ca := newFakeCA(t)
	m, _, _ := newFlakyManager(t, 0)
	iss := newIssuerAt(t, ca, m)
	ctx := context.Background()
	key, err := m.keyStore.LoadCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}

	// The download fails for as long as the attempt lasts.
	ca.mu.Lock()
	ca.failFetch = 100
	ca.mu.Unlock()
	short, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	if _, err := iss.Issue(short, "mx.example.com", key); err == nil {
		t.Fatal("setup: Issue succeeded although the download failed")
	}
	cancel()
	ca.mu.Lock()
	ca.failFetch = 0
	ca.mu.Unlock()

	chain, err := iss.Issue(ctx, "mx.example.com", key)
	if err != nil {
		t.Fatalf("second Issue: %v", err)
	}
	if _, err := buildCertificate(chain, key); err != nil {
		t.Fatalf("resumed chain does not build against the key: %v", err)
	}
	if n, _, _ := ca.counts(); n != 1 {
		t.Fatalf("CA saw %d new-order request(s), want 1 — the second attempt must collect the first order", n)
	}
	if _, err := iss.journal.load(ctx, "mx.example.com"); !absentFromStorage(err) {
		t.Errorf("journal entry still present after the certificate was collected: %v", err)
	}
}

// An order placed for another key is not this attempt's: a key-replacement
// ceremony orders for the staged key while renewals order for the live one.
func TestIssue_DoesNotResumeAnOrderForAnotherKey(t *testing.T) {
	ca := newFakeCA(t)
	m, _, _ := newFlakyManager(t, 0)
	iss := newIssuerAt(t, ca, m)
	ctx := context.Background()
	key, err := m.keyStore.LoadCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	other, _ := generateSigner(KeyTypeECDSAP256)

	ca.mu.Lock()
	ca.failFetch = 100
	ca.mu.Unlock()
	short, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	iss.Issue(short, "mx.example.com", other)
	cancel()
	ca.mu.Lock()
	ca.failFetch = 0
	ca.mu.Unlock()

	if _, err := iss.Issue(ctx, "mx.example.com", key); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if n, _, _ := ca.counts(); n != 2 {
		t.Fatalf("CA saw %d new-order request(s), want 2 — an order for another key must not be collected", n)
	}
}

// If the journal cannot be read, the attempt cannot know whether an order is
// outstanding, and the one thing it must not do is place another.
func TestIssue_DoesNotOrderWhenTheJournalCannotBeRead(t *testing.T) {
	ca := newFakeCA(t)
	m, _, flaky := newFlakyManager(t, 0)
	iss := newIssuerAt(t, ca, m)
	iss.journal.backend = &readErrorBackend{Backend: flaky.Backend, failGetFor: "orders/"}
	ctx := context.Background()
	key, _ := m.keyStore.LoadCertKey(ctx, "mx.example.com")

	if _, err := iss.Issue(ctx, "mx.example.com", key); err == nil {
		t.Fatal("Issue succeeded without knowing whether an order was outstanding")
	}
	if n, _, _ := ca.counts(); n != 0 {
		t.Fatalf("CA saw %d new-order request(s), want 0", n)
	}
}

// A challenge the validating node cannot answer is a validation the CA will
// fail — and count. The mirror write used to be a warning; the challenge was
// accepted regardless.
func TestIssue_DoesNotAcceptAChallengeItCouldNotMirror(t *testing.T) {
	ca := newFakeCA(t)
	ca.mu.Lock()
	ca.challenges = true
	ca.mu.Unlock()
	m, _, flaky := newFlakyManager(t, 0)
	m.challenges = NewChallengeServer(&flakyBackend{Backend: flaky.Backend, failFor: "challenges/", failPuts: 100}, "", testLogger())
	iss := newIssuerAt(t, ca, m)
	ctx := context.Background()
	key, _ := m.keyStore.LoadCertKey(ctx, "mx.example.com")

	if _, err := iss.Issue(ctx, "mx.example.com", key); err == nil {
		t.Fatal("Issue succeeded although the challenge could not be shared with the cluster")
	}
	if _, accepts, _ := ca.counts(); accepts != 0 {
		t.Fatalf("CA saw %d challenge accept(s) for a token only this node can serve, want 0", accepts)
	}
}

// The whole flow, with challenges, against the fake: the harness itself has
// to be shown to work before anything above it means anything.
func TestIssue_EndToEndWithChallenges(t *testing.T) {
	ca := newFakeCA(t)
	ca.mu.Lock()
	ca.challenges = true
	ca.mu.Unlock()
	m, _, _ := newFlakyManager(t, 0)
	iss := newIssuerAt(t, ca, m)
	ctx := context.Background()
	key, _ := m.keyStore.LoadCertKey(ctx, "mx.example.com")

	chain, err := iss.Issue(ctx, "mx.example.com", key)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := buildCertificate(chain, key); err != nil {
		t.Fatal(err)
	}
	if n, accepts, _ := ca.counts(); n != 1 || accepts != 1 {
		t.Fatalf("orders=%d accepts=%d, want 1 and 1", n, accepts)
	}
}
