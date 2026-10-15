package certmanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Open-Email/go-certs-manager/internal/layout"
	"github.com/Open-Email/go-certs-manager/storage"
)

const companionName = "mx.example.com" + layout.CompanionSuffix

// newCompanionLeader is a leader for mx.example.com with RSACompanion on and
// nothing issued yet.
func newCompanionLeader(t *testing.T) (*Manager, *countingCA, *flakyBackend) {
	t.Helper()
	m, ca, backend := newFlakyManager(t, 0)
	m.rsaCompanion = true
	return m, ca, backend
}

func storedKey(t *testing.T, b storage.Backend, name string) bool {
	t.Helper()
	_, err := b.StatObject(context.Background(), layout.Key("", name))
	return err == nil
}

// The companion is a second certificate for the same hostname, under its own
// RSA key, and the CA is asked for the hostname, never for the name it is
// filed under.
func TestCompanion_LeaderIssuesAnRSACertificateNextToTheECDSAOne(t *testing.T) {
	m, ca, backend := newCompanionLeader(t)

	m.maintainOnce()

	if got := ca.orderedNames(); !slices.Equal(got, []string{"mx.example.com", companionName}) {
		t.Fatalf("orders placed under %v, want the primary and then its companion", got)
	}
	primary, ok := m.certCache.Get("mx.example.com")
	if !ok {
		t.Fatal("no primary certificate served")
	}
	if _, isEC := primary.PrivateKey.(*ecdsa.PrivateKey); !isEC {
		t.Fatalf("primary key is %T, want ECDSA", primary.PrivateKey)
	}
	companion, ok := m.certCache.Get(companionName)
	if !ok {
		t.Fatal("no companion certificate held")
	}
	rsaKey, isRSA := companion.PrivateKey.(*rsa.PrivateKey)
	if !isRSA || rsaKey.N.BitLen() != 2048 {
		t.Fatalf("companion key is %T, want RSA 2048", companion.PrivateKey)
	}
	if !slices.Equal(companion.Leaf.DNSNames, []string{"mx.example.com"}) {
		t.Fatalf("companion certifies %v, want the hostname itself", companion.Leaf.DNSNames)
	}
	if storedSerial(t, m, companionName) == 0 || !storedKey(t, backend, companionName) {
		t.Fatal("companion chain or key not in storage, so no follower can serve it")
	}

	// Both fresh: the next pass orders nothing.
	m.maintainOnce()
	if ca.orders != 2 {
		t.Fatalf("CA saw %d orders after a second pass, want 2", ca.orders)
	}
}

func TestCompanion_OffByDefault(t *testing.T) {
	m, ca, backend := newFlakyManager(t, 0)

	m.maintainOnce()

	if ca.orders != 1 {
		t.Fatalf("CA saw %d orders, want 1 (the primary only)", ca.orders)
	}
	if _, ok := m.certCache.Get(companionName); ok || storedKey(t, backend, companionName) {
		t.Fatal("a companion was made although RSACompanion is off")
	}
}

// The companion never competes with the primary for the CA's budget: while the
// primary cannot be had, one failed order per pass is all the hostname costs.
func TestCompanion_FollowsThePrimary(t *testing.T) {
	m, ca, _ := newCompanionLeader(t)
	ca.err = errors.New("validation failed")

	m.maintainOnce()

	if got := ca.orderedNames(); !slices.Equal(got, []string{"mx.example.com"}) {
		t.Fatalf("orders placed under %v, want the primary only", got)
	}
}

// The CA limits failed validations and duplicate certificates per hostname,
// so the companion spends the same retry budget as the primary.
func TestCompanion_SharesTheHostnamesRetryBudget(t *testing.T) {
	m, ca, _ := newCompanionLeader(t)
	m.renewIfNeeded(context.Background(), "mx.example.com")
	ca.err = errors.New("validation failed")

	for i := 0; i < 3; i++ {
		m.maintainOnce()
	}

	if got := ca.orderedNames(); len(got) != 4 || got[1] != companionName {
		t.Fatalf("orders placed under %v, want the primary and three companion attempts", got)
	}
	if _, ok := m.retries.allow("mx.example.com"); ok {
		t.Fatal("three failed companion orders left the hostname's retry budget untouched")
	}
}

// One issuance per hostname at a time, cluster-wide: the TLS-ALPN-01 answer is
// filed by hostname, so a companion order racing a peer's primary order would
// present one token over the other.
func TestCompanion_WaitsForTheHostnamesLease(t *testing.T) {
	m, ca, backend := newCompanionLeader(t)
	ctx := context.Background()
	if err := m.renewIfNeeded(ctx, "mx.example.com"); err != nil {
		t.Fatal(err)
	}
	release, ok := newLeaser(t, backend, "node-other", time.Minute).acquire(ctx, "mx.example.com")
	if !ok {
		t.Fatal("setup: could not take the lease")
	}

	m.maintainOnce()
	if ca.orders != 1 {
		t.Fatalf("CA saw %d orders while another node held the hostname's lease, want 1", ca.orders)
	}

	release()
	m.maintainOnce()
	if got := ca.orderedNames(); !slices.Equal(got, []string{"mx.example.com", companionName}) {
		t.Fatalf("orders placed under %v once the lease was free, want the companion's", got)
	}
}

func TestCompanion_FollowerLoadsItFromStorage(t *testing.T) {
	leader, _, backend := newCompanionLeader(t)
	leader.maintainOnce()

	follower := &Manager{
		keyStore:     NewKeyStore(backend, "", KeyTypeECDSAP256, func() bool { return false }, nil),
		logger:       testLogger(),
		domains:      []string{"mx.example.com"},
		domainSet:    map[string]bool{"mx.example.com": true},
		isLeaderF:    func() bool { return false },
		renewBefore:  30 * 24 * time.Hour,
		rsaCompanion: true,
	}
	follower.certCache = newCertCache(backend, "", follower.keyStore.LoadCertKey, nil)

	follower.preload(context.Background())
	if _, ok := follower.certCache.Get(companionName); !ok {
		t.Fatal("preload did not load the companion")
	}

	follower.certCache = newCertCache(backend, "", follower.keyStore.LoadCertKey, nil)
	follower.maintainOnce()
	if _, ok := follower.certCache.Get(companionName); !ok {
		t.Fatal("a follower's maintenance pass did not load the companion")
	}
}

// The leader writes back a companion storage lost, as it does a primary,
// rather than leave every restarting node without it until renewal.
func TestCompanion_RestoredWhenStorageLosesIt(t *testing.T) {
	m, ca, backend := newCompanionLeader(t)
	m.maintainOnce()
	deleteChain(t, backend, companionName)

	m.maintainOnce()

	if storedSerial(t, m, companionName) == 0 {
		t.Fatal("the companion chain was not written back")
	}
	if ca.orders != 2 {
		t.Fatalf("CA saw %d orders, want 2: a chain in memory is restored, not re-ordered", ca.orders)
	}
}

func TestNewManager_RefusesACompanionNextToAnRSAPrimary(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(context.Background(), &Config{
		Enabled:  true,
		Provider: "letsencrypt",
		LetsEncrypt: LetsEncryptConfig{
			Domains:      []string{"mx.example.com"},
			KeyType:      KeyTypeRSA2048,
			RSACompanion: true,
		},
	}, backend, "", testLogger(), func() bool { return false })
	if err == nil {
		m.Stop()
		t.Fatal("NewManager accepted an RSA companion next to an RSA primary")
	}
}

func TestKeyStore_CompanionKeyIsRSA(t *testing.T) {
	ks := newTestKeyStore(t, KeyTypeECDSAP256, nil)
	key, err := ks.LoadOrCreateCertKey(context.Background(), companionName)
	if err != nil {
		t.Fatal(err)
	}
	if k, ok := key.(*rsa.PrivateKey); !ok || k.N.BitLen() != 2048 {
		t.Fatalf("companion key is %T, want RSA 2048", key)
	}
}

// The real Issuer: the order and the CSR name the hostname, and the order is
// journaled under the companion's own name, so it neither collects nor
// overwrites the primary's outstanding order.
func TestIssue_CompanionOrdersTheHostnameAndJournalsApart(t *testing.T) {
	ca := newFakeCA(t)
	m, _, _ := newFlakyManager(t, 0)
	iss := newIssuerAt(t, ca, m)
	ctx := context.Background()
	ecKey, err := m.keyStore.LoadCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := m.keyStore.LoadOrCreateCertKey(ctx, companionName)
	if err != nil {
		t.Fatal(err)
	}

	// The primary's order is left outstanding: its download fails.
	ca.mu.Lock()
	ca.failFetch = 100
	ca.mu.Unlock()
	short, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	if _, err := iss.Issue(short, "mx.example.com", ecKey); err == nil {
		t.Fatal("setup: Issue succeeded although the download failed")
	}
	cancel()
	ca.mu.Lock()
	ca.failFetch = 0
	ca.mu.Unlock()

	chain, err := iss.Issue(ctx, companionName, rsaKey)
	if err != nil {
		t.Fatalf("companion Issue: %v", err)
	}
	leaf := parseFirstLeaf(t, chain)
	if !slices.Equal(leaf.DNSNames, []string{"mx.example.com"}) {
		t.Fatalf("companion certificate names %v, want the hostname", leaf.DNSNames)
	}
	ca.mu.Lock()
	ordered := append([]string(nil), ca.ordered...)
	ca.mu.Unlock()
	if !slices.Equal(ordered, []string{"mx.example.com", "mx.example.com"}) {
		t.Fatalf("CA was asked for %v, want the hostname both times", ordered)
	}

	// The primary's outstanding order is still collected, not re-ordered.
	if _, err := iss.Issue(ctx, "mx.example.com", ecKey); err != nil {
		t.Fatalf("primary Issue: %v", err)
	}
	if n, _, _ := ca.counts(); n != 2 {
		t.Fatalf("CA saw %d new orders, want 2: the companion's order must not displace the primary's journal entry", n)
	}
}

// --- handshakes -------------------------------------------------------------

// companionServer is a follower serving mx.example.com with both certificates
// in memory, built by the leader so they are the real thing.
func companionServer(t *testing.T) *Manager {
	t.Helper()
	leader, _, backend := newCompanionLeader(t)
	leader.maintainOnce()
	m := newServingManager(t)
	m.keyStore = NewKeyStore(backend, "", KeyTypeECDSAP256, func() bool { return false }, nil)
	m.certCache = newCertCache(backend, "", m.keyStore.LoadCertKey, nil)
	m.rsaCompanion = true
	m.preload(context.Background())
	m.tlsConfig = m.buildTLSConfig()
	if _, ok := m.certCache.Get(companionName); !ok {
		t.Fatal("setup: the serving node holds no companion")
	}
	return m
}

// handshake runs one TLS handshake over an in-memory pipe and reports what the
// client saw: the leaf it was served, the suite, and the server's error.
func handshake(t *testing.T, serverCfg, clientCfg *tls.Config) (*x509.Certificate, uint16, error) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	type result struct {
		state tls.ConnectionState
		err   error
	}
	done := make(chan result, 1)
	go func() {
		c := tls.Client(clientConn, clientCfg)
		err := c.Handshake()
		done <- result{c.ConnectionState(), err}
	}()
	server := tls.Server(serverConn, serverCfg)
	serr := server.Handshake()
	// Close the pipes, not the tls.Conns: a close_notify write blocks on an
	// unbuffered pipe whose peer is also closing.
	serverConn.Close()
	clientConn.Close()
	r := <-done
	if serr != nil {
		return nil, 0, serr
	}
	if r.err != nil {
		return nil, 0, r.err
	}
	return r.state.PeerCertificates[0], r.state.CipherSuite, nil
}

// listener is the tls.Config an SMTP listener derives from the manager's.
func listener(m *Manager, suites ...uint16) *tls.Config {
	cfg := m.TLSConfig()
	cfg.NextProtos = nil
	// As the SMTP services set it, and a TLS 1.3 ticket written to an
	// unbuffered pipe nobody reads would stall the handshake.
	cfg.SessionTicketsDisabled = true
	if len(suites) > 0 {
		cfg.CipherSuites = append(secureSuites(), suites...)
	}
	return cfg
}

func secureSuites() []uint16 {
	var ids []uint16
	for _, cs := range tls.CipherSuites() {
		ids = append(ids, cs.ID)
	}
	return ids
}

func tls12(suites ...uint16) *tls.Config {
	return &tls.Config{
		ServerName:         "mx.example.com",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       suites,
	}
}

func keyAlgorithm(leaf *x509.Certificate) string { return leaf.PublicKeyAlgorithm.String() }

func TestCompanion_Handshakes(t *testing.T) {
	m := companionServer(t)

	t.Run("modern client keeps the ECDSA certificate", func(t *testing.T) {
		for _, client := range []*tls.Config{
			{ServerName: "mx.example.com", InsecureSkipVerify: true},
			tls12(),
		} {
			leaf, _, err := handshake(t, listener(m), client)
			if err != nil {
				t.Fatal(err)
			}
			if keyAlgorithm(leaf) != "ECDSA" {
				t.Fatalf("served %s, want ECDSA", keyAlgorithm(leaf))
			}
		}
	})

	t.Run("ECDHE_RSA-only client gets the companion and keeps forward secrecy", func(t *testing.T) {
		leaf, suite, err := handshake(t, listener(m), tls12(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256))
		if err != nil {
			t.Fatalf("handshake failed: %v", err)
		}
		if keyAlgorithm(leaf) != "RSA" || suite != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
			t.Fatalf("served %s with %s, want RSA with ECDHE_RSA", keyAlgorithm(leaf), tls.CipherSuiteName(suite))
		}
	})

	legacy := tls12(tls.TLS_RSA_WITH_AES_128_CBC_SHA)

	t.Run("RSA key exchange client gets the companion where the listener allows the suite", func(t *testing.T) {
		leaf, suite, err := handshake(t, listener(m, tls.TLS_RSA_WITH_AES_128_CBC_SHA), legacy)
		if err != nil {
			t.Fatalf("handshake failed: %v", err)
		}
		if keyAlgorithm(leaf) != "RSA" || suite != tls.TLS_RSA_WITH_AES_128_CBC_SHA {
			t.Fatalf("served %s with %s", keyAlgorithm(leaf), tls.CipherSuiteName(suite))
		}
	})

	t.Run("without SNI, through the default domain", func(t *testing.T) {
		noSNI := legacy.Clone()
		noSNI.ServerName = ""
		leaf, _, err := handshake(t, listener(m, tls.TLS_RSA_WITH_AES_128_CBC_SHA), noSNI)
		if err != nil {
			t.Fatalf("handshake failed: %v", err)
		}
		if keyAlgorithm(leaf) != "RSA" {
			t.Fatalf("served %s, want RSA", keyAlgorithm(leaf))
		}
	})

	t.Run("RSA key exchange stays refused where the listener does not allow it", func(t *testing.T) {
		if _, _, err := handshake(t, listener(m), legacy); err == nil || !strings.Contains(err.Error(), "no cipher suite supported by both") {
			t.Fatalf("got %v, want the cipher suite mismatch Go's defaults give", err)
		}
	})

	// Go's probe rejects an ECDSA certificate whose curve is missing from a TLS
	// 1.2 client's supported_groups, but the handshake does not: it negotiates
	// X25519 and signs with P-256. Switching such a client to RSA would cost
	// nothing at the handshake and break DANE, so it keeps the primary.
	t.Run("a client that only omits P-256 keeps the ECDSA certificate", func(t *testing.T) {
		client := tls12(tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
		client.CurvePreferences = []tls.CurveID{tls.X25519}
		leaf, _, err := handshake(t, listener(m), client)
		if err != nil {
			t.Fatalf("handshake failed: %v", err)
		}
		if keyAlgorithm(leaf) != "ECDSA" {
			t.Fatalf("served %s, want ECDSA", keyAlgorithm(leaf))
		}
	})

	t.Run("not served when RSACompanion is off", func(t *testing.T) {
		off := companionServer(t)
		off.rsaCompanion = false
		off.tlsConfig = off.buildTLSConfig()
		if _, _, err := handshake(t, listener(off), tls12(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)); err == nil {
			t.Fatal("an ECDHE_RSA-only client was served although RSACompanion is off")
		}
	})
}

// The on-demand index tells followers which on-demand hostnames to re-read. A
// companion is neither: followers re-read it every tick, as they do its domain.
func TestAnnounceStoredChains_LeavesCompanionsOut(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	leader := newOnDemandManager(t, backend, true, OnDemandConfig{})
	leader.rsaCompanion = true
	storedChain(t, leader, companionName, 13)

	leader.announceStoredChains(context.Background(), true, []string{companionName})

	if _, known := leader.onDemand.indexNotAfter(companionName); known {
		t.Fatal("a companion was written into the on-demand index")
	}
}
