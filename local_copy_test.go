package certmanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Open-Email/go-certs-manager/internal/layout"
	"github.com/Open-Email/go-certs-manager/storage"
)

// errStorageDown is what a node that cannot reach storage gets back.
var errStorageDown = errors.New("dial tcp 203.0.113.9:443: connect: connection refused")

// switchBackend is storage that can be taken down and brought back: every call
// fails while down is set, and reaches the wrapped backend otherwise.
type switchBackend struct {
	storage.Backend
	down atomic.Bool
}

func newSwitchBackend(t *testing.T) *switchBackend {
	t.Helper()
	fs, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return &switchBackend{Backend: fs}
}

func (b *switchBackend) PutObject(ctx context.Context, key string, r io.Reader, size int64, opts storage.PutOptions) error {
	if b.down.Load() {
		return errStorageDown
	}
	return b.Backend.PutObject(ctx, key, r, size, opts)
}

func (b *switchBackend) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	if b.down.Load() {
		return nil, errStorageDown
	}
	return b.Backend.GetObject(ctx, key)
}

func (b *switchBackend) StatObject(ctx context.Context, key string) (storage.ObjectInfo, error) {
	if b.down.Load() {
		return storage.ObjectInfo{}, errStorageDown
	}
	return b.Backend.StatObject(ctx, key)
}

func (b *switchBackend) RemoveObject(ctx context.Context, key string) error {
	if b.down.Load() {
		return errStorageDown
	}
	return b.Backend.RemoveObject(ctx, key)
}

func (b *switchBackend) ListObjects(ctx context.Context, prefix string, recursive bool) ([]storage.ObjectInfo, error) {
	if b.down.Load() {
		return nil, errStorageDown
	}
	return b.Backend.ListObjects(ctx, prefix, recursive)
}

// hangingBackend never answers: every call waits for its context, the way an
// endpoint that accepts the connection and then says nothing behaves.
type hangingBackend struct{ storage.Backend }

func (hangingBackend) PutObject(ctx context.Context, _ string, _ io.Reader, _ int64, _ storage.PutOptions) error {
	<-ctx.Done()
	return ctx.Err()
}

func (hangingBackend) GetObject(ctx context.Context, _ string) (io.ReadCloser, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (hangingBackend) RemoveObject(ctx context.Context, _ string) error {
	<-ctx.Done()
	return ctx.Err()
}

func (hangingBackend) ListObjects(ctx context.Context, _ string, _ bool) ([]storage.ObjectInfo, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// seedStorage stores name's persistent key and a chain with the given serial
// and expiry, as a leader that issued it would have left them.
func seedStorage(t *testing.T, b storage.Backend, name string, serial int64, notAfter time.Time) crypto.Signer {
	t.Helper()
	ctx := context.Background()
	ks := NewKeyStore(b, "", KeyTypeECDSAP256, nil, nil)
	key, err := ks.LoadOrCreateCertKey(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := chainWithSerialNotAfter(key, layout.CertDomain(name), serial, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.PutObject(ctx, layout.Chain("", name), strings.NewReader(string(chain)), int64(len(chain)), storage.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	return key
}

// startManager runs NewManager as smtp-in and the gateway do, keeping a local
// copy in dir when dir is set.
func startManager(t *testing.T, b storage.Backend, dir string, leader bool, companion bool) *Manager {
	t.Helper()
	m, err := NewManager(context.Background(), &Config{
		Enabled:  true,
		Provider: "letsencrypt",
		LetsEncrypt: LetsEncryptConfig{
			Domains:      []string{"mx.example.com"},
			LocalDir:     dir,
			RSACompanion: companion,
		},
	}, b, "", testLogger(), func() bool { return leader })
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(m.Stop)
	return m
}

// handshakeSerial is the serial of the certificate a handshake for name gets, or
// 0 when the handshake gets none.
func handshakeSerial(t *testing.T, m *Manager, serverName string) int64 {
	t.Helper()
	cert, err := m.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: serverName})
	if err != nil || cert == nil {
		return 0
	}
	return cert.Leaf.SerialNumber.Int64()
}

// The reported failure, end to end: a node that served a certificate is
// restarted while storage cannot be reached. It must come back serving that
// certificate rather than refusing every handshake until storage answers.
func TestNewManager_StartsFromTheLocalCopyWhenStorageCannotBeRead(t *testing.T) {
	for _, leader := range []bool{false, true} {
		name := "follower"
		if leader {
			name = "leader"
		}
		t.Run(name, func(t *testing.T) {
			b := newSwitchBackend(t)
			seedStorage(t, b, "mx.example.com", 7, time.Now().Add(80*24*time.Hour))
			dir := filepath.Join(t.TempDir(), "tls")

			first := startManager(t, b, dir, false, false)
			if got := handshakeSerial(t, first, "mx.example.com"); got != 7 {
				t.Fatalf("setup: served serial %d, want 7", got)
			}
			first.Stop()

			b.down.Store(true)
			restarted := startManager(t, b, dir, leader, false)

			if got := handshakeSerial(t, restarted, "mx.example.com"); got != 7 {
				t.Fatalf("after a restart with storage down: served serial %d, want 7 from the local copy", got)
			}
			if missing := restarted.MissingCertificates(); len(missing) != 0 {
				t.Fatalf("MissingCertificates() = %v, want none", missing)
			}

			// Without a local copy nothing changes from today: no certificate.
			bare := startManager(t, b, "", leader, false)
			if got := handshakeSerial(t, bare, "mx.example.com"); got != 0 {
				t.Fatalf("without a local copy: served serial %d, want none", got)
			}
			if missing := bare.MissingCertificates(); len(missing) != 1 || missing[0] != "mx.example.com" {
				t.Fatalf("MissingCertificates() = %v, want [mx.example.com]", missing)
			}
		})
	}
}

// The companion is kept and restored like the primary, so the legacy clients
// it exists for are not the ones a restart leaves out.
func TestNewManager_StartsTheCompanionFromTheLocalCopy(t *testing.T) {
	b := newSwitchBackend(t)
	seedStorage(t, b, "mx.example.com", 7, time.Now().Add(80*24*time.Hour))
	seedStorage(t, b, layout.Companion("mx.example.com"), 8, time.Now().Add(80*24*time.Hour))
	dir := filepath.Join(t.TempDir(), "tls")

	startManager(t, b, dir, false, true).Stop()
	b.down.Store(true)
	m := startManager(t, b, dir, false, true)

	cert, ok := m.certCache.Get(layout.Companion("mx.example.com"))
	if !ok || cert.Leaf.SerialNumber.Int64() != 8 {
		t.Fatal("the companion was not loaded from the local copy")
	}
}

// writeLocalFile puts raw bytes where the local copy of name is kept.
func writeLocalFile(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".pem"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func localFileFor(t *testing.T, key crypto.Signer, chain []byte) []byte {
	t.Helper()
	keyPEM, err := marshalKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	return append(keyPEM, chain...)
}

// A local file is served only if it is a certificate this node could have
// served: anything else is skipped with a warning, never handed to a client.
func TestNewManager_SkipsAnUnusableLocalCopy(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	good, err := chainWithSerial(key, "mx.example.com", 7)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := chainWithSerialNotAfter(key, "mx.example.com", 7, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := chainWithSerial(key, "other.example.com", 7)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"not PEM":             []byte("this is not a certificate"),
		"key only":            localFileFor(t, key, nil),
		"chain only":          good,
		"key for another":     localFileFor(t, other, good),
		"expired":             localFileFor(t, key, expired),
		"for another name":    localFileFor(t, key, foreign),
		"truncated":           localFileFor(t, key, good)[:200],
		"empty":               {},
		"chain block garbled": localFileFor(t, key, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			b := newSwitchBackend(t)
			b.down.Store(true)
			dir := t.TempDir()
			writeLocalFile(t, dir, "mx.example.com", data)

			h := &capturingHandler{}
			m, err := NewManager(context.Background(), &Config{
				Enabled:     true,
				Provider:    "letsencrypt",
				LetsEncrypt: LetsEncryptConfig{Domains: []string{"mx.example.com"}, LocalDir: dir},
			}, b, "", slog.New(h), func() bool { return false })
			if err != nil {
				t.Fatalf("NewManager: %v", err)
			}
			defer m.Stop()

			if got := handshakeSerial(t, m, "mx.example.com"); got != 0 {
				t.Fatalf("served serial %d from an unusable local copy", got)
			}
			if !h.warnedAbout("local copy") {
				t.Fatal("no warning that the local copy was skipped")
			}
		})
	}
}

// Storage's answer wins whenever it gives one. "There is none" is an answer:
// the local copy is for a storage that cannot be read, not a second opinion.
func TestNewManager_StorageThatAnswersNoneIsNotOverriddenByTheLocalCopy(t *testing.T) {
	b := newSwitchBackend(t)
	seedStorage(t, b, "mx.example.com", 7, time.Now().Add(80*24*time.Hour))
	dir := filepath.Join(t.TempDir(), "tls")
	startManager(t, b, dir, false, false).Stop()

	deleteChain(t, b, "mx.example.com")
	m := startManager(t, b, dir, false, false)

	if got := handshakeSerial(t, m, "mx.example.com"); got != 0 {
		t.Fatalf("served serial %d although storage said there is no chain", got)
	}
}

// What storage holds replaces an older local copy at startup, and the copy
// follows it.
func TestNewManager_PrefersStorageAndUpdatesTheLocalCopy(t *testing.T) {
	b := newSwitchBackend(t)
	key := seedStorage(t, b, "mx.example.com", 7, time.Now().Add(80*24*time.Hour))
	dir := filepath.Join(t.TempDir(), "tls")
	startManager(t, b, dir, false, false).Stop()

	newer, err := chainWithSerialNotAfter(key, "mx.example.com", 9, time.Now().Add(85*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.PutObject(context.Background(), layout.Chain("", "mx.example.com"), strings.NewReader(string(newer)), int64(len(newer)), storage.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	startManager(t, b, dir, false, false).Stop()

	b.down.Store(true)
	m := startManager(t, b, dir, false, false)
	if got := handshakeSerial(t, m, "mx.example.com"); got != 9 {
		t.Fatalf("served serial %d, want 9: the local copy did not follow storage", got)
	}
}

// A leader holding a certificate outside its renewal window never re-reads
// storage for it. Started from the local copy, it would keep serving that
// copy after storage came back: after a key replacement, a retired key that
// DANE clients refuse. The first tick that can read storage must take its
// chain.
func TestMaintainOnce_LeaderReplacesTheLocalCopyOnceStorageAnswers(t *testing.T) {
	b := newSwitchBackend(t)
	key := seedStorage(t, b, "mx.example.com", 7, time.Now().Add(80*24*time.Hour))
	dir := filepath.Join(t.TempDir(), "tls")
	startManager(t, b, dir, false, false).Stop()

	// While this node is away, storage moves on to a new key and chain.
	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyPEM, err := marshalKeyPEM(newKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := b.PutObject(ctx, layout.Key("", "mx.example.com"), strings.NewReader(string(keyPEM)), int64(len(keyPEM)), storage.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	newChain, err := chainWithSerial(newKey, "mx.example.com", 9)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.PutObject(ctx, layout.Chain("", "mx.example.com"), strings.NewReader(string(newChain)), int64(len(newChain)), storage.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	_ = key

	b.down.Store(true)
	m, ca := leaderOver(t, b, dir)
	if got := handshakeSerial(t, m, "mx.example.com"); got != 7 {
		t.Fatalf("setup: served serial %d, want 7 from the local copy", got)
	}

	b.down.Store(false)
	m.maintainOnce()

	if got := handshakeSerial(t, m, "mx.example.com"); got != 9 {
		t.Fatalf("after storage came back: served serial %d, want 9 from storage", got)
	}
	if ca.orders != 0 {
		t.Fatalf("CA saw %d orders, want none", ca.orders)
	}
	// The copy follows, so a second restart does not go back to the old key.
	b.down.Store(true)
	again, _ := leaderOver(t, b, dir)
	if got := handshakeSerial(t, again, "mx.example.com"); got != 9 {
		t.Fatalf("second restart: served serial %d, want 9", got)
	}
}

// leaderOver is a leader built the way NewManager builds one, but with a
// counting CA and no maintenance goroutine, so a test drives the ticks.
func leaderOver(t *testing.T, b storage.Backend, dir string) (*Manager, *countingCA) {
	t.Helper()
	leader := func() bool { return true }
	ks := NewKeyStore(b, "", KeyTypeECDSAP256, leader, nil)
	ca := &countingCA{}
	local, err := newLocalCopy(dir, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		keyStore:      ks,
		certCache:     newCertCache(b, "", ks.LoadCertKey, nil),
		issuer:        ca,
		logger:        testLogger(),
		domains:       []string{"mx.example.com"},
		domainSet:     map[string]bool{"mx.example.com": true},
		defaultDomain: "mx.example.com",
		isLeaderF:     leader,
		renewBefore:   30 * 24 * time.Hour,
		retries:       newRetryBudget(3),
		leaser:        newLeaser(t, b, "node-self", time.Minute),
		stopCh:        make(chan struct{}),
	}
	m.useLocalCopy(local)
	m.tlsConfig = m.buildTLSConfig()
	m.preload(context.Background())
	return m, ca
}

// Serving the local copy never reaches the CA, even for a certificate inside
// its renewal window: ordering needs the issuance lease, which is a storage
// write.
func TestMaintainOnce_NoOrderWhileServingTheLocalCopy(t *testing.T) {
	b := newSwitchBackend(t)
	seedStorage(t, b, "mx.example.com", 7, time.Now().Add(10*24*time.Hour))
	dir := filepath.Join(t.TempDir(), "tls")
	startManager(t, b, dir, false, false).Stop()

	b.down.Store(true)
	m, ca := leaderOver(t, b, dir)
	if got := handshakeSerial(t, m, "mx.example.com"); got != 7 {
		t.Fatalf("setup: served serial %d, want 7", got)
	}
	m.maintainOnce()
	m.maintainOnce()

	if ca.orders != 0 {
		t.Fatalf("CA saw %d orders while storage was down", ca.orders)
	}
	if got := handshakeSerial(t, m, "mx.example.com"); got != 7 {
		t.Fatalf("served serial %d after the ticks, want 7", got)
	}
}

// The local copy is for names a restart can serve: the configured ones. An
// on-demand name also needs the allow-set, which lives in storage, so copying
// it would only fill the directory.
func TestLocalCopy_KeepsOnlyConfiguredNames(t *testing.T) {
	b := newSwitchBackend(t)
	seedStorage(t, b, "mx.example.com", 7, time.Now().Add(80*24*time.Hour))
	seedStorage(t, b, "mail.customer.example", 8, time.Now().Add(80*24*time.Hour))
	dir := filepath.Join(t.TempDir(), "tls")
	m := startManager(t, b, dir, false, false)

	if _, err := m.certCache.Refresh(context.Background(), "mail.customer.example"); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(dir, "mx.example.com.pem")); err != nil {
		t.Fatalf("configured name not copied: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "mail.customer.example.pem")); !os.IsNotExist(err) {
		t.Fatalf("on-demand name copied (stat err %v)", err)
	}
}

// The copy holds a private key: owner-only, whatever the umask.
func TestLocalCopy_IsOwnerOnly(t *testing.T) {
	b := newSwitchBackend(t)
	seedStorage(t, b, "mx.example.com", 7, time.Now().Add(80*24*time.Hour))
	dir := filepath.Join(t.TempDir(), "tls")
	startManager(t, b, dir, false, false).Stop()

	for path, want := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, "mx.example.com.pem"): 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode %o, want %o", path, got, want)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries, want only the copy (no temp files left behind)", len(entries))
	}
}

// A directory the process cannot use is a configuration error, reported at
// startup rather than discovered during the outage it was meant for.
func TestNewManager_RefusesALocalDirItCannotWrite(t *testing.T) {
	parent := t.TempDir()
	blocker := filepath.Join(parent, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	b := newSwitchBackend(t)
	m, err := NewManager(context.Background(), &Config{
		Enabled:     true,
		Provider:    "letsencrypt",
		LetsEncrypt: LetsEncryptConfig{Domains: []string{"mx.example.com"}, LocalDir: filepath.Join(blocker, "tls")},
	}, b, "", testLogger(), func() bool { return false })
	if err == nil {
		m.Stop()
		t.Fatal("NewManager accepted a local_dir it cannot create")
	}
}

// Callers pass contexts without a deadline (smtp-in passes its process
// context). A storage endpoint that never answers must not hold startup.
func TestNewManager_ReturnsWhenStorageHangs(t *testing.T) {
	defer func(probe, preload time.Duration) { storageProbeTimeout, preloadTimeout = probe, preload }(storageProbeTimeout, preloadTimeout)
	storageProbeTimeout, preloadTimeout = 200*time.Millisecond, 200*time.Millisecond

	fs, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *Manager, 1)
	go func() {
		m, err := NewManager(context.Background(), &Config{
			Enabled:     true,
			Provider:    "letsencrypt",
			LetsEncrypt: LetsEncryptConfig{Domains: []string{"mx.example.com"}},
		}, hangingBackend{fs}, "", testLogger(), func() bool { return false })
		if err != nil {
			t.Errorf("NewManager: %v", err)
		}
		done <- m
	}()
	select {
	case m := <-done:
		m.Stop()
	case <-time.After(5 * time.Second):
		t.Fatal("NewManager did not return while storage hung")
	}
}
