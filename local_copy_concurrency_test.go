package certmanager

import (
	"context"
	"crypto"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Open-Email/go-certs-manager/internal/layout"
	"github.com/Open-Email/go-certs-manager/storage"
)

func awaitLocalCopyEvent(t *testing.T, description string, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func runLocalCopyPass(t *testing.T, m *Manager) {
	t.Helper()
	done := make(chan struct{})
	go func() { m.supersedeLocalCopies(); close(done) }()
	awaitLocalCopyEvent(t, "local-copy recovery pass", done)
}

// pauseLocalKeyRead holds one already-read old key just before Refresh can
// install its pair. This makes an overlapping activation deterministic.
type pauseLocalKeyRead struct {
	storage.Backend
	armed   atomic.Bool
	reached chan struct{}
	resume  chan struct{}
}

func (b *pauseLocalKeyRead) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	rc, err := b.Backend.GetObject(ctx, key)
	if err != nil || key != layout.Key("", "mx.example.com") || !b.armed.Swap(false) {
		return rc, err
	}
	return &pauseLocalKeyClose{ReadCloser: rc, reached: b.reached, resume: b.resume}, nil
}

type pauseLocalKeyClose struct {
	io.ReadCloser
	reached chan struct{}
	resume  chan struct{}
}

func (r *pauseLocalKeyClose) Close() error {
	err := r.ReadCloser.Close()
	close(r.reached)
	<-r.resume
	return err
}

type pauseLocalCopyCA struct {
	orderer
	started chan struct{}
	resume  chan struct{}
}

func (ca *pauseLocalCopyCA) Issue(ctx context.Context, name string, key crypto.Signer) ([]byte, error) {
	close(ca.started)
	<-ca.resume
	return ca.orderer.Issue(ctx, name, key)
}

// A leader that restarted from its local copy must not let a recovering read
// undo a successful key activation. Without serialization the old read can
// replace BOTH the live pair and the on-disk copy, then clear fromLocal so
// later leader ticks keep serving the retired key until its renewal window.
func TestSupersedeLocalCopies_DoesNotUndoConcurrentKeyActivation(t *testing.T) {
	b := newSwitchBackend(t)
	seedStorage(t, b, "mx.example.com", 7, time.Now().Add(80*24*time.Hour))
	dir := t.TempDir()
	startManager(t, b, dir, false, false).Stop()
	b.down.Store(true)
	m, ca := leaderOver(t, b, dir)
	b.down.Store(false)
	if _, err := m.ReplaceCertificateKey("mx.example.com"); err != nil {
		t.Fatal(err)
	}
	paused := &pauseLocalCopyCA{orderer: ca, started: make(chan struct{}), resume: make(chan struct{})}
	resumeCA := sync.OnceFunc(func() { close(paused.resume) })
	defer resumeCA()
	m.issuer = paused
	activationDone := make(chan error, 1)
	go func() { activationDone <- m.ActivateCertificateKey("mx.example.com", false) }()
	awaitLocalCopyEvent(t, "activation owning the domain's issuance lock", paused.started)

	read := &pauseLocalKeyRead{Backend: b, reached: make(chan struct{}), resume: make(chan struct{})}
	resumeRead := sync.OnceFunc(func() { close(read.resume) })
	defer resumeRead()
	read.armed.Store(true)
	m.certCache.backend = read
	m.keyStore.backend = read
	refreshDone := make(chan struct{})
	go func() { m.supersedeLocalCopies(); close(refreshDone) }()
	select {
	case <-refreshDone: // busy name skipped
	case <-read.reached: // regression: old pair read despite the activation
	case <-time.After(5 * time.Second):
		t.Fatal("recovery neither skipped the busy name nor read its old key")
	}
	resumeCA()
	select {
	case err := <-activationDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("activation did not finish while recovery was paused")
	}
	activated := handshakeSerial(t, m, "mx.example.com")
	resumeRead()
	awaitLocalCopyEvent(t, "paused recovery to finish", refreshDone)
	if activated == 0 || activated == 7 {
		t.Fatalf("setup: activation served serial %d, want a new certificate", activated)
	}

	if got := handshakeSerial(t, m, "mx.example.com"); got != activated {
		t.Errorf("recovery reverted activated serial %d to %d", activated, got)
	}
	if pending := m.certCache.servedFromLocal(); len(pending) != 0 {
		t.Errorf("activated certificate is still marked as local: %v", pending)
	}
	m.maintainOnce()
	if got := handshakeSerial(t, m, "mx.example.com"); got != activated {
		t.Errorf("next tick serves serial %d, want activated %d", got, activated)
	}
	copy, err := m.local.load("mx.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := copy.Leaf.SerialNumber.Int64(); got != activated {
		t.Errorf("disk copy holds serial %d, want activated %d", got, activated)
	}
}

// Both names use the same lock key as their own renewal/flush writer. Skipping
// a busy name keeps its recovery marker so a later pass can still adopt storage.
func TestSupersedeLocalCopies_RetriesBusyPrimaryAndCompanion(t *testing.T) {
	for _, name := range []string{"mx.example.com", layout.Companion("mx.example.com")} {
		t.Run(name, func(t *testing.T) {
			b := newSwitchBackend(t)
			key := seedStorage(t, b, name, 7, time.Now().Add(80*24*time.Hour))
			m, _ := leaderOver(t, b, t.TempDir())
			if layout.IsCompanion(name) {
				m.rsaCompanion = true
			}
			cert, err := m.certCache.Refresh(context.Background(), name)
			if err != nil {
				t.Fatal(err)
			}
			m.certCache.setFromLocal(name, cert)
			newer, err := chainWithSerial(key, layout.CertDomain(name), 9)
			if err != nil {
				t.Fatal(err)
			}
			if err := m.certCache.persist(context.Background(), name, newer, 1); err != nil {
				t.Fatal(err)
			}

			unlock := sync.OnceFunc(m.inflight.lock(name))
			defer unlock()
			runLocalCopyPass(t, m)
			unlock()
			if got, _ := m.certCache.Get(name); got.Leaf.SerialNumber.Int64() != 7 {
				t.Fatal("recovery changed a name while its writer held the lock")
			}
			if pending := m.certCache.servedFromLocal(); len(pending) != 1 || pending[0] != name {
				t.Fatalf("busy name lost its recovery marker: %v", pending)
			}
			runLocalCopyPass(t, m)
			if got, _ := m.certCache.Get(name); got.Leaf.SerialNumber.Int64() != 9 {
				t.Fatal("next pass did not adopt storage after the writer finished")
			}
			if pending := m.certCache.servedFromLocal(); len(pending) != 0 {
				t.Fatalf("successful recovery left markers: %v", pending)
			}
		})
	}
}
