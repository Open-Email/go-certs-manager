package certmanager

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Open-Email/go-certs-manager/internal/layout"
)

// storageProbeTimeout bounds NewManager's conditional-write probe, and
// preloadTimeout its first read of the configured names. Callers pass
// contexts without a deadline (smtp-in passes its process context), and a
// storage endpoint that accepts the connection and never answers would
// otherwise hold startup for as long as it stayed that way. Variables so a
// test can shorten them.
var (
	storageProbeTimeout = 10 * time.Second
	preloadTimeout      = 15 * time.Second
)

// localRecheckTimeout bounds one storage read for a name served from the local
// copy, on each maintenance tick until one succeeds.
const localRecheckTimeout = 30 * time.Second

// localCopy keeps, on this node's own disk, the certificate and key this node
// serves for each configured name, so a process that starts while storage
// cannot be read still has something to serve.
//
// Storage stays the source of truth. A file is written only after storage
// confirmed what it holds, and read only when storage could not be read at
// startup: a definite "none" from storage, or a chain bound to another key,
// is storage's answer and is kept. A name served from the file is re-read
// from storage on every maintenance tick until a read succeeds.
//
// The file holds the private key. It is the key the process can already read
// from storage with the credentials in its own configuration, on the same host
// under the same user, so it adds no reader; it is written owner-only all the
// same. Each name is one file, "<name>.pem": the key, then the chain leaf
// first, so the pair is replaced in one rename and never read half-written.
type localCopy struct {
	dir    string
	logger *slog.Logger
}

// newLocalCopy prepares dir for the local copy and proves it writable. A
// directory that cannot be used is a configuration error, reported at startup
// rather than discovered during the outage it exists for.
func newLocalCopy(dir string, logger *slog.Logger) (*localCopy, error) {
	if logger == nil {
		logger = slog.Default()
	}
	switch info, err := os.Stat(dir); {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("tls: local certificate directory %s: %w", dir, err)
		}
		// MkdirAll's mode is filtered by the umask; this one is not.
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("tls: local certificate directory %s: %w", dir, err)
		}
	case err != nil:
		return nil, fmt.Errorf("tls: local certificate directory %s: %w", dir, err)
	case !info.IsDir():
		return nil, fmt.Errorf("tls: local certificate directory %s is not a directory", dir)
	case info.Mode().Perm()&0o077 != 0:
		// The files are 0600 whatever the directory says; a directory others
		// can list still tells them which names this node serves.
		logger.Warn("TLS: the local certificate directory is open to other users; the files in it are not", "dir", dir, "mode", fmt.Sprintf("%o", info.Mode().Perm()))
	}
	probe, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return nil, fmt.Errorf("tls: local certificate directory %s is not writable: %w", dir, err)
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())
	return &localCopy{dir: dir, logger: logger}, nil
}

// path is where name's copy is kept. Names come from configuration, already
// normalized; the check keeps one that is not a hostname from naming a file
// outside the directory, or one of its own temp files.
func (l *localCopy) path(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, `/\`) || strings.HasPrefix(name, ".") {
		return "", fmt.Errorf("tls: %q is not a name the local copy can file", name)
	}
	return filepath.Join(l.dir, name+".pem"), nil
}

// save writes cert as name's copy, unless the file already holds exactly
// that, so a follower's refresh every tick does not rewrite it every tick.
func (l *localCopy) save(name string, cert *tls.Certificate) error {
	path, err := l.path(name)
	if err != nil {
		return err
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("tls: private key for %s is %T, not a crypto.Signer", name, cert.PrivateKey)
	}
	keyPEM, err := marshalKeyPEM(signer)
	if err != nil {
		return err
	}
	data := append(keyPEM, encodeChainPEM(cert.Certificate)...)
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, data) {
		return nil
	}

	// CreateTemp makes the file 0600, before a byte of the key is in it.
	f, err := os.CreateTemp(l.dir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // a no-op once renamed
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// The rename survives a power cut only once the directory is synced too.
	if d, err := os.Open(l.dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// load reads name's copy and returns it only if this node could have served
// it: one key, a chain that parses, the key matching the leaf, the leaf
// covering the name's hostname, and not expired at now. Anything else is an
// error and nothing is served from the file.
func (l *localCopy) load(name string, now time.Time) (*tls.Certificate, error) {
	path, err := l.path(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keyPEM, chainPEM []byte
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "PRIVATE KEY":
			if keyPEM != nil {
				return nil, errors.New("more than one private key in the file")
			}
			keyPEM = pem.EncodeToMemory(block)
		case "CERTIFICATE":
			chainPEM = append(chainPEM, pem.EncodeToMemory(block)...)
		}
	}
	if keyPEM == nil {
		return nil, errors.New("no private key in the file")
	}
	key, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	cert, err := buildCertificate(chainPEM, key)
	if err != nil {
		return nil, err
	}
	if err := cert.Leaf.VerifyHostname(layout.CertDomain(name)); err != nil {
		return nil, err
	}
	if !now.Before(cert.Leaf.NotAfter) {
		return nil, fmt.Errorf("the certificate expired at %s", cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return cert, nil
}

// useLocalCopy wires the local copy into the manager and its cache.
func (m *Manager) useLocalCopy(l *localCopy) {
	m.local = l
	m.certCache.local = l
	m.certCache.localFor = m.keepsLocalCopy
}

// keepsLocalCopy reports whether name's certificate is kept in the local copy:
// the configured domains and their companions. An on-demand name could not be
// served after a restart without its allow-set, which lives in storage too.
func (m *Manager) keepsLocalCopy(name string) bool {
	if layout.IsCompanion(name) {
		return m.rsaCompanion && m.domainSet[layout.CertDomain(name)]
	}
	return m.domainSet[name]
}

// startFromLocalCopy serves name's local copy because storage could not be
// read at startup.
func (m *Manager) startFromLocalCopy(name string, readErr error) {
	cert, err := m.local.load(name, time.Now())
	if err != nil {
		m.logger.Warn("TLS: storage cannot be read and the local copy cannot be served: no certificate for this name until storage answers",
			"domain", name, "storage_error", readErr, "error", err)
		return
	}
	m.certCache.setFromLocal(name, cert)
	m.logger.Warn("TLS: storage cannot be read, serving the local copy until it can",
		"domain", name, "not_after", cert.Leaf.NotAfter, "storage_error", readErr)
}

// supersedeLocalCopies re-reads storage for every name served from the local
// copy, so the first tick that can read storage serves what it holds. A
// follower's refresh would do that anyway, but a leader re-reads only names it
// holds nothing for or that are due for renewal: it would keep serving the
// copy for as long as the copy was fresh, which after a key replacement made
// elsewhere is a retired key that DANE clients refuse.
func (m *Manager) supersedeLocalCopies() {
	for _, name := range m.certCache.servedFromLocal() {
		// An operator may be renewing or activating a replacement key while
		// storage recovers. Do not let a read begun before that order install
		// the old pair after the new one. Skip a busy name rather than spend
		// this tick waiting for the whole order; the next tick retries it.
		unlock, free := m.inflight.tryLock(name)
		if !free {
			continue
		}
		ctx, cancel := m.tickContext(localRecheckTimeout)
		_, err := m.certCache.Refresh(ctx, name)
		cancel()
		unlock()
		if err == nil {
			m.logger.Info("TLS: storage answers again, serving its certificate instead of the local copy", "domain", name)
		}
	}
}

// MissingCertificates lists the configured domains this node holds no
// certificate for. A caller that starts without storage asks it right after
// NewManager: an empty list means every configured name is served, from
// storage or from the local copy, and starting is safe.
func (m *Manager) MissingCertificates() []string {
	if m == nil {
		return nil
	}
	var missing []string
	for _, d := range m.domains {
		if _, ok := m.certCache.Get(d); !ok {
			missing = append(missing, d)
		}
	}
	return missing
}

// storageReadError marks a failure to read storage, as opposed to storage
// answering "there is none" or answering with something unusable. Only this
// one may send a starting node to its local copy. It matches
// ErrStorageUnavailable and the error underneath, and prints as the latter.
type storageReadError struct{ err error }

func (e storageReadError) Error() string        { return e.err.Error() }
func (e storageReadError) Unwrap() error        { return e.err }
func (e storageReadError) Is(target error) bool { return target == ErrStorageUnavailable }

// readFailure marks err as a failed read, unless it is the definite "none".
func readFailure(err error) error {
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return err
	}
	return storageReadError{err}
}
