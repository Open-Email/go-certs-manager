package certmanager

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Open-Email/go-certs-manager/dane"
	"github.com/Open-Email/go-certs-manager/storage"
)

// certCache serves the current leaf certificate for each domain from memory and
// persists the issued chain in the shared storage.Backend. It replaces the
// autocert FallbackCache/S3Cache/CertSyncWorker stack.
//
// The private key is NOT stored here — it lives solely in the KeyStore (one
// source of truth). A certificate is reconstructed by pairing the durable chain
// (certs/<domain>) with the persistent key (keys/<domain>); keyFor supplies the
// latter. Followers call Refresh on a poll interval to pick up certs the leader
// re-issued.
type certCache struct {
	backend storage.Backend
	prefix  string // "<base>certs/"
	keyFor  func(ctx context.Context, domain string) (crypto.Signer, error)
	logger  *slog.Logger

	mu  sync.RWMutex
	mem map[string]*tls.Certificate

	negMu sync.Mutex
	neg   map[string]time.Time // domain -> last cache-miss time (follower read throttle)
}

// certMissNegativeTTL throttles follower storage reads: after a miss, a follower
// won't re-read storage for a domain for this long, bounding storage load to ~one
// GET per domain per window instead of one per ClientHello before the leader issues.
const certMissNegativeTTL = 3 * time.Second

func newCertCache(backend storage.Backend, basePrefix string, keyFor func(ctx context.Context, domain string) (crypto.Signer, error), logger *slog.Logger) *certCache {
	if logger == nil {
		logger = slog.Default()
	}
	return &certCache{
		backend: backend,
		prefix:  basePrefix + "certs/",
		keyFor:  keyFor,
		logger:  logger,
		mem:     make(map[string]*tls.Certificate),
		neg:     make(map[string]time.Time),
	}
}

func (c *certCache) chainKey(domain string) string {
	return c.prefix + strings.ToLower(domain)
}

// Get returns the in-memory certificate for a domain, if present.
func (c *certCache) Get(domain string) (*tls.Certificate, bool) {
	c.mu.RLock()
	cert, ok := c.mem[strings.ToLower(domain)]
	c.mu.RUnlock()
	return cert, ok
}

// Store persists a freshly-issued chain and installs the rebuilt certificate in
// memory. Used by the leader after issuance. key is the private key the chain was
// issued against (the live key for renewals, the staged-next key during a
// key-replacement ceremony) — it MUST match the chain's leaf.
func (c *certCache) Store(ctx context.Context, domain string, chainPEM []byte, key crypto.Signer) (*tls.Certificate, error) {
	cert, err := buildCertificate(chainPEM, key)
	if err != nil {
		return nil, err
	}
	data := string(chainPEM)
	if err := c.backend.PutObject(ctx, c.chainKey(domain), strings.NewReader(data), int64(len(data)), storage.PutOptions{
		ContentType: "application/x-pem-file",
	}); err != nil {
		return nil, fmt.Errorf("persist chain for %s: %w", domain, err)
	}
	c.set(domain, cert)
	return cert, nil
}

// Refresh loads the durable chain for a domain and rebuilds the in-memory
// certificate. Returns os.ErrNotExist (wrapped) if no chain has been issued yet.
func (c *certCache) Refresh(ctx context.Context, domain string) (*tls.Certificate, error) {
	chainPEM, err := c.loadChain(ctx, domain)
	if err != nil {
		return nil, err
	}
	key, err := c.keyFor(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("load key for %s: %w", domain, err)
	}
	cert, err := buildCertificate(chainPEM, key)
	if err != nil {
		return nil, err
	}
	c.set(domain, cert)
	return cert, nil
}

// storedLeafSPKI returns the DANE SPKI SHA-256 digest of the leaf in the durable
// chain for a domain (os.ErrNotExist if none is stored). Used to detect an
// interrupted key-replacement ceremony independent of the in-memory cert.
func (c *certCache) storedLeafSPKI(ctx context.Context, domain string) (string, error) {
	chainPEM, err := c.loadChain(ctx, domain)
	if err != nil {
		return "", err
	}
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return "", fmt.Errorf("parse stored leaf: %w", err)
			}
			return dane.SPKISHA256(cert.PublicKey)
		}
	}
	return "", errors.New("no CERTIFICATE block in stored chain")
}

func (c *certCache) loadChain(ctx context.Context, domain string) ([]byte, error) {
	rc, err := c.backend.GetObject(ctx, c.chainKey(domain))
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func (c *certCache) set(domain string, cert *tls.Certificate) {
	key := strings.ToLower(domain)
	c.mu.Lock()
	c.mem[key] = cert
	c.mu.Unlock()
	c.negMu.Lock()
	delete(c.neg, key)
	c.negMu.Unlock()
}

// recentMiss reports whether a follower recently failed to find this domain in
// storage, so repeated handshakes don't each trigger a storage read.
func (c *certCache) recentMiss(domain string) bool {
	c.negMu.Lock()
	defer c.negMu.Unlock()
	t, ok := c.neg[strings.ToLower(domain)]
	return ok && time.Since(t) < certMissNegativeTTL
}

func (c *certCache) noteMiss(domain string) {
	c.negMu.Lock()
	defer c.negMu.Unlock()
	c.neg[strings.ToLower(domain)] = time.Now()
}

// leafNotAfter returns the in-memory leaf's expiry, if a cert is loaded.
func (c *certCache) leafNotAfter(domain string) (time.Time, bool) {
	cert, ok := c.Get(domain)
	if !ok || cert.Leaf == nil {
		return time.Time{}, false
	}
	return cert.Leaf.NotAfter, true
}

// buildCertificate pairs a PEM chain with a private key into a tls.Certificate
// with Leaf populated.
//
// It verifies the key matches the leaf's public key. This guards against a
// transiently-inconsistent (chain, key) pair read from storage: during a
// key-replacement ceremony the leader writes the new chain (Store) and promotes
// the new live key (PromoteNextCertKey) as two sequential storage writes. A
// follower refreshing in the millisecond window between them would otherwise pair
// the new chain with the not-yet-promoted old key and serve a certificate whose
// private key can't sign for it. Rejecting the mismatch makes Refresh a no-op, so
// the follower keeps serving its last-good certificate until both objects are
// consistent. (tls.X509KeyPair performs the same check; we replicate it because we
// assemble the certificate manually.)
func buildCertificate(chainPEM []byte, key crypto.Signer) (*tls.Certificate, error) {
	var ders [][]byte
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			ders = append(ders, block.Bytes)
		}
	}
	if len(ders) == 0 {
		return nil, errors.New("no CERTIFICATE blocks in chain")
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	if err := verifyKeyMatchesLeaf(key, leaf); err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: ders,
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// verifyKeyMatchesLeaf confirms the private key's public half equals the leaf
// certificate's public key. All stdlib key types (*ecdsa.PublicKey,
// *rsa.PublicKey, ed25519.PublicKey) implement Equal(crypto.PublicKey) bool.
func verifyKeyMatchesLeaf(key crypto.Signer, leaf *x509.Certificate) error {
	type equalPublicKey interface{ Equal(x crypto.PublicKey) bool }
	pub, ok := key.Public().(equalPublicKey)
	if !ok {
		return errors.New("private key type does not support public-key comparison")
	}
	if !pub.Equal(leaf.PublicKey) {
		return ErrKeyCertMismatch
	}
	return nil
}
