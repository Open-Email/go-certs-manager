package certmanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/Open-Email/go-certs-manager/dane"
	"github.com/Open-Email/go-certs-manager/storage"
)

// Key algorithm identifiers accepted in configuration.
const (
	KeyTypeECDSAP256 = "ecdsa-p256"
	KeyTypeRSA2048   = "rsa-2048"
)

// KeyStore manages long-lived private keys persisted in a storage.Backend:
//   - one ACME account key for the whole cluster
//   - one certificate key per domain, REUSED across every renewal
//
// Reusing the per-domain key is what keeps the leaf's SubjectPublicKeyInfo (and
// therefore its DANE "3 1 1" digest) stable forever. KeyStore never regenerates a
// key that already exists — this is the root-cause fix for autocert's behaviour of
// minting a fresh key on any cache miss.
//
// Creation is serialized cluster-wide by a conditional create (IfNoneMatch:"*"):
// if two nodes race, the loser observes ConditionalPutError and re-reads the
// winner's key rather than overwriting it. Creation is additionally gated behind
// isLeaderF so only the leader mints keys under normal operation; reads are
// unrestricted so followers can serve.
type KeyStore struct {
	backend   storage.Backend
	prefix    string // storage base prefix (e.g. "" or "prod/")
	keyType   string
	isLeaderF func() bool
	logger    *slog.Logger
}

// NewKeyStore creates a KeyStore. prefix is the storage base prefix shared with
// the deployment's other objects; keys live under "<prefix>keys/" and the account key
// under "<prefix>acme/account.key". isLeaderF may be nil (single-node), in which
// case this node may always create keys.
func NewKeyStore(backend storage.Backend, prefix, keyType string, isLeaderF func() bool, logger *slog.Logger) *KeyStore {
	if keyType == "" {
		keyType = KeyTypeECDSAP256
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &KeyStore{
		backend:   backend,
		prefix:    prefix,
		keyType:   keyType,
		isLeaderF: isLeaderF,
		logger:    logger,
	}
}

func (k *KeyStore) accountKeyName() string { return k.prefix + "acme/account.key" }

func (k *KeyStore) certKeyName(domain string) string {
	return k.prefix + "keys/" + strings.ToLower(domain)
}

// nextCertKeyName is the staging slot for a key-replacement ceremony. The next
// key is generated and persisted here, pre-published in DNS, then promoted to the
// live slot only once the new TLSA record has propagated.
func (k *KeyStore) nextCertKeyName(domain string) string {
	return k.prefix + "keys/" + strings.ToLower(domain) + ".next"
}

func (k *KeyStore) canCreate() bool {
	return k.isLeaderF == nil || k.isLeaderF()
}

// LoadOrCreateAccountKey returns the cluster's ACME account key, creating it once
// if absent.
func (k *KeyStore) LoadOrCreateAccountKey(ctx context.Context) (crypto.Signer, error) {
	// Account keys are ECDSA P-256 regardless of the cert key type — the algorithm
	// is irrelevant to ACME and P-256 is universally accepted.
	return k.loadOrCreate(ctx, k.accountKeyName(), KeyTypeECDSAP256)
}

// LoadOrCreateCertKey returns the persistent certificate key for a domain,
// creating it once if absent. The returned key MUST be reused on every renewal.
func (k *KeyStore) LoadOrCreateCertKey(ctx context.Context, domain string) (crypto.Signer, error) {
	return k.loadOrCreate(ctx, k.certKeyName(domain), k.keyType)
}

// LoadCertKey loads an existing certificate key, returning os.ErrNotExist if none
// has been created yet. It never creates a key.
func (k *KeyStore) LoadCertKey(ctx context.Context, domain string) (crypto.Signer, error) {
	return k.load(ctx, k.certKeyName(domain))
}

// GenerateNextCertKey creates the staging "next" key for a domain's
// key-replacement ceremony and returns it. It is created once via conditional put;
// if one already exists it is loaded and returned (so the ceremony is resumable).
// Leader-only.
func (k *KeyStore) GenerateNextCertKey(ctx context.Context, domain string) (crypto.Signer, error) {
	if !k.canCreate() {
		return nil, errNotLeader
	}
	return k.loadOrCreate(ctx, k.nextCertKeyName(domain), k.keyType)
}

// LoadNextCertKey loads the staging "next" key, or os.ErrNotExist if no ceremony
// is in progress.
func (k *KeyStore) LoadNextCertKey(ctx context.Context, domain string) (crypto.Signer, error) {
	return k.load(ctx, k.nextCertKeyName(domain))
}

// PromoteNextCertKey replaces the live key with the staged "next" key and removes
// the staging object. Leader-only. Called only after the new key's TLSA record has
// been published and propagated and a cert bound to it has been issued.
func (k *KeyStore) PromoteNextCertKey(ctx context.Context, domain string) error {
	if !k.canCreate() {
		return errNotLeader
	}
	next, err := k.load(ctx, k.nextCertKeyName(domain))
	if err != nil {
		return fmt.Errorf("load next key: %w", err)
	}
	pemBytes, err := marshalKeyPEM(next)
	if err != nil {
		return err
	}
	// Overwrite the live key (no IfNoneMatch — this is a deliberate replacement).
	if err := k.put(ctx, k.certKeyName(domain), pemBytes, false); err != nil {
		return fmt.Errorf("promote next key: %w", err)
	}
	if err := k.backend.RemoveObject(ctx, k.nextCertKeyName(domain)); err != nil {
		k.logger.Warn("keystore: failed to remove staged next key after promotion", "domain", domain, "error", err)
	}
	return nil
}

// SPKISHA256 returns the DANE "3 1 1" digest (lowercase hex) for a signer's public
// key.
func (k *KeyStore) SPKISHA256(signer crypto.Signer) (string, error) {
	return dane.SPKISHA256(signer.Public())
}

func (k *KeyStore) loadOrCreate(ctx context.Context, name, keyType string) (crypto.Signer, error) {
	signer, err := k.load(ctx, name)
	if err == nil {
		return signer, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if !k.canCreate() {
		// Follower observed no key yet; the leader will create it shortly.
		return nil, fmt.Errorf("key %q not yet created by leader: %w", name, os.ErrNotExist)
	}

	signer, err = generateSigner(keyType)
	if err != nil {
		return nil, err
	}
	pemBytes, err := marshalKeyPEM(signer)
	if err != nil {
		return nil, err
	}

	// Atomic create-once: lose the race -> read the winner, NEVER regenerate.
	err = k.put(ctx, name, pemBytes, true)
	var condErr *storage.ConditionalPutError
	if errors.As(err, &condErr) {
		k.logger.Info("keystore: lost create race, loading existing key", "key", name)
		return k.load(ctx, name)
	}
	if err != nil {
		return nil, fmt.Errorf("persist key %q: %w", name, err)
	}
	// Always adopt the durably-stored key by reading it back. On a backend that
	// honors IfNoneMatch this is exactly what we just wrote; on one that silently
	// ignored it while a peer raced, this is the winner's bytes. Either way every
	// node converges on a single key per name — essential for a stable DANE SPKI
	// across the cluster. We discard the locally-generated signer if they differ.
	stored, err := k.load(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("read back key %q after create: %w", name, err)
	}
	k.logger.Info("keystore: created new persistent key", "key", name, "type", keyType)
	return stored, nil
}

func (k *KeyStore) load(ctx context.Context, name string) (crypto.Signer, error) {
	rc, err := k.backend.GetObject(ctx, name)
	if err != nil {
		return nil, err // includes os.ErrNotExist for missing keys
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("read key %q: %w", name, err)
	}
	return parseKeyPEM(data)
}

func (k *KeyStore) put(ctx context.Context, name string, data []byte, createOnly bool) error {
	opts := storage.PutOptions{ContentType: "application/x-pem-file"}
	if createOnly {
		opts.IfNoneMatch = "*"
	}
	return k.backend.PutObject(ctx, name, strings.NewReader(string(data)), int64(len(data)), opts)
}

func generateSigner(keyType string) (crypto.Signer, error) {
	switch keyType {
	case KeyTypeECDSAP256, "":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyTypeRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("unsupported key type %q", keyType)
	}
}

func marshalKeyPEM(signer crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func parseKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in key data")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("stored key is not a crypto.Signer")
	}
	return signer, nil
}
