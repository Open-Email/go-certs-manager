// Package certstore is the operator's view of the certificates go-certs-manager
// keeps in storage — what is there, why, and whether a node can serve it — and
// the tls list, delete and clean commands every service's admin CLI runs on it.
//
// It lives here rather than in each CLI because the storage layout is this
// module's, and three hand-kept copies of it had already drifted: one still
// deleted an object no version of the manager writes, and two told operators
// that deleting a certificate gets them a new one, which it does not.
//
// It never writes a certificate or a key. Issuance belongs to the leader.
package certstore

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	certmanager "github.com/Open-Email/go-certs-manager"
	"github.com/Open-Email/go-certs-manager/internal/layout"
	"github.com/Open-Email/go-certs-manager/storage"
)

// Role says why a certificate is in storage.
type Role string

const (
	// RoleConfigured is a name in the service's configured domains.
	RoleConfigured Role = "configured"
	// RoleOnDemand is a name in the on-demand allow-set the leader publishes.
	RoleOnDemand Role = "on-demand"
	// RoleOrphan is neither: a name no node serves any more.
	RoleOrphan Role = "orphan"
)

// Certificate is one certificate chain in storage.
type Certificate struct {
	Domain       string    `json:"domain"`
	Key          string    `json:"key"` // the chain's storage key
	Role         Role      `json:"role"`
	Algorithm    string    `json:"algorithm,omitempty"` // ECDSA, RSA, Ed25519
	Names        []string  `json:"names,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Expired      bool      `json:"expired"`
	Invalid      string    `json:"invalid,omitempty"` // why the chain could not be read
	HasKey       bool      `json:"has_key"`           // the persistent key the next order reuses
	HasStagedKey bool      `json:"has_staged_key"`    // a key replacement in progress
	Size         int64     `json:"size"`
	LastModified time.Time `json:"last_modified"`
}

// Unservable says why no node can serve this chain — it has expired, or it is
// not a chain — or "" when one can.
func (c Certificate) Unservable() string {
	switch {
	case c.Invalid != "":
		return "invalid (" + c.Invalid + ")"
	case c.Expired:
		return "expired"
	}
	return ""
}

// InUse reports whether nodes serve this certificate: it can be served, and it
// is for a name the fleet still serves.
func (c Certificate) InUse() bool {
	return c.Unservable() == "" && c.Role != RoleOrphan
}

var (
	// ErrNotStored is the answer for a name with no certificate in storage.
	ErrNotStored = errors.New("no certificate in storage for that name")
	// ErrInUse refuses to delete a certificate nodes are serving. Deleting it
	// does not replace it: the leader serves its copy from memory and writes it
	// back. RenewCertificate is what replaces a certificate.
	ErrInUse = errors.New("the certificate is valid and in use")
)

// Inventory reads and deletes certificates in one deployment's storage.
type Inventory struct {
	backend     storage.Backend
	prefix      string
	configured  map[string]bool
	renewBefore time.Duration
	now         func() time.Time
}

// New opens an inventory over backend, described with the service's own
// config: prefix is the storage base prefix it passes to
// certmanager.NewManager, domains its configured domains (they decide each
// name's role), and renewBefore its renewal window, 0 for
// certmanager.DefaultRenewBefore (the listing reads expiry against it).
func New(backend storage.Backend, prefix string, domains []string, renewBefore time.Duration) *Inventory {
	if renewBefore <= 0 {
		renewBefore = certmanager.DefaultRenewBefore
	}
	inv := &Inventory{backend: backend, prefix: prefix, configured: map[string]bool{}, renewBefore: renewBefore, now: time.Now}
	for _, d := range domains {
		if d = normalize(d); d != "" {
			inv.configured[d] = true
		}
	}
	return inv
}

// RenewBefore is the renewal window the inventory reads expiry against.
func (inv *Inventory) RenewBefore() time.Duration { return inv.renewBefore }

func normalize(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// List reads every certificate in storage, sorted by name. Each chain is
// fetched and parsed: the listing alone cannot say when one expires.
func (inv *Inventory) List(ctx context.Context) ([]Certificate, error) {
	dir := inv.prefix + layout.ChainDir
	objects, err := inv.backend.ListObjects(ctx, dir, true)
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", dir, err)
	}
	keys, err := inv.keyNames(ctx)
	if err != nil {
		return nil, err
	}
	onDemand, err := inv.onDemand(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Certificate, 0, len(objects))
	for _, o := range objects {
		domain := strings.TrimPrefix(o.Key, dir)
		if domain == "" || strings.Contains(domain, "/") {
			continue // not a chain the manager wrote
		}
		c := Certificate{Domain: domain, Key: o.Key, Size: o.Size, LastModified: o.LastModified}
		inv.describe(ctx, &c, keys, onDemand)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out, nil
}

// Get reads one name's certificate, or ErrNotStored.
func (inv *Inventory) Get(ctx context.Context, domain string) (Certificate, error) {
	domain = normalize(domain)
	key := layout.Chain(inv.prefix, domain)
	info, err := inv.backend.StatObject(ctx, key)
	if errors.Is(err, os.ErrNotExist) {
		return Certificate{Domain: domain}, ErrNotStored
	}
	if err != nil {
		return Certificate{Domain: domain}, err
	}
	keys, err := inv.keyNames(ctx)
	if err != nil {
		return Certificate{Domain: domain}, err
	}
	onDemand, err := inv.onDemand(ctx)
	if err != nil {
		return Certificate{Domain: domain}, err
	}
	c := Certificate{Domain: domain, Key: key, Size: info.Size, LastModified: info.LastModified}
	inv.describe(ctx, &c, keys, onDemand)
	return c, nil
}

// Delete removes one name's certificate chain and returns what it removed.
//
// A certificate that is in use is refused with ErrInUse unless force is set,
// and the check is made on a fresh read, not on an earlier listing: a chain
// that was expired when listed may have been renewed since.
//
// The persistent key is never removed, so a certificate issued later for the
// name has the same SPKI and any TLSA record pinned to it keeps matching.
func (inv *Inventory) Delete(ctx context.Context, domain string, force bool) (Certificate, error) {
	c, err := inv.Get(ctx, domain)
	if err != nil {
		return c, err
	}
	if c.InUse() && !force {
		return c, ErrInUse
	}
	if err := inv.backend.RemoveObject(ctx, c.Key); err != nil {
		return c, fmt.Errorf("removing %s: %w", c.Key, err)
	}
	return c, nil
}

func (inv *Inventory) describe(ctx context.Context, c *Certificate, keys, onDemand map[string]bool) {
	switch {
	case inv.configured[c.Domain]:
		c.Role = RoleConfigured
	case onDemand[c.Domain]:
		c.Role = RoleOnDemand
	default:
		c.Role = RoleOrphan
	}
	c.HasKey = keys[c.Domain]
	c.HasStagedKey = keys[c.Domain+layout.NextKeySuffix]
	data, err := inv.read(ctx, c.Key)
	if err != nil {
		c.Invalid = "unreadable: " + err.Error()
		return
	}
	inv.parse(data, c)
}

// keyNames lists the key objects, by name.
func (inv *Inventory) keyNames(ctx context.Context) (map[string]bool, error) {
	dir := inv.prefix + layout.KeyDir
	objects, err := inv.backend.ListObjects(ctx, dir, true)
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", dir, err)
	}
	out := make(map[string]bool, len(objects))
	for _, o := range objects {
		out[strings.TrimPrefix(o.Key, dir)] = true
	}
	return out, nil
}

// onDemand reads the allow-set the leader publishes. Absent means the feature
// is off. Unreadable is an error, not an empty set: calling every on-demand
// name an orphan would let a delete through that the role exists to stop.
func (inv *Inventory) onDemand(ctx context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	data, err := inv.read(ctx, inv.prefix+layout.OnDemandHosts)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the on-demand allow-set: %w", err)
	}
	var state layout.OnDemandState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("reading the on-demand allow-set: %w", err)
	}
	for _, h := range state.Hosts {
		out[normalize(h)] = true
	}
	return out, nil
}

func (inv *Inventory) read(ctx context.Context, key string) ([]byte, error) {
	rc, err := inv.backend.GetObject(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, 1<<20))
}

// parse reads the leaf: the stored object is the chain, leaf first, with no
// private key in it.
func (inv *Inventory) parse(data []byte, c *Certificate) {
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			c.Invalid = "no certificate in the PEM"
			return
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			c.Invalid = "does not parse: " + err.Error()
			return
		}
		c.Algorithm = leaf.PublicKeyAlgorithm.String()
		c.Names = leaf.DNSNames
		c.Issuer = leaf.Issuer.CommonName
		c.NotBefore, c.NotAfter = leaf.NotBefore, leaf.NotAfter
		c.Expired = inv.now().After(leaf.NotAfter)
		return
	}
}
