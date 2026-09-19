// Package layout names the objects go-certs-manager keeps in storage, relative
// to the deployment's base prefix.
//
// One copy, because two packages depend on it: the manager writes these
// objects and certstore reads and deletes them for the operator. Each
// service's admin CLI used to keep its own list of these paths, and one of
// them was still deleting an object that no version of this manager writes.
package layout

import "strings"

const (
	// ChainDir holds each name's certificate chain, leaf first. The private key
	// is never in it.
	ChainDir = "certs/"
	// KeyDir holds each name's persistent private key, reused by every
	// renewal so the SPKI (and any DANE "3 1 1" record pinned to it) survives.
	KeyDir = "keys/"
	// NextKeySuffix marks a key staged by a key-replacement ceremony and not
	// yet promoted.
	NextKeySuffix = ".next"
	// OnDemandHosts is the on-demand allow-set the leader publishes.
	OnDemandHosts = "ondemand/hosts.json"
	// OnDemandCertIndex maps each on-demand hostname to the expiry of the
	// chain storage holds for it.
	OnDemandCertIndex = "ondemand/certs-index.json"
)

// Chain is the storage key of a name's certificate chain.
func Chain(prefix, domain string) string { return prefix + ChainDir + strings.ToLower(domain) }

// Key is the storage key of a name's persistent private key.
func Key(prefix, domain string) string { return prefix + KeyDir + strings.ToLower(domain) }

// NextKey is the storage key of a name's staged replacement key.
func NextKey(prefix, domain string) string { return Key(prefix, domain) + NextKeySuffix }

// OnDemandState is the object at OnDemandHosts.
type OnDemandState struct {
	GeneratedAt int64    `json:"generated_at"`
	Hosts       []string `json:"hosts"`
}
