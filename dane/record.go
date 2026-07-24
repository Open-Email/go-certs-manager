package dane

import (
	"fmt"
	"strings"
)

// TLSA usage / selector / matching-type constants used by this module.
//
// Only DANE-EE(3) / SPKI(1) / SHA-256(1) records are emitted: this is the profile
// recommended for SMTP by RFC 7672 §3.1.3 because it pins the server's own public
// key and is unaffected by CA intermediate/root rotation.
const (
	UsageDANEEE    uint8 = 3 // DANE-EE: the cert/key is the end-entity itself
	SelectorSPKI   uint8 = 1 // match on SubjectPublicKeyInfo (stable across renewals)
	MatchingSHA256 uint8 = 1 // SHA-256 of the selected data
)

// SMTPPort is the only port TLSA records are published for. DANE for SMTP
// (RFC 7672) applies to MTA-to-MTA delivery on port 25; submission ports
// (587/465) authenticate via PKIX and are out of scope.
const SMTPPort = 25

// TLSARecord is a single desired TLSA resource record for an MX hostname.
type TLSARecord struct {
	// Name is the owner name, e.g. "_25._tcp.mx.example.com." (fully qualified).
	Name string `json:"name"`
	// MXHost is the bare MX hostname the record protects, e.g. "mx.example.com".
	MXHost       string `json:"mx_host"`
	Usage        uint8  `json:"usage"`
	Selector     uint8  `json:"selector"`
	MatchingType uint8  `json:"matching_type"`
	// Cert is the certificate-association data (lowercase hex SPKI SHA-256 digest).
	Cert string `json:"cert"`
	TTL  uint32 `json:"ttl"`
	// Note is an optional human annotation (e.g. "retiring — keep published until …").
	Note string `json:"note,omitempty"`
}

// OwnerName returns the fully-qualified TLSA owner name for an MX hostname on the
// SMTP port, e.g. "_25._tcp.mx.example.com." (trailing dot included).
func OwnerName(mxHost string) string {
	host := strings.TrimSuffix(strings.ToLower(mxHost), ".")
	return fmt.Sprintf("_%d._tcp.%s.", SMTPPort, host)
}

// NewSPKIRecord builds a DANE-EE/SPKI/SHA-256 record for an MX host from a digest.
func NewSPKIRecord(mxHost, digest string, ttl uint32) TLSARecord {
	return TLSARecord{
		Name:         OwnerName(mxHost),
		MXHost:       strings.ToLower(strings.TrimSuffix(mxHost, ".")),
		Usage:        UsageDANEEE,
		Selector:     SelectorSPKI,
		MatchingType: MatchingSHA256,
		Cert:         strings.ToLower(digest),
		TTL:          ttl,
	}
}

// RData returns the TLSA record's RDATA in presentation form, e.g.
// "3 1 1 abcd…". This is what an operator pastes into the zone after the
// owner name and TTL.
func (r TLSARecord) RData() string {
	return fmt.Sprintf("%d %d %d %s", r.Usage, r.Selector, r.MatchingType, r.Cert)
}

// ZoneLine returns a full presentation-format line for the record, e.g.
// "_25._tcp.mx.example.com. 3600 IN TLSA 3 1 1 abcd…".
func (r TLSARecord) ZoneLine() string {
	return fmt.Sprintf("%s %d IN TLSA %s", r.Name, r.TTL, r.RData())
}

// Fingerprint identifies a record independent of its TTL, for set comparison.
func (r TLSARecord) Fingerprint() string {
	return r.Name + "|" + r.RData()
}
