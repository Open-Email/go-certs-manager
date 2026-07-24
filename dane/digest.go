// Package dane computes DANE (RFC 6698 / RFC 7672) TLSA records for a mail host's
// inbound SMTP (port 25) certificates.
//
// The certmanager package pins a stable certificate public key (see KeyStore), so a single
// DANE-EE "3 1 1" TLSA record — usage DANE-EE(3), selector SPKI(1), matching
// SHA-256(1) — stays valid across certificate renewals. This package only
// *computes* the desired records; publishing them into the (DNSSEC-signed) zone
// is the operator's responsibility when the external publisher is used.
package dane

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// SPKISHA256 returns the lowercase-hex SHA-256 digest of the DER-encoded
// SubjectPublicKeyInfo of pub. This is the certificate-association data for a
// TLSA record with selector SPKI(1) and matching-type SHA-256(1).
//
// Because it depends only on the public key (not the certificate), the digest is
// stable across renewals as long as the underlying key is reused.
func SPKISHA256(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}
