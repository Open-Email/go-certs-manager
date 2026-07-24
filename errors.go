package certmanager

import "errors"

var (
	// ErrMissingServerName is returned when a TLS handshake is attempted without SNI
	// and no default domain is configured.
	ErrMissingServerName = errors.New("tls: missing server name (SNI) and no default domain configured")

	// ErrHostNotAllowed is returned when a certificate is requested for a domain
	// that is not in the configured whitelist.
	ErrHostNotAllowed = errors.New("tls: host not allowed")

	// ErrCertificateUnavailable is returned when a certificate cannot be retrieved
	// due to transient errors (S3 down, ACME rate limits, network issues).
	// This allows the server to continue serving cached certificates for other domains.
	ErrCertificateUnavailable = errors.New("tls: certificate unavailable")

	// errNotLeader is returned by CA-mutating operations (key creation, issuance,
	// rollover) when invoked on a non-leader node.
	errNotLeader = errors.New("tls: operation must run on the cluster leader")

	// ErrKeyCertMismatch is returned when a private key does not match the leaf
	// certificate's public key — e.g. a follower refreshing a new chain before the
	// corresponding key promotion has landed in storage.
	ErrKeyCertMismatch = errors.New("tls: private key does not match certificate leaf public key")
)
