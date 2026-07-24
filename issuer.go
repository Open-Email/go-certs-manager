package certmanager

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// letsEncryptProductionURL and letsEncryptStagingURL are the ACME directory
// endpoints. Staging issues certs from an untrusted root — use only to exercise
// the flow without consuming production rate limits.
const (
	letsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Issuer drives RFC 8555 certificate issuance directly via x/crypto/acme,
// building the CSR from a caller-owned key so the issued leaf binds to a stable
// SubjectPublicKeyInfo. It is the replacement for autocert's hidden issuance, and
// is the only part of the system that talks to the CA — all of its mutating
// methods are leader-gated by the caller.
type Issuer struct {
	client     *acme.Client
	challenges *ChallengeServer
	email      string
	logger     *slog.Logger

	registerMu sync.Mutex
	registered bool
}

// NewIssuer constructs an Issuer. accountKey is the persistent ACME account key
// from the KeyStore; staging selects the Let's Encrypt staging directory.
func NewIssuer(accountKey crypto.Signer, email string, staging bool, challenges *ChallengeServer, logger *slog.Logger) *Issuer {
	if logger == nil {
		logger = slog.Default()
	}
	client := &acme.Client{Key: accountKey}
	if staging {
		client.DirectoryURL = letsEncryptStagingURL
		logger.Warn("TLS: using Let's Encrypt STAGING — issued certificates are NOT trusted by clients")
	}
	return &Issuer{
		client:     client,
		challenges: challenges,
		email:      email,
		logger:     logger,
	}
}

// ensureRegistered registers the ACME account exactly once, even under concurrent
// Issue() calls for distinct domains. Re-registration with an existing key returns
// ErrAccountAlreadyExists, which is treated as success.
func (i *Issuer) ensureRegistered(ctx context.Context) error {
	i.registerMu.Lock()
	defer i.registerMu.Unlock()
	if i.registered {
		return nil
	}
	acct := &acme.Account{}
	if i.email != "" {
		acct.Contact = []string{"mailto:" + i.email}
	}
	_, err := i.client.Register(ctx, acct, acme.AcceptTOS)
	if err != nil && err != acme.ErrAccountAlreadyExists {
		// Not marked registered — a transient failure is retried on the next call.
		return fmt.Errorf("acme account registration: %w", err)
	}
	i.registered = true
	return nil
}

// Issue obtains a certificate for domain, using certKey as the certificate key.
// The returned chain is PEM (leaf first, then intermediates). certKey is reused
// across renewals by the caller so the leaf's SPKI — and its DANE digest — stays
// constant.
func (i *Issuer) Issue(ctx context.Context, domain string, certKey crypto.Signer) ([]byte, error) {
	domain = strings.ToLower(domain)
	if err := i.ensureRegistered(ctx); err != nil {
		return nil, err
	}

	order, err := i.client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return nil, fmt.Errorf("authorize order for %s: %w", domain, err)
	}

	for _, authzURL := range order.AuthzURLs {
		if err := i.fulfillAuthorization(ctx, domain, authzURL); err != nil {
			return nil, err
		}
	}

	csrDER, err := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, certKey)
	if err != nil {
		return nil, fmt.Errorf("create CSR for %s: %w", domain, err)
	}

	chainDER, _, err := i.client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, fmt.Errorf("finalize order for %s: %w", domain, err)
	}

	var pemChain []byte
	for _, der := range chainDER {
		pemChain = append(pemChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	i.logger.Info("TLS: certificate issued", "domain", domain, "chain_len", len(chainDER))
	return pemChain, nil
}

// fulfillAuthorization completes a single authorization, preferring TLS-ALPN-01
// (served by the dedicated :443 listener) and falling back to HTTP-01.
func (i *Issuer) fulfillAuthorization(ctx context.Context, domain, authzURL string) error {
	authz, err := i.client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("get authorization %s: %w", authzURL, err)
	}
	if authz.Status == acme.StatusValid {
		return nil // reused, already authorized
	}

	chal := pickChallenge(authz.Challenges)
	if chal == nil {
		return fmt.Errorf("no supported challenge (tls-alpn-01/http-01) for %s", domain)
	}

	cleanup, err := i.present(domain, chal)
	if err != nil {
		return err
	}
	defer cleanup()

	if _, err := i.client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accept %s challenge for %s: %w", chal.Type, domain, err)
	}
	if _, err := i.client.WaitAuthorization(ctx, authz.URI); err != nil {
		return fmt.Errorf("wait authorization for %s: %w", domain, err)
	}
	return nil
}

// present installs the challenge response and returns a cleanup func.
func (i *Issuer) present(domain string, chal *acme.Challenge) (func(), error) {
	switch chal.Type {
	case "tls-alpn-01":
		cert, err := i.client.TLSALPN01ChallengeCert(chal.Token, domain)
		if err != nil {
			return nil, fmt.Errorf("build tls-alpn-01 cert for %s: %w", domain, err)
		}
		i.challenges.PutALPN(domain, &cert)
		return func() { i.challenges.DeleteALPN(domain) }, nil
	case "http-01":
		resp, err := i.client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return nil, fmt.Errorf("build http-01 response for %s: %w", domain, err)
		}
		i.challenges.PutHTTP(chal.Token, resp)
		return func() { i.challenges.DeleteHTTP(chal.Token) }, nil
	default:
		return nil, fmt.Errorf("unsupported challenge type %q", chal.Type)
	}
}

// pickChallenge prefers tls-alpn-01, then http-01.
func pickChallenge(challenges []*acme.Challenge) *acme.Challenge {
	var httpChal *acme.Challenge
	for _, c := range challenges {
		switch c.Type {
		case "tls-alpn-01":
			return c
		case "http-01":
			httpChal = c
		}
	}
	return httpChal
}

// issueTimeout bounds a single issuance attempt (challenge + finalize).
const issueTimeout = 2 * time.Minute
