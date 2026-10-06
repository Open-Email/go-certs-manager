package certmanager

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Open-Email/go-certs-manager/dane"

	"golang.org/x/crypto/acme"
)

// letsEncryptProductionURL and letsEncryptStagingURL are the ACME directory
// endpoints. Staging issues certs from an untrusted root — use only to exercise
// the flow without consuming production rate limits.
const (
	letsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// orderer is the one call the Manager makes on the CA: a chain for domain, bound
// to certKey. *Issuer is the only production implementation; the seam exists so
// a test can count orders and hand back a chain without a CA behind it.
type orderer interface {
	Issue(ctx context.Context, domain string, certKey crypto.Signer) ([]byte, error)
}

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

	// journal remembers the order in flight per domain, so an interrupted
	// attempt collects its certificate instead of ordering again. nil: no
	// resumption (tests).
	journal *orderJournal
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
//
// The order is written to the journal before anything the CA can charge for,
// and an order a previous attempt left outstanding is collected rather than
// repeated. The CA counts an order the moment it signs, so an attempt that
// died between finalize and download — a deploy restart, a deadline, a reset
// connection — used to lose a certificate already charged to the weekly limit,
// and the next attempt spent another.
func (i *Issuer) Issue(ctx context.Context, domain string, certKey crypto.Signer) ([]byte, error) {
	domain = strings.ToLower(domain)
	if err := i.ensureRegistered(ctx); err != nil {
		return nil, err
	}
	spki, err := dane.SPKISHA256(certKey.Public())
	if err != nil {
		return nil, err
	}

	order, err := i.resumeOrder(ctx, domain, spki)
	if err != nil {
		return nil, err
	}
	if order == nil {
		order, err = i.client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
		if err != nil {
			return nil, fmt.Errorf("authorize order for %s: %w", domain, err)
		}
		if err := i.journal.record(ctx, domain, order.URI, spki); err != nil {
			i.logger.Warn("TLS: could not journal the order — if this attempt is interrupted after issuance the certificate will not be collected",
				"domain", domain, "error", err)
		}
	}

	chainDER, err := i.complete(ctx, domain, order, certKey)
	if err != nil {
		return nil, err
	}

	// The certificate is in hand: the record has done its job. A context the
	// caller has already given up on must not keep the record alive.
	clearCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), challengeIO)
	i.journal.clear(clearCtx, domain)
	cancel()

	var pemChain []byte
	for _, der := range chainDER {
		pemChain = append(pemChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	i.logger.Info("TLS: certificate issued", "domain", domain, "chain_len", len(chainDER))
	return pemChain, nil
}

// complete takes an order from whatever state it is in to a downloaded chain.
func (i *Issuer) complete(ctx context.Context, domain string, order *acme.Order, certKey crypto.Signer) ([][]byte, error) {
	switch order.Status {
	case acme.StatusValid:
		// Issued already; only the download was lost.
		return i.fetch(ctx, domain, order)
	case acme.StatusProcessing:
		o, err := i.client.WaitOrder(ctx, order.URI)
		if err != nil {
			return nil, fmt.Errorf("wait for order %s: %w", domain, err)
		}
		return i.fetch(ctx, domain, o)
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
	return chainDER, nil
}

func (i *Issuer) fetch(ctx context.Context, domain string, order *acme.Order) ([][]byte, error) {
	if order.CertURL == "" {
		return nil, fmt.Errorf("order for %s is %s but names no certificate", domain, order.Status)
	}
	chainDER, err := i.client.FetchCert(ctx, order.CertURL, true)
	if err != nil {
		return nil, fmt.Errorf("download certificate for %s: %w", domain, err)
	}
	return chainDER, nil
}

// resumeOrder returns the order a previous attempt for this domain and key
// left outstanding, or nil when there is none worth collecting. It fails —
// rather than answer nil — when the journal cannot be read or the CA cannot
// say what became of the order: in either case the one thing this attempt
// must not do is place another.
func (i *Issuer) resumeOrder(ctx context.Context, domain, spki string) (*acme.Order, error) {
	rec, err := i.journal.load(ctx, domain)
	switch {
	case err == nil:
	case errors.Is(err, errNoJournal), absentFromStorage(err):
		return nil, nil
	default:
		return nil, fmt.Errorf("cannot tell whether an order is outstanding for %s: %w: %v", domain, ErrStorageUnavailable, err)
	}
	if rec.OrderURL == "" || time.Since(time.Unix(rec.CreatedAt, 0)) > orderMaxAge {
		i.journal.clear(ctx, domain)
		return nil, nil
	}
	if rec.SPKI != spki {
		// Somebody else's order: a replacement ceremony's, or a renewal's seen
		// from one. Left in place for its owner; this attempt orders afresh.
		return nil, nil
	}

	order, err := i.client.GetOrder(ctx, rec.OrderURL)
	if err != nil {
		var ae *acme.Error
		if errors.As(err, &ae) && ae.StatusCode >= 400 && ae.StatusCode < 500 {
			i.logger.Info("TLS: the CA no longer knows the outstanding order — ordering afresh", "domain", domain, "error", err)
			i.journal.clear(ctx, domain)
			return nil, nil
		}
		return nil, fmt.Errorf("cannot check the outstanding order for %s: %w", domain, err)
	}
	if order.Status == acme.StatusInvalid || (!order.Expires.IsZero() && time.Now().After(order.Expires)) {
		i.journal.clear(ctx, domain)
		return nil, nil
	}
	i.logger.Info("TLS: collecting the order a previous attempt left outstanding", "domain", domain, "status", order.Status)
	return order, nil
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
//
// A response that could not be shared with the cluster is not presented at
// all: the CA's validation reaches whichever node it likes, and one that
// cannot answer is a failed validation the CA counts against the hostname.
func (i *Issuer) present(domain string, chal *acme.Challenge) (func(), error) {
	switch chal.Type {
	case "tls-alpn-01":
		cert, err := i.client.TLSALPN01ChallengeCert(chal.Token, domain)
		if err != nil {
			return nil, fmt.Errorf("build tls-alpn-01 cert for %s: %w", domain, err)
		}
		if err := i.challenges.PutALPN(domain, &cert); err != nil {
			return nil, fmt.Errorf("not accepting the tls-alpn-01 challenge for %s: %w", domain, err)
		}
		return func() { i.challenges.DeleteALPN(domain) }, nil
	case "http-01":
		resp, err := i.client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return nil, fmt.Errorf("build http-01 response for %s: %w", domain, err)
		}
		if err := i.challenges.PutHTTP(chal.Token, resp); err != nil {
			return nil, fmt.Errorf("not accepting the http-01 challenge for %s: %w", domain, err)
		}
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

// IssueTimeout is issueTimeout, exported so callers that wait on an issuance —
// an admin client above all — can size their own deadlines from it rather than
// guess, and keep up when it changes.
const IssueTimeout = issueTimeout
