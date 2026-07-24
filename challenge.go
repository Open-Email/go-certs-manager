package certmanager

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Open-Email/go-certs-manager/storage"
)

// ChallengeServer holds in-flight ACME challenge state and serves it. Because only
// the cluster leader drives ACME orders but Let's Encrypt's validation request can
// reach ANY node (shared/gossiped MX hostname behind a load balancer), challenge
// material is mirrored to the shared storage backend: the leader writes the token
// when presenting the challenge, and whichever node the CA connects to serves it,
// reading from storage on a local-map miss.
//
//   - TLS-ALPN-01: an in-memory self-signed token certificate keyed by domain,
//     returned during the handshake when the client negotiates "acme-tls/1".
//   - HTTP-01: a token->keyAuth map served at /.well-known/acme-challenge/<token>.
type ChallengeServer struct {
	logger  *slog.Logger
	backend storage.Backend // may be nil (single-node / tests): storage mirroring disabled
	prefix  string

	alpnMu sync.RWMutex
	alpn   map[string]*tls.Certificate // domain -> token cert

	httpMu sync.RWMutex
	http   map[string]string // token -> key authorization
}

// NewChallengeServer creates a challenge server. backend/prefix enable cluster-wide
// challenge serving; backend may be nil to disable storage mirroring.
func NewChallengeServer(backend storage.Backend, prefix string, logger *slog.Logger) *ChallengeServer {
	if logger == nil {
		logger = slog.Default()
	}
	return &ChallengeServer{
		logger:  logger,
		backend: backend,
		prefix:  prefix,
		alpn:    make(map[string]*tls.Certificate),
		http:    make(map[string]string),
	}
}

func (c *ChallengeServer) alpnKey(domain string) string {
	return c.prefix + "challenges/alpn/" + strings.ToLower(domain)
}

func (c *ChallengeServer) httpKey(token string) string {
	return c.prefix + "challenges/http/" + token
}

// challengeIO bounds storage operations for challenge material.
const challengeIO = 5 * time.Second

// PutALPN registers a TLS-ALPN-01 token certificate for a domain, mirroring it to
// storage so any node can answer the CA.
func (c *ChallengeServer) PutALPN(domain string, cert *tls.Certificate) {
	domain = strings.ToLower(domain)
	c.alpnMu.Lock()
	c.alpn[domain] = cert
	c.alpnMu.Unlock()

	if c.backend == nil {
		return
	}
	pemBytes, err := encodeChallengeCert(cert)
	if err != nil {
		c.logger.Warn("acme: failed to encode tls-alpn-01 token for storage", "domain", domain, "error", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), challengeIO)
	defer cancel()
	if err := c.backend.PutObject(ctx, c.alpnKey(domain), strings.NewReader(string(pemBytes)), int64(len(pemBytes)), storage.PutOptions{ContentType: "application/x-pem-file"}); err != nil {
		c.logger.Warn("acme: failed to mirror tls-alpn-01 token to storage", "domain", domain, "error", err)
	}
}

// DeleteALPN clears a TLS-ALPN-01 token certificate locally and in storage.
func (c *ChallengeServer) DeleteALPN(domain string) {
	domain = strings.ToLower(domain)
	c.alpnMu.Lock()
	delete(c.alpn, domain)
	c.alpnMu.Unlock()
	c.removeFromStorage(c.alpnKey(domain))
}

// GetALPN returns the TLS-ALPN-01 token certificate for a domain, consulting
// storage if it is not staged locally (i.e. another node drove the order).
func (c *ChallengeServer) GetALPN(domain string) (*tls.Certificate, bool) {
	domain = strings.ToLower(domain)
	c.alpnMu.RLock()
	cert, ok := c.alpn[domain]
	c.alpnMu.RUnlock()
	if ok {
		return cert, true
	}
	if c.backend == nil {
		return nil, false
	}
	data, err := c.readFromStorage(c.alpnKey(domain))
	if err != nil {
		return nil, false
	}
	cert, err = decodeChallengeCert(data)
	if err != nil {
		c.logger.Warn("acme: failed to decode tls-alpn-01 token from storage", "domain", domain, "error", err)
		return nil, false
	}
	return cert, true
}

// PutHTTP registers an HTTP-01 token/keyAuth pair, mirroring it to storage.
func (c *ChallengeServer) PutHTTP(token, keyAuth string) {
	c.httpMu.Lock()
	c.http[token] = keyAuth
	c.httpMu.Unlock()

	if c.backend == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), challengeIO)
	defer cancel()
	if err := c.backend.PutObject(ctx, c.httpKey(token), strings.NewReader(keyAuth), int64(len(keyAuth)), storage.PutOptions{ContentType: "text/plain"}); err != nil {
		c.logger.Warn("acme: failed to mirror http-01 token to storage", "error", err)
	}
}

// DeleteHTTP clears an HTTP-01 token locally and in storage.
func (c *ChallengeServer) DeleteHTTP(token string) {
	c.httpMu.Lock()
	delete(c.http, token)
	c.httpMu.Unlock()
	c.removeFromStorage(c.httpKey(token))
}

// HTTPHandler serves HTTP-01 challenge responses under
// /.well-known/acme-challenge/, falling back to storage on a local miss.
func (c *ChallengeServer) HTTPHandler() http.Handler {
	const prefix = "/.well-known/acme-challenge/"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		token := strings.TrimPrefix(r.URL.Path, prefix)

		c.httpMu.RLock()
		keyAuth, ok := c.http[token]
		c.httpMu.RUnlock()

		if !ok && c.backend != nil {
			if data, err := c.readFromStorage(c.httpKey(token)); err == nil {
				keyAuth, ok = string(data), true
			}
		}
		if !ok {
			c.logger.Debug("acme http-01: unknown token", "token", token, "remote", r.RemoteAddr)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(keyAuth))
	})
}

func (c *ChallengeServer) readFromStorage(key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), challengeIO)
	defer cancel()
	rc, err := c.backend.GetObject(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func (c *ChallengeServer) removeFromStorage(key string) {
	if c.backend == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), challengeIO)
	defer cancel()
	if err := c.backend.RemoveObject(ctx, key); err != nil {
		c.logger.Debug("acme: failed to remove challenge token from storage", "key", key, "error", err)
	}
}

// encodeChallengeCert serializes a TLS-ALPN-01 token certificate (single leaf DER
// plus its ephemeral private key) to PEM for storage.
func encodeChallengeCert(cert *tls.Certificate) ([]byte, error) {
	if len(cert.Certificate) == 0 {
		return nil, errors.New("token certificate has no DER")
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("token certificate key is not a crypto.Signer")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	return out, nil
}

func decodeChallengeCert(data []byte) (*tls.Certificate, error) {
	var certDER, keyDER []byte
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			certDER = block.Bytes
		case "PRIVATE KEY":
			keyDER = block.Bytes
		}
	}
	if certDER == nil || keyDER == nil {
		return nil, errors.New("challenge cert PEM missing certificate or key")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}, nil
}
