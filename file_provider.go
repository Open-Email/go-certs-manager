package certmanager

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// FileCertProvider loads TLS certificates from disk and supports reloading.
// It implements GetCertificate for use in tls.Config, returning the cached
// certificate. Call Reload() to re-read certificates from disk (e.g. on SIGHUP).
type FileCertProvider struct {
	certFile string
	keyFile  string
	logger   *slog.Logger

	mu   sync.RWMutex
	cert *tls.Certificate
}

// NewFileCertProvider creates a provider that loads certs from the given paths.
// The certificate is loaded immediately; returns an error if the initial load fails.
func NewFileCertProvider(certFile, keyFile string, logger *slog.Logger) (*FileCertProvider, error) {
	p := &FileCertProvider{
		certFile: certFile,
		keyFile:  keyFile,
		logger:   logger,
	}
	if err := p.Reload(); err != nil {
		return nil, fmt.Errorf("initial certificate load: %w", err)
	}
	return p, nil
}

// Reload re-reads the certificate and key from disk.
// On success the cached certificate is replaced atomically.
// On failure the previous certificate remains active and an error is returned.
func (p *FileCertProvider) Reload() error {
	cert, err := tls.LoadX509KeyPair(p.certFile, p.keyFile)
	if err != nil {
		p.logger.Error("failed to reload TLS certificate",
			"cert_file", p.certFile,
			"key_file", p.keyFile,
			"error", err)
		return fmt.Errorf("load certificate: %w", err)
	}

	p.mu.Lock()
	p.cert = &cert
	p.mu.Unlock()

	// Log certificate details including expiry for operational visibility
	logAttrs := []any{"cert_file", p.certFile, "key_file", p.keyFile}
	if cert.Leaf == nil {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	if cert.Leaf != nil {
		logAttrs = append(logAttrs,
			"subject", cert.Leaf.Subject.CommonName,
			"not_after", cert.Leaf.NotAfter.Format(time.RFC3339),
			"expires_in", time.Until(cert.Leaf.NotAfter).Round(time.Hour))
	}
	p.logger.Info("TLS certificate loaded", logAttrs...)
	return nil
}

// GetCertificate returns the cached certificate. Suitable for use as
// tls.Config.GetCertificate callback.
func (p *FileCertProvider) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.mu.RLock()
	cert := p.cert
	p.mu.RUnlock()

	if cert == nil {
		return nil, fmt.Errorf("no certificate loaded")
	}
	return cert, nil
}
