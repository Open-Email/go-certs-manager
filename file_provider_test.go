package certmanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	certOut, _ := os.Create(certFile)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyBytes, _ := x509.MarshalECPrivateKey(key)
	keyOut, _ := os.Create(keyFile)
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()

	return certFile, keyFile
}

func TestFileCertProvider_LoadAndGetCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestCert(t, dir)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	provider, err := NewFileCertProvider(certFile, keyFile, logger)
	if err != nil {
		t.Fatalf("NewFileCertProvider failed: %v", err)
	}

	cert, err := provider.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert == nil {
		t.Fatal("GetCertificate returned nil")
	}
}

func TestFileCertProvider_Reload(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestCert(t, dir)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	provider, err := NewFileCertProvider(certFile, keyFile, logger)
	if err != nil {
		t.Fatalf("NewFileCertProvider failed: %v", err)
	}

	// Reload should succeed with same files
	if err := provider.Reload(); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// Cert should still work after reload
	cert, err := provider.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate after reload failed: %v", err)
	}
	if cert == nil {
		t.Fatal("GetCertificate returned nil after reload")
	}
}

func TestFileCertProvider_InvalidPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	_, err := NewFileCertProvider("/nonexistent/cert.pem", "/nonexistent/key.pem", logger)
	if err == nil {
		t.Fatal("expected error for nonexistent files")
	}
}

func TestFileCertProvider_ReloadKeepsPreviousOnError(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestCert(t, dir)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	provider, err := NewFileCertProvider(certFile, keyFile, logger)
	if err != nil {
		t.Fatalf("NewFileCertProvider failed: %v", err)
	}

	// Corrupt the cert file
	os.WriteFile(certFile, []byte("bad data"), 0600)

	// Reload should fail
	if err := provider.Reload(); err == nil {
		t.Fatal("expected Reload to fail with corrupt cert")
	}

	// Previous cert should still be served
	cert, err := provider.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate should still work after failed reload: %v", err)
	}
	if cert == nil {
		t.Fatal("expected previous cert to be retained after failed reload")
	}
}
