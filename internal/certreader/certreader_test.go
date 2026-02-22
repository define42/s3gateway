package certreader

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func makeTestCertPEM(t *testing.T, commonName string) []byte {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestLoadCertBundleFromPEM(t *testing.T) {
	t.Run("single certificate", func(t *testing.T) {
		certPEM := makeTestCertPEM(t, "single-cert")
		certs, err := LoadCertBundleFromPEM(certPEM)
		if err != nil {
			t.Fatalf("LoadCertBundleFromPEM returned error: %v", err)
		}
		if len(certs) != 1 {
			t.Fatalf("expected 1 certificate, got %d", len(certs))
		}
		if certs[0].Subject.CommonName != "single-cert" {
			t.Fatalf("expected common name single-cert, got %q", certs[0].Subject.CommonName)
		}
	})

	t.Run("multiple certificates", func(t *testing.T) {
		pemBytes := append(makeTestCertPEM(t, "first"), makeTestCertPEM(t, "second")...)
		certs, err := LoadCertBundleFromPEM(pemBytes)
		if err != nil {
			t.Fatalf("LoadCertBundleFromPEM returned error: %v", err)
		}
		if len(certs) != 2 {
			t.Fatalf("expected 2 certificates, got %d", len(certs))
		}
	})

	t.Run("invalid block type", func(t *testing.T) {
		invalid := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("abc")})
		_, err := LoadCertBundleFromPEM(invalid)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid pem block type") {
			t.Fatalf("expected invalid pem block type error, got %v", err)
		}
	})

	t.Run("no valid certificates", func(t *testing.T) {
		_, err := LoadCertBundleFromPEM([]byte("not-a-pem"))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "no valid certificates found") {
			t.Fatalf("expected no valid certificates found error, got %v", err)
		}
	})
}

func TestLoadCertBundleFromFile(t *testing.T) {
	t.Run("file not found", func(t *testing.T) {
		_, err := LoadCertBundleFromFile(filepath.Join(t.TempDir(), "missing.pem"))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("valid file", func(t *testing.T) {
		dir := t.TempDir()
		certPath := filepath.Join(dir, "cert.pem")
		if err := os.WriteFile(certPath, makeTestCertPEM(t, "file-cert"), 0o600); err != nil {
			t.Fatalf("write cert file: %v", err)
		}
		certs, err := LoadCertBundleFromFile(certPath)
		if err != nil {
			t.Fatalf("LoadCertBundleFromFile returned error: %v", err)
		}
		if len(certs) != 1 {
			t.Fatalf("expected 1 certificate, got %d", len(certs))
		}
	})
}

func TestReadCertificates(t *testing.T) {
	t.Run("fails on directory entry in strict mode", func(t *testing.T) {
		dir := t.TempDir()
		badDir := filepath.Join(dir, "00-dir")
		if err := os.Mkdir(badDir, 0o755); err != nil {
			t.Fatalf("create directory entry: %v", err)
		}

		_, err := ReadCertificates(dir)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "is a directory") {
			t.Fatalf("expected directory error, got %v", err)
		}
		if !strings.Contains(err.Error(), badDir) {
			t.Fatalf("expected path %q in error, got %v", badDir, err)
		}
	})

	t.Run("fails on invalid certificate file in strict mode", func(t *testing.T) {
		dir := t.TempDir()
		badFile := filepath.Join(dir, "broken.pem")
		if err := os.WriteFile(badFile, []byte("not a certificate"), 0o600); err != nil {
			t.Fatalf("write invalid cert file: %v", err)
		}

		_, err := ReadCertificates(dir)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "load root CA file") {
			t.Fatalf("expected load root CA file error, got %v", err)
		}
		if !strings.Contains(err.Error(), badFile) {
			t.Fatalf("expected path %q in error, got %v", badFile, err)
		}
	})

	t.Run("loads valid certificate directory", func(t *testing.T) {
		dir := t.TempDir()
		certPEM := makeTestCertPEM(t, "local-ca")
		certPath := filepath.Join(dir, "local-ca.pem")
		if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
			t.Fatalf("write cert file: %v", err)
		}

		pool, err := ReadCertificates(dir)
		if err != nil {
			t.Fatalf("ReadCertificates returned error: %v", err)
		}
		if pool == nil {
			t.Fatal("expected non-nil cert pool")
		}

		parsed, err := LoadCertBundleFromPEM(certPEM)
		if err != nil {
			t.Fatalf("parse local cert: %v", err)
		}

		if _, err := parsed[0].Verify(x509.VerifyOptions{
			Roots:       pool,
			CurrentTime: time.Now(),
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			t.Fatalf("expected cert from %s to verify with returned pool: %v", certPath, err)
		}
	})
}
