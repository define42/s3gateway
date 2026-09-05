package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TrustTLSCertificate adds a test certificate to a test-scoped AWS_CA_BUNDLE.
// Existing bundle certificates are preserved. Tests using this helper cannot
// run in parallel because the AWS SDK loads the bundle from the environment.
func TrustTLSCertificate(tb testing.TB, certificate *x509.Certificate) {
	tb.Helper()
	var bundle []byte
	if existing := os.Getenv("AWS_CA_BUNDLE"); existing != "" {
		var err error
		bundle, err = os.ReadFile(existing)
		if err != nil {
			tb.Fatalf("read existing AWS CA bundle: %v", err)
		}
		bundle = append(bundle, '\n')
	}
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
	filename := filepath.Join(tb.TempDir(), "aws-test-ca.pem")
	if err := os.WriteFile(filename, bundle, 0o600); err != nil {
		tb.Fatalf("write AWS test CA bundle: %v", err)
	}
	tb.Setenv("AWS_CA_BUNDLE", filename)
}

// NewTLSServer starts a test HTTPS server and trusts its certificate through
// AWS_CA_BUNDLE. The server and trust configuration are cleaned up with tb.
func NewTLSServer(tb testing.TB, handler http.Handler) *httptest.Server {
	tb.Helper()
	server := httptest.NewTLSServer(handler)
	TrustTLSCertificate(tb, server.Certificate())
	tb.Cleanup(server.Close)
	return server
}

// NewHTTPClient returns a standard HTTP client that verifies certificates using
// the system roots and the current test's AWS_CA_BUNDLE. It is useful for
// non-SDK fixture connections, such as a reverse proxy to a test S3 service.
func NewHTTPClient(tb testing.TB) *http.Client {
	tb.Helper()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	roots, err := x509.SystemCertPool()
	if err != nil {
		tb.Fatalf("load system certificate roots: %v", err)
	}
	if bundlePath := os.Getenv("AWS_CA_BUNDLE"); bundlePath != "" {
		bundle, err := os.ReadFile(bundlePath)
		if err != nil {
			tb.Fatalf("read AWS test CA bundle: %v", err)
		}
		if !roots.AppendCertsFromPEM(bundle) {
			tb.Fatal("AWS test CA bundle contains no certificates")
		}
	}
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	tb.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

func writeTestTLSCertificate(tb testing.TB, host string) (certificatePath, keyPath string, certificate *x509.Certificate) {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate test TLS private key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		tb.Fatalf("generate test certificate serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "s3gateway MinIO test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("create test TLS certificate: %v", err)
	}
	certificate, err = x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("parse test TLS certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		tb.Fatalf("marshal test TLS private key: %v", err)
	}
	directory := tb.TempDir()
	certificatePath = filepath.Join(directory, "public.crt")
	keyPath = filepath.Join(directory, "private.key")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		tb.Fatalf("write test TLS certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		tb.Fatalf("write test TLS private key: %v", err)
	}
	return certificatePath, keyPath, certificate
}
