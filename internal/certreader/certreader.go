// Package certreader loads PEM and DER certificate bundles for TLS trust
// configuration.
package certreader

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// ReadCertificates extends the system certificate pool with every non-directory
// entry in caFolder and, when present, the Debian-style default CA bundle at
// /etc/ssl/certs/ca-certificates.crt. A directory entry or malformed certificate
// causes the whole operation to fail.
func ReadCertificates(caFolder string) (*x509.CertPool, error) {
	certpool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	files, err := os.ReadDir(caFolder)
	if err != nil {
		return nil, fmt.Errorf("read root CA directory %s: %w", caFolder, err)
	}

	loaded := 0
	for _, file := range files {
		caPath := filepath.Join(caFolder, file.Name())
		info, err := file.Info()
		if err != nil {
			return nil, fmt.Errorf("read root CA entry %s info: %w", caPath, err)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("root CA entry %s is a directory", caPath)
		}

		certs, err := LoadCertBundleFromFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("load root CA file %s: %w", caPath, err)
		}

		for _, cert := range certs {
			certpool.AddCert(cert)
		}
		loaded++
	}
	slog.Info("loaded CA files", "count", loaded, "dir", caFolder)

	// Read system default Root CA
	defaultCaFile := "/etc/ssl/certs/ca-certificates.crt"
	certs, err := LoadCertBundleFromFile(defaultCaFile)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("load default root CA file %s: %w", defaultCaFile, err)
		}
		slog.Info("default CA file not found, skipping", "path", defaultCaFile)
	} else {
		slog.Info("adding default CA root certificate", "path", defaultCaFile)
		for _, cert := range certs {
			certpool.AddCert(cert)
		}
	}
	return certpool, nil
}

// LoadCertBundleFromFile reads a PEM or DER certificate bundle. The first PEM
// block determines whether the file is decoded as PEM; otherwise it is parsed
// as DER.
func LoadCertBundleFromFile(filename string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(filename) // #nosec G304 -- filename is from os.ReadDir output or a trusted constant
	if err != nil {
		return nil, err
	}

	// Detect format by peeking at the first PEM block; the full original bytes are passed to LoadCertBundleFromPEM.
	if block, _ := pem.Decode(b); block != nil {
		return LoadCertBundleFromPEM(b)
	}

	return LoadCertBundleFromDER(b)
}

// LoadCertBundleFromDER parses one or more concatenated DER certificates.
func LoadCertBundleFromDER(derBytes []byte) ([]*x509.Certificate, error) {
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, fmt.Errorf("parse DER certificate: %w", err)
	}
	return certs, nil
}

// LoadCertBundleFromPEM parses one or more CERTIFICATE blocks. It rejects
// non-certificate PEM blocks and input containing no certificates.
func LoadCertBundleFromPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	certificates := []*x509.Certificate{}
	var block *pem.Block
	block, pemBytes = pem.Decode(pemBytes)
	for ; block != nil; block, pemBytes = pem.Decode(pemBytes) {
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certificates = append(certificates, cert)
		} else {
			return nil, fmt.Errorf("invalid pem block type: %s", block.Type)
		}
	}

	if len(certificates) == 0 {
		return nil, fmt.Errorf("no valid certificates found")
	}

	return certificates, nil
}
