package certreader

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

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
	log.Printf("loaded %d CA file(s) from %s", loaded, caFolder)

	// Read system default Root CA
	defaultCaFile := "/etc/ssl/certs/ca-certificates.crt"
	certs, err := LoadCertBundleFromFile(defaultCaFile)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("load default root CA file %s: %w", defaultCaFile, err)
		}
		log.Printf("default CA file %s not found, skipping", defaultCaFile)
	} else {
		log.Printf("adding default CA Root certificate from: %s", defaultCaFile)
		for _, cert := range certs {
			certpool.AddCert(cert)
		}
	}
	return certpool, nil
}

func LoadCertBundleFromFile(filename string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Detect format by peeking at the first PEM block; the full original bytes are passed to LoadCertBundleFromPEM.
	if block, _ := pem.Decode(b); block != nil {
		return LoadCertBundleFromPEM(b)
	}

	return LoadCertBundleFromDER(b)
}

func LoadCertBundleFromDER(derBytes []byte) ([]*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("parse DER certificate: %w", err)
	}
	return []*x509.Certificate{cert}, nil
}

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
