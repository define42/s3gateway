package main

import (
	"strings"
	"testing"

	"github.com/define42/s3gateway/internal/s3credentials"
)

func TestGenerateGatewayKeysRoundTrip(t *testing.T) {
	privateKeyHex, publicKeyHex, err := s3credentials.GenerateX25519TestKeys()
	if err != nil {
		t.Fatalf("generate gateway key pair: %v", err)
	}
	privateKey, err := s3credentials.X25519PrivateKeyFromHex(privateKeyHex)
	if err != nil {
		t.Fatalf("parse gateway private key: %v", err)
	}

	accessKey, secretKey, err := generateGatewayKeys("testuser", "dogood", publicKeyHex)
	if err != nil {
		t.Fatalf("generateGatewayKeys() error = %v", err)
	}
	if !strings.HasPrefix(accessKey, x25519TokenVersion) {
		t.Fatalf("access key prefix = %q, want %q", accessKey[:2], x25519TokenVersion)
	}

	username, password, decodedSecretKey, err := s3credentials.Decode(accessKey, privateKey)
	if err != nil {
		t.Fatalf("gateway Decode() error = %v", err)
	}
	if username != "testuser" || password != "dogood" {
		t.Fatalf("decoded credentials = %q/%q, want testuser/dogood", username, password)
	}
	if decodedSecretKey != secretKey {
		t.Fatalf("decoded secret key = %q, want %q", decodedSecretKey, secretKey)
	}
}

func TestGenerateGatewayKeysValidation(t *testing.T) {
	_, publicKeyHex, err := s3credentials.GenerateX25519TestKeys()
	if err != nil {
		t.Fatalf("generate gateway key pair: %v", err)
	}

	tests := []struct {
		name         string
		username     string
		password     string
		publicKeyHex string
	}{
		{
			name:         "missing username",
			password:     "password",
			publicKeyHex: publicKeyHex,
		},
		{
			name:         "username contains separator",
			username:     "user:name",
			password:     "password",
			publicKeyHex: publicKeyHex,
		},
		{
			name:         "missing password",
			username:     "username",
			publicKeyHex: publicKeyHex,
		},
		{
			name:         "invalid public key encoding",
			username:     "username",
			password:     "password",
			publicKeyHex: "not-hex",
		},
		{
			name:         "invalid public key length",
			username:     "username",
			password:     "password",
			publicKeyHex: "00",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := generateGatewayKeys(tc.username, tc.password, tc.publicKeyHex); err == nil {
				t.Fatal("generateGatewayKeys() error = nil, want validation error")
			}
		})
	}
}
