package s3credentials

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// Decode extracts LDAP credentials from an S3 access key and derives the
// signing secret used to verify the request. Only X25519-encrypted tokens are
// accepted, and the gateway private key is required.
func Decode(accessKey string, s3gatewayPrivateKey *ecdh.PrivateKey) (username, password, secretKey string, err error) {
	if s3gatewayPrivateKey == nil {
		return "", "", "", errors.New("X25519 private key is required")
	}
	return decryptToken(accessKey, s3gatewayPrivateKey)
}

// EncodeSecretKey derives the S3 signing secret as the URL-safe Base64 encoding
// of the input's SHA-256 digest.
func EncodeSecretKey(secretKey string) string {
	key := sha256.Sum256([]byte(secretKey))
	return base64.URLEncoding.EncodeToString(key[:])
}
