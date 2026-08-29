package s3credentials

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// Decode extracts LDAP credentials from an S3 access key and derives the
// signing secret used to verify the request. X25519 tokens are decrypted when
// a private key is supplied; all other inputs use the legacy AD-prefixed
// Base64 format.
func Decode(accessKey string, s3gatewayPrivateKey *ecdh.PrivateKey) (username, password, secretKey string, err error) {
	if s3gatewayPrivateKey != nil && strings.HasPrefix(accessKey, s3CredentialsX25519V1) {
		return decryptToken(accessKey, s3gatewayPrivateKey)
	}
	// legacy base64-encoded credentials
	return decodeBase64(accessKey)
}

// EncodeSecretKey derives the S3 signing secret as the URL-safe Base64 encoding
// of the input's SHA-256 digest.
func EncodeSecretKey(secretKey string) string {
	key := sha256.Sum256([]byte(secretKey))
	return base64.URLEncoding.EncodeToString(key[:])
}
