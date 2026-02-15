package s3credentials

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

func S3credentials(accessKey string, s3gatewayPrivateKey *ecdh.PrivateKey) (username, password, secretKey string, err error) {
	if s3gatewayPrivateKey != nil && strings.HasPrefix(accessKey, s3credentials_x25519_v1) {
		return GetDecryptedToken(accessKey, s3gatewayPrivateKey)
	} else {
		// legacy base64-encoded credentials
		return S3credentials_base64encoded(accessKey)
	}
}

func EncodeSecretKey(secretKey string) string {
	key := sha256.Sum256([]byte(secretKey))
	return base64.URLEncoding.EncodeToString(key[:])
}
