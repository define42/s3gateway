package s3credentials

import (
	"crypto/ecdh"
	"strings"
)

func S3credentials(accessKey string, s3gatewayPrivateKey *ecdh.PrivateKey) (username, password string, err error) {

	if strings.HasPrefix(accessKey, s3credentials_x25519_v1) {

		username, password, _, err = GetDecryptedToken(accessKey, s3gatewayPrivateKey)
		if err != nil {
			return "", "", err
		}
		return username, password, nil
	} else {
		// legacy base64-encoded credentials
		return S3credentials_base64encoded(accessKey)
	}

}
