package s3credentials

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// ==================== Credential hack ====================
// accessKey = "AD" + 'AD'base64("username:password")
// secretKey = constant "password"
func decodeBase64(accessKey string) (username, password, secretKey string, err error) {

	if !strings.HasPrefix(accessKey, "AD") {
		return "", "", "", fmt.Errorf("accessKey must start with 'AD' prefix")
	}

	raw, err := base64.StdEncoding.DecodeString(accessKey[2:])
	if err != nil {
		return "", "", "", fmt.Errorf("accessKey not base64: %w", err)
	}

	s := strings.TrimSpace(string(raw))

	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("accessKey must decode to 'username:password' format")
	}

	username = strings.TrimSpace(parts[0])
	password = parts[1] // keep password as-is (can contain spaces); may include ':' when encoded in the password segment
	if username == "" || password == "" {
		return "", "", "", fmt.Errorf("accessKey must decode to 'username:password' with non-empty username and password")
	}

	return username, password, EncodeSecretKey(s), nil
}

func GenerateKeysBase64Encoded(ldapUsername, ldapPassword string) (accessKey string, secretKey string, err error) {
	if strings.Contains(ldapUsername, ":") {
		return "", "", errors.New("ldap username cannot contain ':' character")
	}
	token := ldapUsername + ":" + ldapPassword
	accessKey = "AD" + base64.StdEncoding.EncodeToString([]byte(token))

	secretKey = EncodeSecretKey(token)
	return accessKey, secretKey, nil
}
