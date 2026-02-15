package s3credentials

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestS3credentials(t *testing.T) {

	privateKey, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate receiver key: %v", err)
	}
	publicKey := privateKey.PublicKey()

	inLdapUsername := "ldapUser42"
	inLdapPassword := "ldapPass42"

	accessKey, _, err := GenerateAccessSecretKey(inLdapUsername, inLdapPassword, hex.EncodeToString(publicKey.Bytes()))
	if err != nil {
		t.Fatalf("failed to generate access and secret keys: %v", err)
	}

	username, password, err := S3credentials(accessKey, privateKey)
	if err != nil {
		t.Fatalf("failed to get credentials: %v", err)
	}

	if username != inLdapUsername {
		t.Fatalf("expected username %s, got %s", inLdapUsername, username)
	}
	if password != inLdapPassword {
		t.Fatalf("expected password %s, got %s", inLdapPassword, password)
	}
}
