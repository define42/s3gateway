package s3credentials

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestDecode(t *testing.T) {

	privateKey, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate receiver key: %v", err)
	}
	publicKey := privateKey.PublicKey()

	inLdapUsername := "ldapUser42"
	inLdapPassword := "ldapPass42"

	accessKey, _, err := GenerateKeysX25519(inLdapUsername, inLdapPassword, hex.EncodeToString(publicKey.Bytes()))
	if err != nil {
		t.Fatalf("failed to generate access and secret keys: %v", err)
	}

	username, password, secretKey, err := Decode(accessKey, privateKey)
	if err != nil {
		t.Fatalf("failed to get credentials: %v", err)
	}

	if username != inLdapUsername {
		t.Fatalf("expected username %s, got %s", inLdapUsername, username)
	}
	if password != inLdapPassword {
		t.Fatalf("expected password %s, got %s", inLdapPassword, password)
	}
	expectedSecretKey := EncodeSecretKey(inLdapUsername + ":" + inLdapPassword)
	if secretKey != expectedSecretKey {
		t.Fatalf("expected secretKey %s, got %s", expectedSecretKey, secretKey)
	}
	if secretKey != "5mWQjp9l0gPnYM3BkYvmheh3a9sjPK6Cu8kNrqhTk4w=" {
		t.Fatalf("expected secretKey %s, got %s", "5mWQjp9l0gPnYM3BkYvmheh3a9sjPK6Cu8kNrqhTk4w=", secretKey)
	}
}
