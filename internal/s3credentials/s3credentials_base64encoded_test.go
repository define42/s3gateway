package s3credentials_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/define42/s3gateway/internal/s3credentials"
)

func TestDecodeUserPassFromAccessKeyErrorPaths(t *testing.T) {
	t.Run("accessKey not base64", func(t *testing.T) {
		_, _, _, err := s3credentials.S3CredentialsBase64Encoded("AD!not-base64!")
		if err == nil {
			t.Fatalf("expected error for non-base64 access key")
		}
		if !strings.Contains(err.Error(), "accessKey not base64") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("accessKey must decode to user pass", func(t *testing.T) {
		accessKey := base64.StdEncoding.EncodeToString([]byte("useronly"))
		_, _, _, err := s3credentials.S3CredentialsBase64Encoded("AD" + accessKey)
		if err == nil {
			t.Fatalf("expected error for decoded access key without username:password format")
		}
		if !strings.Contains(err.Error(), "accessKey must decode to 'username:password'") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("accessKey must decode to username and password", func(t *testing.T) {
		accessKey, secretKey, err := s3credentials.GenerateKeysBase64Encoded("username", "password")
		if err != nil {
			t.Fatalf("unexpected error generating access key: %v", err)
		}

		username, password, secretKeyGot, err := s3credentials.S3CredentialsBase64Encoded(accessKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if username != "username" {
			t.Fatalf("expected username 'username', got '%s'", username)
		}
		if password != "password" {
			t.Fatalf("expected password 'password', got '%s'", password)
		}

		want := s3credentials.EncodeSecretKey("username:password")
		if secretKey != want {
			t.Fatalf("expected secretKey '%s', got '%s'", want, secretKey)
		}
		if secretKeyGot != want {
			t.Fatalf("expected secretKey '%s', got '%s'", want, secretKeyGot)
		}
	})
}
