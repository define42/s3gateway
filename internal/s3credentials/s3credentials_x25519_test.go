package s3credentials

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestGenerateKeys(t *testing.T) {
	receiverPriv, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate receiver key: %v", err)
	}
	receiverPub := receiverPriv.PublicKey()

	inLdapUsername := "ldapUser42"
	inLdapPassword := "ldapPass42"

	accessKey, secretKey, err := GenerateKeysX25519(inLdapUsername, inLdapPassword, hex.EncodeToString(receiverPub.Bytes()))
	if err != nil {
		t.Fatalf("failed to generate access and secret keys: %v", err)
	}
	privateKey, err := X25519PrivateKeyFromHex(hex.EncodeToString(receiverPriv.Bytes()))
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}

	outLdapUsername, outLdapPassword, outSecretKey, err := decryptToken(accessKey, privateKey)
	if err != nil {
		t.Fatalf("failed to decrypt token: %v", err)
	}

	if secretKey != outSecretKey {
		t.Fatalf("secret keys do not match")
	}
	if outLdapUsername != inLdapUsername {
		t.Fatalf("LDAP usernames do not match")
	}
	if outLdapPassword != inLdapPassword {
		t.Fatalf("LDAP passwords do not match")
	}
}

func TestDecryptErrors(t *testing.T) {
	receiverPriv, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate receiver key: %v", err)
	}

	tests := []struct {
		name    string
		encoded string
		wantErr string
	}{
		{
			name:    "invalid base64",
			encoded: "X1%%%",
			wantErr: "illegal base64 data",
		},
		{
			name:    "empty payload",
			encoded: base64.RawURLEncoding.EncodeToString(nil),
			wantErr: "payload too short",
		},
		{
			name:    "one-byte payload",
			encoded: base64.RawURLEncoding.EncodeToString([]byte("X")),
			wantErr: "ciphertext too short",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := decrypt(receiverPriv, tc.encoded)
			if err == nil {
				t.Fatalf("expected error %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestDecryptTamperedHeader(t *testing.T) {
	receiverPriv, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate receiver key: %v", err)
	}

	encoded, err := encrypt(receiverPriv.PublicKey(), []byte("user:pass"))
	if err != nil {
		t.Fatalf("failed to encrypt test payload: %v", err)
	}

	rawPayload, err := base64.RawURLEncoding.DecodeString(encoded[len(s3CredentialsX25519V1):])
	if err != nil {
		t.Fatalf("failed to decode encrypted test payload: %v", err)
	}

	// Tamper with ephemeral public key byte — AAD mismatch must cause auth failure.
	tamperedEpub := bytes.Clone(rawPayload)
	tamperedEpub[0] ^= 0x01
	_, err = decrypt(receiverPriv, base64.RawURLEncoding.EncodeToString(tamperedEpub))
	if err == nil {
		t.Fatalf("expected authentication error for tampered ephemeral public key")
	}
	if !strings.Contains(err.Error(), "message authentication failed") {
		t.Fatalf("expected message authentication failed error for tampered epub, got %v", err)
	}

	// Tamper with salt byte — AAD mismatch must cause auth failure.
	tamperedSalt := bytes.Clone(rawPayload)
	tamperedSalt[x25519KeySize] ^= 0x01
	_, err = decrypt(receiverPriv, base64.RawURLEncoding.EncodeToString(tamperedSalt))
	if err == nil {
		t.Fatalf("expected authentication error for tampered salt")
	}
	if !strings.Contains(err.Error(), "message authentication failed") {
		t.Fatalf("expected message authentication failed error for tampered salt, got %v", err)
	}
}


func TestDecryptTamperedCiphertext(t *testing.T) {
	receiverPriv, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate receiver key: %v", err)
	}

	encoded, err := encrypt(receiverPriv.PublicKey(), []byte("user:pass"))
	if err != nil {
		t.Fatalf("failed to encrypt test payload: %v", err)
	}

	data, err := base64.RawURLEncoding.DecodeString(encoded[len(s3CredentialsX25519V1):])
	if err != nil {
		t.Fatalf("failed to decode encrypted test payload: %v", err)
	}
	data[len(data)-1] ^= 0x01

	tampered := base64.RawURLEncoding.EncodeToString(data)
	if _, err := decrypt(receiverPriv, tampered); err == nil {
		t.Fatalf("expected authentication error for tampered ciphertext")
	}
}

func TestDecryptTokenInvalidFormat(t *testing.T) {
	receiverPriv, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate receiver key: %v", err)
	}

	encoded, err := encrypt(receiverPriv.PublicKey(), []byte("noseparator"))
	if err != nil {
		t.Fatalf("failed to encrypt test payload: %v", err)
	}

	_, _, _, err = decryptToken(encoded, receiverPriv)
	if err == nil {
		t.Fatalf("expected invalid token format error")
	}
	if !strings.Contains(err.Error(), "invalid token format") {
		t.Fatalf("expected invalid token format error, got %v", err)
	}
}

func TestDecryptTokenRejectsEmptyCredentials(t *testing.T) {
	receiverPriv, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate receiver key: %v", err)
	}

	tests := []struct {
		name  string
		token string
	}{
		{name: "empty username", token: ":pass"},
		{name: "whitespace username", token: "  :pass"},
		{name: "empty password", token: "user:"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := encrypt(receiverPriv.PublicKey(), []byte(tc.token))
			if err != nil {
				t.Fatalf("failed to encrypt test payload: %v", err)
			}
			_, _, _, err = decryptToken(encoded, receiverPriv)
			if err == nil {
				t.Fatalf("expected invalid token format error")
			}
			if !strings.Contains(err.Error(), "invalid token format") {
				t.Fatalf("expected invalid token format error, got %v", err)
			}
		})
	}
}

func TestGenerateAccessSecretKeyValidationErrors(t *testing.T) {
	receiverPriv, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate receiver key: %v", err)
	}
	validPublicKeyHex := hex.EncodeToString(receiverPriv.PublicKey().Bytes())

	tests := []struct {
		name      string
		username  string
		password  string
		publicHex string
		wantErr   string
	}{
		{
			name:      "invalid public key hex",
			username:  "ldapUser",
			password:  "ldapPass",
			publicHex: "zz",
			wantErr:   "invalid byte",
		},
		{
			name:      "public key wrong length",
			username:  "ldapUser",
			password:  "ldapPass",
			publicHex: "00",
			wantErr:   "must be 32 bytes",
		},
		{
			name:      "username contains separator",
			username:  "ldap:User",
			password:  "ldapPass",
			publicHex: validPublicKeyHex,
			wantErr:   "cannot contain ':'",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := GenerateKeysX25519(tc.username, tc.password, tc.publicHex)
			if err == nil {
				t.Fatalf("expected error %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestX25519PublicKeyFromHex(t *testing.T) {
	receiverPriv, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate receiver key: %v", err)
	}
	validHex := hex.EncodeToString(receiverPriv.PublicKey().Bytes())

	pub, err := X25519PublicKeyFromHex(validHex)
	if err != nil {
		t.Fatalf("valid public key should parse: %v", err)
	}
	if got, want := hex.EncodeToString(pub.Bytes()), validHex; got != want {
		t.Fatalf("parsed public key mismatch: got %s want %s", got, want)
	}

	if _, err := X25519PublicKeyFromHex("zz"); err == nil {
		t.Fatalf("expected invalid hex to fail")
	}
	if _, err := X25519PublicKeyFromHex("00"); err == nil {
		t.Fatalf("expected short public key to fail")
	}
}

func TestX25519PrivateKeyFromHex(t *testing.T) {
	priv, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	validHex := hex.EncodeToString(priv.Bytes())

	parsed, err := X25519PrivateKeyFromHex(validHex)
	if err != nil {
		t.Fatalf("valid private key should parse: %v", err)
	}
	if got, want := hex.EncodeToString(parsed.Bytes()), validHex; got != want {
		t.Fatalf("parsed private key mismatch: got %s want %s", got, want)
	}

	if _, err := X25519PrivateKeyFromHex("zz"); err == nil {
		t.Fatalf("expected invalid hex to fail")
	}
	if _, err := X25519PrivateKeyFromHex("00"); err == nil {
		t.Fatalf("expected short private key to fail")
	}
}

func TestDecryptTokenDecryptError(t *testing.T) {
	receiverPriv, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate receiver key: %v", err)
	}

	_, _, _, err = decryptToken("X1%%%", receiverPriv)
	if err == nil {
		t.Fatalf("expected decrypt error")
	}
	if !strings.Contains(err.Error(), "illegal base64 data") {
		t.Fatalf("expected base64 error, got %v", err)
	}
}

func TestGenerateAccessSecretKeyEncryptError(t *testing.T) {
	lowOrderPublicKeyHex := hex.EncodeToString(make([]byte, x25519KeySize))
	_, _, err := GenerateKeysX25519("ldapUser", "ldapPass", lowOrderPublicKeyHex)
	if err == nil {
		t.Fatalf("expected low-order-point ECDH error")
	}
	if !strings.Contains(err.Error(), "low order point") {
		t.Fatalf("expected low-order-point error, got %v", err)
	}
}

type errorReader struct {
	err error
}

func (r errorReader) Read(_ []byte) (int, error) {
	return 0, r.err
}

func withRandReader(t *testing.T, r io.Reader) {
	t.Helper()
	oldReader := rand.Reader
	rand.Reader = r
	t.Cleanup(func() {
		rand.Reader = oldReader
	})
}

func withCurve(t *testing.T, curve ecdh.Curve) {
	t.Helper()
	oldCurve := x25519Curve
	x25519Curve = curve
	t.Cleanup(func() {
		x25519Curve = oldCurve
	})
}

func TestEncryptGenerateKeyError(t *testing.T) {
	receiverPriv, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate receiver key: %v", err)
	}

	withRandReader(t, errorReader{err: errors.New("rand failure")})

	_, err = encrypt(receiverPriv.PublicKey(), []byte("user:pass"))
	if err == nil {
		t.Fatalf("expected key generation error")
	}
	if !strings.Contains(err.Error(), "rand failure") {
		t.Fatalf("expected key generation rand error, got %v", err)
	}
}

func TestEncryptECDHError(t *testing.T) {
	lowOrderPub, err := x25519Curve.NewPublicKey(make([]byte, x25519KeySize))
	if err != nil {
		t.Fatalf("failed to build low-order public key: %v", err)
	}

	_, err = encrypt(lowOrderPub, []byte("user:pass"))
	if err == nil {
		t.Fatalf("expected low-order-point ECDH error")
	}
	if !strings.Contains(err.Error(), "low order point") {
		t.Fatalf("expected low-order-point error, got %v", err)
	}
}

func TestEncryptSaltRandomReadError(t *testing.T) {
	receiverPriv, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate receiver key: %v", err)
	}

	// Enough bytes for GenerateKey (32 bytes), but not enough for the salt read (needs another 32 bytes) — simulates EOF during salt generation.
	withRandReader(t, bytes.NewReader(make([]byte, 32)))

	_, err = encrypt(receiverPriv.PublicKey(), []byte("user:pass"))
	if err == nil {
		t.Fatalf("expected salt rand.Read error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "eof") {
		t.Fatalf("expected EOF-like salt read error, got %v", err)
	}
}

func TestEncryptNonceRandomReadError(t *testing.T) {
	receiverPriv, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate receiver key: %v", err)
	}

	// Enough bytes for GenerateKey (32 bytes) and salt (32 bytes), but not enough for the nonce read.
	withRandReader(t, bytes.NewReader(make([]byte, 64)))

	_, err = encrypt(receiverPriv.PublicKey(), []byte("user:pass"))
	if err == nil {
		t.Fatalf("expected nonce rand.Read error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "eof") {
		t.Fatalf("expected EOF-like nonce read error, got %v", err)
	}
}

func TestDeriveKey(t *testing.T) {
	secret := make([]byte, 32)
	salt := make([]byte, 32)
	key1, err := deriveKey(secret, salt)
	if err != nil {
		t.Fatalf("deriveKey failed: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d bytes", len(key1))
	}

	// Same input must always produce the same output (deterministic).
	key2, err := deriveKey(secret, salt)
	if err != nil {
		t.Fatalf("deriveKey failed on second call: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatalf("deriveKey is not deterministic")
	}

	// Different secret must produce a different key.
	otherSecret := make([]byte, 32)
	otherSecret[0] = 0xff
	keyOtherSecret, err := deriveKey(otherSecret, salt)
	if err != nil {
		t.Fatalf("deriveKey failed for other secret: %v", err)
	}
	if bytes.Equal(key1, keyOtherSecret) {
		t.Fatalf("deriveKey returned same key for different secrets")
	}

	// Different salt must produce a different key.
	otherSalt := make([]byte, 32)
	otherSalt[0] = 0xff
	keyOtherSalt, err := deriveKey(secret, otherSalt)
	if err != nil {
		t.Fatalf("deriveKey failed for other salt: %v", err)
	}
	if bytes.Equal(key1, keyOtherSalt) {
		t.Fatalf("deriveKey returned same key for different salts")
	}
}

func TestDecryptPublicKeyParseError(t *testing.T) {
	withCurve(t, ecdh.P384())

	receiverPriv, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate receiver key: %v", err)
	}

	// decrypt still slices a fixed 32-byte ephemeral public key for v1.
	payload := make([]byte, x25519KeySize+hkdfSaltSize+chacha20poly1305.NonceSize)
	encoded := base64.RawURLEncoding.EncodeToString(payload)

	_, err = decrypt(receiverPriv, encoded)
	if err == nil {
		t.Fatalf("expected public key parsing error")
	}
	if !strings.Contains(err.Error(), "invalid public key") {
		t.Fatalf("expected invalid public key error, got %v", err)
	}
}
