package s3credentials

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

var x25519Curve = ecdh.X25519()

const s3credentials_x25519_v1 = "X1"
const x25519KeySize = 32

func decrypt(receiverPriv *ecdh.PrivateKey, encoded string) ([]byte, error) {
	payload := encoded
	if strings.HasPrefix(payload, "X") && len(payload) >= len(s3credentials_x25519_v1) {
		version := payload[:len(s3credentials_x25519_v1)]
		if version != s3credentials_x25519_v1 {
			return nil, errors.New("unsupported payload version")
		}
		payload = payload[len(s3credentials_x25519_v1):]
	}

	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("payload too short")
	}

	if len(data) >= len(s3credentials_x25519_v1) && data[0] == 'X' {
		version := string(data[:len(s3credentials_x25519_v1)])
		if version != s3credentials_x25519_v1 {
			return nil, errors.New("unsupported payload version")
		}
		data = data[len(s3credentials_x25519_v1):]
	}

	// fixed framing for v1
	if len(data) < x25519KeySize+chacha20poly1305.NonceSize {
		return nil, errors.New("ciphertext too short")
	}

	ephemeralPubBytes := data[:x25519KeySize]
	nonce := data[x25519KeySize : x25519KeySize+chacha20poly1305.NonceSize]
	ciphertext := data[x25519KeySize+chacha20poly1305.NonceSize:]

	ephemeralPub, err := x25519Curve.NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := receiverPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonce, ciphertext, nil)

}

func X25519PublicKeyFromHex(hexKey string) (*ecdh.PublicKey, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}

	if len(keyBytes) != x25519KeySize {
		return nil, errors.New("X25519 public key must be 32 bytes")
	}

	return x25519Curve.NewPublicKey(keyBytes)
}

func GenerateKeysX25519(ldapUsername, ldapPassword, publicKeyHex string) (accessKey string, secretKey string, err error) {
	publicKey, err := X25519PublicKeyFromHex(publicKeyHex)
	if err != nil {
		return "", "", err
	}
	// Username must not contain ":" since it's used as a separator in the token. This is a simple validation to prevent token parsing issues.
	if strings.Contains(ldapUsername, ":") {
		return "", "", errors.New("ldap username cannot contain ':' character")
	}
	token := ldapUsername + ":" + ldapPassword
	accessKey, err = encrypt(publicKey, []byte(token))
	if err != nil {
		return "", "", err
	}
	hash := sha256.Sum256([]byte(token))
	secretKey = base64.RawURLEncoding.EncodeToString(hash[:])

	return accessKey, secretKey, nil
}

func encrypt(receiverPub *ecdh.PublicKey, plaintext []byte) (string, error) {
	ephemeralPriv, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}

	sharedSecret, err := ephemeralPriv.ECDH(receiverPub)
	if err != nil {
		return "", err
	}

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	epub := ephemeralPriv.PublicKey().Bytes()

	// version (1) + epub (32) + nonce (12) + ciphertext
	payload := make([]byte, 0, len(epub)+len(nonce)+len(ciphertext))
	payload = append(payload, epub...)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)

	return s3credentials_x25519_v1 + base64.RawURLEncoding.EncodeToString(payload), nil
}

func GetDecryptedToken(encoded string, privateKey *ecdh.PrivateKey) (ldapUsername, ldapPassword, secretKey string, err error) {
	if !strings.HasPrefix(encoded, s3credentials_x25519_v1) {
		return "", "", "", errors.New("invalid token version")
	}
	decrypted, err := decrypt(privateKey, encoded[2:])
	if err != nil {
		return "", "", "", err
	}

	ldapUsername, ldapPassword, ok := strings.Cut(string(decrypted), ":")
	if !ok {
		return "", "", "", errors.New("invalid token format")
	}

	hash := sha256.Sum256(decrypted)
	secretKey = base64.RawURLEncoding.EncodeToString(hash[:])

	return ldapUsername, ldapPassword, secretKey, nil
}

func X25519PrivateKeyFromHex(hexKey string) (*ecdh.PrivateKey, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}

	if len(keyBytes) != 32 {
		return nil, errors.New("X25519 private key must be 32 bytes")
	}

	curve := ecdh.X25519()
	return curve.NewPrivateKey(keyBytes)
}
