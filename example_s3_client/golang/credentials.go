package main

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	x25519TokenVersion = "X1"
	x25519HKDFInfo     = "s3gateway-x25519-v1"
	x25519KeySize      = 32
	x25519SaltSize     = 32
)

func generateGatewayKeys(username, password, publicKeyHex string) (string, string, error) {
	if strings.TrimSpace(username) == "" {
		return "", "", errors.New("username is required")
	}
	if strings.Contains(username, ":") {
		return "", "", errors.New("username cannot contain ':'")
	}
	if password == "" {
		return "", "", errors.New("password is required")
	}

	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(publicKeyHex))
	if err != nil {
		return "", "", fmt.Errorf("decode X25519 public key: %w", err)
	}
	if len(publicKeyBytes) != x25519KeySize {
		return "", "", errors.New("X25519 public key must be 32 bytes")
	}

	curve := ecdh.X25519()
	receiverPublicKey, err := curve.NewPublicKey(publicKeyBytes)
	if err != nil {
		return "", "", fmt.Errorf("parse X25519 public key: %w", err)
	}
	ephemeralPrivateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate ephemeral X25519 key: %w", err)
	}
	sharedSecret, err := ephemeralPrivateKey.ECDH(receiverPublicKey)
	if err != nil {
		return "", "", fmt.Errorf("derive X25519 shared secret: %w", err)
	}

	salt := make([]byte, x25519SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", "", fmt.Errorf("generate HKDF salt: %w", err)
	}
	key, err := hkdf.Key(
		sha256.New,
		sharedSecret,
		salt,
		x25519HKDFInfo,
		chacha20poly1305.KeySize,
	)
	if err != nil {
		return "", "", fmt.Errorf("derive encryption key: %w", err)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", "", fmt.Errorf("initialize ChaCha20-Poly1305: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", fmt.Errorf("generate ChaCha20-Poly1305 nonce: %w", err)
	}

	ephemeralPublicKey := ephemeralPrivateKey.PublicKey().Bytes()
	aad := make([]byte, 0, len(x25519TokenVersion)+len(ephemeralPublicKey)+len(salt))
	aad = append(aad, x25519TokenVersion...)
	aad = append(aad, ephemeralPublicKey...)
	aad = append(aad, salt...)
	token := []byte(username + ":" + password)
	ciphertext := aead.Seal(nil, nonce, token, aad)

	payload := make([]byte, 0, len(ephemeralPublicKey)+len(salt)+len(nonce)+len(ciphertext))
	payload = append(payload, ephemeralPublicKey...)
	payload = append(payload, salt...)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)
	accessKey := x25519TokenVersion + base64.RawURLEncoding.EncodeToString(payload)

	secretHash := sha256.Sum256(token)
	secretKey := base64.URLEncoding.EncodeToString(secretHash[:])
	return accessKey, secretKey, nil
}
