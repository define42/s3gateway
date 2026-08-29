package sigv4_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/define42/s3gateway/internal/sigv4"
)

func TestCanonicalURI(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{input: "", expected: "/"},
		{input: "bucket/key", expected: "/bucket/key"},
		{input: "/already/escaped", expected: "/already/escaped"},
	}

	for _, test := range tests {
		if got := sigv4.CanonicalURI(test.input); got != test.expected {
			t.Fatalf("CanonicalURI(%q) = %q, want %q", test.input, got, test.expected)
		}
	}
}

func TestVerifySigV4PayloadDigest(t *testing.T) {
	const secret = "test-secret"

	t.Run("matching body streams completely", func(t *testing.T) {
		body := "authenticated object contents"
		req, auth := signedTestRequest(t, http.MethodPut, "https://example.com/bucket/key", body, sha256Hex(body), nil)
		if err := sigv4.VerifySigV4(req, auth, secret); err != nil {
			t.Fatalf("VerifySigV4() error = %v", err)
		}
		got, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read verified body: %v", err)
		}
		if string(got) != body {
			t.Fatalf("verified body = %q, want %q", got, body)
		}
	})

	t.Run("tampered body withholds final byte", func(t *testing.T) {
		original := "authenticated object contents"
		tampered := "tampered----- object contents"
		if len(original) != len(tampered) {
			t.Fatal("test payloads must have equal lengths")
		}
		req, auth := signedTestRequest(t, http.MethodPut, "https://example.com/bucket/key", tampered, sha256Hex(original), nil)
		if err := sigv4.VerifySigV4(req, auth, secret); err != nil {
			t.Fatalf("VerifySigV4() setup error = %v", err)
		}
		got, err := io.ReadAll(req.Body)
		if !errors.Is(err, sigv4.ErrPayloadHashMismatch) {
			t.Fatalf("read error = %v, want ErrPayloadHashMismatch", err)
		}
		if len(got) >= len(tampered) {
			t.Fatalf("reader released complete tampered body: got %d of %d bytes", len(got), len(tampered))
		}
		if err := sigv4.StreamValidationError(req.Body); !errors.Is(err, sigv4.ErrPayloadHashMismatch) {
			t.Fatalf("StreamValidationError() = %v, want ErrPayloadHashMismatch", err)
		}
	})

	t.Run("empty body is checked before dispatch", func(t *testing.T) {
		req, auth := signedTestRequest(t, http.MethodPut, "https://example.com/bucket/key", "", sha256Hex("not empty"), nil)
		if err := sigv4.VerifySigV4(req, auth, secret); !errors.Is(err, sigv4.ErrPayloadHashMismatch) {
			t.Fatalf("VerifySigV4() error = %v, want ErrPayloadHashMismatch", err)
		}
	})

	t.Run("malformed digest is rejected", func(t *testing.T) {
		req, auth := signedTestRequest(t, http.MethodPut, "https://example.com/bucket/key", "body", strings.Repeat("z", 64), nil)
		if err := sigv4.VerifySigV4(req, auth, secret); !errors.Is(err, sigv4.ErrInvalidPayloadHash) {
			t.Fatalf("VerifySigV4() error = %v, want ErrInvalidPayloadHash", err)
		}
	})

	t.Run("unsigned payload requires TLS", func(t *testing.T) {
		req, auth := signedTestRequest(t, http.MethodPut, "http://example.com/bucket/key", "body", "UNSIGNED-PAYLOAD", nil)
		if err := sigv4.VerifySigV4(req, auth, secret); !errors.Is(err, sigv4.ErrUnsignedPayloadRequiresTLS) {
			t.Fatalf("plaintext VerifySigV4() error = %v, want ErrUnsignedPayloadRequiresTLS", err)
		}

		tlsReq, tlsAuth := signedTestRequest(t, http.MethodPut, "https://example.com/bucket/key", "body", "UNSIGNED-PAYLOAD", nil)
		if err := sigv4.VerifySigV4(tlsReq, tlsAuth, secret); err != nil {
			t.Fatalf("TLS VerifySigV4() error = %v", err)
		}

		emptyReq, emptyAuth := signedTestRequest(t, http.MethodGet, "http://example.com/bucket/key", "", "UNSIGNED-PAYLOAD", nil)
		if err := sigv4.VerifySigV4(emptyReq, emptyAuth, secret); err != nil {
			t.Fatalf("bodyless plaintext VerifySigV4() error = %v", err)
		}
	})

	t.Run("unsigned streaming payload requires TLS", func(t *testing.T) {
		headers := http.Header{
			"Content-Encoding":             {"aws-chunked"},
			"X-Amz-Decoded-Content-Length": {"4"},
			"X-Amz-Trailer":                {"x-amz-checksum-crc32"},
		}
		req, auth := signedTestRequest(t, http.MethodPut, "http://example.com/bucket/key", "body", sigv4.StreamingUnsignedPayloadTrailer, headers)
		if err := sigv4.VerifySigV4(req, auth, secret); !errors.Is(err, sigv4.ErrUnsignedPayloadRequiresTLS) {
			t.Fatalf("VerifySigV4() error = %v, want ErrUnsignedPayloadRequiresTLS", err)
		}
	})
}

func TestVerifySigV4RequiresSecurityRelevantHeaders(t *testing.T) {
	const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	tests := []struct {
		name  string
		value string
	}{
		{name: "Content-MD5", value: "CY9rzUYh03PK3k6DJie09g=="},
		{name: "Content-Type", value: "application/xml"},
		{name: "If-Match", value: `"etag"`},
		{name: "Range", value: "bytes=1-2"},
		{name: "x-amz-copy-source", value: "/source/key"},
		{name: "x-amz-meta-owner", value: "attacker"},
		{name: "x-amz-server-side-encryption", value: "AES256"},
		{name: "x-amz-tagging", value: "role=admin"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, auth := signedTestRequest(t, http.MethodGet, "https://example.com/bucket/key", "", emptyHash, nil)
			req.Header.Set(test.name, test.value)
			if err := sigv4.VerifySigV4(req, auth, "test-secret"); !errors.Is(err, sigv4.ErrRequiredHeaderNotSigned) {
				t.Fatalf("VerifySigV4() error = %v, want ErrRequiredHeaderNotSigned", err)
			}
		})
	}

	t.Run("present before signing is accepted", func(t *testing.T) {
		headers := http.Header{
			"Content-Type":     {"application/xml"},
			"X-Amz-Meta-Owner": {"authenticated-user"},
		}
		req, auth := signedTestRequest(t, http.MethodGet, "https://example.com/bucket/key", "", emptyHash, headers)
		if err := sigv4.VerifySigV4(req, auth, "test-secret"); err != nil {
			t.Fatalf("VerifySigV4() error = %v", err)
		}
	})
}

func signedTestRequest(
	t *testing.T,
	method string,
	target string,
	body string,
	payloadHash string,
	headers http.Header,
) (*http.Request, *sigv4.Auth) {
	t.Helper()

	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	req.Header.Set("x-amz-content-sha256", payloadHash)
	signingTime := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	credentials := aws.Credentials{AccessKeyID: "test-access-key", SecretAccessKey: "test-secret"}
	if err := v4.NewSigner().SignHTTP(t.Context(), credentials, req, payloadHash, "s3", "us-east-1", signingTime); err != nil {
		t.Fatalf("sign request: %v", err)
	}
	auth, err := sigv4.ParseSigV4Authorization(req)
	if err != nil {
		t.Fatalf("parse signed request: %v", err)
	}
	return req, auth
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
