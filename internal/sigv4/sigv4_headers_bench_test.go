package sigv4

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const benchmarkSigningSecret = "benchmark-signing-secret"

func BenchmarkVerifySigV4Headers(b *testing.B) {
	for _, headerCount := range []int{6, 25, 100} {
		b.Run(fmt.Sprintf("headers=%d", headerCount), func(b *testing.B) {
			req, auth := benchmarkSignedRequest(b, headerCount)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := VerifySigV4(req, auth, benchmarkSigningSecret); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchmarkSignedRequest(b *testing.B, headerCount int) (*http.Request, *Auth) {
	b.Helper()
	// Sign and parse outside the timed loop. The empty signed payload avoids
	// accumulating body-reader wrappers as the verifier reuses this request.
	digest := sha256.Sum256(nil)
	payloadHash := hex.EncodeToString(digest[:])
	req := httptest.NewRequest(http.MethodPut, "https://gateway.example/team2-incoming/reports/September.csv?x-id=PutObject", nil)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Cache-Control", "max-age=60")
	req.Header.Set("User-Agent", "aws-sdk-go-v2/benchmark")
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	// Signing adds x-amz-date and Authorization, yielding six base headers.
	for i := 6; i < headerCount; i++ {
		req.Header.Set(fmt.Sprintf("X-Amz-Meta-K%03d", i), "case-0123 item-0042")
	}
	signingTime := time.Date(2026, time.September, 6, 10, 0, 0, 0, time.UTC)
	credentials := aws.Credentials{AccessKeyID: "benchmark-access", SecretAccessKey: benchmarkSigningSecret}
	err := v4.NewSigner().SignHTTP(b.Context(), credentials, req, payloadHash, "s3", "us-east-1", signingTime, func(o *v4.SignerOptions) {
		o.DisableURIPathEscaping = true
	})
	if err != nil {
		b.Fatal(err)
	}
	if len(req.Header) != headerCount {
		b.Fatalf("fixture has %d headers, want %d", len(req.Header), headerCount)
	}
	auth, err := ParseSigV4Authorization(req)
	if err != nil {
		b.Fatal(err)
	}
	if err := VerifySigV4(req, auth, benchmarkSigningSecret); err != nil {
		b.Fatalf("invalid signed fixture: %v", err)
	}
	return req, auth
}

var normalizedHeaderSink string

func BenchmarkCompressSpaces(b *testing.B) {
	for _, tt := range []struct{ name, value string }{
		{name: "empty"},
		{name: "clean-short", value: "application/octet-stream"},
		{name: "clean-spaces", value: "case-0123 item-0042"},
		{name: "clean-long", value: strings.Repeat("a", 512)},
		{name: "repeated-spaces", value: "case-0123   item-0042"},
		{name: "tabs-and-spaces", value: "case-0123\t \titem-0042"},
		{name: "Unicode", value: "café 中 🙂"},
		{name: "invalid-UTF8", value: "case\xff item\xfe"},
	} {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				normalizedHeaderSink = compressSpaces(tt.value)
			}
		})
	}
}
