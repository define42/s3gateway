package sigv4_test

import (
	"crypto/sha1" // #nosec G505 -- exercising the S3 trailing-checksum algorithms
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sigv4 "github.com/define42/s3gateway/internal/sigv4"
)

const testSecret = "test-secret"

func newTestAuth() *sigv4.Auth {
	return &sigv4.Auth{
		AccessKey:     "test-access-key",
		Date:          "20260207",
		Region:        "us-east-1",
		Service:       "s3",
		SignedHeaders: []string{"host", "x-amz-date"},
		SignatureHex:  strings.Repeat("0", 64),
		AmzDate:       "20260207T010203Z",
	}
}

func testScope(auth *sigv4.Auth) string {
	return fmt.Sprintf("%s/%s/%s/aws4_request", auth.Date, auth.Region, auth.Service)
}

func signTestChunk(auth *sigv4.Auth, prevSig string, chunk []byte) string {
	signingKey := sigv4.DeriveSigningKey(testSecret, auth.Date, auth.Region, auth.Service)
	emptyHash := sha256.Sum256(nil)
	chunkHash := sha256.Sum256(chunk)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256-PAYLOAD",
		auth.AmzDate,
		testScope(auth),
		prevSig,
		hex.EncodeToString(emptyHash[:]),
		hex.EncodeToString(chunkHash[:]),
	}, "\n")
	return sigv4.HmacSHA256Hex(signingKey, []byte(stringToSign))
}

// signTestTrailer mirrors the AWS trailer signature: it chains from the final
// chunk signature and covers the canonical "name:value\n" trailer block.
func signTestTrailer(auth *sigv4.Auth, prevSig, trailerBlock string) string {
	signingKey := sigv4.DeriveSigningKey(testSecret, auth.Date, auth.Region, auth.Service)
	blockHash := sha256.Sum256([]byte(trailerBlock))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256-TRAILER",
		auth.AmzDate,
		testScope(auth),
		prevSig,
		hex.EncodeToString(blockHash[:]),
	}, "\n")
	return sigv4.HmacSHA256Hex(signingKey, []byte(stringToSign))
}

func newStreamingRequest(mode, body string, decodedLen int, trailerNames ...string) *http.Request {
	req := httptest.NewRequest(http.MethodPut, "/team2-bucket/object.txt", strings.NewReader(body))
	req.Header.Set("x-amz-content-sha256", mode)
	req.Header.Set("x-amz-decoded-content-length", fmt.Sprintf("%d", decodedLen))
	for _, name := range trailerNames {
		req.Header.Add("x-amz-trailer", name)
	}
	return req
}

func decodeAll(t *testing.T, req *http.Request, verifier *sigv4.AWSChunkSignatureVerifier) (string, error) {
	t.Helper()
	body, _, err := sigv4.DecodeBodyForS3Write(req, verifier)
	if err != nil {
		t.Fatalf("DecodeBodyForS3Write returned setup error: %v", err)
	}
	defer body.Close()
	got, err := io.ReadAll(body)
	return string(got), err
}

func TestDecodeUnsignedPayloadTrailerMultiChunk(t *testing.T) {
	// botocore-style framing: fixed-size chunks, CRLF-terminated trailer line.
	payload := "hello world"
	sum := crc32.ChecksumIEEE([]byte(payload))
	checksum := base64.StdEncoding.EncodeToString([]byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)})
	if checksum != "DUoRhQ==" { // known-answer check guards the encoding above
		t.Fatalf("crc32 known-answer mismatch: got=%q want=%q", checksum, "DUoRhQ==")
	}

	body := "5\r\nhello\r\n" +
		"6\r\n world\r\n" +
		"0\r\n" +
		"x-amz-checksum-crc32:" + checksum + "\r\n" +
		"\r\n"

	req := newStreamingRequest(sigv4.StreamingUnsignedPayloadTrailer, body, len(payload), "x-amz-checksum-crc32")
	got, err := decodeAll(t, req, nil)
	if err != nil {
		t.Fatalf("read decoded body: %v", err)
	}
	if got != payload {
		t.Fatalf("decoded body mismatch: got=%q want=%q", got, payload)
	}
}

func TestDecodeUnsignedPayloadTrailerSingleChunkGoSDKFormat(t *testing.T) {
	// The AWS SDK for Go sends the whole payload as a single unsigned chunk:
	//   <hex-len>\r\n<data>\r\n0\r\nname:value\r\n\r\n
	payload := strings.Repeat("large unsigned chunk ", 4096) // ~86 KiB single chunk
	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	_, _ = h.Write([]byte(payload))
	checksum := base64.StdEncoding.EncodeToString(h.Sum(nil))

	body := fmt.Sprintf("%x\r\n%s\r\n0\r\nx-amz-checksum-crc32c:%s\r\n\r\n", len(payload), payload, checksum)

	req := newStreamingRequest(sigv4.StreamingUnsignedPayloadTrailer, body, len(payload), "x-amz-checksum-crc32c")
	got, err := decodeAll(t, req, nil)
	if err != nil {
		t.Fatalf("read decoded body: %v", err)
	}
	if got != payload {
		t.Fatalf("decoded body mismatch: got len=%d want len=%d", len(got), len(payload))
	}
}

func TestDecodeUnsignedPayloadTrailerChecksumAlgorithms(t *testing.T) {
	payload := "checksum algorithm coverage"
	cases := []struct {
		name string
		hash func() hash.Hash
	}{
		{"x-amz-checksum-crc32", func() hash.Hash { return crc32.NewIEEE() }},
		{"x-amz-checksum-crc32c", func() hash.Hash { return crc32.New(crc32.MakeTable(crc32.Castagnoli)) }},
		{"x-amz-checksum-crc64nvme", func() hash.Hash { return crc64.New(crc64.MakeTable(0x9a6c9329ac4bc9b5)) }},
		{"x-amz-checksum-sha1", sha1.New},
		{"x-amz-checksum-sha256", sha256.New},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.hash()
			_, _ = h.Write([]byte(payload))
			checksum := base64.StdEncoding.EncodeToString(h.Sum(nil))
			body := fmt.Sprintf("%x\r\n%s\r\n0\r\n%s:%s\r\n\r\n", len(payload), payload, tc.name, checksum)

			req := newStreamingRequest(sigv4.StreamingUnsignedPayloadTrailer, body, len(payload), tc.name)
			got, err := decodeAll(t, req, nil)
			if err != nil {
				t.Fatalf("read decoded body: %v", err)
			}
			if got != payload {
				t.Fatalf("decoded body mismatch: got=%q", got)
			}

			// Corrupt the trailing checksum: decode must fail with BadDigest semantics.
			badBody := fmt.Sprintf("%x\r\n%s\r\n0\r\n%s:%s\r\n\r\n", len(payload), payload, tc.name, "AAAA"+checksum[4:])
			badReq := newStreamingRequest(sigv4.StreamingUnsignedPayloadTrailer, badBody, len(payload), tc.name)
			if _, err := decodeAll(t, badReq, nil); !sigv4.IsTrailerChecksumMismatchError(err) {
				t.Fatalf("expected trailer checksum mismatch error, got: %v", err)
			}
		})
	}
}

func TestDecodeUnsignedPayloadTrailerWithoutTrailers(t *testing.T) {
	payload := "no trailers"
	body := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(payload), payload)

	req := newStreamingRequest(sigv4.StreamingUnsignedPayloadTrailer, body, len(payload))
	got, err := decodeAll(t, req, nil)
	if err != nil {
		t.Fatalf("read decoded body: %v", err)
	}
	if got != payload {
		t.Fatalf("decoded body mismatch: got=%q want=%q", got, payload)
	}
}

func TestDecodeUnsignedPayloadTrailerEmptyPayload(t *testing.T) {
	checksum := base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 0})
	body := "0\r\nx-amz-checksum-crc32:" + checksum + "\r\n\r\n"

	req := newStreamingRequest(sigv4.StreamingUnsignedPayloadTrailer, body, 0, "x-amz-checksum-crc32")
	got, err := decodeAll(t, req, nil)
	if err != nil {
		t.Fatalf("read decoded body: %v", err)
	}
	if got != "" {
		t.Fatalf("decoded body mismatch: got=%q want empty", got)
	}
}

func TestDecodeSignedPayloadTrailerMinioGoFormat(t *testing.T) {
	// minio-go writes trailing headers with bare-LF endings, then a CRLF
	// separator before the x-amz-trailer-signature line:
	//   0;chunk-signature=<sig>\r\n
	//   x-amz-checksum-crc32c:<value>\n
	//   \r\n
	//   x-amz-trailer-signature:<sig>\r\n\r\n
	auth := newTestAuth()
	payload := "signed trailer payload"
	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	_, _ = h.Write([]byte(payload))
	checksum := base64.StdEncoding.EncodeToString(h.Sum(nil))

	chunkSig := signTestChunk(auth, strings.ToLower(auth.SignatureHex), []byte(payload))
	finalSig := signTestChunk(auth, chunkSig, nil)
	trailerBlock := "x-amz-checksum-crc32c:" + checksum + "\n"
	trailerSig := signTestTrailer(auth, finalSig, trailerBlock)

	body := fmt.Sprintf("%x;chunk-signature=%s\r\n%s\r\n", len(payload), chunkSig, payload) +
		"0;chunk-signature=" + finalSig + "\r\n" +
		trailerBlock +
		"\r\n" +
		"x-amz-trailer-signature:" + trailerSig + "\r\n\r\n"

	req := newStreamingRequest(sigv4.StreamingSignedPayloadTrailer, body, len(payload), "x-amz-checksum-crc32c")
	got, err := decodeAll(t, req, sigv4.NewAWSChunkSignatureVerifier(auth, testSecret))
	if err != nil {
		t.Fatalf("read decoded body: %v", err)
	}
	if got != payload {
		t.Fatalf("decoded body mismatch: got=%q want=%q", got, payload)
	}
}

func TestDecodeSignedPayloadTrailerCRLFFormat(t *testing.T) {
	// CRLF-terminated trailer lines directly after the final chunk, as in the
	// AWS documentation example.
	auth := newTestAuth()
	payload := "crlf trailer payload"
	sum := sha256.Sum256([]byte(payload))
	checksum := base64.StdEncoding.EncodeToString(sum[:])

	chunkSig := signTestChunk(auth, strings.ToLower(auth.SignatureHex), []byte(payload))
	finalSig := signTestChunk(auth, chunkSig, nil)
	trailerBlock := "x-amz-checksum-sha256:" + checksum + "\n"
	trailerSig := signTestTrailer(auth, finalSig, trailerBlock)

	body := fmt.Sprintf("%x;chunk-signature=%s\r\n%s\r\n", len(payload), chunkSig, payload) +
		"0;chunk-signature=" + finalSig + "\r\n" +
		"x-amz-checksum-sha256:" + checksum + "\r\n" +
		"x-amz-trailer-signature:" + trailerSig + "\r\n" +
		"\r\n"

	req := newStreamingRequest(sigv4.StreamingSignedPayloadTrailer, body, len(payload), "x-amz-checksum-sha256")
	got, err := decodeAll(t, req, sigv4.NewAWSChunkSignatureVerifier(auth, testSecret))
	if err != nil {
		t.Fatalf("read decoded body: %v", err)
	}
	if got != payload {
		t.Fatalf("decoded body mismatch: got=%q want=%q", got, payload)
	}
}

func TestDecodeSignedPayloadTrailerTamperedSignature(t *testing.T) {
	auth := newTestAuth()
	payload := "tampered trailer signature"

	chunkSig := signTestChunk(auth, strings.ToLower(auth.SignatureHex), []byte(payload))
	finalSig := signTestChunk(auth, chunkSig, nil)
	badTrailerSig := strings.Repeat("ab", 32)

	body := fmt.Sprintf("%x;chunk-signature=%s\r\n%s\r\n", len(payload), chunkSig, payload) +
		"0;chunk-signature=" + finalSig + "\r\n" +
		"x-amz-trailer-signature:" + badTrailerSig + "\r\n\r\n"

	req := newStreamingRequest(sigv4.StreamingSignedPayloadTrailer, body, len(payload))
	_, err := decodeAll(t, req, sigv4.NewAWSChunkSignatureVerifier(auth, testSecret))
	if !errors.Is(err, sigv4.ErrInvalidChunkSignature) {
		t.Fatalf("expected invalid trailer signature error, got: %v", err)
	}
	if !sigv4.IsChunkSignatureValidationError(err) {
		t.Fatalf("expected error to be classified as signature validation error: %v", err)
	}
}

func TestDecodeSignedPayloadTrailerMissingSignature(t *testing.T) {
	auth := newTestAuth()
	payload := "missing trailer signature"

	chunkSig := signTestChunk(auth, strings.ToLower(auth.SignatureHex), []byte(payload))
	finalSig := signTestChunk(auth, chunkSig, nil)

	body := fmt.Sprintf("%x;chunk-signature=%s\r\n%s\r\n", len(payload), chunkSig, payload) +
		"0;chunk-signature=" + finalSig + "\r\n" +
		"x-amz-checksum-crc32:AAAAAA==\r\n" +
		"\r\n"

	req := newStreamingRequest(sigv4.StreamingSignedPayloadTrailer, body, len(payload))
	_, err := decodeAll(t, req, sigv4.NewAWSChunkSignatureVerifier(auth, testSecret))
	if !errors.Is(err, sigv4.ErrMissingTrailerSignature) {
		t.Fatalf("expected missing trailer signature error, got: %v", err)
	}
}

func TestDecodeSignedPayloadTrailerChecksumMismatchWithValidSignature(t *testing.T) {
	// The trailer signature covers the (wrong) declared checksum, so signature
	// verification passes and the payload/checksum comparison must catch it.
	auth := newTestAuth()
	payload := "checksum vs signature"
	wrongChecksum := base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4})

	chunkSig := signTestChunk(auth, strings.ToLower(auth.SignatureHex), []byte(payload))
	finalSig := signTestChunk(auth, chunkSig, nil)
	trailerBlock := "x-amz-checksum-crc32:" + wrongChecksum + "\n"
	trailerSig := signTestTrailer(auth, finalSig, trailerBlock)

	body := fmt.Sprintf("%x;chunk-signature=%s\r\n%s\r\n", len(payload), chunkSig, payload) +
		"0;chunk-signature=" + finalSig + "\r\n" +
		trailerBlock +
		"\r\n" +
		"x-amz-trailer-signature:" + trailerSig + "\r\n\r\n"

	req := newStreamingRequest(sigv4.StreamingSignedPayloadTrailer, body, len(payload), "x-amz-checksum-crc32")
	_, err := decodeAll(t, req, sigv4.NewAWSChunkSignatureVerifier(auth, testSecret))
	if !sigv4.IsTrailerChecksumMismatchError(err) {
		t.Fatalf("expected trailer checksum mismatch error, got: %v", err)
	}
}

func TestDecodeSignedPayloadWithoutTrailerStillWorks(t *testing.T) {
	auth := newTestAuth()
	payload := "plain signed streaming"

	chunkSig := signTestChunk(auth, strings.ToLower(auth.SignatureHex), []byte(payload))
	finalSig := signTestChunk(auth, chunkSig, nil)
	body := fmt.Sprintf("%x;chunk-signature=%s\r\n%s\r\n", len(payload), chunkSig, payload) +
		"0;chunk-signature=" + finalSig + "\r\n\r\n"

	req := newStreamingRequest(sigv4.StreamingSignedPayload, body, len(payload))
	got, err := decodeAll(t, req, sigv4.NewAWSChunkSignatureVerifier(auth, testSecret))
	if err != nil {
		t.Fatalf("read decoded body: %v", err)
	}
	if got != payload {
		t.Fatalf("decoded body mismatch: got=%q want=%q", got, payload)
	}
}

func TestChunkSignatureVerifierFromRequestModes(t *testing.T) {
	t.Run("unsigned trailer needs no sigv4 context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
		req.Header.Set("x-amz-content-sha256", sigv4.StreamingUnsignedPayloadTrailer)
		verifier, err := sigv4.ChunkSignatureVerifierFromRequest(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if verifier != nil {
			t.Fatalf("expected nil verifier for unsigned trailer mode, got %+v", verifier)
		}
	})

	t.Run("signed trailer requires sigv4 context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
		req.Header.Set("x-amz-content-sha256", sigv4.StreamingSignedPayloadTrailer)
		if _, err := sigv4.ChunkSignatureVerifierFromRequest(req); !errors.Is(err, sigv4.ErrMissingSigV4AuthContext) {
			t.Fatalf("expected missing auth context error, got: %v", err)
		}
	})

	t.Run("unknown streaming mode rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
		req.Header.Set("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD")
		if _, err := sigv4.ChunkSignatureVerifierFromRequest(req); !errors.Is(err, sigv4.ErrUnsupportedStreamingMode) {
			t.Fatalf("expected unsupported streaming mode error, got: %v", err)
		}
		req.Header.Set("x-amz-decoded-content-length", "1")
		if _, _, err := sigv4.DecodeBodyForS3Write(req, nil); !errors.Is(err, sigv4.ErrUnsupportedStreamingMode) {
			t.Fatalf("expected unsupported streaming mode error from decode, got: %v", err)
		}
	})
}

func TestDecodeChunkHeaderLineTooLong(t *testing.T) {
	body := strings.Repeat("f", 5*1024) + "\r\npayload\r\n0\r\n\r\n"
	req := newStreamingRequest(sigv4.StreamingUnsignedPayloadTrailer, body, 7)
	_, err := decodeAll(t, req, nil)
	if !errors.Is(err, sigv4.ErrInvalidChunkHeader) {
		t.Fatalf("expected invalid chunk header error for oversized header line, got: %v", err)
	}
}

func TestDecodeUnsignedPayloadTrailerTruncatedChunk(t *testing.T) {
	body := "b\r\nhello" // claims 11 bytes, delivers 5, then EOF
	req := newStreamingRequest(sigv4.StreamingUnsignedPayloadTrailer, body, 11)
	_, err := decodeAll(t, req, nil)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected unexpected EOF for truncated chunk, got: %v", err)
	}
}
