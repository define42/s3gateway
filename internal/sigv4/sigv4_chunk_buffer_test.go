package sigv4

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

const chunkBufferTestSecret = "chunk-buffer-test-secret"

func TestAWSChunkedReaderReusesSignedChunkBuffer(t *testing.T) {
	chunks := [][]byte{
		bytes.Repeat([]byte{'a'}, 64),
		bytes.Repeat([]byte{'b'}, 32),
		bytes.Repeat([]byte{'c'}, 128),
		bytes.Repeat([]byte{'d'}, 64),
	}
	body, auth := buildSignedChunkBody(chunks)
	reader := newAWSChunkedReader(
		strings.NewReader(body),
		NewAWSChunkSignatureVerifier(auth, chunkBufferTestSecret),
		false,
		nil,
		int64(totalChunkBytes(chunks)),
	)

	var firstBacking, grownBacking *byte
	for i, want := range chunks {
		got := make([]byte, len(want))
		if _, err := io.ReadFull(reader, got); err != nil {
			t.Fatalf("chunk %d: ReadFull() error = %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("chunk %d: decoded bytes differ", i)
		}
		if cap(reader.buf) < len(want) {
			t.Fatalf("chunk %d: buffer capacity = %d, want at least %d", i, cap(reader.buf), len(want))
		}

		backing := &reader.buf[:1][0]
		switch i {
		case 0:
			firstBacking = backing
		case 1:
			if backing != firstBacking {
				t.Fatal("smaller second chunk did not reuse the first backing array")
			}
		case 2:
			if backing == firstBacking {
				t.Fatal("larger third chunk did not grow the backing array")
			}
			grownBacking = backing
		case 3:
			if backing != grownBacking {
				t.Fatal("smaller fourth chunk did not reuse the grown backing array")
			}
		}
	}

	if n, err := reader.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("final Read() = (%d, %v), want (0, EOF)", n, err)
	}
	if reader.buf != nil || cap(reader.buf) != 0 {
		t.Fatalf("completed reader retained chunk buffer with capacity %d", cap(reader.buf))
	}
}

func TestAWSChunkedReaderReleasesSignedChunkBufferOnError(t *testing.T) {
	chunks := [][]byte{bytes.Repeat([]byte{'x'}, 128)}
	body, auth := buildSignedChunkBody(chunks)
	marker := strings.LastIndex(body, "chunk-signature=")
	if marker < 0 {
		t.Fatal("test body has no final chunk signature")
	}
	corrupt := []byte(body)
	sigStart := marker + len("chunk-signature=")
	if corrupt[sigStart] == '0' {
		corrupt[sigStart] = '1'
	} else {
		corrupt[sigStart] = '0'
	}

	reader := newAWSChunkedReader(
		bytes.NewReader(corrupt),
		NewAWSChunkSignatureVerifier(auth, chunkBufferTestSecret),
		false,
		nil,
		int64(totalChunkBytes(chunks)),
	)
	if _, err := io.ReadAll(reader); !errors.Is(err, ErrInvalidChunkSignature) {
		t.Fatalf("ReadAll() error = %v, want ErrInvalidChunkSignature", err)
	}
	if reader.buf != nil || cap(reader.buf) != 0 {
		t.Fatalf("failed reader retained chunk buffer with capacity %d", cap(reader.buf))
	}
}

func TestAWSChunkedReadCloserReleasesSignedChunkBufferOnClose(t *testing.T) {
	chunks := [][]byte{bytes.Repeat([]byte{'z'}, 128)}
	body, auth := buildSignedChunkBody(chunks)
	underlying := io.NopCloser(strings.NewReader(body))
	reader := newAWSChunkedReader(
		underlying,
		NewAWSChunkSignatureVerifier(auth, chunkBufferTestSecret),
		false,
		nil,
		int64(totalChunkBytes(chunks)),
	)
	bodyReader := &awsChunkedReadCloser{
		reader: reader,
		guard:  trailerGuardReader{r: reader},
		c:      underlying,
	}

	if n, err := bodyReader.Read(make([]byte, 8)); n == 0 || err != nil {
		t.Fatalf("Read() = (%d, %v), want buffered payload data", n, err)
	}
	if cap(reader.buf) == 0 {
		t.Fatal("Read() did not allocate the signed chunk buffer")
	}
	if err := bodyReader.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if reader.buf != nil || cap(reader.buf) != 0 {
		t.Fatalf("closed reader retained chunk buffer with capacity %d", cap(reader.buf))
	}
}

func buildSignedChunkBody(chunks [][]byte) (string, *Auth) {
	auth := &Auth{
		Date:         "20260830",
		Region:       "us-east-1",
		Service:      "s3",
		SignatureHex: strings.Repeat("0", 64),
		AmzDate:      "20260830T010203Z",
	}
	verifier := NewAWSChunkSignatureVerifier(auth, chunkBufferTestSecret)

	var body strings.Builder
	for _, chunk := range chunks {
		sig := signChunkForBufferTest(verifier, chunk)
		_, _ = fmt.Fprintf(&body, "%x;chunk-signature=%s\r\n", len(chunk), sig)
		_, _ = body.Write(chunk)
		_, _ = body.WriteString("\r\n")
		verifier.PrevSig = sig
	}
	finalSig := signChunkForBufferTest(verifier, nil)
	_, _ = fmt.Fprintf(&body, "0;chunk-signature=%s\r\n\r\n", finalSig)
	return body.String(), auth
}

func signChunkForBufferTest(verifier *AWSChunkSignatureVerifier, chunk []byte) string {
	emptyHash := sha256.Sum256(nil)
	chunkHash := sha256.Sum256(chunk)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256-PAYLOAD",
		verifier.amzDate,
		verifier.scope,
		verifier.PrevSig,
		hex.EncodeToString(emptyHash[:]),
		hex.EncodeToString(chunkHash[:]),
	}, "\n")
	return HmacSHA256Hex(verifier.signingKey, []byte(stringToSign))
}

func totalChunkBytes(chunks [][]byte) int {
	total := 0
	for _, chunk := range chunks {
		total += len(chunk)
	}
	return total
}
