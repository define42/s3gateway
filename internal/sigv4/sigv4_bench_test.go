package sigv4

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func BenchmarkAWSChunkedReaderSignedChunks(b *testing.B) {
	const (
		payloadSize = 8 << 20
		chunkSize   = 64 << 10
	)
	payload := bytes.Repeat([]byte{0xa5}, payloadSize)
	chunks := make([][]byte, 0, payloadSize/chunkSize)
	for offset := 0; offset < len(payload); offset += chunkSize {
		chunks = append(chunks, payload[offset:offset+chunkSize])
	}
	body, auth := buildSignedChunkBody(chunks)
	buf := make([]byte, 32<<10)

	b.SetBytes(payloadSize)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		reader := newAWSChunkedReader(
			strings.NewReader(body),
			NewAWSChunkSignatureVerifier(auth, chunkBufferTestSecret),
			false,
			nil,
			payloadSize,
		)
		total := 0
		for {
			n, err := reader.Read(buf)
			total += n
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				b.Fatalf("Read() error = %v", err)
			}
		}
		if total != payloadSize {
			b.Fatalf("read %d bytes, want %d", total, payloadSize)
		}
	}
}
