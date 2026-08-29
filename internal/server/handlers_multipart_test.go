package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/define42/s3gateway/internal/s3xml"
)

func completeMultipartDocument(count int, etag string) string {
	var body strings.Builder
	body.WriteString("<CompleteMultipartUpload>")
	for range count {
		body.WriteString("<Part><PartNumber>1</PartNumber><ETag>")
		body.WriteString(etag)
		body.WriteString("</ETag></Part>")
	}
	body.WriteString("</CompleteMultipartUpload>")
	return body.String()
}

func TestDecodeCompleteMultipartUploadLimits(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantErr   error
		wantParts int
	}{
		{
			name:      "accepts ten thousand parts",
			body:      completeMultipartDocument(maxCompleteMultipartParts, "etag"),
			wantParts: maxCompleteMultipartParts,
		},
		{
			name:      "rejects part ten thousand and one before append",
			body:      completeMultipartDocument(maxCompleteMultipartParts+1, "etag"),
			wantErr:   s3xml.ErrXMLElementLimit,
			wantParts: maxCompleteMultipartParts,
		},
		{
			name:    "rejects oversized etag",
			body:    completeMultipartDocument(1, strings.Repeat("e", maxCompleteMultipartETagBytes+1)),
			wantErr: s3xml.ErrXMLFieldTooLong,
		},
		{
			name:    "rejects oversized body",
			body:    "<CompleteMultipartUpload>" + strings.Repeat(" ", int(maxCompleteMultipartBodyBytes)) + "</CompleteMultipartUpload>",
			wantErr: s3xml.ErrXMLBodyTooLarge,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeCompleteMultipartUpload(strings.NewReader(tc.body))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("decodeCompleteMultipartUpload() error = %v, want %v", err, tc.wantErr)
			}
			if len(got.Parts) != tc.wantParts {
				t.Fatalf("decodeCompleteMultipartUpload() appended %d parts, want %d", len(got.Parts), tc.wantParts)
			}
		})
	}
}
