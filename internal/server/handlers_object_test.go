package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/define42/s3gateway/internal/s3xml"
)

func deleteObjectsDocument(count int, key string) string {
	var body strings.Builder
	body.WriteString("<Delete>")
	for range count {
		body.WriteString("<Object><Key>")
		body.WriteString(key)
		body.WriteString("</Key></Object>")
	}
	body.WriteString("</Delete>")
	return body.String()
}

func TestDecodeDeleteObjectsRequestLimits(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantErr     error
		wantObjects int
	}{
		{
			name:        "accepts one thousand objects",
			body:        deleteObjectsDocument(maxDeleteObjects, "key"),
			wantObjects: maxDeleteObjects,
		},
		{
			name:        "rejects object one thousand and one before append",
			body:        deleteObjectsDocument(maxDeleteObjects+1, "key"),
			wantErr:     s3xml.ErrXMLElementLimit,
			wantObjects: maxDeleteObjects,
		},
		{
			name:    "rejects oversized key",
			body:    deleteObjectsDocument(1, strings.Repeat("k", maxDeleteObjectKeyBytes+1)),
			wantErr: s3xml.ErrXMLFieldTooLong,
		},
		{
			name:    "rejects oversized body",
			body:    "<Delete>" + strings.Repeat(" ", int(maxDeleteObjectsBodyBytes)) + "</Delete>",
			wantErr: s3xml.ErrXMLBodyTooLarge,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeDeleteObjectsRequest(strings.NewReader(tc.body))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("decodeDeleteObjectsRequest() error = %v, want %v", err, tc.wantErr)
			}
			if len(got.Objects) != tc.wantObjects {
				t.Fatalf("decodeDeleteObjectsRequest() appended %d objects, want %d", len(got.Objects), tc.wantObjects)
			}
		})
	}
}
