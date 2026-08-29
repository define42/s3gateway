package s3xml_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/define42/s3gateway/internal/s3xml"
)

func TestDecodeLimitedRejectsResourceLimitViolations(t *testing.T) {
	type document struct {
		Items []string `xml:"Item"`
	}

	tests := []struct {
		name      string
		body      string
		limits    s3xml.DecodeLimits
		wantErr   error
		wantItems int
	}{
		{
			name: "body bytes",
			body: `<Document>` + strings.Repeat("x", 64) + `</Document>`,
			limits: s3xml.DecodeLimits{
				MaxBodyBytes: 32,
			},
			wantErr: s3xml.ErrXMLBodyTooLarge,
		},
		{
			name: "total elements",
			body: `<Document><Item>a</Item><Item>b</Item></Document>`,
			limits: s3xml.DecodeLimits{
				MaxBodyBytes: 1024,
				MaxElements:  2,
			},
			wantErr:   s3xml.ErrXMLElementLimit,
			wantItems: 1,
		},
		{
			name: "named elements before slice append",
			body: `<Document><Item>a</Item><Item>b</Item><Item>c</Item></Document>`,
			limits: s3xml.DecodeLimits{
				MaxBodyBytes:  1024,
				ElementLimits: map[string]int{"Item": 2},
			},
			wantErr:   s3xml.ErrXMLElementLimit,
			wantItems: 2,
		},
		{
			name: "field bytes",
			body: `<Document><Item>12345</Item></Document>`,
			limits: s3xml.DecodeLimits{
				MaxBodyBytes:    1024,
				FieldByteLimits: map[string]int{"Item": 4},
			},
			wantErr: s3xml.ErrXMLFieldTooLong,
		},
		{
			name: "nesting depth",
			body: `<Document><Unknown><Nested/></Unknown></Document>`,
			limits: s3xml.DecodeLimits{
				MaxBodyBytes: 1024,
				MaxDepth:     2,
			},
			wantErr: s3xml.ErrXMLElementLimit,
		},
		{
			name: "attribute count",
			body: `<Document a="1" b="2"/>`,
			limits: s3xml.DecodeLimits{
				MaxBodyBytes:  1024,
				MaxAttributes: 1,
			},
			wantErr: s3xml.ErrXMLElementLimit,
		},
		{
			name: "attribute bytes",
			body: `<Document attribute="12345"/>`,
			limits: s3xml.DecodeLimits{
				MaxBodyBytes:      1024,
				MaxAttributeBytes: 4,
			},
			wantErr: s3xml.ErrXMLFieldTooLong,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got document
			err := s3xml.DecodeLimited(strings.NewReader(tc.body), &got, tc.limits)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("DecodeLimited() error = %v, want %v", err, tc.wantErr)
			}
			if len(got.Items) != tc.wantItems {
				t.Fatalf("DecodeLimited() appended %d items, want %d", len(got.Items), tc.wantItems)
			}
		})
	}
}

func TestDecodeLimitedAcceptsOneBoundedDocument(t *testing.T) {
	var got struct {
		Items []string `xml:"Item"`
	}
	err := s3xml.DecodeLimited(
		strings.NewReader("<Document><Item>a</Item><Item>b</Item></Document> \n<!-- ok -->"),
		&got,
		s3xml.DecodeLimits{
			MaxBodyBytes:    1024,
			MaxDepth:        2,
			MaxElements:     3,
			ElementLimits:   map[string]int{"Item": 2},
			FieldByteLimits: map[string]int{"Item": 1},
		},
	)
	if err != nil {
		t.Fatalf("DecodeLimited() error = %v", err)
	}
	if got.Items[0] != "a" || got.Items[1] != "b" {
		t.Fatalf("DecodeLimited() items = %q, want [a b]", got.Items)
	}
}
