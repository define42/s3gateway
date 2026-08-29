package s3xml_test

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/define42/s3gateway/internal/s3xml"
)

func taggingDocument(count int, key, value string) string {
	var body strings.Builder
	body.WriteString("<Tagging><TagSet>")
	for range count {
		body.WriteString("<Tag><Key>")
		body.WriteString(key)
		body.WriteString("</Key><Value>")
		body.WriteString(value)
		body.WriteString("</Value></Tag>")
	}
	body.WriteString("</TagSet></Tagging>")
	return body.String()
}

func TestDecodeVersioningConfigMFADeleteValues(t *testing.T) {
	allowed := types.MFADelete("").Values()
	if len(allowed) == 0 {
		t.Fatalf("expected MFADelete values to be non-empty")
	}

	for _, v := range allowed {
		t.Run("exact_"+string(v), func(t *testing.T) {
			cfg, err := s3xml.DecodeVersioningConfig(strings.NewReader(
				`<VersioningConfiguration><MfaDelete>` + string(v) + `</MfaDelete></VersioningConfiguration>`,
			))
			if err != nil {
				t.Fatalf("s3xml.DecodeVersioningConfig() error = %v", err)
			}
			if cfg.MFADelete != v {
				t.Fatalf("s3xml.DecodeVersioningConfig() MFADelete = %q, want %q", cfg.MFADelete, v)
			}
		})

		t.Run("trimmed_case_insensitive_"+string(v), func(t *testing.T) {
			cfg, err := s3xml.DecodeVersioningConfig(strings.NewReader(
				`<VersioningConfiguration><MfaDelete>  ` + strings.ToLower(string(v)) + ` </MfaDelete></VersioningConfiguration>`,
			))
			if err != nil {
				t.Fatalf("s3xml.DecodeVersioningConfig() error = %v", err)
			}
			if cfg.MFADelete != v {
				t.Fatalf("s3xml.DecodeVersioningConfig() MFADelete = %q, want %q", cfg.MFADelete, v)
			}
		})
	}

	if _, err := s3xml.DecodeVersioningConfig(strings.NewReader(
		`<VersioningConfiguration><MfaDelete>invalid</MfaDelete></VersioningConfiguration>`,
	)); err == nil {
		t.Fatalf("s3xml.DecodeVersioningConfig() expected error for invalid MfaDelete")
	}
}

func TestDecodeVersioningConfigLimits(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr error
	}{
		{
			name:    "body bytes",
			body:    "<VersioningConfiguration>" + strings.Repeat(" ", 20*1024) + "</VersioningConfiguration>",
			wantErr: s3xml.ErrXMLBodyTooLarge,
		},
		{
			name:    "duplicate status elements",
			body:    "<VersioningConfiguration><Status>Enabled</Status><Status>Suspended</Status></VersioningConfiguration>",
			wantErr: s3xml.ErrXMLElementLimit,
		},
		{
			name:    "status field bytes",
			body:    "<VersioningConfiguration><Status>" + strings.Repeat("x", 33) + "</Status></VersioningConfiguration>",
			wantErr: s3xml.ErrXMLFieldTooLong,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s3xml.DecodeVersioningConfig(strings.NewReader(tc.body))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("DecodeVersioningConfig() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDecodeTaggingOperationLimits(t *testing.T) {
	tests := []struct {
		name     string
		decode   func(io.Reader) (*types.Tagging, error)
		body     string
		wantErr  error
		anyError bool
		wantTags int
	}{
		{
			name:     "object accepts ten tags",
			decode:   s3xml.DecodeObjectTagging,
			body:     taggingDocument(10, "key", "value"),
			wantTags: 10,
		},
		{
			name:    "object rejects eleven tags",
			decode:  s3xml.DecodeObjectTagging,
			body:    taggingDocument(11, "key", "value"),
			wantErr: s3xml.ErrXMLElementLimit,
		},
		{
			name:     "bucket accepts fifty tags",
			decode:   s3xml.DecodeBucketTagging,
			body:     taggingDocument(50, "key", "value"),
			wantTags: 50,
		},
		{
			name:    "bucket rejects fifty-one tags",
			decode:  s3xml.DecodeBucketTagging,
			body:    taggingDocument(51, "key", "value"),
			wantErr: s3xml.ErrXMLElementLimit,
		},
		{
			name:     "tag key character limit",
			decode:   s3xml.DecodeObjectTagging,
			body:     taggingDocument(1, strings.Repeat("k", 129), "value"),
			anyError: true,
		},
		{
			name:     "tag value character limit",
			decode:   s3xml.DecodeObjectTagging,
			body:     taggingDocument(1, "key", strings.Repeat("v", 257)),
			anyError: true,
		},
		{
			name:    "object body bytes",
			decode:  s3xml.DecodeObjectTagging,
			body:    "<Tagging>" + strings.Repeat(" ", 70*1024) + "</Tagging>",
			wantErr: s3xml.ErrXMLBodyTooLarge,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.decode(strings.NewReader(tc.body))
			if (tc.wantErr != nil || tc.anyError) && err == nil {
				t.Fatalf("decode tagging expected an error")
			}
			if tc.wantErr == nil && !tc.anyError && err != nil {
				t.Fatalf("decode tagging error = %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("decode tagging error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && !tc.anyError && len(got.TagSet) != tc.wantTags {
				t.Fatalf("decode tagging returned %d tags, want %d", len(got.TagSet), tc.wantTags)
			}
		})
	}
}
