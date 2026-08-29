package s3xml_test

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/define42/s3gateway/internal/s3xml"
)

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
