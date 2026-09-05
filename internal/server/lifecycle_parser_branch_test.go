package server

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/define42/s3gateway/internal/s3xml"
)

func TestDecodeLifecycleFilterCoverage(t *testing.T) {
	t.Run("nil filter", func(t *testing.T) {
		got, err := decodeLifecycleFilter(nil)
		if err != nil {
			t.Fatalf("decodeLifecycleFilter(nil) error = %v", err)
		}
		if got != nil {
			t.Fatalf("decodeLifecycleFilter(nil) = %+v, want nil", got)
		}
	})

	t.Run("tag filter", func(t *testing.T) {
		got, err := decodeLifecycleFilter(&lifecycleFilterXML{Tag: &lifecycleTagXML{Key: " k ", Value: " v "}})
		if err != nil {
			t.Fatalf("decodeLifecycleFilter(tag) error = %v", err)
		}
		if got == nil || got.Tag == nil || aws.ToString(got.Tag.Key) != " k " || aws.ToString(got.Tag.Value) != " v " {
			t.Fatalf("decodeLifecycleFilter(tag) unexpected output: %+v", got)
		}
	})

	t.Run("invalid tag", func(t *testing.T) {
		_, err := decodeLifecycleFilter(&lifecycleFilterXML{Tag: &lifecycleTagXML{Key: "", Value: "v"}})
		if err == nil {
			t.Fatalf("expected error for missing tag key")
		}
	})

	t.Run("invalid and filter", func(t *testing.T) {
		gt := int64(10)
		lt := int64(5)
		_, err := decodeLifecycleFilter(&lifecycleFilterXML{And: &lifecycleAndXML{ObjectSizeGreaterThan: &gt, ObjectSizeLessThan: &lt}})
		if err == nil {
			t.Fatalf("expected error for invalid And filter")
		}
	})

	t.Run("negative object size greater than", func(t *testing.T) {
		neg := int64(-1)
		_, err := decodeLifecycleFilter(&lifecycleFilterXML{ObjectSizeGreaterThan: &neg})
		if err == nil {
			t.Fatalf("expected error for negative object size greater-than")
		}
	})

	t.Run("negative object size less than", func(t *testing.T) {
		neg := int64(-1)
		_, err := decodeLifecycleFilter(&lifecycleFilterXML{ObjectSizeLessThan: &neg})
		if err == nil {
			t.Fatalf("expected error for negative object size less-than")
		}
	})

	t.Run("multiple top-level predicates", func(t *testing.T) {
		prefix := "p"
		lt := int64(10)
		_, err := decodeLifecycleFilter(&lifecycleFilterXML{Prefix: &prefix, ObjectSizeLessThan: &lt})
		if err == nil {
			t.Fatalf("expected error for multiple top-level predicates")
		}
	})

	t.Run("single object size greater than", func(t *testing.T) {
		gt := int64(10)
		got, err := decodeLifecycleFilter(&lifecycleFilterXML{ObjectSizeGreaterThan: &gt})
		if err != nil {
			t.Fatalf("decodeLifecycleFilter(object size greater) error = %v", err)
		}
		if got == nil || got.ObjectSizeGreaterThan == nil || aws.ToInt64(got.ObjectSizeGreaterThan) != 10 {
			t.Fatalf("decodeLifecycleFilter(object size greater) unexpected output: %+v", got)
		}
	})

	t.Run("single object size less than", func(t *testing.T) {
		lt := int64(20)
		got, err := decodeLifecycleFilter(&lifecycleFilterXML{ObjectSizeLessThan: &lt})
		if err != nil {
			t.Fatalf("decodeLifecycleFilter(object size less) error = %v", err)
		}
		if got == nil || got.ObjectSizeLessThan == nil || aws.ToInt64(got.ObjectSizeLessThan) != 20 {
			t.Fatalf("decodeLifecycleFilter(object size less) unexpected output: %+v", got)
		}
	})
}

func TestDecodeLifecycleTransitionCoverage(t *testing.T) {
	vals := types.TransitionStorageClass("").Values()
	if len(vals) == 0 {
		t.Fatalf("expected transition storage classes")
	}
	validSC := string(vals[0])

	t.Run("negative days", func(t *testing.T) {
		d := int32(-1)
		_, err := decodeLifecycleTransition(lifecycleTransitionXML{Days: &d, StorageClass: &validSC})
		if err == nil {
			t.Fatalf("expected error for negative transition days")
		}
	})

	t.Run("invalid date", func(t *testing.T) {
		badDate := "not-a-date"
		_, err := decodeLifecycleTransition(lifecycleTransitionXML{Date: &badDate, StorageClass: &validSC})
		if err == nil {
			t.Fatalf("expected error for invalid transition date")
		}
	})

	t.Run("both date and days", func(t *testing.T) {
		d := int32(7)
		date := "2026-02-07"
		_, err := decodeLifecycleTransition(lifecycleTransitionXML{Days: &d, Date: &date, StorageClass: &validSC})
		if err == nil {
			t.Fatalf("expected error when both date and days are set")
		}
	})

	t.Run("missing date and days", func(t *testing.T) {
		_, err := decodeLifecycleTransition(lifecycleTransitionXML{StorageClass: &validSC})
		if err == nil {
			t.Fatalf("expected error when date and days are missing")
		}
	})

	t.Run("missing storage class", func(t *testing.T) {
		d := int32(7)
		_, err := decodeLifecycleTransition(lifecycleTransitionXML{Days: &d})
		if err == nil {
			t.Fatalf("expected error for missing storage class")
		}
	})

	t.Run("invalid storage class", func(t *testing.T) {
		d := int32(7)
		badSC := "INVALID"
		_, err := decodeLifecycleTransition(lifecycleTransitionXML{Days: &d, StorageClass: &badSC})
		if err == nil {
			t.Fatalf("expected error for invalid storage class")
		}
	})

	t.Run("valid days", func(t *testing.T) {
		d := int32(7)
		got, err := decodeLifecycleTransition(lifecycleTransitionXML{Days: &d, StorageClass: &validSC})
		if err != nil {
			t.Fatalf("decodeLifecycleTransition(days) error = %v", err)
		}
		if got.Days == nil || aws.ToInt32(got.Days) != 7 {
			t.Fatalf("decodeLifecycleTransition(days) unexpected output: %+v", got)
		}
	})

	t.Run("valid date", func(t *testing.T) {
		date := "2026-02-07T01:02:03Z"
		got, err := decodeLifecycleTransition(lifecycleTransitionXML{Date: &date, StorageClass: &validSC})
		if err != nil {
			t.Fatalf("decodeLifecycleTransition(date) error = %v", err)
		}
		if got.Date == nil {
			t.Fatalf("decodeLifecycleTransition(date) expected date in output")
		}
	})
}

func TestLifecycleRuleLegacyPrefixReflectionPath(t *testing.T) {
	var r types.LifecycleRule
	field := reflect.ValueOf(&r).Elem().FieldByName("Prefix")
	if !field.IsValid() || field.Kind() != reflect.Pointer || !field.CanSet() {
		t.Skip("types.LifecycleRule Prefix field not available in this SDK version")
	}
	prefix := "  legacy-prefix  "
	field.Set(reflect.ValueOf(&prefix))

	got := lifecycleRuleLegacyPrefix(r)
	if got == nil {
		t.Fatalf("lifecycleRuleLegacyPrefix() returned nil")
	}
	if *got != prefix {
		t.Fatalf("lifecycleRuleLegacyPrefix() = %q, want %q", *got, prefix)
	}
}

func TestDecodeLifecycleConfigXMLBranches(t *testing.T) {
	t.Run("empty rules", func(t *testing.T) {
		_, err := decodeLifecycleConfigXML(strings.NewReader(`<LifecycleConfiguration></LifecycleConfiguration>`))
		if err == nil {
			t.Fatal("expected error for missing lifecycle rules")
		}
	})

	t.Run("disabled status", func(t *testing.T) {
		cfg, err := decodeLifecycleConfigXML(strings.NewReader(`<LifecycleConfiguration><Rule><Status>Disabled</Status><Filter><Prefix>x</Prefix></Filter><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`))
		if err != nil {
			t.Fatalf("decodeLifecycleConfigXML(disabled) error = %v", err)
		}
		if cfg.Rules[0].Status != types.ExpirationStatusDisabled {
			t.Fatalf("expected Disabled status, got %q", cfg.Rules[0].Status)
		}
	})

	t.Run("invalid status", func(t *testing.T) {
		_, err := decodeLifecycleConfigXML(strings.NewReader(`<LifecycleConfiguration><Rule><Status>Invalid</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`))
		if err == nil {
			t.Fatal("expected error for invalid status")
		}
	})

	t.Run("both prefix and filter", func(t *testing.T) {
		_, err := decodeLifecycleConfigXML(strings.NewReader(`<LifecycleConfiguration><Rule><Status>Enabled</Status><Prefix>p</Prefix><Filter><Prefix>q</Prefix></Filter><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`))
		if err == nil {
			t.Fatal("expected error for rule with both Prefix and Filter")
		}
	})

	t.Run("invalid filter tag empty key", func(t *testing.T) {
		_, err := decodeLifecycleConfigXML(strings.NewReader(`<LifecycleConfiguration><Rule><Status>Enabled</Status><Filter><Tag><Key></Key><Value>v</Value></Tag></Filter><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`))
		if err == nil {
			t.Fatal("expected error for filter with empty tag key")
		}
	})

	t.Run("top-level prefix legacy", func(t *testing.T) {
		cfg, err := decodeLifecycleConfigXML(strings.NewReader(`<LifecycleConfiguration><Rule><Status>Enabled</Status><Prefix>logs/</Prefix><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`))
		if err != nil {
			t.Fatalf("decodeLifecycleConfigXML(legacy prefix) error = %v", err)
		}
		if cfg.Rules[0].Filter == nil || aws.ToString(cfg.Rules[0].Filter.Prefix) != "logs/" {
			t.Fatalf("expected filter with prefix logs/, got %+v", cfg.Rules[0].Filter)
		}
	})

	t.Run("invalid expiration days zero", func(t *testing.T) {
		_, err := decodeLifecycleConfigXML(strings.NewReader(`<LifecycleConfiguration><Rule><Status>Enabled</Status><Filter><Prefix>x</Prefix></Filter><Expiration><Days>0</Days></Expiration></Rule></LifecycleConfiguration>`))
		if err == nil {
			t.Fatal("expected error for expiration with Days=0")
		}
	})

	t.Run("invalid transition negative days", func(t *testing.T) {
		_, err := decodeLifecycleConfigXML(strings.NewReader(`<LifecycleConfiguration><Rule><Status>Enabled</Status><Filter><Prefix>x</Prefix></Filter><Transition><Days>-1</Days><StorageClass>GLACIER</StorageClass></Transition></Rule></LifecycleConfiguration>`))
		if err == nil {
			t.Fatal("expected error for transition with negative days")
		}
	})

	t.Run("invalid noncurrent transition missing storage class", func(t *testing.T) {
		_, err := decodeLifecycleConfigXML(strings.NewReader(`<LifecycleConfiguration><Rule><Status>Enabled</Status><NoncurrentVersionTransition><NoncurrentDays>30</NoncurrentDays></NoncurrentVersionTransition></Rule></LifecycleConfiguration>`))
		if err == nil {
			t.Fatal("expected error for noncurrent transition with missing storage class")
		}
	})

	t.Run("invalid noncurrent expiration days zero", func(t *testing.T) {
		_, err := decodeLifecycleConfigXML(strings.NewReader(`<LifecycleConfiguration><Rule><Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>0</NoncurrentDays></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>`))
		if err == nil {
			t.Fatal("expected error for noncurrent expiration with NoncurrentDays=0")
		}
	})

	t.Run("invalid abort incomplete multipart upload days zero", func(t *testing.T) {
		_, err := decodeLifecycleConfigXML(strings.NewReader(`<LifecycleConfiguration><Rule><Status>Enabled</Status><AbortIncompleteMultipartUpload><DaysAfterInitiation>0</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule></LifecycleConfiguration>`))
		if err == nil {
			t.Fatal("expected error for abort multipart with DaysAfterInitiation=0")
		}
	})
}

func TestEncodeLifecycleFilterBranches(t *testing.T) {
	t.Run("nil filter", func(t *testing.T) {
		if got := encodeLifecycleFilter(nil); got != nil {
			t.Fatalf("encodeLifecycleFilter(nil) = %+v, want nil", got)
		}
	})

	t.Run("tag filter", func(t *testing.T) {
		f := &types.LifecycleRuleFilter{Tag: &types.Tag{Key: aws.String("k"), Value: aws.String("v")}}
		got := encodeLifecycleFilter(f)
		if got == nil || got.Tag == nil || got.Tag.Key != "k" {
			t.Fatalf("encodeLifecycleFilter(tag) mismatch: %+v", got)
		}
	})

	t.Run("object size greater than", func(t *testing.T) {
		gt := int64(100)
		f := &types.LifecycleRuleFilter{ObjectSizeGreaterThan: &gt}
		got := encodeLifecycleFilter(f)
		if got == nil || got.ObjectSizeGreaterThan == nil || *got.ObjectSizeGreaterThan != 100 {
			t.Fatalf("encodeLifecycleFilter(objectSizeGreaterThan) mismatch: %+v", got)
		}
	})

	t.Run("object size less than", func(t *testing.T) {
		lt := int64(200)
		f := &types.LifecycleRuleFilter{ObjectSizeLessThan: &lt}
		got := encodeLifecycleFilter(f)
		if got == nil || got.ObjectSizeLessThan == nil || *got.ObjectSizeLessThan != 200 {
			t.Fatalf("encodeLifecycleFilter(objectSizeLessThan) mismatch: %+v", got)
		}
	})
}

func lifecycleRulesDocument(count int) string {
	return "<LifecycleConfiguration>" +
		strings.Repeat("<Rule><Status>Enabled</Status></Rule>", count) +
		"</LifecycleConfiguration>"
}

func TestDecodeLifecycleConfigLimits(t *testing.T) {
	var tags strings.Builder
	for range maxLifecycleTagsPerAnd + 1 {
		tags.WriteString("<Tag><Key>key</Key><Value>value</Value></Tag>")
	}
	tooManyTags := "<LifecycleConfiguration><Rule><Status>Enabled</Status><Filter><And>" +
		tags.String() +
		"</And></Filter></Rule></LifecycleConfiguration>"

	var transitions strings.Builder
	for range maxLifecycleTransitionsPerRule + 1 {
		transitions.WriteString("<Transition><Days>1</Days><StorageClass>GLACIER</StorageClass></Transition>")
	}
	tooManyTransitions := "<LifecycleConfiguration><Rule><Status>Enabled</Status>" +
		transitions.String() +
		"</Rule></LifecycleConfiguration>"

	tests := []struct {
		name      string
		body      string
		wantErr   error
		anyError  bool
		wantRules int
	}{
		{
			name:      "accepts one thousand rules",
			body:      lifecycleRulesDocument(maxLifecycleRules),
			wantRules: maxLifecycleRules,
		},
		{
			name:    "rejects rule one thousand and one",
			body:    lifecycleRulesDocument(maxLifecycleRules + 1),
			wantErr: s3xml.ErrXMLElementLimit,
		},
		{
			name:    "rejects oversized prefix field",
			body:    "<LifecycleConfiguration><Rule><Status>Enabled</Status><Prefix>" + strings.Repeat("p", maxLifecyclePrefixBytes+1) + "</Prefix></Rule></LifecycleConfiguration>",
			wantErr: s3xml.ErrXMLFieldTooLong,
		},
		{
			name:     "rejects prefix character limit",
			body:     "<LifecycleConfiguration><Rule><Status>Enabled</Status><Prefix>" + strings.Repeat("p", maxLifecyclePrefixRunes+1) + "</Prefix></Rule></LifecycleConfiguration>",
			anyError: true,
		},
		{
			name:      "accepts whitespace prefix at character limit",
			body:      "<LifecycleConfiguration><Rule><Status>Enabled</Status><Filter><Prefix>" + strings.Repeat(" ", maxLifecyclePrefixRunes) + "</Prefix></Filter></Rule></LifecycleConfiguration>",
			wantRules: 1,
		},
		{
			name:     "counts whitespace toward prefix character limit",
			body:     "<LifecycleConfiguration><Rule><Status>Enabled</Status><Filter><Prefix>" + strings.Repeat(" ", maxLifecyclePrefixRunes+1) + "</Prefix></Filter></Rule></LifecycleConfiguration>",
			anyError: true,
		},
		{
			name:     "counts whitespace toward tag key character limit",
			body:     "<LifecycleConfiguration><Rule><Status>Enabled</Status><Filter><Tag><Key>" + strings.Repeat(" ", maxLifecycleTagKeyRunes) + "k</Key><Value>v</Value></Tag></Filter></Rule></LifecycleConfiguration>",
			anyError: true,
		},
		{
			name:     "counts whitespace toward tag value character limit",
			body:     "<LifecycleConfiguration><Rule><Status>Enabled</Status><Filter><Tag><Key>k</Key><Value>" + strings.Repeat(" ", maxLifecycleTagValueRunes) + "v</Value></Tag></Filter></Rule></LifecycleConfiguration>",
			anyError: true,
		},
		{
			name:     "rejects oversized rule ID",
			body:     "<LifecycleConfiguration><Rule><ID>" + strings.Repeat("i", maxLifecycleRuleIDRunes+1) + "</ID><Status>Enabled</Status></Rule></LifecycleConfiguration>",
			anyError: true,
		},
		{
			name:     "rejects excess tags in And filter",
			body:     tooManyTags,
			anyError: true,
		},
		{
			name:     "rejects excess transitions in one rule",
			body:     tooManyTransitions,
			anyError: true,
		},
		{
			name:    "rejects oversized body",
			body:    "<LifecycleConfiguration>" + strings.Repeat(" ", int(maxLifecycleBodyBytes)) + "</LifecycleConfiguration>",
			wantErr: s3xml.ErrXMLBodyTooLarge,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := decodeLifecycleConfigXML(strings.NewReader(tc.body))
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("decodeLifecycleConfigXML() error = %v, want %v", err, tc.wantErr)
			}
			if tc.anyError && err == nil {
				t.Fatalf("decodeLifecycleConfigXML() expected an error")
			}
			if tc.wantErr == nil && !tc.anyError && err != nil {
				t.Fatalf("decodeLifecycleConfigXML() error = %v", err)
			}
			if err == nil && len(cfg.Rules) != tc.wantRules {
				t.Fatalf("decodeLifecycleConfigXML() returned %d rules, want %d", len(cfg.Rules), tc.wantRules)
			}
		})
	}
}
