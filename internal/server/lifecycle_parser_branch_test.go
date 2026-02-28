package server

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/define42/s3gateway/internal/xmlhelper"
)

func TestParseMetadataDirective(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    types.MetadataDirective
		wantErr bool
	}{
		{name: "empty", input: "", want: "", wantErr: false},
		{name: "copy", input: "copy", want: types.MetadataDirective("COPY"), wantErr: false},
		{name: "replace trimmed case insensitive", input: "  RePlAcE ", want: types.MetadataDirective("REPLACE"), wantErr: false},
		{name: "unsupported", input: "merge", want: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := xmlhelper.ParseMetadataDirective(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("xmlhelper.ParseMetadataDirective() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("xmlhelper.ParseMetadataDirective() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseOptionalObjectAttributesMatrix(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{name: "empty", input: "", wantLen: 0, wantErr: false},
		{name: "single restore status", input: "RestoreStatus", wantLen: 1, wantErr: false},
		{name: "duplicate and whitespace", input: " RestoreStatus , RestoreStatus ", wantLen: 1, wantErr: false},
		{name: "only commas and whitespace", input: " ,  , ", wantLen: 0, wantErr: true},
		{name: "unsupported", input: "Checksum", wantLen: 0, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := xmlhelper.ParseOptionalObjectAttributes(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("xmlhelper.ParseOptionalObjectAttributes() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && len(got) != tt.wantLen {
				t.Fatalf("xmlhelper.ParseOptionalObjectAttributes() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

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
		if got == nil || got.Tag == nil || aws.ToString(got.Tag.Key) != "k" {
			t.Fatalf("decodeLifecycleFilter(tag) unexpected output: %+v", got)
		}
	})

	t.Run("invalid tag", func(t *testing.T) {
		_, err := decodeLifecycleFilter(&lifecycleFilterXML{Tag: &lifecycleTagXML{Key: "   ", Value: "v"}})
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
	if *got != "legacy-prefix" {
		t.Fatalf("lifecycleRuleLegacyPrefix() = %q, want %q", *got, "legacy-prefix")
	}
}

func TestParseOptionalHTTPTime(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantNil bool
		wantErr bool
	}{
		{name: "empty", input: "", wantNil: true, wantErr: false},
		{name: "invalid", input: "not-a-time", wantNil: true, wantErr: true},
		{name: "valid", input: time.Now().UTC().Format(http.TimeFormat), wantNil: false, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := xmlhelper.ParseOptionalHTTPTime(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("xmlhelper.ParseOptionalHTTPTime() error = %v, wantErr %v", err, tt.wantErr)
			}
			if (got == nil) != tt.wantNil {
				t.Fatalf("xmlhelper.ParseOptionalHTTPTime() nil = %v, want %v", got == nil, tt.wantNil)
			}
		})
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
