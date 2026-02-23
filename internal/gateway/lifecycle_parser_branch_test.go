package gateway

import (
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
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
			got, err := parseMetadataDirective(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseMetadataDirective() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("parseMetadataDirective() = %q, want %q", got, tt.want)
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
			got, err := parseOptionalObjectAttributes(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseOptionalObjectAttributes() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && len(got) != tt.wantLen {
				t.Fatalf("parseOptionalObjectAttributes() len = %d, want %d", len(got), tt.wantLen)
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
			got, err := parseOptionalHTTPTime(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseOptionalHTTPTime() error = %v, wantErr %v", err, tt.wantErr)
			}
			if (got == nil) != tt.wantNil {
				t.Fatalf("parseOptionalHTTPTime() nil = %v, want %v", got == nil, tt.wantNil)
			}
		})
	}
}
