package s3http_test

import (
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/define42/s3gateway/internal/s3http"
)

func TestParseRequestPayerHeader(t *testing.T) {
	tests := []struct {
		name      string
		headerVal string
		want      types.RequestPayer
		wantErr   bool
	}{
		{name: "empty", headerVal: "", want: "", wantErr: false},
		{name: "valid requester", headerVal: "requester", want: types.RequestPayerRequester, wantErr: false},
		{name: "valid requester trimmed case insensitive", headerVal: "  ReQuEsTeR ", want: types.RequestPayerRequester, wantErr: false},
		{name: "unsupported", headerVal: "owner", want: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if tt.headerVal != "" {
				h.Set("x-amz-request-payer", tt.headerVal)
			}
			got, err := s3http.ParseRequestPayerHeader(h)
			if (err != nil) != tt.wantErr {
				t.Fatalf("s3http.ParseRequestPayerHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("s3http.ParseRequestPayerHeader() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseTaggingDirective(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    types.TaggingDirective
		wantErr bool
	}{
		{name: "empty", input: "", want: "", wantErr: false},
		{name: "copy", input: "copy", want: types.TaggingDirective("COPY"), wantErr: false},
		{name: "replace trimmed case insensitive", input: "  RePlAcE ", want: types.TaggingDirective("REPLACE"), wantErr: false},
		{name: "unsupported", input: "merge", want: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s3http.ParseTaggingDirective(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("s3http.ParseTaggingDirective() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("s3http.ParseTaggingDirective() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseStorageClass(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    types.StorageClass
		wantErr bool
	}{
		{name: "empty", input: "", want: "", wantErr: false},
		{name: "standard", input: "standard", want: types.StorageClass("STANDARD"), wantErr: false},
		{name: "glacier trimmed case insensitive", input: "  gLaCiEr ", want: types.StorageClass("GLACIER"), wantErr: false},
		{name: "unsupported", input: "WARM", want: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s3http.ParseStorageClass(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("s3http.ParseStorageClass() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("s3http.ParseStorageClass() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseChecksumAlgorithmHeader(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    types.ChecksumAlgorithm
		wantErr bool
	}{
		{name: "empty", input: "", want: "", wantErr: false},
		{name: "crc32", input: "crc32", want: types.ChecksumAlgorithmCrc32, wantErr: false},
		{name: "crc32c", input: "CRC32C", want: types.ChecksumAlgorithmCrc32c, wantErr: false},
		{name: "crc64nvme", input: "  crc64nvme ", want: types.ChecksumAlgorithmCrc64nvme, wantErr: false},
		{name: "sha1", input: "sha1", want: types.ChecksumAlgorithmSha1, wantErr: false},
		{name: "sha256", input: "SHA256", want: types.ChecksumAlgorithmSha256, wantErr: false},
		{name: "unsupported", input: "md5", want: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s3http.ParseChecksumAlgorithmHeader(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("s3http.ParseChecksumAlgorithmHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("s3http.ParseChecksumAlgorithmHeader() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseChecksumTypeHeader(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		want    types.ChecksumType
		wantErr bool
	}{
		{name: "empty"},
		{name: "whitespace", input: " \t "},
		{name: "full object", input: "FULL_OBJECT", want: types.ChecksumTypeFullObject},
		{name: "composite", input: "COMPOSITE", want: types.ChecksumTypeComposite},
		{name: "trimmed case insensitive", input: " full_object ", want: types.ChecksumTypeFullObject},
		{name: "unsupported", input: "PART", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s3http.ParseChecksumTypeHeader(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseChecksumTypeHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("ParseChecksumTypeHeader() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseChecksumWriteHeadersSupportedAlgorithms(t *testing.T) {
	for _, algorithm := range []types.ChecksumAlgorithm{
		types.ChecksumAlgorithmCrc32,
		types.ChecksumAlgorithmCrc32c,
		types.ChecksumAlgorithmCrc64nvme,
		types.ChecksumAlgorithmSha1,
		types.ChecksumAlgorithmSha256,
	} {
		for _, source := range []string{
			"x-amz-checksum-algorithm",
			"x-amz-sdk-checksum-algorithm",
			"STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
			"STREAMING-UNSIGNED-PAYLOAD-TRAILER",
		} {
			t.Run(string(algorithm)+"/"+source, func(t *testing.T) {
				h := http.Header{}
				if source[0] == 'x' {
					h.Set(source, string(algorithm))
				} else {
					h.Set("x-amz-content-sha256", source)
					h.Set("x-amz-trailer", "x-amz-checksum-"+string(algorithm))
				}
				got, err := s3http.ParseChecksumWriteHeaders(h)
				if err != nil {
					t.Fatalf("ParseChecksumWriteHeaders() error = %v", err)
				}
				want := s3http.ChecksumWriteHeaders{ChecksumAlgorithm: algorithm}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("ParseChecksumWriteHeaders() = %#v, want %#v", got, want)
				}
			})
		}
	}
}

func TestParseChecksumWriteHeadersCombinations(t *testing.T) {
	for _, tt := range []struct {
		name    string
		headers map[string][]string
		want    s3http.ChecksumWriteHeaders
		wantErr bool
	}{
		{name: "empty"},
		{
			name: "matching selectors normalized",
			headers: map[string][]string{
				"x-amz-checksum-algorithm":     {" crc32c "},
				"x-amz-sdk-checksum-algorithm": {"CRC32C"},
			},
			want: s3http.ChecksumWriteHeaders{ChecksumAlgorithm: types.ChecksumAlgorithmCrc32c},
		},
		{
			name: "conflicting selectors",
			headers: map[string][]string{
				"x-amz-checksum-algorithm":     {"CRC32"},
				"x-amz-sdk-checksum-algorithm": {"CRC32C"},
			},
			wantErr: true,
		},
		{
			name: "conflicting repeated selector",
			headers: map[string][]string{
				"x-amz-sdk-checksum-algorithm": {"CRC32", "SHA256"},
			},
			wantErr: true,
		},
		{
			name: "empty or repeated selector values rejected",
			headers: map[string][]string{
				"x-amz-checksum-algorithm":     {" "},
				"x-amz-sdk-checksum-algorithm": {"", "SHA256", "sha256"},
			},
			wantErr: true,
		},
		{
			name:    "unsupported SHA512 checksum value",
			headers: map[string][]string{"x-amz-checksum-sha512": {"incorrect"}},
			wantErr: true,
		},
		{
			name:    "empty unsupported checksum value",
			headers: map[string][]string{"x-amz-checksum-xxhash64": {""}},
			wantErr: true,
		},
		{
			name:    "unknown checksum alongside supported value",
			headers: map[string][]string{"x-amz-checksum-future": {"incorrect"}, "x-amz-checksum-crc32": {"AAAAAA=="}},
			wantErr: true,
		},
		{
			name:    "empty supported checksum",
			headers: map[string][]string{"x-amz-checksum-crc32": {" "}},
			wantErr: true,
		},
		{
			name:    "duplicate supported checksum",
			headers: map[string][]string{"x-amz-checksum-crc32": {"AAAAAA==", "BBBBBB=="}},
			wantErr: true,
		},
		{
			name:    "identical duplicate supported checksum",
			headers: map[string][]string{"x-amz-checksum-crc32": {"AAAAAA==", "AAAAAA=="}},
			wantErr: true,
		},
		{
			name:    "checksum metadata is not an integrity header",
			headers: map[string][]string{"x-amz-meta-checksum-sha512": {"opaque metadata"}},
		},
		{
			name:    "checksum type normalized",
			headers: map[string][]string{"x-amz-checksum-type": {" composite "}},
			want:    s3http.ChecksumWriteHeaders{ChecksumType: types.ChecksumTypeComposite},
		},
		{
			name:    "duplicate checksum type",
			headers: map[string][]string{"x-amz-checksum-type": {"COMPOSITE", "COMPOSITE"}},
			wantErr: true,
		},
		{
			name:    "blank checksum type",
			headers: map[string][]string{"x-amz-checksum-type": {""}},
			wantErr: true,
		},
		{
			name:    "read-only checksum mode rejected",
			headers: map[string][]string{"x-amz-checksum-mode": {"ENABLED"}},
			wantErr: true,
		},
		{
			name:    "unsupported SDK selector",
			headers: map[string][]string{"x-amz-sdk-checksum-algorithm": {"MD5"}},
			wantErr: true,
		},
		{
			name:    "value without selector remains value only",
			headers: map[string][]string{"x-amz-checksum-crc32": {"  AAAAAA== "}},
			want:    s3http.ChecksumWriteHeaders{ChecksumCRC32: aws.String("AAAAAA==")},
		},
		{
			name: "matching selector and value",
			headers: map[string][]string{
				"x-amz-sdk-checksum-algorithm": {"CRC32"},
				"x-amz-checksum-crc32":         {"AAAAAA=="},
			},
			want: s3http.ChecksumWriteHeaders{
				ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
				ChecksumCRC32:     aws.String("AAAAAA=="),
			},
		},
		{
			name: "selector and value disagree",
			headers: map[string][]string{
				"x-amz-sdk-checksum-algorithm": {"SHA256"},
				"x-amz-checksum-crc32":         {"AAAAAA=="},
			},
			wantErr: true,
		},
		{
			name: "multiple value headers",
			headers: map[string][]string{
				"x-amz-checksum-crc32":  {"AAAAAA=="},
				"x-amz-checksum-crc32c": {"AAAAAA=="},
			},
			wantErr: true,
		},
		{
			name: "trailer selector duplicates and unrelated fields",
			headers: map[string][]string{
				"x-amz-content-sha256":         {"STREAMING-UNSIGNED-PAYLOAD-TRAILER"},
				"x-amz-sdk-checksum-algorithm": {"CRC32"},
				"x-amz-trailer":                {" , X-Amz-Checksum-CRC32, x-amz-trailer-signature", "x-amz-checksum-crc32"},
			},
			want: s3http.ChecksumWriteHeaders{ChecksumAlgorithm: types.ChecksumAlgorithmCrc32},
		},
		{
			name: "trailer conflicts with selector",
			headers: map[string][]string{
				"x-amz-content-sha256":         {"STREAMING-UNSIGNED-PAYLOAD-TRAILER"},
				"x-amz-sdk-checksum-algorithm": {"CRC32"},
				"x-amz-trailer":                {"x-amz-checksum-sha256"},
			},
			wantErr: true,
		},
		{
			name: "trailer conflicts with value header",
			headers: map[string][]string{
				"x-amz-content-sha256": {"STREAMING-UNSIGNED-PAYLOAD-TRAILER"},
				"x-amz-checksum-crc32": {"AAAAAA=="},
				"x-amz-trailer":        {"x-amz-checksum-sha256"},
			},
			wantErr: true,
		},
		{
			name: "matching trailer and value header",
			headers: map[string][]string{
				"x-amz-content-sha256": {"STREAMING-UNSIGNED-PAYLOAD-TRAILER"},
				"x-amz-checksum-crc32": {"AAAAAA=="},
				"x-amz-trailer":        {"x-amz-checksum-crc32"},
			},
			want: s3http.ChecksumWriteHeaders{
				ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
				ChecksumCRC32:     aws.String("AAAAAA=="),
			},
		},
		{
			name: "multiple trailer algorithms",
			headers: map[string][]string{
				"x-amz-content-sha256": {"STREAMING-UNSIGNED-PAYLOAD-TRAILER"},
				"x-amz-trailer":        {"x-amz-checksum-crc32,x-amz-checksum-sha256"},
			},
			wantErr: true,
		},
		{
			name: "unsupported checksum trailer",
			headers: map[string][]string{
				"x-amz-content-sha256": {"STREAMING-UNSIGNED-PAYLOAD-TRAILER"},
				"x-amz-trailer":        {"x-amz-checksum-md5"},
			},
			wantErr: true,
		},
		{
			name: "empty checksum trailer algorithm",
			headers: map[string][]string{
				"x-amz-content-sha256": {"STREAMING-UNSIGNED-PAYLOAD-TRAILER"},
				"x-amz-trailer":        {"x-amz-checksum-"},
			},
			wantErr: true,
		},
		{
			name: "ordinary request does not infer from trailer",
			headers: map[string][]string{
				"x-amz-content-sha256": {"UNSIGNED-PAYLOAD"},
				"x-amz-trailer":        {"x-amz-checksum-crc32"},
			},
		},
		{
			name: "signed chunks without verified trailers do not infer",
			headers: map[string][]string{
				"x-amz-content-sha256": {"STREAMING-AWS4-HMAC-SHA256-PAYLOAD"},
				"x-amz-trailer":        {"x-amz-checksum-crc32"},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			for name, values := range tt.headers {
				for _, value := range values {
					h.Add(name, value)
				}
			}
			got, err := s3http.ParseChecksumWriteHeaders(h)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseChecksumWriteHeaders() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseChecksumWriteHeaders() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParseChecksumWriteHeadersRawHeaderNames(t *testing.T) {
	for _, tt := range []struct {
		name    string
		header  http.Header
		wantErr bool
	}{
		{name: "mixed case value", header: http.Header{"x-AMZ-Checksum-CrC32": {"AAAAAA=="}}},
		{name: "aliased duplicate value", header: http.Header{"x-amz-checksum-crc32": {"AAAAAA=="}, "X-Amz-Checksum-Crc32": {"BBBBBB=="}}, wantErr: true},
		{name: "missing value slice", header: http.Header{"X-Amz-Checksum-Crc32": nil}, wantErr: true},
		{name: "mixed case unsupported value", header: http.Header{"X-AMZ-CHECKSUM-SHA512": {"incorrect"}}, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s3http.ParseChecksumWriteHeaders(tt.header)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseChecksumWriteHeaders() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && (!got.HasValue() || aws.ToString(got.ChecksumCRC32) != "AAAAAA==") {
				t.Errorf("supported mixed-case checksum was not preserved: %#v", got)
			}
		})
	}
}

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
			got, err := s3http.ParseMetadataDirective(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("s3http.ParseMetadataDirective() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("s3http.ParseMetadataDirective() = %q, want %q", got, tt.want)
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
			got, err := s3http.ParseOptionalObjectAttributes(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("s3http.ParseOptionalObjectAttributes() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && len(got) != tt.wantLen {
				t.Fatalf("s3http.ParseOptionalObjectAttributes() len = %d, want %d", len(got), tt.wantLen)
			}
		})
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
			got, err := s3http.ParseOptionalHTTPTime(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("s3http.ParseOptionalHTTPTime() error = %v, wantErr %v", err, tt.wantErr)
			}
			if (got == nil) != tt.wantNil {
				t.Fatalf("s3http.ParseOptionalHTTPTime() nil = %v, want %v", got == nil, tt.wantNil)
			}
		})
	}
}
