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

func TestParseSSEWriteHeaders(t *testing.T) {
	mkHeader := func(vals map[string]string) http.Header {
		h := http.Header{}
		for k, v := range vals {
			h.Set(k, v)
		}
		return h
	}

	tests := []struct {
		name    string
		headers http.Header
		want    s3http.SSEWriteHeaders
		wantErr bool
	}{
		{
			name:    "empty",
			headers: mkHeader(nil),
			want:    s3http.SSEWriteHeaders{},
			wantErr: false,
		},
		{
			name: "aes256",
			headers: mkHeader(map[string]string{
				"x-amz-server-side-encryption": "AES256",
			}),
			want: s3http.SSEWriteHeaders{
				ServerSideEncryption: types.ServerSideEncryptionAes256,
			},
			wantErr: false,
		},
		{
			name: "aws kms with key and context",
			headers: mkHeader(map[string]string{
				"x-amz-server-side-encryption":                "aws:kms",
				"x-amz-server-side-encryption-aws-kms-key-id": "key-arn",
				"x-amz-server-side-encryption-context":        "{\"a\":\"b\"}",
			}),
			want: s3http.SSEWriteHeaders{
				ServerSideEncryption:    types.ServerSideEncryptionAwsKms,
				SSEKMSKeyID:             aws.String("key-arn"),
				SSEKMSEncryptionContext: aws.String("{\"a\":\"b\"}"),
			},
			wantErr: false,
		},
		{
			name: "aws kms dsse with key and context",
			headers: mkHeader(map[string]string{
				"x-amz-server-side-encryption":                "aws:kms:dsse",
				"x-amz-server-side-encryption-aws-kms-key-id": "key-arn-dsse",
				"x-amz-server-side-encryption-context":        "{\"c\":\"d\"}",
			}),
			want: s3http.SSEWriteHeaders{
				ServerSideEncryption:    types.ServerSideEncryptionAwsKmsDsse,
				SSEKMSKeyID:             aws.String("key-arn-dsse"),
				SSEKMSEncryptionContext: aws.String("{\"c\":\"d\"}"),
			},
			wantErr: false,
		},
		{
			name: "unsupported server side encryption",
			headers: mkHeader(map[string]string{
				"x-amz-server-side-encryption": "AES128",
			}),
			wantErr: true,
		},
		{
			name: "kms key requires kms mode",
			headers: mkHeader(map[string]string{
				"x-amz-server-side-encryption-aws-kms-key-id": "key-arn",
			}),
			wantErr: true,
		},
		{
			name: "kms context requires kms mode",
			headers: mkHeader(map[string]string{
				"x-amz-server-side-encryption-context": "{\"a\":\"b\"}",
			}),
			wantErr: true,
		},
		{
			name: "ssec complete",
			headers: mkHeader(map[string]string{
				"x-amz-server-side-encryption-customer-algorithm": "AES256",
				"x-amz-server-side-encryption-customer-key":       "Zm9v",
				"x-amz-server-side-encryption-customer-key-md5":   "YmFy",
			}),
			want: s3http.SSEWriteHeaders{
				SSECustomerAlgorithm: aws.String("AES256"),
				SSECustomerKey:       aws.String("Zm9v"),
				SSECustomerKeyMD5:    aws.String("YmFy"),
			},
			wantErr: false,
		},
		{
			name: "ssec incomplete",
			headers: mkHeader(map[string]string{
				"x-amz-server-side-encryption-customer-algorithm": "AES256",
				"x-amz-server-side-encryption-customer-key":       "Zm9v",
			}),
			wantErr: true,
		},
		{
			name: "ssec cannot be combined with sse header",
			headers: mkHeader(map[string]string{
				"x-amz-server-side-encryption":                    "AES256",
				"x-amz-server-side-encryption-customer-algorithm": "AES256",
				"x-amz-server-side-encryption-customer-key":       "Zm9v",
				"x-amz-server-side-encryption-customer-key-md5":   "YmFy",
			}),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s3http.ParseSSEWriteHeaders(tt.headers)
			if (err != nil) != tt.wantErr {
				t.Fatalf("s3http.ParseSSEWriteHeaders() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got.ServerSideEncryption != tt.want.ServerSideEncryption {
				t.Fatalf("s3http.ParseSSEWriteHeaders() ServerSideEncryption = %q, want %q", got.ServerSideEncryption, tt.want.ServerSideEncryption)
			}
			if aws.ToString(got.SSEKMSKeyID) != aws.ToString(tt.want.SSEKMSKeyID) {
				t.Fatalf("s3http.ParseSSEWriteHeaders() SSEKMSKeyID = %q, want %q", aws.ToString(got.SSEKMSKeyID), aws.ToString(tt.want.SSEKMSKeyID))
			}
			if aws.ToString(got.SSEKMSEncryptionContext) != aws.ToString(tt.want.SSEKMSEncryptionContext) {
				t.Fatalf("s3http.ParseSSEWriteHeaders() SSEKMSEncryptionContext = %q, want %q", aws.ToString(got.SSEKMSEncryptionContext), aws.ToString(tt.want.SSEKMSEncryptionContext))
			}
			if aws.ToString(got.SSECustomerAlgorithm) != aws.ToString(tt.want.SSECustomerAlgorithm) {
				t.Fatalf("s3http.ParseSSEWriteHeaders() SSECustomerAlgorithm = %q, want %q", aws.ToString(got.SSECustomerAlgorithm), aws.ToString(tt.want.SSECustomerAlgorithm))
			}
			if aws.ToString(got.SSECustomerKey) != aws.ToString(tt.want.SSECustomerKey) {
				t.Fatalf("s3http.ParseSSEWriteHeaders() SSECustomerKey = %q, want %q", aws.ToString(got.SSECustomerKey), aws.ToString(tt.want.SSECustomerKey))
			}
			if aws.ToString(got.SSECustomerKeyMD5) != aws.ToString(tt.want.SSECustomerKeyMD5) {
				t.Fatalf("s3http.ParseSSEWriteHeaders() SSECustomerKeyMD5 = %q, want %q", aws.ToString(got.SSECustomerKeyMD5), aws.ToString(tt.want.SSECustomerKeyMD5))
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
			name: "empty selector values ignored",
			headers: map[string][]string{
				"x-amz-checksum-algorithm":     {" "},
				"x-amz-sdk-checksum-algorithm": {"", "SHA256", "sha256"},
			},
			want: s3http.ChecksumWriteHeaders{ChecksumAlgorithm: types.ChecksumAlgorithmSha256},
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
