package s3http_test

import (
	"net/http"
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
