package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authz "github.com/define42/s3gateway/internal/authz"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	sigv4 "github.com/define42/s3gateway/internal/sigv4"
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
			got, err := parseRequestPayerHeader(h)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseRequestPayerHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("parseRequestPayerHeader() = %q, want %q", got, tt.want)
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
			got, err := parseTaggingDirective(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseTaggingDirective() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("parseTaggingDirective() = %q, want %q", got, tt.want)
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
			got, err := parseStorageClass(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseStorageClass() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("parseStorageClass() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseObjectCannedACL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    types.ObjectCannedACL
		wantErr bool
	}{
		{name: "empty", input: "", want: "", wantErr: false},
		{name: "private", input: "private", want: types.ObjectCannedACL("private"), wantErr: false},
		{name: "public read trimmed case insensitive", input: "  PuBlIc-ReAd ", want: types.ObjectCannedACL("public-read"), wantErr: false},
		{name: "unsupported", input: "authenticated", want: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseObjectCannedACL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseObjectCannedACL() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("parseObjectCannedACL() = %q, want %q", got, tt.want)
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
		want    sseWriteHeaders
		wantErr bool
	}{
		{
			name:    "empty",
			headers: mkHeader(nil),
			want:    sseWriteHeaders{},
			wantErr: false,
		},
		{
			name: "aes256",
			headers: mkHeader(map[string]string{
				"x-amz-server-side-encryption": "AES256",
			}),
			want: sseWriteHeaders{
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
			want: sseWriteHeaders{
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
			want: sseWriteHeaders{
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
			want: sseWriteHeaders{
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
			got, err := parseSSEWriteHeaders(tt.headers)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseSSEWriteHeaders() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got.ServerSideEncryption != tt.want.ServerSideEncryption {
				t.Fatalf("parseSSEWriteHeaders() ServerSideEncryption = %q, want %q", got.ServerSideEncryption, tt.want.ServerSideEncryption)
			}
			if aws.ToString(got.SSEKMSKeyID) != aws.ToString(tt.want.SSEKMSKeyID) {
				t.Fatalf("parseSSEWriteHeaders() SSEKMSKeyID = %q, want %q", aws.ToString(got.SSEKMSKeyID), aws.ToString(tt.want.SSEKMSKeyID))
			}
			if aws.ToString(got.SSEKMSEncryptionContext) != aws.ToString(tt.want.SSEKMSEncryptionContext) {
				t.Fatalf("parseSSEWriteHeaders() SSEKMSEncryptionContext = %q, want %q", aws.ToString(got.SSEKMSEncryptionContext), aws.ToString(tt.want.SSEKMSEncryptionContext))
			}
			if aws.ToString(got.SSECustomerAlgorithm) != aws.ToString(tt.want.SSECustomerAlgorithm) {
				t.Fatalf("parseSSEWriteHeaders() SSECustomerAlgorithm = %q, want %q", aws.ToString(got.SSECustomerAlgorithm), aws.ToString(tt.want.SSECustomerAlgorithm))
			}
			if aws.ToString(got.SSECustomerKey) != aws.ToString(tt.want.SSECustomerKey) {
				t.Fatalf("parseSSEWriteHeaders() SSECustomerKey = %q, want %q", aws.ToString(got.SSECustomerKey), aws.ToString(tt.want.SSECustomerKey))
			}
			if aws.ToString(got.SSECustomerKeyMD5) != aws.ToString(tt.want.SSECustomerKeyMD5) {
				t.Fatalf("parseSSEWriteHeaders() SSECustomerKeyMD5 = %q, want %q", aws.ToString(got.SSECustomerKeyMD5), aws.ToString(tt.want.SSECustomerKeyMD5))
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
			got, err := parseChecksumAlgorithmHeader(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseChecksumAlgorithmHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("parseChecksumAlgorithmHeader() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeVersioningConfigXMLMFADeleteValues(t *testing.T) {
	allowed := types.MFADelete("").Values()
	if len(allowed) == 0 {
		t.Fatalf("expected MFADelete values to be non-empty")
	}

	for _, v := range allowed {
		v := v
		t.Run("exact_"+string(v), func(t *testing.T) {
			cfg, err := decodeVersioningConfigXML(strings.NewReader(
				`<VersioningConfiguration><MfaDelete>` + string(v) + `</MfaDelete></VersioningConfiguration>`,
			))
			if err != nil {
				t.Fatalf("decodeVersioningConfigXML() error = %v", err)
			}
			if cfg.MFADelete != v {
				t.Fatalf("decodeVersioningConfigXML() MFADelete = %q, want %q", cfg.MFADelete, v)
			}
		})

		t.Run("trimmed_case_insensitive_"+string(v), func(t *testing.T) {
			cfg, err := decodeVersioningConfigXML(strings.NewReader(
				`<VersioningConfiguration><MfaDelete>  ` + strings.ToLower(string(v)) + ` </MfaDelete></VersioningConfiguration>`,
			))
			if err != nil {
				t.Fatalf("decodeVersioningConfigXML() error = %v", err)
			}
			if cfg.MFADelete != v {
				t.Fatalf("decodeVersioningConfigXML() MFADelete = %q, want %q", cfg.MFADelete, v)
			}
		})
	}

	if _, err := decodeVersioningConfigXML(strings.NewReader(
		`<VersioningConfiguration><MfaDelete>invalid</MfaDelete></VersioningConfiguration>`,
	)); err == nil {
		t.Fatalf("decodeVersioningConfigXML() expected error for invalid MfaDelete")
	}
}

func TestSigV4AuthFromCtx(t *testing.T) {
	t.Run("missing context value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
		if got := sigv4.SigV4AuthFromCtx(req); got != nil {
			t.Fatalf("sigV4AuthFromCtx() = %+v, want nil", got)
		}
	})

	t.Run("wrong context value type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil).WithContext(
			context.WithValue(context.Background(), sigv4.CtxSigV4AuthKey, "not-auth"),
		)
		if got := sigv4.SigV4AuthFromCtx(req); got != nil {
			t.Fatalf("sigV4AuthFromCtx() = %+v, want nil for wrong context type", got)
		}
	})

	t.Run("valid auth value", func(t *testing.T) {
		want := &sigv4.SigV4Auth{
			AccessKey:    "access",
			Date:         "20260207",
			Region:       "us-east-1",
			Service:      "s3",
			SignatureHex: strings.Repeat("a", 64),
			AmzDate:      "20260207T010203Z",
		}
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil).WithContext(
			context.WithValue(context.Background(), sigv4.CtxSigV4AuthKey, want),
		)
		got := sigv4.SigV4AuthFromCtx(req)
		if got != want {
			t.Fatalf("sigV4AuthFromCtx() pointer mismatch: got=%p want=%p", got, want)
		}
	})
}

func TestSigV4SecretFromCtx(t *testing.T) {
	t.Run("missing context value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
		if got := sigv4.SigV4SecretFromCtx(req); got != "" {
			t.Fatalf("sigV4SecretFromCtx() = %q, want empty string", got)
		}
	})

	t.Run("wrong context value type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil).WithContext(
			context.WithValue(context.Background(), sigv4.CtxSigV4SecretKey, 123),
		)
		if got := sigv4.SigV4SecretFromCtx(req); got != "" {
			t.Fatalf("sigV4SecretFromCtx() = %q, want empty string for wrong context type", got)
		}
	})

	t.Run("valid secret value", func(t *testing.T) {
		const want = "derived-secret"
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil).WithContext(
			context.WithValue(context.Background(), sigv4.CtxSigV4SecretKey, want),
		)
		if got := sigv4.SigV4SecretFromCtx(req); got != want {
			t.Fatalf("sigV4SecretFromCtx() = %q, want %q", got, want)
		}
	})
}

func TestChunkSignatureVerifierFromRequestUsesSigV4AuthFromCtx(t *testing.T) {
	const mode = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"

	t.Run("missing sigv4 auth context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
		req.Header.Set("x-amz-content-sha256", mode)

		verifier, err := sigv4.ChunkSignatureVerifierFromRequest(req)
		if !errors.Is(err, sigv4.ErrMissingSigV4AuthContext) {
			t.Fatalf("chunkSignatureVerifierFromRequest() error = %v, want %v", err, sigv4.ErrMissingSigV4AuthContext)
		}
		if verifier != nil {
			t.Fatalf("chunkSignatureVerifierFromRequest() verifier = %+v, want nil on missing context", verifier)
		}
	})

	t.Run("missing sigv4 secret context", func(t *testing.T) {
		auth := &sigv4.SigV4Auth{
			AccessKey:    "access",
			Date:         "20260207",
			Region:       "us-east-1",
			Service:      "s3",
			SignatureHex: strings.Repeat("b", 64),
			AmzDate:      "20260207T010203Z",
		}
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil).WithContext(
			context.WithValue(context.Background(), sigv4.CtxSigV4AuthKey, auth),
		)
		req.Header.Set("x-amz-content-sha256", mode)

		verifier, err := sigv4.ChunkSignatureVerifierFromRequest(req)
		if !errors.Is(err, sigv4.ErrMissingSigV4SecretContext) {
			t.Fatalf("chunkSignatureVerifierFromRequest() error = %v, want %v", err, sigv4.ErrMissingSigV4SecretContext)
		}
		if verifier != nil {
			t.Fatalf("chunkSignatureVerifierFromRequest() verifier = %+v, want nil on missing secret context", verifier)
		}
	})

	t.Run("with sigv4 auth context", func(t *testing.T) {
		auth := &sigv4.SigV4Auth{
			AccessKey:    "access",
			Date:         "20260207",
			Region:       "us-east-1",
			Service:      "s3",
			SignatureHex: strings.Repeat("b", 64),
			AmzDate:      "20260207T010203Z",
		}
		ctx := context.WithValue(context.Background(), sigv4.CtxSigV4AuthKey, auth)
		ctx = context.WithValue(ctx, sigv4.CtxSigV4SecretKey, "secret")
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil).WithContext(ctx)
		req.Header.Set("x-amz-content-sha256", mode)

		verifier, err := sigv4.ChunkSignatureVerifierFromRequest(req)
		if err != nil {
			t.Fatalf("chunkSignatureVerifierFromRequest() error = %v", err)
		}
		if verifier == nil {
			t.Fatalf("chunkSignatureVerifierFromRequest() verifier is nil")
		}
		if verifier.PrevSig != auth.SignatureHex {
			t.Fatalf("chunkSignatureVerifierFromRequest() prevSig = %q, want %q", verifier.PrevSig, auth.SignatureHex)
		}
	})
}

func TestParseGroupPermissions(t *testing.T) {
	tests := []struct {
		name       string
		group      string
		wantPrefix string
		wantPerm   authz.Perm
		wantOK     bool
	}{
		{
			name:       "read only",
			group:      "team2-r",
			wantPrefix: "team2",
			wantPerm:   authz.PermRead,
			wantOK:     true,
		},
		{
			name:       "read write",
			group:      "team2-rw",
			wantPrefix: "team2",
			wantPerm:   authz.PermRead | authz.PermWrite,
			wantOK:     true,
		},
		{
			name:       "full letters mixed order",
			group:      "team2-bcdwr",
			wantPrefix: "team2",
			wantPerm:   authz.PermRead | authz.PermWrite | authz.PermCreateBucket | authz.PermDeleteObject | authz.PermDeleteBucket,
			wantOK:     true,
		},
		{
			name:       "trimmed and case insensitive",
			group:      "  TEAM2-RWCDB  ",
			wantPrefix: "team2",
			wantPerm:   authz.PermRead | authz.PermWrite | authz.PermCreateBucket | authz.PermDeleteObject | authz.PermDeleteBucket,
			wantOK:     true,
		},
		{
			name:   "missing prefix",
			group:  "-r",
			wantOK: false,
		},
		{
			name:   "missing permission letters",
			group:  "team2-",
			wantOK: false,
		},
		{
			name:   "group has separator but no access flag",
			group:  "team2-   ",
			wantOK: false,
		},
		{
			name:   "unsupported permission letter",
			group:  "team2-rx",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPrefix, gotPerm, gotOK := authz.ParseGroup(tt.group)
			if gotOK != tt.wantOK {
				t.Fatalf("parseGroup() ok = %v, want %v", gotOK, tt.wantOK)
			}
			if !gotOK {
				return
			}
			if gotPrefix != tt.wantPrefix {
				t.Fatalf("parseGroup() prefix = %q, want %q", gotPrefix, tt.wantPrefix)
			}
			if gotPerm != tt.wantPerm {
				t.Fatalf("parseGroup() perm = %v, want %v", gotPerm, tt.wantPerm)
			}
		})
	}
}

func TestRulesFromGroupsCombinesPermissions(t *testing.T) {
	rules := authz.RulesFromGroups(map[string]struct{}{
		"team2-r": {},
		"team2-w": {},
		"team2-c": {},
		"team2-d": {},
		"team2-b": {},
	})
	bucket := "team2-bucket"

	if !authz.CanRead(rules, bucket) {
		t.Fatalf("expected read permission")
	}
	if !authz.CanWrite(rules, bucket) {
		t.Fatalf("expected write permission")
	}
	if !authz.CanCreateBucket(rules, bucket) {
		t.Fatalf("expected create-bucket permission")
	}
	if !authz.CanDeleteObject(rules, bucket) {
		t.Fatalf("expected delete-object permission")
	}
	if !authz.CanDeleteBucket(rules, bucket) {
		t.Fatalf("expected delete-bucket permission")
	}

	readOnlyRules := authz.RulesFromGroups(map[string]struct{}{
		"team2-r": {},
	})
	if authz.CanWrite(readOnlyRules, bucket) || authz.CanCreateBucket(readOnlyRules, bucket) || authz.CanDeleteObject(readOnlyRules, bucket) || authz.CanDeleteBucket(readOnlyRules, bucket) {
		t.Fatalf("read-only permissions unexpectedly granted write/create/delete")
	}
}

func TestRulesFromGroupsIgnoresGroupWithoutAccessFlag(t *testing.T) {
	rules := authz.RulesFromGroups(map[string]struct{}{
		"team2-":    {},
		"team2-   ": {},
	})

	if len(rules) != 0 {
		t.Fatalf("expected no rules from groups without access flags, got=%+v", rules)
	}
	if authz.CanRead(rules, "team2-any") || authz.CanWrite(rules, "team2-any") || authz.CanCreateBucket(rules, "team2-any") || authz.CanDeleteObject(rules, "team2-any") || authz.CanDeleteBucket(rules, "team2-any") {
		t.Fatalf("expected no permissions from groups without access flags")
	}
}
