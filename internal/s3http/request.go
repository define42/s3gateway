package s3http

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// ParseEncodingType parses the optional S3 encoding-type parameter. URL is the
// only accepted non-empty value and is matched case-insensitively.
func ParseEncodingType(v string) (types.EncodingType, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return "", nil
	}
	if strings.EqualFold(raw, string(types.EncodingTypeUrl)) {
		return types.EncodingTypeUrl, nil
	}
	return "", fmt.Errorf("unsupported encoding-type %q", raw)
}

// ParseRequestPayerHeader parses x-amz-request-payer. Requester is the only
// accepted non-empty value and is matched case-insensitively.
func ParseRequestPayerHeader(h http.Header) (types.RequestPayer, error) {
	raw := strings.TrimSpace(h.Get("x-amz-request-payer"))
	if raw == "" {
		return "", nil
	}
	if strings.EqualFold(raw, string(types.RequestPayerRequester)) {
		return types.RequestPayerRequester, nil
	}
	return "", fmt.Errorf("unsupported request payer %q", raw)
}

// ParseOptionalObjectAttributes parses a comma-separated optional-attributes
// header, removes duplicates, and accepts only RestoreStatus. Empty tokens are
// ignored, but a non-empty header containing no attributes is invalid.
func ParseOptionalObjectAttributes(v string) ([]types.OptionalObjectAttributes, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return nil, nil
	}
	seen := map[types.OptionalObjectAttributes]struct{}{}
	out := make([]types.OptionalObjectAttributes, 0, 2)
	for token := range strings.SplitSeq(raw, ",") {
		t := strings.TrimSpace(token)
		if t == "" {
			continue
		}
		var attr types.OptionalObjectAttributes
		switch strings.ToLower(t) {
		case strings.ToLower(string(types.OptionalObjectAttributesRestoreStatus)):
			attr = types.OptionalObjectAttributesRestoreStatus
		default:
			return nil, fmt.Errorf("unsupported optional object attribute %q", t)
		}
		if _, ok := seen[attr]; ok {
			continue
		}
		seen[attr] = struct{}{}
		out = append(out, attr)
	}
	if len(out) == 0 {
		return nil, errors.New("no optional object attributes requested")
	}
	return out, nil
}

// ParseMetadataDirective parses an optional, case-insensitive S3 metadata
// directive supported by the AWS SDK.
func ParseMetadataDirective(v string) (types.MetadataDirective, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return "", nil
	}
	for _, allowed := range types.MetadataDirective("").Values() {
		if strings.EqualFold(raw, string(allowed)) {
			return allowed, nil
		}
	}
	return "", fmt.Errorf("unsupported metadata directive %q", raw)
}

// ParseTaggingDirective parses an optional, case-insensitive S3 tagging
// directive supported by the AWS SDK.
func ParseTaggingDirective(v string) (types.TaggingDirective, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return "", nil
	}
	for _, allowed := range types.TaggingDirective("").Values() {
		if strings.EqualFold(raw, string(allowed)) {
			return allowed, nil
		}
	}
	return "", fmt.Errorf("unsupported tagging directive %q", raw)
}

// ParseStorageClass parses an optional, case-insensitive S3 storage class
// supported by the AWS SDK.
func ParseStorageClass(v string) (types.StorageClass, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return "", nil
	}
	for _, allowed := range types.StorageClass("").Values() {
		if strings.EqualFold(raw, string(allowed)) {
			return allowed, nil
		}
	}
	return "", fmt.Errorf("unsupported storage class %q", raw)
}

// ParseOptionalHTTPTime parses an HTTP date and normalizes it to UTC. Blank
// input returns nil without an error.
func ParseOptionalHTTPTime(v string) (*time.Time, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return nil, nil
	}
	t, err := http.ParseTime(raw)
	if err != nil {
		return nil, err
	}
	utc := t.UTC()
	return &utc, nil
}

// ParseOptionalBool parses an optional case-insensitive boolean. The second
// result reports whether a value was present.
func ParseOptionalBool(v string) (bool, bool, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return false, false, nil
	}
	switch strings.ToLower(raw) {
	case "true":
		return true, true, nil
	case "false":
		return false, true, nil
	default:
		return false, false, fmt.Errorf("invalid boolean %q", raw)
	}
}

// ParseSSECustomerHeaders extracts the three SSE-C request headers. The present
// result is true when any header is set; in that case all three are required.
// The function does not validate the algorithm, key encoding, or MD5 value.
func ParseSSECustomerHeaders(h http.Header) (algo, key, keyMD5 *string, present bool, err error) {
	a := strings.TrimSpace(h.Get("x-amz-server-side-encryption-customer-algorithm"))
	k := strings.TrimSpace(h.Get("x-amz-server-side-encryption-customer-key"))
	m := strings.TrimSpace(h.Get("x-amz-server-side-encryption-customer-key-md5"))
	present = a != "" || k != "" || m != ""
	if !present {
		return nil, nil, nil, false, nil
	}
	if a == "" || k == "" || m == "" {
		return nil, nil, nil, true, errors.New("incomplete SSE-C headers")
	}
	return aws.String(a), aws.String(k), aws.String(m), true, nil
}

// ParseCopySourceSSECustomerHeaders extracts the three copy-source SSE-C
// headers. The present result is true when any header is set; in that case all
// three are required. Header values are not cryptographically validated.
func ParseCopySourceSSECustomerHeaders(h http.Header) (algo, key, keyMD5 *string, present bool, err error) {
	a := strings.TrimSpace(h.Get("x-amz-copy-source-server-side-encryption-customer-algorithm"))
	k := strings.TrimSpace(h.Get("x-amz-copy-source-server-side-encryption-customer-key"))
	m := strings.TrimSpace(h.Get("x-amz-copy-source-server-side-encryption-customer-key-md5"))
	present = a != "" || k != "" || m != ""
	if !present {
		return nil, nil, nil, false, nil
	}
	if a == "" || k == "" || m == "" {
		return nil, nil, nil, true, errors.New("incomplete copy-source SSE-C headers")
	}
	return aws.String(a), aws.String(k), aws.String(m), true, nil
}

// ParseCopySourceConditionalHeaders extracts copy-source ETag and date
// preconditions. It returns an error when either non-empty date is invalid.
func ParseCopySourceConditionalHeaders(h http.Header) (ifMatch, ifNoneMatch *string, ifModifiedSince, ifUnmodifiedSince *time.Time, err error) {
	if raw := strings.TrimSpace(h.Get("x-amz-copy-source-if-match")); raw != "" {
		ifMatch = aws.String(raw)
	}
	if raw := strings.TrimSpace(h.Get("x-amz-copy-source-if-none-match")); raw != "" {
		ifNoneMatch = aws.String(raw)
	}
	if ifModifiedSince, err = ParseOptionalHTTPTime(h.Get("x-amz-copy-source-if-modified-since")); err != nil {
		return nil, nil, nil, nil, err
	}
	if ifUnmodifiedSince, err = ParseOptionalHTTPTime(h.Get("x-amz-copy-source-if-unmodified-since")); err != nil {
		return nil, nil, nil, nil, err
	}
	return ifMatch, ifNoneMatch, ifModifiedSince, ifUnmodifiedSince, nil
}

// SourceBucketFromCopySource returns the path-unescaped bucket segment from an
// x-amz-copy-source value. It accepts an optional leading slash and discards
// query parameters such as versionId.
func SourceBucketFromCopySource(copySource string) (string, error) {
	raw := strings.TrimSpace(copySource)
	if raw == "" {
		return "", errors.New("empty copy source")
	}
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.TrimPrefix(raw, "/")
	if raw == "" {
		return "", errors.New("invalid copy source")
	}
	parts := strings.SplitN(raw, "/", 2)
	bucketEnc := strings.TrimSpace(parts[0])
	if bucketEnc == "" {
		return "", errors.New("invalid copy source bucket")
	}
	bucket, err := url.PathUnescape(bucketEnc)
	if err != nil {
		return "", err
	}
	bucket = strings.TrimSpace(bucket)
	if bucket == "" {
		return "", errors.New("invalid copy source bucket")
	}
	return bucket, nil
}

// SSEWriteHeaders contains parsed server-side-encryption headers for an S3
// write request. Nil pointer fields were absent from the request.
type SSEWriteHeaders struct {
	ServerSideEncryption    types.ServerSideEncryption
	BucketKeyEnabled        *bool
	SSEKMSKeyID             *string
	SSEKMSEncryptionContext *string
	SSECustomerAlgorithm    *string
	SSECustomerKey          *string
	SSECustomerKeyMD5       *string
}

// ParseSSEWriteHeaders validates S3 write-encryption header combinations. KMS
// fields require aws:kms or aws:kms:dsse, and SSE-C cannot be combined with
// x-amz-server-side-encryption.
func ParseSSEWriteHeaders(h http.Header) (SSEWriteHeaders, error) {
	out := SSEWriteHeaders{}
	sse := strings.TrimSpace(h.Get("x-amz-server-side-encryption"))
	if sse != "" {
		switch strings.ToLower(sse) {
		case "aes256":
			out.ServerSideEncryption = types.ServerSideEncryptionAes256
		case "aws:kms":
			out.ServerSideEncryption = types.ServerSideEncryptionAwsKms
		case "aws:kms:dsse":
			out.ServerSideEncryption = types.ServerSideEncryptionAwsKmsDsse
		default:
			return out, fmt.Errorf("unsupported server-side encryption %q", sse)
		}
	}
	if values := h.Values("x-amz-server-side-encryption-bucket-key-enabled"); len(values) > 0 {
		if len(values) != 1 {
			return out, errors.New("multiple bucket-key-enabled headers are not supported")
		}
		enabled, present, err := ParseOptionalBool(values[0])
		if err != nil || !present {
			return out, errors.New("invalid bucket-key-enabled header")
		}
		if out.ServerSideEncryption != "" && out.ServerSideEncryption != types.ServerSideEncryptionAwsKms {
			return out, errors.New("bucket-key-enabled requires aws:kms encryption")
		}
		out.BucketKeyEnabled = aws.Bool(enabled)
	}

	kmsKeyID := strings.TrimSpace(h.Get("x-amz-server-side-encryption-aws-kms-key-id"))
	if kmsKeyID != "" {
		if out.ServerSideEncryption != types.ServerSideEncryptionAwsKms &&
			out.ServerSideEncryption != types.ServerSideEncryptionAwsKmsDsse {
			return out, errors.New("kms key id requires aws:kms or aws:kms:dsse")
		}
		out.SSEKMSKeyID = aws.String(kmsKeyID)
	}

	kmsCtx := strings.TrimSpace(h.Get("x-amz-server-side-encryption-context"))
	if kmsCtx != "" {
		if out.ServerSideEncryption != types.ServerSideEncryptionAwsKms &&
			out.ServerSideEncryption != types.ServerSideEncryptionAwsKmsDsse {
			return out, errors.New("kms context requires aws:kms or aws:kms:dsse")
		}
		out.SSEKMSEncryptionContext = aws.String(kmsCtx)
	}

	ssecAlgo, ssecKey, ssecMD5, presentSSEC, err := ParseSSECustomerHeaders(h)
	if err != nil {
		return out, err
	}
	if presentSSEC {
		if out.ServerSideEncryption != "" {
			return out, errors.New("SSE-C cannot be combined with x-amz-server-side-encryption")
		}
		if out.BucketKeyEnabled != nil {
			return out, errors.New("SSE-C cannot be combined with bucket-key-enabled")
		}
		out.SSECustomerAlgorithm = ssecAlgo
		out.SSECustomerKey = ssecKey
		out.SSECustomerKeyMD5 = ssecMD5
	}

	return out, nil
}

// ChecksumWriteHeaders contains checksum selection and value headers from an
// S3 write request. At most one checksum value field may be non-nil.
type ChecksumWriteHeaders struct {
	ChecksumAlgorithm types.ChecksumAlgorithm
	ChecksumCRC32     *string
	ChecksumCRC32C    *string
	ChecksumCRC64NVME *string
	ChecksumSHA1      *string
	ChecksumSHA256    *string
}

// ParseChecksumAlgorithmHeader parses an optional checksum algorithm. CRC32,
// CRC32C, CRC64NVME, SHA1, and SHA256 are accepted case-insensitively.
func ParseChecksumAlgorithmHeader(v string) (types.ChecksumAlgorithm, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return "", nil
	}
	switch strings.ToUpper(raw) {
	case "CRC32":
		return types.ChecksumAlgorithmCrc32, nil
	case "CRC32C":
		return types.ChecksumAlgorithmCrc32c, nil
	case "CRC64NVME":
		return types.ChecksumAlgorithmCrc64nvme, nil
	case "SHA1":
		return types.ChecksumAlgorithmSha1, nil
	case "SHA256":
		return types.ChecksumAlgorithmSha256, nil
	default:
		return "", fmt.Errorf("unsupported checksum algorithm %q", raw)
	}
}

// ParseChecksumTypeHeader parses an optional checksum type. FULL_OBJECT and
// COMPOSITE are accepted case-insensitively.
func ParseChecksumTypeHeader(v string) (types.ChecksumType, error) {
	raw := strings.TrimSpace(v)
	switch strings.ToUpper(raw) {
	case "":
		return "", nil
	case "FULL_OBJECT":
		return types.ChecksumTypeFullObject, nil
	case "COMPOSITE":
		return types.ChecksumTypeComposite, nil
	default:
		return "", fmt.Errorf("unsupported checksum type %q", raw)
	}
}

// ParseChecksumWriteHeaders extracts the selected algorithm and checksum value
// headers, accepting either algorithm-selection header. For verified streaming
// trailer payloads, a declared checksum trailer selects the upstream algorithm
// while value fields remain unset unless supplied as request headers. Conflicting
// algorithms and multiple checksum value headers are rejected.
func ParseChecksumWriteHeaders(h http.Header) (ChecksumWriteHeaders, error) {
	out := ChecksumWriteHeaders{}
	for _, name := range []string{"x-amz-checksum-algorithm", "x-amz-sdk-checksum-algorithm"} {
		for _, value := range h.Values(name) {
			algorithm, err := ParseChecksumAlgorithmHeader(value)
			if err != nil {
				return out, err
			}
			if algorithm == "" {
				continue
			}
			if out.ChecksumAlgorithm != "" && out.ChecksumAlgorithm != algorithm {
				return out, errors.New("conflicting checksum algorithm headers")
			}
			out.ChecksumAlgorithm = algorithm
		}
	}

	var setCount int
	var valueAlgorithm types.ChecksumAlgorithm
	setField := func(v string, algorithm types.ChecksumAlgorithm) *string {
		s := strings.TrimSpace(v)
		if s == "" {
			return nil
		}
		setCount++
		valueAlgorithm = algorithm
		return aws.String(s)
	}
	out.ChecksumCRC32 = setField(h.Get("x-amz-checksum-crc32"), types.ChecksumAlgorithmCrc32)
	out.ChecksumCRC32C = setField(h.Get("x-amz-checksum-crc32c"), types.ChecksumAlgorithmCrc32c)
	out.ChecksumCRC64NVME = setField(h.Get("x-amz-checksum-crc64nvme"), types.ChecksumAlgorithmCrc64nvme)
	out.ChecksumSHA1 = setField(h.Get("x-amz-checksum-sha1"), types.ChecksumAlgorithmSha1)
	out.ChecksumSHA256 = setField(h.Get("x-amz-checksum-sha256"), types.ChecksumAlgorithmSha256)

	if setCount > 1 {
		return out, errors.New("multiple checksum value headers are not allowed")
	}
	trailerAlgorithm, err := checksumTrailerAlgorithm(h)
	if err != nil {
		return out, err
	}
	if trailerAlgorithm != "" {
		if out.ChecksumAlgorithm != "" && out.ChecksumAlgorithm != trailerAlgorithm {
			return out, errors.New("checksum trailer does not match the selected algorithm")
		}
		out.ChecksumAlgorithm = trailerAlgorithm
	}
	if valueAlgorithm != "" && out.ChecksumAlgorithm != "" && valueAlgorithm != out.ChecksumAlgorithm {
		return out, errors.New("checksum value header does not match the selected algorithm")
	}
	return out, nil
}

func checksumTrailerAlgorithm(h http.Header) (types.ChecksumAlgorithm, error) {
	// Match the modes whose declared checksums DecodeBodyForS3Write verifies.
	switch strings.ToUpper(strings.TrimSpace(h.Get("x-amz-content-sha256"))) {
	case "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", "STREAMING-UNSIGNED-PAYLOAD-TRAILER":
	default:
		return "", nil
	}

	var selected types.ChecksumAlgorithm
	for _, value := range h.Values("x-amz-trailer") {
		for name := range strings.SplitSeq(value, ",") {
			name = strings.ToLower(strings.TrimSpace(name))
			algorithmName, isChecksum := strings.CutPrefix(name, "x-amz-checksum-")
			if !isChecksum {
				continue
			}
			algorithm, err := ParseChecksumAlgorithmHeader(algorithmName)
			if err != nil || algorithm == "" {
				return "", fmt.Errorf("unsupported checksum trailer %q", name)
			}
			if selected != "" && selected != algorithm {
				return "", errors.New("multiple checksum trailer algorithms are not allowed")
			}
			selected = algorithm
		}
	}
	return selected, nil
}

// ParseChecksumMode parses the optional x-amz-checksum-mode value. ENABLED is
// the only accepted non-empty value and is matched case-insensitively.
func ParseChecksumMode(v string) (types.ChecksumMode, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return "", nil
	}
	switch strings.ToUpper(raw) {
	case "ENABLED":
		return types.ChecksumModeEnabled, nil
	default:
		return "", fmt.Errorf("unsupported checksum mode %q", raw)
	}
}
