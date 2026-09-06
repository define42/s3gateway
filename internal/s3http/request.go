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

// ChecksumWriteHeaders contains checksum selection and value headers from an
// S3 write request. At most one checksum value field may be non-nil.
type ChecksumWriteHeaders struct {
	ChecksumAlgorithm types.ChecksumAlgorithm
	ChecksumType      types.ChecksumType
	ChecksumCRC32     *string
	ChecksumCRC32C    *string
	ChecksumCRC64NVME *string
	ChecksumSHA1      *string
	ChecksumSHA256    *string
}

// HasValue reports whether the request supplies a checksum value, as opposed
// to asking the upstream to select or calculate a checksum.
func (h ChecksumWriteHeaders) HasValue() bool {
	return h.ChecksumCRC32 != nil || h.ChecksumCRC32C != nil || h.ChecksumCRC64NVME != nil ||
		h.ChecksumSHA1 != nil || h.ChecksumSHA256 != nil
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
// algorithms, unknown headers, empty values, and repeated headers are rejected.
// Callers must reject parsed fields their particular operation cannot forward.
func ParseChecksumWriteHeaders(h http.Header) (ChecksumWriteHeaders, error) {
	out := ChecksumWriteHeaders{}
	var valueAlgorithm types.ChecksumAlgorithm
	seen := make(map[string]bool)
	for name, values := range h {
		name = strings.ToLower(name)
		if !strings.HasPrefix(name, "x-amz-checksum-") && name != "x-amz-sdk-checksum-algorithm" {
			continue
		}
		if seen[name] || len(values) != 1 || strings.TrimSpace(values[0]) == "" {
			return out, fmt.Errorf("%s must contain one nonempty value", name)
		}
		seen[name] = true
		value := strings.TrimSpace(values[0])
		var field **string
		var algorithm types.ChecksumAlgorithm
		switch name {
		case "x-amz-checksum-algorithm", "x-amz-sdk-checksum-algorithm":
			algorithm, err := ParseChecksumAlgorithmHeader(value)
			if err != nil {
				return out, err
			}
			if out.ChecksumAlgorithm != "" && out.ChecksumAlgorithm != algorithm {
				return out, errors.New("conflicting checksum algorithm headers")
			}
			out.ChecksumAlgorithm = algorithm
			continue
		case "x-amz-checksum-type":
			checksumType, err := ParseChecksumTypeHeader(value)
			if err != nil {
				return out, err
			}
			out.ChecksumType = checksumType
			continue
		case "x-amz-checksum-crc32":
			field, algorithm = &out.ChecksumCRC32, types.ChecksumAlgorithmCrc32
		case "x-amz-checksum-crc32c":
			field, algorithm = &out.ChecksumCRC32C, types.ChecksumAlgorithmCrc32c
		case "x-amz-checksum-crc64nvme":
			field, algorithm = &out.ChecksumCRC64NVME, types.ChecksumAlgorithmCrc64nvme
		case "x-amz-checksum-sha1":
			field, algorithm = &out.ChecksumSHA1, types.ChecksumAlgorithmSha1
		case "x-amz-checksum-sha256":
			field, algorithm = &out.ChecksumSHA256, types.ChecksumAlgorithmSha256
		default:
			return out, fmt.Errorf("unsupported checksum header %q", name)
		}
		if out.HasValue() {
			return out, errors.New("multiple checksum value headers are not allowed")
		}
		*field = aws.String(value)
		valueAlgorithm = algorithm
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
