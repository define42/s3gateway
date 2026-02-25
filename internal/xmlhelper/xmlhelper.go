package xmlhelper

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const (
	s3XMLNamespace     = "http://s3.amazonaws.com/doc/2006-03-01/"
	s3TimeMillisFormat = "2006-01-02T15:04:05.000Z"
	xmlDeclaration     = `<?xml version="1.0" encoding="UTF-8"?>`
)

var xmlEscaper = strings.NewReplacer(
	`&`, "&amp;",
	`<`, "&lt;",
	`>`, "&gt;",
	`"`, "&quot;",
	`'`, "&apos;",
)

// ==================== XML helpers ====================
func XMLEscape(s string) string {
	return xmlEscaper.Replace(s)
}

func FormatS3Time(t time.Time) string {
	return t.UTC().Format(s3TimeMillisFormat)
}

func BoolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func WriteXMLError(w http.ResponseWriter, status int, code, msg string) {
	xw := BeginXMLWriterResponse(w, status)
	xw.Start("Error")
	xw.Elem("Code", code)
	xw.Elem("Message", msg)
	xw.End("Error")
	_ = xw.Flush()
}

func beginXMLResponse(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
}

type XMLWriter struct {
	enc *xml.Encoder
	out io.Writer
	err error
}

func BeginXMLWriterResponse(w http.ResponseWriter, status int) *XMLWriter {
	beginXMLResponse(w, status)
	xw := &XMLWriter{enc: xml.NewEncoder(w), out: w}
	_, err := io.WriteString(w, xmlDeclaration)
	xw.setErr(err)
	return xw
}

func FlushXMLWriterResponse(xw *XMLWriter) {
	_ = xw.Flush()
}

func (xw *XMLWriter) setErr(err error) {
	if xw.err == nil {
		xw.err = err
	}
}

func (xw *XMLWriter) Start(name string, attrs ...xml.Attr) {
	if xw.err != nil {
		return
	}
	xw.setErr(xw.enc.EncodeToken(xml.StartElement{Name: xml.Name{Local: name}, Attr: attrs}))
}

func (xw *XMLWriter) End(name string) {
	if xw.err != nil {
		return
	}
	xw.setErr(xw.enc.EncodeToken(xml.EndElement{Name: xml.Name{Local: name}}))
}

func (xw *XMLWriter) Elem(name, value string) {
	if xw.err != nil {
		return
	}
	xw.setErr(xw.enc.EncodeElement(value, xml.StartElement{Name: xml.Name{Local: name}}))
}

func (xw *XMLWriter) RawString(value string) {
	if xw.err != nil {
		return
	}
	if err := xw.enc.Flush(); err != nil {
		xw.setErr(err)
		return
	}
	_, err := io.WriteString(xw.out, value)
	xw.setErr(err)
}

func (xw *XMLWriter) ElemInt(name string, value int64) {
	xw.Elem(name, strconv.FormatInt(value, 10))
}

func (xw *XMLWriter) ElemBool(name string, value bool) {
	xw.Elem(name, BoolString(value))
}

func (xw *XMLWriter) Flush() error {
	if xw.err != nil {
		return xw.err
	}
	if err := xw.enc.Flush(); err != nil {
		xw.setErr(err)
	}
	return xw.err
}

func EncodeS3RootStart(xw *XMLWriter, name string) {
	xw.Start(name, xml.Attr{
		Name:  xml.Name{Local: "xmlns"},
		Value: s3XMLNamespace,
	})
}

func EncodeCommonPrefixes(xw *XMLWriter, prefixes []types.CommonPrefix) {
	for _, cp := range prefixes {
		if cp.Prefix == nil {
			continue
		}
		xw.Start("CommonPrefixes")
		xw.Elem("Prefix", *cp.Prefix)
		xw.End("CommonPrefixes")
	}
}

func EncodeOwnerIDThenDisplayName(xw *XMLWriter, owner *types.Owner) {
	if owner == nil {
		return
	}
	xw.Start("Owner")
	if owner.ID != nil {
		xw.Elem("ID", *owner.ID)
	}
	if owner.DisplayName != nil {
		xw.Elem("DisplayName", *owner.DisplayName)
	}
	xw.End("Owner")
}

func EncodeOwnerDisplayNameThenID(xw *XMLWriter, owner *types.Owner) {
	if owner == nil {
		return
	}
	xw.Start("Owner")
	if owner.DisplayName != nil {
		xw.Elem("DisplayName", *owner.DisplayName)
	}
	if owner.ID != nil {
		xw.Elem("ID", *owner.ID)
	}
	xw.End("Owner")
}

func EncodeInitiatorDisplayNameThenID(xw *XMLWriter, initiator *types.Initiator) {
	if initiator == nil {
		return
	}
	xw.Start("Initiator")
	if initiator.DisplayName != nil {
		xw.Elem("DisplayName", *initiator.DisplayName)
	}
	if initiator.ID != nil {
		xw.Elem("ID", *initiator.ID)
	}
	xw.End("Initiator")
}

func EncodeRestoreStatus(xw *XMLWriter, restore *types.RestoreStatus) {
	if restore == nil {
		return
	}
	xw.Start("RestoreStatus")
	if restore.IsRestoreInProgress != nil {
		xw.ElemBool("IsRestoreInProgress", *restore.IsRestoreInProgress)
	}
	if restore.RestoreExpiryDate != nil {
		xw.Elem("RestoreExpiryDate", FormatS3Time(*restore.RestoreExpiryDate))
	}
	xw.End("RestoreStatus")
}

type upstreamErrorInfo struct {
	status  int
	code    string
	message string
	headers http.Header
}

func extractUpstreamErrorInfo(err error) upstreamErrorInfo {
	info := upstreamErrorInfo{
		status:  http.StatusBadGateway,
		code:    "BadGateway",
		message: "Upstream error",
		headers: make(http.Header),
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		if c := strings.TrimSpace(apiErr.ErrorCode()); c != "" {
			info.code = c
		}
		if m := strings.TrimSpace(apiErr.ErrorMessage()); m != "" {
			info.message = m
		}
		if info.status == http.StatusBadGateway && apiErr.ErrorFault() == smithy.FaultClient {
			info.status = http.StatusBadRequest
		}
	}

	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		if sc := respErr.HTTPStatusCode(); sc > 0 {
			info.status = sc
		}
		if hr := respErr.HTTPResponse(); hr != nil {
			for k, vals := range hr.Header {
				kl := strings.ToLower(k)
				if strings.HasPrefix(kl, "x-amz-") || kl == "retry-after" {
					for _, v := range vals {
						info.headers.Add(k, v)
					}
				}
			}
		}
	}
	return info
}

func WriteUpstreamError(w http.ResponseWriter, err error) {
	info := extractUpstreamErrorInfo(err)
	for k, vals := range info.headers {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	WriteXMLError(w, info.status, info.code, info.message)
}

func WriteUpstreamHeadError(w http.ResponseWriter, err error) {
	info := extractUpstreamErrorInfo(err)
	for k, vals := range info.headers {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(info.status)
}

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

func ParseOptionalObjectAttributes(v string) ([]types.OptionalObjectAttributes, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return nil, nil
	}
	seen := map[types.OptionalObjectAttributes]struct{}{}
	out := make([]types.OptionalObjectAttributes, 0, 2)
	for _, token := range strings.Split(raw, ",") {
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

func ParseObjectCannedACL(v string) (types.ObjectCannedACL, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return "", nil
	}
	for _, allowed := range types.ObjectCannedACL("").Values() {
		if strings.EqualFold(raw, string(allowed)) {
			return allowed, nil
		}
	}
	return "", fmt.Errorf("unsupported x-amz-acl %q", raw)
}

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

type SSEWriteHeaders struct {
	ServerSideEncryption    types.ServerSideEncryption
	SSEKMSKeyID             *string
	SSEKMSEncryptionContext *string
	SSECustomerAlgorithm    *string
	SSECustomerKey          *string
	SSECustomerKeyMD5       *string
}

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
		out.SSECustomerAlgorithm = ssecAlgo
		out.SSECustomerKey = ssecKey
		out.SSECustomerKeyMD5 = ssecMD5
	}

	return out, nil
}

type ChecksumWriteHeaders struct {
	ChecksumAlgorithm types.ChecksumAlgorithm
	ChecksumCRC32     *string
	ChecksumCRC32C    *string
	ChecksumCRC64NVME *string
	ChecksumSHA1      *string
	ChecksumSHA256    *string
}

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

func ParseChecksumWriteHeaders(h http.Header) (ChecksumWriteHeaders, error) {
	out := ChecksumWriteHeaders{}
	var err error
	out.ChecksumAlgorithm, err = ParseChecksumAlgorithmHeader(h.Get("x-amz-checksum-algorithm"))
	if err != nil {
		return out, err
	}

	var setCount int
	setField := func(v string) *string {
		s := strings.TrimSpace(v)
		if s == "" {
			return nil
		}
		setCount++
		return aws.String(s)
	}
	out.ChecksumCRC32 = setField(h.Get("x-amz-checksum-crc32"))
	out.ChecksumCRC32C = setField(h.Get("x-amz-checksum-crc32c"))
	out.ChecksumCRC64NVME = setField(h.Get("x-amz-checksum-crc64nvme"))
	out.ChecksumSHA1 = setField(h.Get("x-amz-checksum-sha1"))
	out.ChecksumSHA256 = setField(h.Get("x-amz-checksum-sha256"))

	if setCount > 1 {
		return out, errors.New("multiple checksum value headers are not allowed")
	}
	return out, nil
}

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
