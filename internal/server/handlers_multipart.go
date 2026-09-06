package server

import (
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	authz "github.com/define42/s3gateway/internal/authz"
	"github.com/define42/s3gateway/internal/s3http"
	"github.com/define42/s3gateway/internal/s3xml"
	sigv4 "github.com/define42/s3gateway/internal/sigv4"
	"github.com/define42/s3gateway/internal/uploadnotify"
	"github.com/define42/s3gateway/internal/upstream"
)

const (
	maxUploadPartSize                 = int64(5 * 1024 * 1024 * 1024) // 5 GiB
	maxCompleteMultipartBodyBytes     = int64(4 * 1024 * 1024)
	maxCompleteMultipartParts         = 10_000
	maxCompleteMultipartETagBytes     = 256
	maxCompleteMultipartChecksumBytes = 256
)

var completeMultipartDecodeLimits = s3xml.DecodeLimits{
	MaxBodyBytes:      maxCompleteMultipartBodyBytes,
	MaxDepth:          8,
	MaxElements:       8*maxCompleteMultipartParts + 1,
	MaxAttributes:     16,
	MaxAttributeBytes: 2048,
	ElementLimits: map[string]int{
		"Part":              maxCompleteMultipartParts,
		"PartNumber":        maxCompleteMultipartParts,
		"ETag":              maxCompleteMultipartParts,
		"ChecksumCRC32":     maxCompleteMultipartParts,
		"ChecksumCRC32C":    maxCompleteMultipartParts,
		"ChecksumCRC64NVME": maxCompleteMultipartParts,
		"ChecksumSHA1":      maxCompleteMultipartParts,
		"ChecksumSHA256":    maxCompleteMultipartParts,
	},
	FieldByteLimits: map[string]int{
		"PartNumber":        16,
		"ETag":              maxCompleteMultipartETagBytes,
		"ChecksumCRC32":     maxCompleteMultipartChecksumBytes,
		"ChecksumCRC32C":    maxCompleteMultipartChecksumBytes,
		"ChecksumCRC64NVME": maxCompleteMultipartChecksumBytes,
		"ChecksumSHA1":      maxCompleteMultipartChecksumBytes,
		"ChecksumSHA256":    maxCompleteMultipartChecksumBytes,
	},
}

func (s *Server) handleListMultipartUploads(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanRead(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	payer, err := s3http.ParseRequestPayerHeader(r.Header)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", err.Error())
		return
	}
	in := &s3.ListMultipartUploadsInput{Bucket: &bucket, RequestPayer: payer}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	q := r.URL.Query()
	if v := q.Get("prefix"); v != "" {
		in.Prefix = &v
	}
	if v := q.Get("delimiter"); v != "" {
		in.Delimiter = &v
	}
	if v := q.Get("key-marker"); v != "" {
		in.KeyMarker = &v
	}
	if v := q.Get("upload-id-marker"); v != "" {
		in.UploadIdMarker = &v
	}
	if v := q.Get("encoding-type"); v != "" {
		in.EncodingType = types.EncodingType(v)
	}
	if v := q.Get("max-uploads"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil || n <= 0 {
			s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "invalid max-uploads")
			return
		}
		in.MaxUploads = aws.Int32(int32(n))
	}

	out, err := s.up.ListMultipartUploads(r.Context(), in)
	if err != nil {
		s3http.WriteUpstreamError(w, err)
		return
	}

	xw := s3xml.BeginResponse(w, http.StatusOK)
	defer s3xml.FlushResponse(xw)

	s3xml.EncodeRootStart(xw, "ListMultipartUploadsResult")
	xw.Elem("Bucket", bucket)
	if out.EncodingType != "" {
		xw.Elem("EncodingType", string(out.EncodingType))
	}
	if out.KeyMarker != nil {
		xw.Elem("KeyMarker", *out.KeyMarker)
	}
	if out.UploadIdMarker != nil {
		xw.Elem("UploadIdMarker", *out.UploadIdMarker)
	}
	if out.NextKeyMarker != nil {
		xw.Elem("NextKeyMarker", *out.NextKeyMarker)
	}
	if out.NextUploadIdMarker != nil {
		xw.Elem("NextUploadIdMarker", *out.NextUploadIdMarker)
	}
	if out.Prefix != nil {
		xw.Elem("Prefix", *out.Prefix)
	}
	if out.Delimiter != nil {
		xw.Elem("Delimiter", *out.Delimiter)
	}
	if out.MaxUploads != nil {
		xw.ElemInt("MaxUploads", int64(*out.MaxUploads))
	}
	xw.ElemBool("IsTruncated", aws.ToBool(out.IsTruncated))
	s3xml.EncodeCommonPrefixes(xw, out.CommonPrefixes)
	for _, u := range out.Uploads {
		xw.Start("Upload")
		if u.Key != nil {
			xw.Elem("Key", *u.Key)
		}
		if u.UploadId != nil {
			xw.Elem("UploadId", *u.UploadId)
		}
		if u.Initiated != nil {
			xw.Elem("Initiated", s3xml.FormatTime(*u.Initiated))
		}
		if u.StorageClass != "" {
			xw.Elem("StorageClass", string(u.StorageClass))
		}
		if u.ChecksumAlgorithm != "" {
			xw.Elem("ChecksumAlgorithm", string(u.ChecksumAlgorithm))
		}
		if u.ChecksumType != "" {
			xw.Elem("ChecksumType", string(u.ChecksumType))
		}
		s3xml.EncodeOwnerDisplayNameThenID(xw, u.Owner)
		s3xml.EncodeInitiatorDisplayNameThenID(xw, u.Initiator)
		xw.End("Upload")
	}
	xw.End("ListMultipartUploadsResult")
}

type completeMultipartUpload struct {
	XMLName xml.Name `xml:"CompleteMultipartUpload"`
	Parts   []struct {
		PartNumber        completeMultipartPartNumber         `xml:"PartNumber"`
		ETag              completeMultipartETag               `xml:"ETag"`
		ChecksumCRC32     completeMultipartChecksum           `xml:"ChecksumCRC32"`
		ChecksumCRC32C    completeMultipartChecksum           `xml:"ChecksumCRC32C"`
		ChecksumCRC64NVME completeMultipartChecksum           `xml:"ChecksumCRC64NVME"`
		ChecksumSHA1      completeMultipartChecksum           `xml:"ChecksumSHA1"`
		ChecksumSHA256    completeMultipartChecksum           `xml:"ChecksumSHA256"`
		Unsupported       unsupportedCompleteMultipartElement `xml:",any"`
	} `xml:"Part"`
	Unsupported unsupportedCompleteMultipartElement `xml:",any"`
}

func decodeCompleteMultipartUpload(r io.Reader) (completeMultipartUpload, error) {
	var upload completeMultipartUpload
	err := s3xml.DecodeLimited(r, &upload, completeMultipartDecodeLimits)
	return upload, err
}

func (s *Server) handleCreateMultipart(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanWrite(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}
	if !requireOwnerRetainingACLHeaders(w, r, false) {
		return
	}
	if !requireSupportedUploadProperties(w, r) {
		return
	}
	properties, err := parseUploadProperties(r)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", err.Error())
		return
	}

	ct := r.Header.Get("Content-Type")
	meta := extractAmzMeta(r.Header)
	meta = ensureUploadedByMetadata(meta, UploaderFromRequest(r))
	if missing := missingRequiredUploadMetadata(meta, s.cfg.RequiredUploadMetadataKeys); len(missing) > 0 {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidRequest", "Missing required metadata header(s): "+strings.Join(missing, ", "))
		return
	}
	expires, err := parseExpiresHeader(r.Header)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "invalid Expires header")
		return
	}
	checksum, err := s3http.ParseChecksumWriteHeaders(r.Header)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", err.Error())
		return
	}
	if checksum.HasValue() {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "Checksum value headers are not supported for CreateMultipartUpload")
		return
	}
	payer, err := s3http.ParseRequestPayerHeader(r.Header)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	}

	in := &s3.CreateMultipartUploadInput{
		Bucket:                  &bucket,
		Key:                     &key,
		Metadata:                meta,
		Expires:                 expires,
		ChecksumType:            checksum.ChecksumType,
		CacheControl:            properties.CacheControl,
		ContentDisposition:      properties.ContentDisposition,
		ContentEncoding:         properties.ContentEncoding,
		ContentLanguage:         properties.ContentLanguage,
		Tagging:                 properties.Tagging,
		StorageClass:            properties.StorageClass,
		WebsiteRedirectLocation: properties.WebsiteRedirectLocation,
		RequestPayer:            payer,
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if ct != "" {
		in.ContentType = &ct
	}
	if checksum.ChecksumAlgorithm != "" {
		in.ChecksumAlgorithm = checksum.ChecksumAlgorithm
	}

	out, err := s.up.CreateMultipartUpload(r.Context(), in)
	if err != nil {
		s3http.WriteUpstreamError(w, err)
		return
	}
	if out.ChecksumAlgorithm != "" {
		w.Header().Set("x-amz-checksum-algorithm", string(out.ChecksumAlgorithm))
	}
	if out.ChecksumType != "" {
		w.Header().Set("x-amz-checksum-type", string(out.ChecksumType))
	}

	xw := s3xml.BeginResponse(w, http.StatusOK)
	defer s3xml.FlushResponse(xw)

	s3xml.EncodeRootStart(xw, "InitiateMultipartUploadResult")
	xw.Elem("Bucket", bucket)
	xw.Elem("Key", key)
	xw.Elem("UploadId", aws.ToString(out.UploadId))
	xw.End("InitiateMultipartUploadResult")
}

func (s *Server) handleUploadPart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string, partNumber int32) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanWrite(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	verifier, err := sigv4.ChunkSignatureVerifierFromRequest(r)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidRequest", "Unsupported or invalid streaming payload signature")
		return
	}

	body, cl, err := sigv4.DecodeBodyForS3Write(r, verifier)
	if err != nil {
		if errors.Is(err, sigv4.ErrContentLengthRequired) || errors.Is(err, sigv4.ErrMissingDecodedContentLength) || errors.Is(err, sigv4.ErrInvalidDecodedContentLength) {
			s3xml.WriteError(w, http.StatusLengthRequired, "MissingContentLength", "Content-Length required")
			return
		}
		if writeBodyValidationError(w, err, nil) {
			return
		}
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidRequest", "Invalid request body")
		return
	}
	defer func() { _ = body.Close() }()
	if cl > maxUploadPartSize {
		s3xml.WriteError(w, http.StatusBadRequest, "EntityTooLarge", "Multipart parts cannot exceed 5 GiB")
		return
	}
	payer, err := s3http.ParseRequestPayerHeader(r.Header)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", err.Error())
		return
	}
	checksum, err := s3http.ParseChecksumWriteHeaders(r.Header)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", err.Error())
		return
	}
	if checksum.ChecksumType != "" {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "Checksum type is not supported for UploadPart")
		return
	}
	contentMD5 := strings.TrimSpace(r.Header.Get("Content-MD5"))

	in := &s3.UploadPartInput{
		Bucket:        &bucket,
		Key:           &key,
		UploadId:      &uploadID,
		PartNumber:    aws.Int32(partNumber),
		Body:          body,
		ContentLength: aws.Int64(cl),
		RequestPayer:  payer,
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if checksum.ChecksumAlgorithm != "" {
		in.ChecksumAlgorithm = checksum.ChecksumAlgorithm
	}
	in.ChecksumCRC32 = checksum.ChecksumCRC32
	in.ChecksumCRC32C = checksum.ChecksumCRC32C
	in.ChecksumCRC64NVME = checksum.ChecksumCRC64NVME
	in.ChecksumSHA1 = checksum.ChecksumSHA1
	in.ChecksumSHA256 = checksum.ChecksumSHA256
	if contentMD5 != "" {
		in.ContentMD5 = aws.String(contentMD5)
	}

	out, err := s.up.UploadPart(r.Context(), in,
		// Allow streaming io.Reader without Seek.
		s3.WithAPIOptions(v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware),
	)
	if err != nil {
		if writeBodyValidationError(w, err, body) {
			return
		}
		s3http.WriteUpstreamError(w, err)
		return
	}

	if out.ETag != nil {
		w.Header().Set("ETag", *out.ETag)
	}
	if out.ChecksumCRC32 != nil {
		w.Header().Set("x-amz-checksum-crc32", *out.ChecksumCRC32)
	}
	if out.ChecksumCRC32C != nil {
		w.Header().Set("x-amz-checksum-crc32c", *out.ChecksumCRC32C)
	}
	if out.ChecksumCRC64NVME != nil {
		w.Header().Set("x-amz-checksum-crc64nvme", *out.ChecksumCRC64NVME)
	}
	if out.ChecksumSHA1 != nil {
		w.Header().Set("x-amz-checksum-sha1", *out.ChecksumSHA1)
	}
	if out.ChecksumSHA256 != nil {
		w.Header().Set("x-amz-checksum-sha256", *out.ChecksumSHA256)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleListParts(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanRead(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	payer, err := s3http.ParseRequestPayerHeader(r.Header)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", err.Error())
		return
	}
	in := &s3.ListPartsInput{
		Bucket:       &bucket,
		Key:          &key,
		UploadId:     &uploadID,
		RequestPayer: payer,
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}

	if pnmStr := r.URL.Query().Get("part-number-marker"); pnmStr != "" {
		pnm, err := strconv.Atoi(pnmStr)
		if err != nil || pnm < 0 {
			s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "invalid part-number-marker")
			return
		}
		in.PartNumberMarker = aws.String(strconv.Itoa(pnm))
	}
	if mpStr := r.URL.Query().Get("max-parts"); mpStr != "" {
		mp, err := strconv.ParseInt(mpStr, 10, 32)
		if err != nil || mp <= 0 {
			s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "invalid max-parts")
			return
		}
		in.MaxParts = aws.Int32(int32(mp))
	}

	out, err := s.up.ListParts(r.Context(), in)
	if err != nil {
		s3http.WriteUpstreamError(w, err)
		return
	}

	xw := s3xml.BeginResponse(w, http.StatusOK)
	defer s3xml.FlushResponse(xw)

	s3xml.EncodeRootStart(xw, "ListPartsResult")
	xw.Elem("Bucket", bucket)
	xw.Elem("Key", key)
	xw.Elem("UploadId", uploadID)
	xw.Elem("PartNumberMarker", aws.ToString(out.PartNumberMarker))
	xw.Elem("NextPartNumberMarker", aws.ToString(out.NextPartNumberMarker))
	xw.ElemInt("MaxParts", int64(aws.ToInt32(out.MaxParts)))
	xw.ElemBool("IsTruncated", aws.ToBool(out.IsTruncated))
	if out.ChecksumAlgorithm != "" {
		xw.Elem("ChecksumAlgorithm", string(out.ChecksumAlgorithm))
	}
	if out.ChecksumType != "" {
		xw.Elem("ChecksumType", string(out.ChecksumType))
	}
	for _, p := range out.Parts {
		xw.Start("Part")
		xw.ElemInt("PartNumber", int64(aws.ToInt32(p.PartNumber)))
		if p.LastModified != nil {
			xw.Elem("LastModified", s3xml.FormatTime(*p.LastModified))
		}
		if p.ETag != nil {
			xw.Elem("ETag", *p.ETag)
		}
		xw.ElemInt("Size", aws.ToInt64(p.Size))
		if p.ChecksumCRC32 != nil {
			xw.Elem("ChecksumCRC32", *p.ChecksumCRC32)
		}
		if p.ChecksumCRC32C != nil {
			xw.Elem("ChecksumCRC32C", *p.ChecksumCRC32C)
		}
		if p.ChecksumCRC64NVME != nil {
			xw.Elem("ChecksumCRC64NVME", *p.ChecksumCRC64NVME)
		}
		if p.ChecksumSHA1 != nil {
			xw.Elem("ChecksumSHA1", *p.ChecksumSHA1)
		}
		if p.ChecksumSHA256 != nil {
			xw.Elem("ChecksumSHA256", *p.ChecksumSHA256)
		}
		xw.End("Part")
	}
	xw.End("ListPartsResult")
}

// CompleteMultipartUpload preserves each part's ETag and optional checksums.
func (s *Server) handleCompleteMultipart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanWrite(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}
	payer, err := s3http.ParseRequestPayerHeader(r.Header)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", err.Error())
		return
	}
	ifMatch := strings.TrimSpace(r.Header.Get("If-Match"))
	ifNoneMatch := strings.TrimSpace(r.Header.Get("If-None-Match"))
	if ifMatch != "" && ifNoneMatch != "" {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidRequest", "If-Match and If-None-Match cannot both be set")
		return
	}
	checksum, err := s3http.ParseChecksumWriteHeaders(r.Header)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", err.Error())
		return
	}
	if checksum.ChecksumAlgorithm != "" {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "Checksum algorithm selection is not supported for CompleteMultipartUpload")
		return
	}
	var objectSize *int64
	if raw := strings.TrimSpace(r.Header.Get("x-amz-mp-object-size")); raw != "" {
		size, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || size < 0 {
			s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "invalid multipart object size")
			return
		}
		objectSize = aws.Int64(size)
	}

	cmu, err := decodeCompleteMultipartUpload(r.Body)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "MalformedXML", "Invalid XML")
		return
	}
	if len(cmu.Parts) > maxCompleteMultipartParts {
		s3xml.WriteError(w, http.StatusBadRequest, "MalformedXML", "Too many multipart parts")
		return
	}

	parts := make([]types.CompletedPart, 0, len(cmu.Parts))
	for _, p := range cmu.Parts {
		etag := strings.TrimSpace(string(p.ETag))
		if p.PartNumber <= 0 || etag == "" {
			s3xml.WriteError(w, http.StatusBadRequest, "MalformedXML", "Each part must have a positive PartNumber and a non-empty ETag")
			return
		}
		if !strings.HasPrefix(etag, `"`) {
			etag = `"` + etag
		}
		if !strings.HasSuffix(etag, `"`) {
			etag = etag + `"`
		}
		pn := int32(p.PartNumber)
		parts = append(parts, types.CompletedPart{
			ETag:              &etag,
			PartNumber:        aws.Int32(pn),
			ChecksumCRC32:     p.ChecksumCRC32.value,
			ChecksumCRC32C:    p.ChecksumCRC32C.value,
			ChecksumCRC64NVME: p.ChecksumCRC64NVME.value,
			ChecksumSHA1:      p.ChecksumSHA1.value,
			ChecksumSHA256:    p.ChecksumSHA256.value,
		})
	}
	if len(parts) == 0 {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidRequest", "No parts provided")
		return
	}
	sort.Slice(parts, func(i, j int) bool {
		return aws.ToInt32(parts[i].PartNumber) < aws.ToInt32(parts[j].PartNumber)
	})

	in := &s3.CompleteMultipartUploadInput{
		Bucket:   &bucket,
		Key:      &key,
		UploadId: &uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: parts,
		},
		ChecksumCRC32:     checksum.ChecksumCRC32,
		ChecksumCRC32C:    checksum.ChecksumCRC32C,
		ChecksumCRC64NVME: checksum.ChecksumCRC64NVME,
		ChecksumSHA1:      checksum.ChecksumSHA1,
		ChecksumSHA256:    checksum.ChecksumSHA256,
		ChecksumType:      checksum.ChecksumType,
		MpuObjectSize:     objectSize,
		RequestPayer:      payer,
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if ifMatch != "" {
		in.IfMatch = aws.String(ifMatch)
	}
	if ifNoneMatch != "" {
		in.IfNoneMatch = aws.String(ifNoneMatch)
	}

	out, err := s.up.CompleteMultipartUpload(r.Context(), in, upstream.TrackResponseProgress)
	if err != nil {
		s3http.WriteUpstreamError(w, err)
		return
	}
	if out.VersionId != nil {
		w.Header().Set("x-amz-version-id", *out.VersionId)
	}
	if out.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption", string(out.ServerSideEncryption))
	}
	if out.SSEKMSKeyId != nil {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", *out.SSEKMSKeyId)
	}
	if out.BucketKeyEnabled != nil {
		w.Header().Set("x-amz-server-side-encryption-bucket-key-enabled", s3xml.BoolString(*out.BucketKeyEnabled))
	}
	if out.Expiration != nil {
		w.Header().Set("x-amz-expiration", *out.Expiration)
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
	}

	s.notifyUpload(r, uploadnotify.Event{
		EventName: uploadnotify.EventObjectCreatedCompleteMultipartUpload,
		Bucket:    bucket,
		Key:       key,
		ETag:      strings.Trim(aws.ToString(out.ETag), `"`),
		VersionID: aws.ToString(out.VersionId),
		UploadID:  uploadID,
	})

	xw := s3xml.BeginResponse(w, http.StatusOK)
	defer s3xml.FlushResponse(xw)

	s3xml.EncodeRootStart(xw, "CompleteMultipartUploadResult")
	xw.Elem("Bucket", bucket)
	xw.Elem("Key", key)
	if out.ETag != nil {
		xw.Start("ETag")
		xw.RawString(`"` + s3xml.Escape(strings.Trim(*out.ETag, `"`)) + `"`)
		xw.End("ETag")
	}
	if out.ChecksumCRC32 != nil {
		xw.Elem("ChecksumCRC32", *out.ChecksumCRC32)
	}
	if out.ChecksumCRC32C != nil {
		xw.Elem("ChecksumCRC32C", *out.ChecksumCRC32C)
	}
	if out.ChecksumCRC64NVME != nil {
		xw.Elem("ChecksumCRC64NVME", *out.ChecksumCRC64NVME)
	}
	if out.ChecksumSHA1 != nil {
		xw.Elem("ChecksumSHA1", *out.ChecksumSHA1)
	}
	if out.ChecksumSHA256 != nil {
		xw.Elem("ChecksumSHA256", *out.ChecksumSHA256)
	}
	if out.ChecksumType != "" {
		xw.Elem("ChecksumType", string(out.ChecksumType))
	}
	xw.End("CompleteMultipartUploadResult")
}

func (s *Server) handleAbortMultipart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanWrite(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}
	payer, err := s3http.ParseRequestPayerHeader(r.Header)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", err.Error())
		return
	}
	in := &s3.AbortMultipartUploadInput{
		Bucket:       &bucket,
		Key:          &key,
		UploadId:     &uploadID,
		RequestPayer: payer,
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	_, err = s.up.AbortMultipartUpload(r.Context(), in)
	if err != nil {
		s3http.WriteUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
