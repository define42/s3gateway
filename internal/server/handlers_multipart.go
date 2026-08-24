package server

import (
	"encoding/xml"
	"errors"
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
)

func (s *Server) handleListMultipartUploads(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanRead(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.ListMultipartUploadsInput{Bucket: &bucket}
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
		PartNumber int32  `xml:"PartNumber"`
		ETag       string `xml:"ETag"`
	} `xml:"Part"`
}

func (s *Server) handleCreateMultipart(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanWrite(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
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
	sse, err := s3http.ParseSSEWriteHeaders(r.Header)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "invalid server-side encryption headers")
		return
	}
	checksum, err := s3http.ParseChecksumWriteHeaders(r.Header)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "invalid checksum headers")
		return
	}

	in := &s3.CreateMultipartUploadInput{
		Bucket:   &bucket,
		Key:      &key,
		Metadata: meta,
		Expires:  expires,
	}
	if ct != "" {
		in.ContentType = &ct
	}
	if sse.ServerSideEncryption != "" {
		in.ServerSideEncryption = sse.ServerSideEncryption
	}
	in.SSEKMSKeyId = sse.SSEKMSKeyID
	in.SSEKMSEncryptionContext = sse.SSEKMSEncryptionContext
	in.SSECustomerAlgorithm = sse.SSECustomerAlgorithm
	in.SSECustomerKey = sse.SSECustomerKey
	in.SSECustomerKeyMD5 = sse.SSECustomerKeyMD5
	if checksum.ChecksumAlgorithm != "" {
		in.ChecksumAlgorithm = checksum.ChecksumAlgorithm
	}

	out, err := s.up.CreateMultipartUpload(r.Context(), in)
	if err != nil {
		s3http.WriteUpstreamError(w, err)
		return
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
		if writeChunkedBodyError(w, err, nil) {
			return
		}
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidRequest", "Invalid request body")
		return
	}
	defer body.Close()
	ssecAlgo, ssecKey, ssecMD5, hasSSEC, err := s3http.ParseSSECustomerHeaders(r.Header)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "invalid SSE-C headers")
		return
	}
	checksum, err := s3http.ParseChecksumWriteHeaders(r.Header)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "invalid checksum headers")
		return
	}
	contentMD5 := strings.TrimSpace(r.Header.Get("Content-MD5"))
	if contentMD5 != "" && checksum.ChecksumAlgorithm != "" {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidRequest", "Content-MD5 cannot be combined with x-amz-checksum-algorithm")
		return
	}

	in := &s3.UploadPartInput{
		Bucket:        &bucket,
		Key:           &key,
		UploadId:      &uploadID,
		PartNumber:    aws.Int32(partNumber),
		Body:          body,
		ContentLength: aws.Int64(cl),
	}
	if hasSSEC {
		in.SSECustomerAlgorithm = ssecAlgo
		in.SSECustomerKey = ssecKey
		in.SSECustomerKeyMD5 = ssecMD5
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
		if writeChunkedBodyError(w, err, body) {
			return
		}
		s3http.WriteUpstreamError(w, err)
		return
	}

	if out.ETag != nil {
		w.Header().Set("ETag", *out.ETag)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleListParts(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanRead(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.ListPartsInput{
		Bucket:   &bucket,
		Key:      &key,
		UploadId: &uploadID,
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
		xw.End("Part")
	}
	xw.End("ListPartsResult")
}

// CompleteMultipartUpload requires PartNumber + ETag for each part.
func (s *Server) handleCompleteMultipart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanWrite(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	var cmu completeMultipartUpload
	if err := xml.NewDecoder(r.Body).Decode(&cmu); err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "MalformedXML", "Invalid XML")
		return
	}

	parts := make([]types.CompletedPart, 0, len(cmu.Parts))
	for _, p := range cmu.Parts {
		etag := strings.TrimSpace(p.ETag)
		if p.PartNumber <= 0 || etag == "" {
			continue
		}
		if !strings.HasPrefix(etag, `"`) {
			etag = `"` + etag
		}
		if !strings.HasSuffix(etag, `"`) {
			etag = etag + `"`
		}
		pn := p.PartNumber
		parts = append(parts, types.CompletedPart{
			ETag:       &etag,
			PartNumber: aws.Int32(pn),
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
	}

	out, err := s.up.CompleteMultipartUpload(r.Context(), in)
	if err != nil {
		s3http.WriteUpstreamError(w, err)
		return
	}

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
	xw.End("CompleteMultipartUploadResult")
}

func (s *Server) handleAbortMultipart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanWrite(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}
	_, err := s.up.AbortMultipartUpload(r.Context(), &s3.AbortMultipartUploadInput{
		Bucket:   &bucket,
		Key:      &key,
		UploadId: &uploadID,
	})
	if err != nil {
		s3http.WriteUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
