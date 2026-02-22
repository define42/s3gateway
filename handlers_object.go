package main

import (
"encoding/xml"
"errors"
"fmt"
"io"
"net/http"
"strconv"
"strings"
"time"

"github.com/aws/aws-sdk-go-v2/aws"
v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
"github.com/aws/aws-sdk-go-v2/service/s3"
"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const maxSinglePutObjectSize = int64(5 * 1024 * 1024 * 1024) // 5 GiB

type deleteObjectsReqXML struct {
	XMLName xml.Name                 `xml:"Delete"`
	Objects []deleteObjectReqItemXML `xml:"Object"`
	Quiet   *bool                    `xml:"Quiet,omitempty"`
}

type deleteObjectReqItemXML struct {
	Key       *string `xml:"Key"`
	VersionID *string `xml:"VersionId,omitempty"`
	ETag      *string `xml:"ETag,omitempty"`
}


func (s *server) handlePutObjectTagging(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	tagging, err := decodeTaggingXML(r.Body)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "MalformedXML", "Invalid tagging payload")
		return
	}
	payer, err := parseRequestPayerHeader(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	}
	checksumAlgorithm, err := parseChecksumAlgorithmHeader(r.Header.Get("x-amz-checksum-algorithm"))
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid checksum algorithm")
		return
	}

	in := &s3.PutObjectTaggingInput{
		Bucket:  &bucket,
		Key:     &key,
		Tagging: tagging,
	}
	if versionID := strings.TrimSpace(r.URL.Query().Get("versionId")); versionID != "" {
		in.VersionId = aws.String(versionID)
	}
	if checksumAlgorithm != "" {
		in.ChecksumAlgorithm = checksumAlgorithm
	}
	if contentMD5 := strings.TrimSpace(r.Header.Get("Content-MD5")); contentMD5 != "" {
		in.ContentMD5 = aws.String(contentMD5)
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if payer != "" {
		in.RequestPayer = payer
	}

	out, err := s.up.PutObjectTagging(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	if out.VersionId != nil {
		w.Header().Set("x-amz-version-id", *out.VersionId)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleGetObjectTagging(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}
	payer, err := parseRequestPayerHeader(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	}

	in := &s3.GetObjectTaggingInput{
		Bucket: &bucket,
		Key:    &key,
	}
	if versionID := strings.TrimSpace(r.URL.Query().Get("versionId")); versionID != "" {
		in.VersionId = aws.String(versionID)
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if payer != "" {
		in.RequestPayer = payer
	}

	out, err := s.up.GetObjectTagging(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	if out.VersionId != nil {
		w.Header().Set("x-amz-version-id", *out.VersionId)
	}
	writeTaggingXMLResponse(w, http.StatusOK, out.TagSet)
}

func (s *server) handleDeleteObjectTagging(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.DeleteObjectTaggingInput{
		Bucket: &bucket,
		Key:    &key,
	}
	if versionID := strings.TrimSpace(r.URL.Query().Get("versionId")); versionID != "" {
		in.VersionId = aws.String(versionID)
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}

	out, err := s.up.DeleteObjectTagging(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	if out.VersionId != nil {
		w.Header().Set("x-amz-version-id", *out.VersionId)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleDeleteObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canDeleteObject(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	var req deleteObjectsReqXML
	if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
		writeXMLError(w, http.StatusBadRequest, "MalformedXML", "Invalid DeleteObjects payload")
		return
	}
	if len(req.Objects) == 0 || len(req.Objects) > 1000 {
		writeXMLError(w, http.StatusBadRequest, "MalformedXML", "DeleteObjects requires 1..1000 objects")
		return
	}

	objects := make([]types.ObjectIdentifier, 0, len(req.Objects))
	for i, obj := range req.Objects {
		key := strings.TrimSpace(aws.ToString(obj.Key))
		if key == "" {
			writeXMLError(w, http.StatusBadRequest, "MalformedXML", fmt.Sprintf("DeleteObjects object[%d] missing Key", i))
			return
		}
		item := types.ObjectIdentifier{Key: aws.String(key)}
		if obj.VersionID != nil {
			v := strings.TrimSpace(*obj.VersionID)
			if v != "" {
				item.VersionId = aws.String(v)
			}
		}
		if obj.ETag != nil {
			e := strings.TrimSpace(*obj.ETag)
			if e != "" {
				item.ETag = aws.String(e)
			}
		}
		objects = append(objects, item)
	}

	in := &s3.DeleteObjectsInput{
		Bucket: &bucket,
		Delete: &types.Delete{
			Objects: objects,
			Quiet:   req.Quiet,
		},
	}
	if bypass, set, err := parseOptionalBool(r.Header.Get("x-amz-bypass-governance-retention")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-bypass-governance-retention header")
		return
	} else if set {
		in.BypassGovernanceRetention = aws.Bool(bypass)
	}
	if mfa := strings.TrimSpace(r.Header.Get("x-amz-mfa")); mfa != "" {
		in.MFA = aws.String(mfa)
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if payer, err := parseRequestPayerHeader(r.Header); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	} else if payer != "" {
		in.RequestPayer = payer
	}

	out, err := s.up.DeleteObjects(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
	}

	xw := beginXMLWriterResponse(w, http.StatusOK)
	defer flushXMLWriterResponse(xw)

	encodeS3RootStart(xw, "DeleteResult")
	for _, d := range out.Deleted {
		xw.Start("Deleted")
		if d.Key != nil {
			xw.Elem("Key", *d.Key)
		}
		if d.VersionId != nil {
			xw.Elem("VersionId", *d.VersionId)
		}
		if d.DeleteMarker != nil {
			xw.ElemBool("DeleteMarker", *d.DeleteMarker)
		}
		if d.DeleteMarkerVersionId != nil {
			xw.Elem("DeleteMarkerVersionId", *d.DeleteMarkerVersionId)
		}
		xw.End("Deleted")
	}
	for _, e := range out.Errors {
		xw.Start("Error")
		if e.Key != nil {
			xw.Elem("Key", *e.Key)
		}
		if e.VersionId != nil {
			xw.Elem("VersionId", *e.VersionId)
		}
		if e.Code != nil {
			xw.Elem("Code", *e.Code)
		}
		if e.Message != nil {
			xw.Elem("Message", *e.Message)
		}
		xw.End("Error")
	}
	xw.End("DeleteResult")
}

func (s *server) handleListObjectVersions(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	q := r.URL.Query()
	in := &s3.ListObjectVersionsInput{Bucket: &bucket}
	if v := q.Get("prefix"); v != "" {
		in.Prefix = &v
	}
	if v := q.Get("delimiter"); v != "" {
		in.Delimiter = &v
	}
	if v := q.Get("key-marker"); v != "" {
		in.KeyMarker = &v
	}
	if v := q.Get("version-id-marker"); v != "" {
		in.VersionIdMarker = &v
	}
	if v := q.Get("max-keys"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil || n < 0 {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid max-keys")
			return
		}
		in.MaxKeys = aws.Int32(int32(n))
	}
	if et, err := parseEncodingType(q.Get("encoding-type")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid encoding-type")
		return
	} else if et != "" {
		in.EncodingType = et
	}
	optionalObjectAttrs := q.Get("optional-object-attributes")
	if optionalObjectAttrs == "" {
		optionalObjectAttrs = strings.TrimSpace(r.Header.Get("x-amz-optional-object-attributes"))
	}
	if attrs, err := parseOptionalObjectAttributes(optionalObjectAttrs); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid optional-object-attributes")
		return
	} else if len(attrs) > 0 {
		in.OptionalObjectAttributes = attrs
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if payer, err := parseRequestPayerHeader(r.Header); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	} else if payer != "" {
		in.RequestPayer = payer
	}

	out, err := s.up.ListObjectVersions(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
	}

	xw := beginXMLWriterResponse(w, http.StatusOK)
	defer flushXMLWriterResponse(xw)

	encodeS3RootStart(xw, "ListVersionsResult")
	if out.Name != nil {
		xw.Elem("Name", *out.Name)
	}
	if out.Prefix != nil {
		xw.Elem("Prefix", *out.Prefix)
	}
	if out.KeyMarker != nil {
		xw.Elem("KeyMarker", *out.KeyMarker)
	}
	if out.VersionIdMarker != nil {
		xw.Elem("VersionIdMarker", *out.VersionIdMarker)
	}
	if out.NextKeyMarker != nil {
		xw.Elem("NextKeyMarker", *out.NextKeyMarker)
	}
	if out.NextVersionIdMarker != nil {
		xw.Elem("NextVersionIdMarker", *out.NextVersionIdMarker)
	}
	if out.Delimiter != nil {
		xw.Elem("Delimiter", *out.Delimiter)
	}
	if out.MaxKeys != nil {
		xw.ElemInt("MaxKeys", int64(*out.MaxKeys))
	}
	if out.EncodingType != "" {
		xw.Elem("EncodingType", string(out.EncodingType))
	}
	xw.ElemBool("IsTruncated", aws.ToBool(out.IsTruncated))
	encodeCommonPrefixes(xw, out.CommonPrefixes)
	for _, v := range out.Versions {
		xw.Start("Version")
		if v.Key != nil {
			xw.Elem("Key", *v.Key)
		}
		if v.VersionId != nil {
			xw.Elem("VersionId", *v.VersionId)
		}
		if v.IsLatest != nil {
			xw.ElemBool("IsLatest", *v.IsLatest)
		}
		if v.LastModified != nil {
			xw.Elem("LastModified", formatS3Time(*v.LastModified))
		}
		if v.ETag != nil {
			xw.Elem("ETag", *v.ETag)
		}
		if v.Size != nil {
			xw.ElemInt("Size", *v.Size)
		}
		if v.StorageClass != "" {
			xw.Elem("StorageClass", string(v.StorageClass))
		}
		encodeOwnerIDThenDisplayName(xw, v.Owner)
		encodeRestoreStatus(xw, v.RestoreStatus)
		xw.End("Version")
	}
	for _, d := range out.DeleteMarkers {
		xw.Start("DeleteMarker")
		if d.Key != nil {
			xw.Elem("Key", *d.Key)
		}
		if d.VersionId != nil {
			xw.Elem("VersionId", *d.VersionId)
		}
		if d.IsLatest != nil {
			xw.ElemBool("IsLatest", *d.IsLatest)
		}
		if d.LastModified != nil {
			xw.Elem("LastModified", formatS3Time(*d.LastModified))
		}
		encodeOwnerIDThenDisplayName(xw, d.Owner)
		xw.End("DeleteMarker")
	}
	xw.End("ListVersionsResult")
}

func (s *server) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	q := r.URL.Query()
	in := &s3.ListObjectsV2Input{Bucket: &bucket}
	if v := q.Get("prefix"); v != "" {
		in.Prefix = &v
	}
	if v := q.Get("delimiter"); v != "" {
		in.Delimiter = &v
	}
	if v := q.Get("continuation-token"); v != "" {
		in.ContinuationToken = &v
	}
	if v := q.Get("start-after"); v != "" {
		in.StartAfter = &v
	}
	if v := q.Get("max-keys"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil || n < 0 {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid max-keys")
			return
		}
		in.MaxKeys = aws.Int32(int32(n))
	}
	if fetchOwner, set, err := parseOptionalBool(q.Get("fetch-owner")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid fetch-owner")
		return
	} else if set {
		in.FetchOwner = aws.Bool(fetchOwner)
	}
	if et, err := parseEncodingType(q.Get("encoding-type")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid encoding-type")
		return
	} else if et != "" {
		in.EncodingType = et
	}
	optionalObjectAttrs := q.Get("optional-object-attributes")
	if optionalObjectAttrs == "" {
		optionalObjectAttrs = strings.TrimSpace(r.Header.Get("x-amz-optional-object-attributes"))
	}
	if attrs, err := parseOptionalObjectAttributes(optionalObjectAttrs); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid optional-object-attributes")
		return
	} else if len(attrs) > 0 {
		in.OptionalObjectAttributes = attrs
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if payer, err := parseRequestPayerHeader(r.Header); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	} else if payer != "" {
		in.RequestPayer = payer
	}

	out, err := s.up.ListObjectsV2(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
	}

	xw := beginXMLWriterResponse(w, http.StatusOK)
	defer flushXMLWriterResponse(xw)

	encodeS3RootStart(xw, "ListBucketResult")
	if out.Name != nil {
		xw.Elem("Name", *out.Name)
	}
	if out.Prefix != nil {
		xw.Elem("Prefix", *out.Prefix)
	}
	if out.StartAfter != nil {
		xw.Elem("StartAfter", *out.StartAfter)
	}
	if out.Delimiter != nil {
		xw.Elem("Delimiter", *out.Delimiter)
	}
	if out.MaxKeys != nil {
		xw.ElemInt("MaxKeys", int64(*out.MaxKeys))
	}
	if out.KeyCount != nil {
		xw.ElemInt("KeyCount", int64(*out.KeyCount))
	}
	if out.EncodingType != "" {
		xw.Elem("EncodingType", string(out.EncodingType))
	}
	if out.ContinuationToken != nil {
		xw.Elem("ContinuationToken", *out.ContinuationToken)
	}
	if out.NextContinuationToken != nil {
		xw.Elem("NextContinuationToken", *out.NextContinuationToken)
	}
	xw.ElemBool("IsTruncated", aws.ToBool(out.IsTruncated))
	encodeCommonPrefixes(xw, out.CommonPrefixes)
	for _, o := range out.Contents {
		xw.Start("Contents")
		if o.Key != nil {
			xw.Elem("Key", *o.Key)
		}
		if o.LastModified != nil {
			xw.Elem("LastModified", formatS3Time(*o.LastModified))
		}
		if o.ETag != nil {
			xw.Elem("ETag", *o.ETag)
		}
		for _, c := range o.ChecksumAlgorithm {
			if c == "" {
				continue
			}
			xw.Elem("ChecksumAlgorithm", string(c))
		}
		if o.ChecksumType != "" {
			xw.Elem("ChecksumType", string(o.ChecksumType))
		}
		if o.Size != nil {
			xw.ElemInt("Size", *o.Size)
		}
		if o.StorageClass != "" {
			xw.Elem("StorageClass", string(o.StorageClass))
		}
		encodeOwnerIDThenDisplayName(xw, o.Owner)
		encodeRestoreStatus(xw, o.RestoreStatus)
		xw.End("Contents")
	}
	xw.End("ListBucketResult")
}


func (s *server) handleGetObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.GetObjectInput{Bucket: &bucket, Key: &key}
	if versionID := r.URL.Query().Get("versionId"); versionID != "" {
		in.VersionId = &versionID
	}
	if partNumStr := strings.TrimSpace(r.URL.Query().Get("partNumber")); partNumStr != "" {
		partNum, err := strconv.ParseInt(partNumStr, 10, 32)
		if err != nil || partNum <= 0 {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid partNumber")
			return
		}
		in.PartNumber = aws.Int32(int32(partNum))
	}
	if rng := r.Header.Get("Range"); rng != "" {
		in.Range = &rng
	}
	if ifMatch := strings.TrimSpace(r.Header.Get("If-Match")); ifMatch != "" {
		in.IfMatch = &ifMatch
	}
	if ifNoneMatch := strings.TrimSpace(r.Header.Get("If-None-Match")); ifNoneMatch != "" {
		in.IfNoneMatch = &ifNoneMatch
	}
	if t, err := parseOptionalHTTPTime(r.Header.Get("If-Modified-Since")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid If-Modified-Since header")
		return
	} else if t != nil {
		in.IfModifiedSince = t
	}
	if t, err := parseOptionalHTTPTime(r.Header.Get("If-Unmodified-Since")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid If-Unmodified-Since header")
		return
	} else if t != nil {
		in.IfUnmodifiedSince = t
	}
	if mode, err := parseChecksumMode(r.Header.Get("x-amz-checksum-mode")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-checksum-mode header")
		return
	} else if mode != "" {
		in.ChecksumMode = mode
	}
	ssecAlgo, ssecKey, ssecMD5, hasSSEC, err := parseSSECustomerHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid SSE-C headers")
		return
	}
	if hasSSEC {
		in.SSECustomerAlgorithm = ssecAlgo
		in.SSECustomerKey = ssecKey
		in.SSECustomerKeyMD5 = ssecMD5
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if payer, err := parseRequestPayerHeader(r.Header); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	} else if payer != "" {
		in.RequestPayer = payer
	}
	q := r.URL.Query()
	if v := q.Get("response-cache-control"); v != "" {
		in.ResponseCacheControl = aws.String(v)
	}
	if v := q.Get("response-content-disposition"); v != "" {
		in.ResponseContentDisposition = aws.String(v)
	}
	if v := q.Get("response-content-encoding"); v != "" {
		in.ResponseContentEncoding = aws.String(v)
	}
	if v := q.Get("response-content-language"); v != "" {
		in.ResponseContentLanguage = aws.String(v)
	}
	if v := q.Get("response-content-type"); v != "" {
		in.ResponseContentType = aws.String(v)
	}
	if v := q.Get("response-expires"); v != "" {
		t, err := parseOptionalHTTPTime(v)
		if err != nil || t == nil {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid response-expires")
			return
		}
		in.ResponseExpires = t
	}

	out, err := s.up.GetObject(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	defer out.Body.Close()

	// Propagate a few headers
	if out.ETag != nil {
		w.Header().Set("ETag", *out.ETag)
	}
	if out.LastModified != nil {
		w.Header().Set("Last-Modified", out.LastModified.UTC().Format(http.TimeFormat))
	}
	if out.ContentType != nil {
		w.Header().Set("Content-Type", *out.ContentType)
	}
	if out.ContentLength != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(*out.ContentLength, 10))
	}
	if out.ContentRange != nil {
		w.Header().Set("Content-Range", *out.ContentRange)
	}
	if out.VersionId != nil {
		w.Header().Set("x-amz-version-id", *out.VersionId)
	}
	if out.DeleteMarker != nil {
		w.Header().Set("x-amz-delete-marker", strconv.FormatBool(*out.DeleteMarker))
	}
	if out.ExpiresString != nil {
		w.Header().Set("Expires", *out.ExpiresString)
	}
	if out.AcceptRanges != nil {
		w.Header().Set("Accept-Ranges", *out.AcceptRanges)
	}
	if out.CacheControl != nil {
		w.Header().Set("Cache-Control", *out.CacheControl)
	}
	if out.ContentDisposition != nil {
		w.Header().Set("Content-Disposition", *out.ContentDisposition)
	}
	if out.ContentEncoding != nil {
		w.Header().Set("Content-Encoding", *out.ContentEncoding)
	}
	if out.ContentLanguage != nil {
		w.Header().Set("Content-Language", *out.ContentLanguage)
	}
	if out.StorageClass != "" {
		w.Header().Set("x-amz-storage-class", string(out.StorageClass))
	}
	if out.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption", string(out.ServerSideEncryption))
	}
	if out.SSEKMSKeyId != nil {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", *out.SSEKMSKeyId)
	}
	if out.SSECustomerAlgorithm != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", *out.SSECustomerAlgorithm)
	}
	if out.SSECustomerKeyMD5 != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-key-MD5", *out.SSECustomerKeyMD5)
	}
	if out.BucketKeyEnabled != nil {
		w.Header().Set("x-amz-server-side-encryption-bucket-key-enabled", boolString(*out.BucketKeyEnabled))
	}
	if out.Expiration != nil {
		w.Header().Set("x-amz-expiration", *out.Expiration)
	}
	if out.Restore != nil {
		w.Header().Set("x-amz-restore", *out.Restore)
	}
	if out.WebsiteRedirectLocation != nil {
		w.Header().Set("x-amz-website-redirect-location", *out.WebsiteRedirectLocation)
	}
	if out.ReplicationStatus != "" {
		w.Header().Set("x-amz-replication-status", string(out.ReplicationStatus))
	}
	if out.TagCount != nil {
		w.Header().Set("x-amz-tagging-count", strconv.Itoa(int(*out.TagCount)))
	}
	if out.PartsCount != nil {
		w.Header().Set("x-amz-mp-parts-count", strconv.Itoa(int(*out.PartsCount)))
	}
	if out.MissingMeta != nil {
		w.Header().Set("x-amz-missing-meta", strconv.Itoa(int(*out.MissingMeta)))
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
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
	if out.ChecksumType != "" {
		w.Header().Set("x-amz-checksum-type", string(out.ChecksumType))
	}
	for k, v := range out.Metadata {
		w.Header().Set("x-amz-meta-"+k, v)
	}
	status := http.StatusOK
	if out.ContentRange != nil {
		status = http.StatusPartialContent
	}
	w.WriteHeader(status)
	_, _ = io.Copy(w, out.Body)
}

func (s *server) handleHeadObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.HeadObjectInput{Bucket: &bucket, Key: &key}
	q := r.URL.Query()
	if versionID := q.Get("versionId"); versionID != "" {
		in.VersionId = &versionID
	}
	if partNumStr := strings.TrimSpace(q.Get("partNumber")); partNumStr != "" {
		partNum, err := strconv.ParseInt(partNumStr, 10, 32)
		if err != nil || partNum <= 0 {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid partNumber")
			return
		}
		in.PartNumber = aws.Int32(int32(partNum))
	}
	if rng := r.Header.Get("Range"); rng != "" {
		in.Range = &rng
	}
	if ifMatch := strings.TrimSpace(r.Header.Get("If-Match")); ifMatch != "" {
		in.IfMatch = &ifMatch
	}
	if ifNoneMatch := strings.TrimSpace(r.Header.Get("If-None-Match")); ifNoneMatch != "" {
		in.IfNoneMatch = &ifNoneMatch
	}
	if t, err := parseOptionalHTTPTime(r.Header.Get("If-Modified-Since")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid If-Modified-Since header")
		return
	} else if t != nil {
		in.IfModifiedSince = t
	}
	if t, err := parseOptionalHTTPTime(r.Header.Get("If-Unmodified-Since")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid If-Unmodified-Since header")
		return
	} else if t != nil {
		in.IfUnmodifiedSince = t
	}
	if mode, err := parseChecksumMode(r.Header.Get("x-amz-checksum-mode")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-checksum-mode header")
		return
	} else if mode != "" {
		in.ChecksumMode = mode
	}
	ssecAlgo, ssecKey, ssecMD5, hasSSEC, err := parseSSECustomerHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid SSE-C headers")
		return
	}
	if hasSSEC {
		in.SSECustomerAlgorithm = ssecAlgo
		in.SSECustomerKey = ssecKey
		in.SSECustomerKeyMD5 = ssecMD5
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if payer, err := parseRequestPayerHeader(r.Header); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	} else if payer != "" {
		in.RequestPayer = payer
	}
	if v := q.Get("response-cache-control"); v != "" {
		in.ResponseCacheControl = aws.String(v)
	}
	if v := q.Get("response-content-disposition"); v != "" {
		in.ResponseContentDisposition = aws.String(v)
	}
	if v := q.Get("response-content-encoding"); v != "" {
		in.ResponseContentEncoding = aws.String(v)
	}
	if v := q.Get("response-content-language"); v != "" {
		in.ResponseContentLanguage = aws.String(v)
	}
	if v := q.Get("response-content-type"); v != "" {
		in.ResponseContentType = aws.String(v)
	}
	if v := q.Get("response-expires"); v != "" {
		t, err := parseOptionalHTTPTime(v)
		if err != nil || t == nil {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid response-expires")
			return
		}
		in.ResponseExpires = t
	}

	out, err := s.up.HeadObject(r.Context(), in)
	if err != nil {
		writeUpstreamHeadError(w, err)
		return
	}

	if out.AcceptRanges != nil {
		w.Header().Set("Accept-Ranges", *out.AcceptRanges)
	}
	if out.ETag != nil {
		w.Header().Set("ETag", *out.ETag)
	}
	if out.LastModified != nil {
		w.Header().Set("Last-Modified", out.LastModified.UTC().Format(http.TimeFormat))
	}
	if out.ContentType != nil {
		w.Header().Set("Content-Type", *out.ContentType)
	}
	if out.ContentLength != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(*out.ContentLength, 10))
	}
	if out.ContentRange != nil {
		w.Header().Set("Content-Range", *out.ContentRange)
	}
	if out.CacheControl != nil {
		w.Header().Set("Cache-Control", *out.CacheControl)
	}
	if out.ContentDisposition != nil {
		w.Header().Set("Content-Disposition", *out.ContentDisposition)
	}
	if out.ContentEncoding != nil {
		w.Header().Set("Content-Encoding", *out.ContentEncoding)
	}
	if out.ContentLanguage != nil {
		w.Header().Set("Content-Language", *out.ContentLanguage)
	}
	if out.ExpiresString != nil {
		w.Header().Set("Expires", *out.ExpiresString)
	}
	if out.VersionId != nil {
		w.Header().Set("x-amz-version-id", *out.VersionId)
	}
	if out.DeleteMarker != nil {
		w.Header().Set("x-amz-delete-marker", boolString(*out.DeleteMarker))
	}
	if out.StorageClass != "" {
		w.Header().Set("x-amz-storage-class", string(out.StorageClass))
	}
	if out.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption", string(out.ServerSideEncryption))
	}
	if out.SSEKMSKeyId != nil {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", *out.SSEKMSKeyId)
	}
	if out.SSECustomerAlgorithm != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", *out.SSECustomerAlgorithm)
	}
	if out.SSECustomerKeyMD5 != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-key-MD5", *out.SSECustomerKeyMD5)
	}
	if out.BucketKeyEnabled != nil {
		w.Header().Set("x-amz-server-side-encryption-bucket-key-enabled", boolString(*out.BucketKeyEnabled))
	}
	if out.Expiration != nil {
		w.Header().Set("x-amz-expiration", *out.Expiration)
	}
	if out.Restore != nil {
		w.Header().Set("x-amz-restore", *out.Restore)
	}
	if out.WebsiteRedirectLocation != nil {
		w.Header().Set("x-amz-website-redirect-location", *out.WebsiteRedirectLocation)
	}
	if out.ReplicationStatus != "" {
		w.Header().Set("x-amz-replication-status", string(out.ReplicationStatus))
	}
	if out.TagCount != nil {
		w.Header().Set("x-amz-tagging-count", strconv.Itoa(int(*out.TagCount)))
	}
	if out.PartsCount != nil {
		w.Header().Set("x-amz-mp-parts-count", strconv.Itoa(int(*out.PartsCount)))
	}
	if out.MissingMeta != nil {
		w.Header().Set("x-amz-missing-meta", strconv.Itoa(int(*out.MissingMeta)))
	}
	if out.ObjectLockMode != "" {
		w.Header().Set("x-amz-object-lock-mode", string(out.ObjectLockMode))
	}
	if out.ObjectLockLegalHoldStatus != "" {
		w.Header().Set("x-amz-object-lock-legal-hold", string(out.ObjectLockLegalHoldStatus))
	}
	if out.ObjectLockRetainUntilDate != nil {
		w.Header().Set("x-amz-object-lock-retain-until-date", out.ObjectLockRetainUntilDate.UTC().Format(time.RFC3339))
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
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
	if out.ChecksumType != "" {
		w.Header().Set("x-amz-checksum-type", string(out.ChecksumType))
	}
	for k, v := range out.Metadata {
		w.Header().Set("x-amz-meta-"+k, v)
	}
	w.WriteHeader(http.StatusOK)
}

func parseObjectAttributesHeader(h http.Header) ([]types.ObjectAttributes, error) {
	values := h.Values("x-amz-object-attributes")
	if len(values) == 0 {
		return nil, errors.New("missing x-amz-object-attributes")
	}

	seen := map[types.ObjectAttributes]struct{}{}
	out := make([]types.ObjectAttributes, 0, len(values))
	for _, raw := range values {
		for _, token := range strings.Split(raw, ",") {
			v := strings.Trim(strings.TrimSpace(token), `"`)
			if v == "" {
				continue
			}
			var attr types.ObjectAttributes
			switch strings.ToLower(v) {
			case "etag":
				attr = types.ObjectAttributesEtag
			case "checksum":
				attr = types.ObjectAttributesChecksum
			case "objectparts":
				attr = types.ObjectAttributesObjectParts
			case "storageclass":
				attr = types.ObjectAttributesStorageClass
			case "objectsize":
				attr = types.ObjectAttributesObjectSize
			default:
				return nil, fmt.Errorf("unsupported object attribute %q", v)
			}
			if _, ok := seen[attr]; ok {
				continue
			}
			seen[attr] = struct{}{}
			out = append(out, attr)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no object attributes requested")
	}
	return out, nil
}

func (s *server) handleGetObjectAttributes(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	attrs, err := parseObjectAttributesHeader(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-object-attributes")
		return
	}

	in := &s3.GetObjectAttributesInput{
		Bucket:           &bucket,
		Key:              &key,
		ObjectAttributes: attrs,
	}
	if versionID := r.URL.Query().Get("versionId"); versionID != "" {
		in.VersionId = &versionID
	}
	if mpStr := strings.TrimSpace(r.Header.Get("x-amz-max-parts")); mpStr != "" {
		mp, err := strconv.ParseInt(mpStr, 10, 32)
		if err != nil || mp <= 0 {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-max-parts")
			return
		}
		in.MaxParts = aws.Int32(int32(mp))
	}
	if marker := strings.TrimSpace(r.Header.Get("x-amz-part-number-marker")); marker != "" {
		if _, err := strconv.Atoi(marker); err != nil {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-part-number-marker")
			return
		}
		in.PartNumberMarker = &marker
	}

	out, err := s.up.GetObjectAttributes(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}

	if out.LastModified != nil {
		w.Header().Set("Last-Modified", out.LastModified.UTC().Format(http.TimeFormat))
	}
	if out.VersionId != nil {
		w.Header().Set("x-amz-version-id", *out.VersionId)
	}
	if out.DeleteMarker != nil {
		w.Header().Set("x-amz-delete-marker", strconv.FormatBool(*out.DeleteMarker))
	}

	xw := beginXMLWriterResponse(w, http.StatusOK)
	defer flushXMLWriterResponse(xw)

	encodeS3RootStart(xw, "GetObjectAttributesOutput")
	if out.ETag != nil {
		xw.Elem("ETag", *out.ETag)
	}
	if out.ObjectSize != nil {
		xw.ElemInt("ObjectSize", *out.ObjectSize)
	}
	if out.StorageClass != "" {
		xw.Elem("StorageClass", string(out.StorageClass))
	}
	if out.Checksum != nil {
		xw.Start("Checksum")
		if out.Checksum.ChecksumCRC32 != nil {
			xw.Elem("ChecksumCRC32", *out.Checksum.ChecksumCRC32)
		}
		if out.Checksum.ChecksumCRC32C != nil {
			xw.Elem("ChecksumCRC32C", *out.Checksum.ChecksumCRC32C)
		}
		if out.Checksum.ChecksumCRC64NVME != nil {
			xw.Elem("ChecksumCRC64NVME", *out.Checksum.ChecksumCRC64NVME)
		}
		if out.Checksum.ChecksumSHA1 != nil {
			xw.Elem("ChecksumSHA1", *out.Checksum.ChecksumSHA1)
		}
		if out.Checksum.ChecksumSHA256 != nil {
			xw.Elem("ChecksumSHA256", *out.Checksum.ChecksumSHA256)
		}
		if out.Checksum.ChecksumType != "" {
			xw.Elem("ChecksumType", string(out.Checksum.ChecksumType))
		}
		xw.End("Checksum")
	}
	if out.ObjectParts != nil {
		xw.Start("ObjectParts")
		if out.ObjectParts.PartNumberMarker != nil {
			xw.Elem("PartNumberMarker", *out.ObjectParts.PartNumberMarker)
		}
		if out.ObjectParts.NextPartNumberMarker != nil {
			xw.Elem("NextPartNumberMarker", *out.ObjectParts.NextPartNumberMarker)
		}
		if out.ObjectParts.MaxParts != nil {
			xw.ElemInt("MaxParts", int64(*out.ObjectParts.MaxParts))
		}
		if out.ObjectParts.TotalPartsCount != nil {
			xw.ElemInt("PartsCount", int64(*out.ObjectParts.TotalPartsCount))
		}
		xw.ElemBool("IsTruncated", aws.ToBool(out.ObjectParts.IsTruncated))
		for _, p := range out.ObjectParts.Parts {
			xw.Start("Part")
			if p.PartNumber != nil {
				xw.ElemInt("PartNumber", int64(*p.PartNumber))
			}
			if p.Size != nil {
				xw.ElemInt("Size", *p.Size)
			}
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
		xw.End("ObjectParts")
	}
	xw.End("GetObjectAttributesOutput")
}

func (s *server) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	verifier, err := chunkSignatureVerifierFromRequest(r)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "Unsupported or invalid streaming payload signature")
		return
	}

	body, cl, err := decodeBodyForS3Write(r, verifier)
	if err != nil {
		if errors.Is(err, errContentLengthRequired) || errors.Is(err, errMissingDecodedContentLength) || errors.Is(err, errInvalidDecodedContentLength) {
			writeXMLError(w, http.StatusLengthRequired, "MissingContentLength", "Content-Length required")
			return
		}
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "Invalid request body")
		return
	}
	defer body.Close()
	if cl > maxSinglePutObjectSize {
		writeXMLError(w, http.StatusBadRequest, "EntityTooLarge", "Use multipart upload for objects larger than 5 GiB")
		return
	}

	ct := r.Header.Get("Content-Type")
	meta := extractAmzMeta(r.Header)
	meta = ensureUploadedByMetadata(meta, uploaderFromCtx(r))
	if missing := missingRequiredUploadMetadata(meta, s.cfg.RequiredUploadMetadataKeys); len(missing) > 0 {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "Missing required metadata header(s): "+strings.Join(missing, ", "))
		return
	}
	expires, err := parseExpiresHeader(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid Expires header")
		return
	}
	ifMatch := strings.TrimSpace(r.Header.Get("If-Match"))
	ifNoneMatch := strings.TrimSpace(r.Header.Get("If-None-Match"))
	if ifMatch != "" && ifNoneMatch != "" {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "If-Match and If-None-Match cannot both be set")
		return
	}

	sse, err := parseSSEWriteHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid server-side encryption headers")
		return
	}
	checksum, err := parseChecksumWriteHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid checksum headers")
		return
	}
	contentMD5 := strings.TrimSpace(r.Header.Get("Content-MD5"))
	if contentMD5 != "" && checksum.ChecksumAlgorithm != "" {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "Content-MD5 cannot be combined with x-amz-checksum-algorithm")
		return
	}
	expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner"))
	payer, err := parseRequestPayerHeader(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	}

	in := &s3.PutObjectInput{
		Bucket:        &bucket,
		Key:           &key,
		Body:          body,
		ContentLength: aws.Int64(cl),
		Metadata:      meta,
		Expires:       expires,
		IfMatch:       nil,
		IfNoneMatch:   nil,
	}
	if ifMatch != "" {
		in.IfMatch = aws.String(ifMatch)
	}
	if ifNoneMatch != "" {
		in.IfNoneMatch = aws.String(ifNoneMatch)
	}
	if expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if payer != "" {
		in.RequestPayer = payer
	}
	if contentMD5 != "" {
		in.ContentMD5 = aws.String(contentMD5)
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
	in.ChecksumCRC32 = checksum.ChecksumCRC32
	in.ChecksumCRC32C = checksum.ChecksumCRC32C
	in.ChecksumCRC64NVME = checksum.ChecksumCRC64NVME
	in.ChecksumSHA1 = checksum.ChecksumSHA1
	in.ChecksumSHA256 = checksum.ChecksumSHA256

	out, err := s.up.PutObject(r.Context(), in,
		// Allow streaming io.Reader without Seek by using Unsigned Payload middleware.
		s3.WithAPIOptions(v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware),
	)
	if err != nil {
		if isChunkSignatureValidationError(err) {
			writeXMLError(w, http.StatusBadRequest, "SignatureDoesNotMatch", "Invalid aws-chunked chunk signature")
			return
		}
		writeUpstreamError(w, err)
		return
	}
	if out.ETag != nil {
		w.Header().Set("ETag", *out.ETag)
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
	if out.SSEKMSEncryptionContext != nil {
		w.Header().Set("x-amz-server-side-encryption-context", *out.SSEKMSEncryptionContext)
	}
	if out.SSECustomerAlgorithm != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", *out.SSECustomerAlgorithm)
	}
	if out.SSECustomerKeyMD5 != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-key-MD5", *out.SSECustomerKeyMD5)
	}
	if out.BucketKeyEnabled != nil {
		w.Header().Set("x-amz-server-side-encryption-bucket-key-enabled", boolString(*out.BucketKeyEnabled))
	}
	if out.Expiration != nil {
		w.Header().Set("x-amz-expiration", *out.Expiration)
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
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
	if out.ChecksumType != "" {
		w.Header().Set("x-amz-checksum-type", string(out.ChecksumType))
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleCopyObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	copySource := strings.TrimSpace(r.Header.Get("x-amz-copy-source"))
	if copySource == "" {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "x-amz-copy-source is required")
		return
	}
	sourceBucket, err := sourceBucketFromCopySource(copySource)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "invalid x-amz-copy-source")
		return
	}
	if !canRead(rules, sourceBucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	ifMatch := strings.TrimSpace(r.Header.Get("If-Match"))
	ifNoneMatch := strings.TrimSpace(r.Header.Get("If-None-Match"))
	if ifMatch != "" && ifNoneMatch != "" {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "If-Match and If-None-Match cannot both be set")
		return
	}

	sse, err := parseSSEWriteHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid server-side encryption headers")
		return
	}
	copySSECAlgo, copySSECKey, copySSECMD5, hasCopySSEC, err := parseCopySourceSSECustomerHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid copy-source SSE-C headers")
		return
	}
	checksumAlgorithm, err := parseChecksumAlgorithmHeader(r.Header.Get("x-amz-checksum-algorithm"))
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid checksum algorithm")
		return
	}

	metadataDirective, err := parseMetadataDirective(r.Header.Get("x-amz-metadata-directive"))
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-metadata-directive header")
		return
	}
	taggingDirective, err := parseTaggingDirective(r.Header.Get("x-amz-tagging-directive"))
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-tagging-directive header")
		return
	}
	storageClass, err := parseStorageClass(r.Header.Get("x-amz-storage-class"))
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-storage-class header")
		return
	}
	acl, err := parseObjectCannedACL(r.Header.Get("x-amz-acl"))
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-acl header")
		return
	}
	payer, err := parseRequestPayerHeader(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	}

	copyIfMatch, copyIfNoneMatch, copyIfModifiedSince, copyIfUnmodifiedSince, err := parseCopySourceConditionalHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid copy-source conditional header")
		return
	}
	expires, err := parseExpiresHeader(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid Expires header")
		return
	}

	in := &s3.CopyObjectInput{
		Bucket:     &bucket,
		Key:        &key,
		CopySource: aws.String(copySource),
		Metadata:   extractAmzMeta(r.Header),
		Expires:    expires,
	}
	if ifMatch != "" {
		in.IfMatch = aws.String(ifMatch)
	}
	if ifNoneMatch != "" {
		in.IfNoneMatch = aws.String(ifNoneMatch)
	}
	if copyIfMatch != nil {
		in.CopySourceIfMatch = copyIfMatch
	}
	if copyIfNoneMatch != nil {
		in.CopySourceIfNoneMatch = copyIfNoneMatch
	}
	if copyIfModifiedSince != nil {
		in.CopySourceIfModifiedSince = copyIfModifiedSince
	}
	if copyIfUnmodifiedSince != nil {
		in.CopySourceIfUnmodifiedSince = copyIfUnmodifiedSince
	}
	if hasCopySSEC {
		in.CopySourceSSECustomerAlgorithm = copySSECAlgo
		in.CopySourceSSECustomerKey = copySSECKey
		in.CopySourceSSECustomerKeyMD5 = copySSECMD5
	}
	if metadataDirective != "" {
		in.MetadataDirective = metadataDirective
	}
	if taggingDirective != "" {
		in.TaggingDirective = taggingDirective
	}
	if tagging := strings.TrimSpace(r.Header.Get("x-amz-tagging")); tagging != "" {
		in.Tagging = aws.String(tagging)
	}
	if storageClass != "" {
		in.StorageClass = storageClass
	}
	if acl != "" {
		in.ACL = acl
	}
	if checksumAlgorithm != "" {
		in.ChecksumAlgorithm = checksumAlgorithm
	}
	if ct := strings.TrimSpace(r.Header.Get("Content-Type")); ct != "" {
		in.ContentType = aws.String(ct)
	}
	if cc := strings.TrimSpace(r.Header.Get("Cache-Control")); cc != "" {
		in.CacheControl = aws.String(cc)
	}
	if cd := strings.TrimSpace(r.Header.Get("Content-Disposition")); cd != "" {
		in.ContentDisposition = aws.String(cd)
	}
	if ce := strings.TrimSpace(r.Header.Get("Content-Encoding")); ce != "" {
		in.ContentEncoding = aws.String(ce)
	}
	if cl := strings.TrimSpace(r.Header.Get("Content-Language")); cl != "" {
		in.ContentLanguage = aws.String(cl)
	}
	if redirect := strings.TrimSpace(r.Header.Get("x-amz-website-redirect-location")); redirect != "" {
		in.WebsiteRedirectLocation = aws.String(redirect)
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if sourceExpectedOwner := strings.TrimSpace(r.Header.Get("x-amz-source-expected-bucket-owner")); sourceExpectedOwner != "" {
		in.ExpectedSourceBucketOwner = aws.String(sourceExpectedOwner)
	}
	if payer != "" {
		in.RequestPayer = payer
	}
	if sse.ServerSideEncryption != "" {
		in.ServerSideEncryption = sse.ServerSideEncryption
	}
	in.SSEKMSKeyId = sse.SSEKMSKeyID
	in.SSEKMSEncryptionContext = sse.SSEKMSEncryptionContext
	in.SSECustomerAlgorithm = sse.SSECustomerAlgorithm
	in.SSECustomerKey = sse.SSECustomerKey
	in.SSECustomerKeyMD5 = sse.SSECustomerKeyMD5

	out, err := s.up.CopyObject(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}

	if out.VersionId != nil {
		w.Header().Set("x-amz-version-id", *out.VersionId)
	}
	if out.CopySourceVersionId != nil {
		w.Header().Set("x-amz-copy-source-version-id", *out.CopySourceVersionId)
	}
	if out.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption", string(out.ServerSideEncryption))
	}
	if out.SSEKMSKeyId != nil {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", *out.SSEKMSKeyId)
	}
	if out.SSEKMSEncryptionContext != nil {
		w.Header().Set("x-amz-server-side-encryption-context", *out.SSEKMSEncryptionContext)
	}
	if out.SSECustomerAlgorithm != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", *out.SSECustomerAlgorithm)
	}
	if out.SSECustomerKeyMD5 != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-key-MD5", *out.SSECustomerKeyMD5)
	}
	if out.BucketKeyEnabled != nil {
		w.Header().Set("x-amz-server-side-encryption-bucket-key-enabled", boolString(*out.BucketKeyEnabled))
	}
	if out.Expiration != nil {
		w.Header().Set("x-amz-expiration", *out.Expiration)
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
	}

	xw := beginXMLWriterResponse(w, http.StatusOK)
	defer flushXMLWriterResponse(xw)

	encodeS3RootStart(xw, "CopyObjectResult")
	if out.CopyObjectResult != nil {
		if out.CopyObjectResult.LastModified != nil {
			xw.Elem("LastModified", formatS3Time(*out.CopyObjectResult.LastModified))
		}
		if out.CopyObjectResult.ETag != nil {
			xw.Elem("ETag", *out.CopyObjectResult.ETag)
		}
		if out.CopyObjectResult.ChecksumCRC32 != nil {
			xw.Elem("ChecksumCRC32", *out.CopyObjectResult.ChecksumCRC32)
		}
		if out.CopyObjectResult.ChecksumCRC32C != nil {
			xw.Elem("ChecksumCRC32C", *out.CopyObjectResult.ChecksumCRC32C)
		}
		if out.CopyObjectResult.ChecksumCRC64NVME != nil {
			xw.Elem("ChecksumCRC64NVME", *out.CopyObjectResult.ChecksumCRC64NVME)
		}
		if out.CopyObjectResult.ChecksumSHA1 != nil {
			xw.Elem("ChecksumSHA1", *out.CopyObjectResult.ChecksumSHA1)
		}
		if out.CopyObjectResult.ChecksumSHA256 != nil {
			xw.Elem("ChecksumSHA256", *out.CopyObjectResult.ChecksumSHA256)
		}
		if out.CopyObjectResult.ChecksumType != "" {
			xw.Elem("ChecksumType", string(out.CopyObjectResult.ChecksumType))
		}
	}
	xw.End("CopyObjectResult")
}

func (s *server) handleUploadPartCopy(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string, partNumber int32) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	copySource := strings.TrimSpace(r.Header.Get("x-amz-copy-source"))
	if copySource == "" {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "x-amz-copy-source is required")
		return
	}
	sourceBucket, err := sourceBucketFromCopySource(copySource)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "invalid x-amz-copy-source")
		return
	}
	if !canRead(rules, sourceBucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	copyIfMatch, copyIfNoneMatch, copyIfModifiedSince, copyIfUnmodifiedSince, err := parseCopySourceConditionalHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid copy-source conditional header")
		return
	}
	copySSECAlgo, copySSECKey, copySSECMD5, hasCopySSEC, err := parseCopySourceSSECustomerHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid copy-source SSE-C headers")
		return
	}
	ssecAlgo, ssecKey, ssecMD5, hasSSEC, err := parseSSECustomerHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid SSE-C headers")
		return
	}
	payer, err := parseRequestPayerHeader(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	}

	in := &s3.UploadPartCopyInput{
		Bucket:     &bucket,
		Key:        &key,
		UploadId:   &uploadID,
		PartNumber: aws.Int32(partNumber),
		CopySource: aws.String(copySource),
	}
	if copyIfMatch != nil {
		in.CopySourceIfMatch = copyIfMatch
	}
	if copyIfNoneMatch != nil {
		in.CopySourceIfNoneMatch = copyIfNoneMatch
	}
	if copyIfModifiedSince != nil {
		in.CopySourceIfModifiedSince = copyIfModifiedSince
	}
	if copyIfUnmodifiedSince != nil {
		in.CopySourceIfUnmodifiedSince = copyIfUnmodifiedSince
	}
	if copySourceRange := strings.TrimSpace(r.Header.Get("x-amz-copy-source-range")); copySourceRange != "" {
		in.CopySourceRange = aws.String(copySourceRange)
	}
	if hasCopySSEC {
		in.CopySourceSSECustomerAlgorithm = copySSECAlgo
		in.CopySourceSSECustomerKey = copySSECKey
		in.CopySourceSSECustomerKeyMD5 = copySSECMD5
	}
	if hasSSEC {
		in.SSECustomerAlgorithm = ssecAlgo
		in.SSECustomerKey = ssecKey
		in.SSECustomerKeyMD5 = ssecMD5
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if sourceExpectedOwner := strings.TrimSpace(r.Header.Get("x-amz-source-expected-bucket-owner")); sourceExpectedOwner != "" {
		in.ExpectedSourceBucketOwner = aws.String(sourceExpectedOwner)
	}
	if payer != "" {
		in.RequestPayer = payer
	}

	out, err := s.up.UploadPartCopy(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}

	if out.CopySourceVersionId != nil {
		w.Header().Set("x-amz-copy-source-version-id", *out.CopySourceVersionId)
	}
	if out.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption", string(out.ServerSideEncryption))
	}
	if out.SSEKMSKeyId != nil {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", *out.SSEKMSKeyId)
	}
	if out.SSECustomerAlgorithm != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", *out.SSECustomerAlgorithm)
	}
	if out.SSECustomerKeyMD5 != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-key-MD5", *out.SSECustomerKeyMD5)
	}
	if out.BucketKeyEnabled != nil {
		w.Header().Set("x-amz-server-side-encryption-bucket-key-enabled", boolString(*out.BucketKeyEnabled))
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
	}

	xw := beginXMLWriterResponse(w, http.StatusOK)
	defer flushXMLWriterResponse(xw)

	encodeS3RootStart(xw, "CopyPartResult")
	if out.CopyPartResult != nil {
		if out.CopyPartResult.LastModified != nil {
			xw.Elem("LastModified", formatS3Time(*out.CopyPartResult.LastModified))
		}
		if out.CopyPartResult.ETag != nil {
			xw.Elem("ETag", *out.CopyPartResult.ETag)
		}
		if out.CopyPartResult.ChecksumCRC32 != nil {
			xw.Elem("ChecksumCRC32", *out.CopyPartResult.ChecksumCRC32)
		}
		if out.CopyPartResult.ChecksumCRC32C != nil {
			xw.Elem("ChecksumCRC32C", *out.CopyPartResult.ChecksumCRC32C)
		}
		if out.CopyPartResult.ChecksumCRC64NVME != nil {
			xw.Elem("ChecksumCRC64NVME", *out.CopyPartResult.ChecksumCRC64NVME)
		}
		if out.CopyPartResult.ChecksumSHA1 != nil {
			xw.Elem("ChecksumSHA1", *out.CopyPartResult.ChecksumSHA1)
		}
		if out.CopyPartResult.ChecksumSHA256 != nil {
			xw.Elem("ChecksumSHA256", *out.CopyPartResult.ChecksumSHA256)
		}
	}
	xw.End("CopyPartResult")
}

func (s *server) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := rulesFromCtx(r)
	if !canDeleteObject(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}
	if versionID := r.URL.Query().Get("versionId"); versionID != "" {
		in.VersionId = &versionID
	}
	if ifMatch := strings.TrimSpace(r.Header.Get("If-Match")); ifMatch != "" {
		in.IfMatch = &ifMatch
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if bypass, set, err := parseOptionalBool(r.Header.Get("x-amz-bypass-governance-retention")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-bypass-governance-retention header")
		return
	} else if set {
		in.BypassGovernanceRetention = aws.Bool(bypass)
	}
	if payer, err := parseRequestPayerHeader(r.Header); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	} else if payer != "" {
		in.RequestPayer = payer
	}

	out, err := s.up.DeleteObject(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	if out.DeleteMarker != nil {
		w.Header().Set("x-amz-delete-marker", boolString(*out.DeleteMarker))
	}
	if out.VersionId != nil {
		w.Header().Set("x-amz-version-id", *out.VersionId)
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
	}
	w.WriteHeader(http.StatusNoContent)
}

func extractAmzMeta(h http.Header) map[string]string {
	meta := map[string]string{}
	for k, vs := range h {
		kl := strings.ToLower(k)
		if strings.HasPrefix(kl, "x-amz-meta-") && len(vs) > 0 {
			mk := normalizeRequiredMetadataKey(strings.TrimPrefix(kl, "x-amz-meta-"))
			if mk == "" {
				continue
			}
			meta[mk] = vs[0]
		}
	}
	if len(meta) == 0 {
		return nil
	}
	return meta
}

func missingRequiredUploadMetadata(meta map[string]string, required []string) []string {
	if len(required) == 0 {
		return nil
	}
	missing := make([]string, 0, len(required))
	for _, key := range required {
		if _, ok := meta[key]; !ok {
			missing = append(missing, "x-amz-meta-"+key)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return missing
}

func ensureUploadedByMetadata(meta map[string]string, uploader string) map[string]string {
	uploader = strings.TrimSpace(uploader)
	if uploader == "" {
		return meta
	}
	if meta == nil {
		meta = make(map[string]string, 1)
	}
	meta["uploaded-by"] = uploader
	return meta
}

func parseExpiresHeader(h http.Header) (*time.Time, error) {
	raw := strings.TrimSpace(h.Get("Expires"))
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


