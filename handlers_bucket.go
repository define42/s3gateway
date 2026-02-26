package main

import (
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	authz "github.com/define42/s3gateway/internal/authz"
	handler_bucket "github.com/define42/s3gateway/internal/handler_bucket"
	"github.com/define42/s3gateway/internal/xmlhelper"
)

func (s *server) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	rules := authz.RulesFromCtx(r)

	out, err := s.up.ListBuckets(r.Context(), &s3.ListBucketsInput{})
	if err != nil {
		xmlhelper.WriteUpstreamError(w, err)
		return
	}

	xw := xmlhelper.BeginXMLWriterResponse(w, http.StatusOK)
	defer xmlhelper.FlushXMLWriterResponse(xw)

	xmlhelper.EncodeS3RootStart(xw, "ListAllMyBucketsResult")
	xw.Start("Buckets")
	for _, bk := range out.Buckets {
		if bk.Name == nil {
			continue
		}
		if authz.BucketPerm(rules, *bk.Name) != authz.PermNone {
			xw.Start("Bucket")
			xw.Elem("Name", *bk.Name)
			xw.End("Bucket")
		}
	}
	xw.End("Buckets")
	xw.End("ListAllMyBucketsResult")
}

func (s *server) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromCtx(r)
	if !authz.CanCreateBucket(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}
	_, err := s.up.CreateBucket(r.Context(), &s3.CreateBucketInput{Bucket: &bucket})
	if err != nil {
		xmlhelper.WriteUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleHeadBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromCtx(r)
	if !authz.CanRead(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.HeadBucketInput{Bucket: &bucket}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	out, err := s.up.HeadBucket(r.Context(), in)
	if err != nil {
		xmlhelper.WriteUpstreamHeadError(w, err)
		return
	}

	if out.BucketRegion != nil {
		w.Header().Set("x-amz-bucket-region", *out.BucketRegion)
	}
	if out.BucketArn != nil {
		w.Header().Set("x-amz-bucket-arn", *out.BucketArn)
	}
	if out.BucketLocationName != nil {
		w.Header().Set("x-amz-bucket-location-name", *out.BucketLocationName)
	}
	if out.BucketLocationType != "" {
		w.Header().Set("x-amz-bucket-location-type", string(out.BucketLocationType))
	}
	if out.AccessPointAlias != nil {
		w.Header().Set("x-amz-access-point-alias", xmlhelper.BoolString(*out.AccessPointAlias))
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleDeleteBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromCtx(r)
	if !authz.CanDeleteBucket(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.DeleteBucketInput{Bucket: &bucket}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	_, err := s.up.DeleteBucket(r.Context(), in)
	if err != nil {
		xmlhelper.WriteUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handlePutBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromCtx(r)
	if !authz.CanWrite(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	cfg, err := handler_bucket.DecodeVersioningConfigXML(r.Body)
	if err != nil {
		xmlhelper.WriteXMLError(w, http.StatusBadRequest, "MalformedXML", "Invalid versioning configuration")
		return
	}
	in := &s3.PutBucketVersioningInput{
		Bucket:                  &bucket,
		VersioningConfiguration: cfg,
	}
	if mfa := strings.TrimSpace(r.Header.Get("x-amz-mfa")); mfa != "" {
		in.MFA = aws.String(mfa)
	}
	if contentMD5 := strings.TrimSpace(r.Header.Get("Content-MD5")); contentMD5 != "" {
		in.ContentMD5 = aws.String(contentMD5)
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	_, err = s.up.PutBucketVersioning(r.Context(), in)
	if err != nil {
		xmlhelper.WriteUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleGetBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromCtx(r)
	if !authz.CanRead(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.GetBucketVersioningInput{Bucket: &bucket}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	out, err := s.up.GetBucketVersioning(r.Context(), in)
	if err != nil {
		xmlhelper.WriteUpstreamError(w, err)
		return
	}

	body, err := handler_bucket.EncodeVersioningConfigXML(out.Status, out.MFADelete)
	if err != nil {
		xmlhelper.WriteUpstreamError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body) // #nosec G705 -- body is generated by xml.Marshal, not user-controlled
}

func (s *server) handlePutBucketTagging(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromCtx(r)
	if !authz.CanWrite(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	tagging, err := handler_bucket.DecodeTaggingXML(r.Body)
	if err != nil {
		xmlhelper.WriteXMLError(w, http.StatusBadRequest, "MalformedXML", "Invalid tagging payload")
		return
	}
	checksumAlgorithm, err := xmlhelper.ParseChecksumAlgorithmHeader(r.Header.Get("x-amz-checksum-algorithm"))
	if err != nil {
		xmlhelper.WriteXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid checksum algorithm")
		return
	}

	in := &s3.PutBucketTaggingInput{
		Bucket:  &bucket,
		Tagging: tagging,
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

	if _, err := s.up.PutBucketTagging(r.Context(), in); err != nil {
		xmlhelper.WriteUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleGetBucketTagging(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromCtx(r)
	if !authz.CanRead(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.GetBucketTaggingInput{
		Bucket: &bucket,
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}

	out, err := s.up.GetBucketTagging(r.Context(), in)
	if err != nil {
		xmlhelper.WriteUpstreamError(w, err)
		return
	}
	handler_bucket.WriteTaggingXMLResponse(w, http.StatusOK, out.TagSet)
}

func (s *server) handleDeleteBucketTagging(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromCtx(r)
	if !authz.CanWrite(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.DeleteBucketTaggingInput{
		Bucket: &bucket,
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}

	if _, err := s.up.DeleteBucketTagging(r.Context(), in); err != nil {
		xmlhelper.WriteUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

