package server

import (
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	authz "github.com/define42/s3gateway/internal/authz"
	"github.com/define42/s3gateway/internal/s3http"
	"github.com/define42/s3gateway/internal/s3xml"
)

func (s *Server) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	rules := authz.RulesFromRequest(r)

	out, err := s.up.ListBuckets(r.Context(), &s3.ListBucketsInput{})
	if err != nil {
		s3http.WriteUpstreamError(w, err)
		return
	}

	xw := s3xml.BeginResponse(w, http.StatusOK)
	defer s3xml.FlushResponse(xw)

	s3xml.EncodeRootStart(xw, "ListAllMyBucketsResult")
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

func (s *Server) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanCreateBucket(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}
	_, err := s.up.CreateBucket(r.Context(), &s3.CreateBucketInput{Bucket: &bucket})
	if err != nil {
		s3http.WriteUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleHeadBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanRead(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.HeadBucketInput{Bucket: &bucket}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	out, err := s.up.HeadBucket(r.Context(), in)
	if err != nil {
		s3http.WriteUpstreamHeadError(w, err)
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
		w.Header().Set("x-amz-access-point-alias", s3xml.BoolString(*out.AccessPointAlias))
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleGetBucketLocation(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromRequest(r)
	// Any permission on the bucket prefix is enough: clients such as `mc` and
	// rclone call GetBucketLocation before read *and* write operations, so
	// requiring `r` would break write-only users.
	if authz.BucketPerm(rules, bucket) == authz.PermNone {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.GetBucketLocationInput{Bucket: &bucket}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	out, err := s.up.GetBucketLocation(r.Context(), in)
	if err != nil {
		s3http.WriteUpstreamError(w, err)
		return
	}

	xw := s3xml.BeginResponse(w, http.StatusOK)
	defer s3xml.FlushResponse(xw)

	s3xml.EncodeRootStart(xw, "LocationConstraint")
	// An empty LocationConstraint means us-east-1, matching AWS behavior.
	if loc := string(out.LocationConstraint); loc != "" {
		xw.RawString(s3xml.Escape(loc))
	}
	xw.End("LocationConstraint")
}

func (s *Server) handleDeleteBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanDeleteBucket(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.DeleteBucketInput{Bucket: &bucket}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	_, err := s.up.DeleteBucket(r.Context(), in)
	if err != nil {
		s3http.WriteUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePutBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanConfigure(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	cfg, err := s3xml.DecodeVersioningConfig(r.Body)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "MalformedXML", "Invalid versioning configuration")
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
		s3http.WriteUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleGetBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanRead(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.GetBucketVersioningInput{Bucket: &bucket}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	out, err := s.up.GetBucketVersioning(r.Context(), in)
	if err != nil {
		s3http.WriteUpstreamError(w, err)
		return
	}

	body, err := s3xml.EncodeVersioningConfig(out.Status, out.MFADelete)
	if err != nil {
		s3http.WriteUpstreamError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body) // #nosec G705 -- body is generated by xml.Marshal, not user-controlled
}

func (s *Server) handlePutBucketTagging(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanConfigure(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	tagging, err := s3xml.DecodeBucketTagging(r.Body)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "MalformedXML", "Invalid tagging payload")
		return
	}
	checksumAlgorithm, err := s3http.ParseChecksumAlgorithmHeader(r.Header.Get("x-amz-checksum-algorithm"))
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "invalid checksum algorithm")
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
		s3http.WriteUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleGetBucketTagging(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanRead(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
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
		s3http.WriteUpstreamError(w, err)
		return
	}
	s3xml.WriteTaggingResponse(w, http.StatusOK, out.TagSet)
}

func (s *Server) handleDeleteBucketTagging(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanDeleteBucket(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.DeleteBucketTaggingInput{
		Bucket: &bucket,
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}

	if _, err := s.up.DeleteBucketTagging(r.Context(), in); err != nil {
		s3http.WriteUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
