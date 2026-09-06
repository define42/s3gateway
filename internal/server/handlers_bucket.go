package server

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	authz "github.com/define42/s3gateway/internal/authz"
	"github.com/define42/s3gateway/internal/s3http"
	"github.com/define42/s3gateway/internal/s3xml"
	"github.com/define42/s3gateway/internal/upstream"
)

func (s *Server) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	rules := authz.RulesFromRequest(r)
	in, paginated, err := parseListBucketsQuery(r.URL.Query())
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", err.Error())
		return
	}

	var out *s3.ListBucketsOutput
	if paginated {
		out, err = s.up.ListBuckets(r.Context(), in)
		if err == nil && aws.ToString(out.ContinuationToken) != "" &&
			aws.ToString(out.ContinuationToken) == aws.ToString(in.ContinuationToken) {
			err = errors.New("upstream returned a repeated bucket continuation token")
		}
	} else {
		// Preserve complete listings for existing clients while always using
		// paginated upstream calls, including accounts with elevated quotas.
		out, err = upstream.ListAllBuckets(r.Context(), s.up)
	}
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
	if out.ContinuationToken != nil && *out.ContinuationToken != "" {
		xw.Elem("ContinuationToken", *out.ContinuationToken)
	}
	if out.Prefix != nil {
		xw.Elem("Prefix", *out.Prefix)
	}
	xw.End("ListAllMyBucketsResult")
}

func parseListBucketsQuery(q url.Values) (*s3.ListBucketsInput, bool, error) {
	in := &s3.ListBucketsInput{MaxBuckets: aws.Int32(upstream.DefaultBucketPageSize)}
	paginated := false
	for name, values := range q {
		if name == "x-id" {
			continue
		}
		switch name {
		case "max-buckets", "bucket-region", "prefix", "continuation-token":
		default:
			return nil, false, errors.New("unsupported query parameter for ListBuckets")
		}
		if len(values) != 1 {
			return nil, false, errors.New("ListBuckets parameters require a single value")
		}
		value := values[0]
		paginated = true
		switch name {
		case "max-buckets":
			limit, err := strconv.ParseInt(value, 10, 32)
			if err != nil || limit < 1 || limit > int64(upstream.DefaultBucketPageSize) {
				return nil, false, errors.New("max-buckets must be between 1 and 10000")
			}
			in.MaxBuckets = aws.Int32(int32(limit))
		case "bucket-region":
			if strings.TrimSpace(value) == "" {
				return nil, false, errors.New("bucket-region must not be empty")
			}
			in.BucketRegion = aws.String(value)
		case "prefix":
			in.Prefix = aws.String(value)
		case "continuation-token":
			if len(value) > 1024 {
				return nil, false, errors.New("continuation-token must not exceed 1024 bytes")
			}
			in.ContinuationToken = aws.String(value)
		}
	}
	return in, paginated, nil
}

func (s *Server) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanCreateBucket(rules, bucket) {
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}
	if !requireOwnerRetainingACLHeaders(w, r, true) {
		return
	}
	in := &s3.CreateBucketInput{Bucket: &bucket}
	if !parseCreateBucketHeaders(w, r, in) {
		return
	}
	cfg, ok := decodeXMLWithContentMD5(w, r, s3xml.DecodeCreateBucketConfig,
		"Invalid or unsupported bucket configuration; only LocationConstraint is supported")
	if !ok {
		return
	}
	in.CreateBucketConfiguration = cfg
	_, err := s.up.CreateBucket(r.Context(), in)
	if err != nil {
		s3http.WriteUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func parseCreateBucketHeaders(w http.ResponseWriter, r *http.Request, in *s3.CreateBucketInput) bool {
	// Reject unsupported settings by presence, including empty header values,
	// before a bucket can be created with weaker protections than requested.
	for name := range r.Header {
		name = strings.ToLower(name)
		if name == "x-amz-bucket-object-lock-enabled" {
			continue
		}
		if strings.HasPrefix(name, "x-amz-bucket-object-lock-") ||
			strings.HasPrefix(name, "x-amz-object-lock-") || name == "x-amz-bucket-namespace" {
			s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Unsupported bucket creation header: "+name)
			return false
		}
	}
	if values := r.Header.Values("x-amz-bucket-object-lock-enabled"); len(values) > 0 {
		if len(values) != 1 || (values[0] != "true" && values[0] != "false") {
			s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "x-amz-bucket-object-lock-enabled must contain one true or false value")
			return false
		}
		in.ObjectLockEnabledForBucket = aws.Bool(values[0] == "true")
	}
	if values := r.Header.Values("x-amz-object-ownership"); len(values) > 0 {
		if len(values) != 1 {
			s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "x-amz-object-ownership must contain one value")
			return false
		}
		switch types.ObjectOwnership(values[0]) {
		case types.ObjectOwnershipBucketOwnerEnforced:
			in.ObjectOwnership = types.ObjectOwnershipBucketOwnerEnforced
		case types.ObjectOwnershipBucketOwnerPreferred, types.ObjectOwnershipObjectWriter:
			s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "ACL-enabled Object Ownership is unsupported; use BucketOwnerEnforced")
			return false
		default:
			s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "Invalid x-amz-object-ownership value")
			return false
		}
	}
	return true
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

	cfg, ok := decodeXMLWithChecksums(w, r, s3xml.DecodeVersioningConfig, "Invalid versioning configuration")
	if !ok {
		return
	}
	in := &s3.PutBucketVersioningInput{
		Bucket:                  &bucket,
		VersioningConfiguration: cfg,
	}
	if mfa := strings.TrimSpace(r.Header.Get("x-amz-mfa")); mfa != "" {
		in.MFA = aws.String(mfa)
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	_, err := s.up.PutBucketVersioning(r.Context(), in)
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

	tagging, ok := decodeXMLWithChecksums(w, r, s3xml.DecodeBucketTagging, "Invalid tagging payload")
	if !ok {
		return
	}
	in := &s3.PutBucketTaggingInput{
		Bucket:  &bucket,
		Tagging: tagging,
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
