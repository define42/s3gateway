package gateway

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func (s *server) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	rules := rulesFromCtx(r)

	out, err := s.up.ListBuckets(r.Context(), &s3.ListBucketsInput{})
	if err != nil {
		writeUpstreamError(w, err)
		return
	}

	xw := beginXMLWriterResponse(w, http.StatusOK)
	defer flushXMLWriterResponse(xw)

	encodeS3RootStart(xw, "ListAllMyBucketsResult")
	xw.Start("Buckets")
	for _, bk := range out.Buckets {
		if bk.Name == nil {
			continue
		}
		if bucketPerm(rules, *bk.Name) != PermNone {
			xw.Start("Bucket")
			xw.Elem("Name", *bk.Name)
			xw.End("Bucket")
		}
	}
	xw.End("Buckets")
	xw.End("ListAllMyBucketsResult")
}

func (s *server) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canCreateBucket(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}
	_, err := s.up.CreateBucket(r.Context(), &s3.CreateBucketInput{Bucket: &bucket})
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

type versioningConfigXML struct {
	XMLName   xml.Name `xml:"VersioningConfiguration"`
	XMLNS     string   `xml:"xmlns,attr,omitempty"`
	Status    *string  `xml:"Status,omitempty"`
	MFADelete *string  `xml:"MfaDelete,omitempty"`
}

func decodeVersioningConfigXML(r io.Reader) (*types.VersioningConfiguration, error) {
	var in versioningConfigXML
	if err := xml.NewDecoder(r).Decode(&in); err != nil {
		return nil, err
	}

	var out types.VersioningConfiguration
	if in.Status != nil {
		rawStatus := strings.TrimSpace(*in.Status)
		if rawStatus != "" {
			matched := false
			for _, allowed := range types.BucketVersioningStatus("").Values() {
				if strings.EqualFold(rawStatus, string(allowed)) {
					out.Status = allowed
					matched = true
					break
				}
			}
			if !matched {
				return nil, fmt.Errorf("invalid versioning status %q", rawStatus)
			}
		}
	}
	if in.MFADelete != nil {
		rawMFA := strings.TrimSpace(*in.MFADelete)
		if rawMFA != "" {
			matched := false
			for _, allowed := range types.MFADelete("").Values() {
				if strings.EqualFold(rawMFA, string(allowed)) {
					out.MFADelete = allowed
					matched = true
					break
				}
			}
			if !matched {
				return nil, fmt.Errorf("invalid mfa delete status %q", rawMFA)
			}
		}
	}
	return &out, nil
}

func encodeVersioningConfigXML(status types.BucketVersioningStatus, mfaDelete types.MFADeleteStatus) ([]byte, error) {
	out := versioningConfigXML{
		XMLNS: "http://s3.amazonaws.com/doc/2006-03-01/",
	}
	if status != "" {
		s := string(status)
		out.Status = &s
	}
	if mfaDelete != "" {
		m := string(mfaDelete)
		out.MFADelete = &m
	}

	body, err := xml.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), body...), nil
}

type taggingXML struct {
	XMLName xml.Name   `xml:"Tagging"`
	XMLNS   string     `xml:"xmlns,attr,omitempty"`
	TagSet  []tagXMLKV `xml:"TagSet>Tag"`
}

type tagXMLKV struct {
	Key   *string `xml:"Key"`
	Value *string `xml:"Value"`
}

func decodeTaggingXML(r io.Reader) (*types.Tagging, error) {
	var in taggingXML
	if err := xml.NewDecoder(r).Decode(&in); err != nil {
		return nil, err
	}
	out := &types.Tagging{
		TagSet: make([]types.Tag, 0, len(in.TagSet)),
	}
	for i, t := range in.TagSet {
		if t.Key == nil {
			return nil, fmt.Errorf("tag[%d] missing key", i)
		}
		if t.Value == nil {
			return nil, fmt.Errorf("tag[%d] missing value", i)
		}
		key := *t.Key
		value := *t.Value
		out.TagSet = append(out.TagSet, types.Tag{
			Key:   aws.String(key),
			Value: aws.String(value),
		})
	}
	return out, nil
}

func writeTaggingXMLResponse(w http.ResponseWriter, status int, tagSet []types.Tag) {
	xw := beginXMLWriterResponse(w, status)
	defer flushXMLWriterResponse(xw)

	encodeS3RootStart(xw, "Tagging")
	xw.Start("TagSet")
	for _, t := range tagSet {
		xw.Start("Tag")
		if t.Key != nil {
			xw.Elem("Key", *t.Key)
		}
		if t.Value != nil {
			xw.Elem("Value", *t.Value)
		}
		xw.End("Tag")
	}
	xw.End("TagSet")
	xw.End("Tagging")
}

func (s *server) handleHeadBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.HeadBucketInput{Bucket: &bucket}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	out, err := s.up.HeadBucket(r.Context(), in)
	if err != nil {
		writeUpstreamHeadError(w, err)
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
		w.Header().Set("x-amz-access-point-alias", boolString(*out.AccessPointAlias))
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleDeleteBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canDeleteBucket(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.DeleteBucketInput{Bucket: &bucket}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	_, err := s.up.DeleteBucket(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handlePutBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	cfg, err := decodeVersioningConfigXML(r.Body)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "MalformedXML", "Invalid versioning configuration")
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
		writeUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleGetBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.GetBucketVersioningInput{Bucket: &bucket}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	out, err := s.up.GetBucketVersioning(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}

	body, err := encodeVersioningConfigXML(out.Status, out.MFADelete)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body) // #nosec G705 -- body is generated by xml.Marshal, not user-controlled
}

func (s *server) handlePutBucketTagging(w http.ResponseWriter, r *http.Request, bucket string) {
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
	checksumAlgorithm, err := parseChecksumAlgorithmHeader(r.Header.Get("x-amz-checksum-algorithm"))
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid checksum algorithm")
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
		writeUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleGetBucketTagging(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
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
		writeUpstreamError(w, err)
		return
	}
	writeTaggingXMLResponse(w, http.StatusOK, out.TagSet)
}

func (s *server) handleDeleteBucketTagging(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.DeleteBucketTaggingInput{
		Bucket: &bucket,
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}

	if _, err := s.up.DeleteBucketTagging(r.Context(), in); err != nil {
		writeUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
