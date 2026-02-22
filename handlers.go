package main

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const maxSinglePutObjectSize = int64(5 * 1024 * 1024 * 1024) // 5 GiB

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

type lifecycleConfigReqXML struct {
	XMLName xml.Name           `xml:"LifecycleConfiguration"`
	Rules   []lifecycleRuleXML `xml:"Rule"`
}

type lifecycleTagXML struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type lifecycleAndXML struct {
	Prefix                *string           `xml:"Prefix,omitempty"`
	Tag                   []lifecycleTagXML `xml:"Tag,omitempty"`
	ObjectSizeGreaterThan *int64            `xml:"ObjectSizeGreaterThan,omitempty"`
	ObjectSizeLessThan    *int64            `xml:"ObjectSizeLessThan,omitempty"`
}

type lifecycleFilterXML struct {
	Prefix                *string          `xml:"Prefix,omitempty"`
	Tag                   *lifecycleTagXML `xml:"Tag,omitempty"`
	And                   *lifecycleAndXML `xml:"And,omitempty"`
	ObjectSizeGreaterThan *int64           `xml:"ObjectSizeGreaterThan,omitempty"`
	ObjectSizeLessThan    *int64           `xml:"ObjectSizeLessThan,omitempty"`
}

type lifecycleExpirationXML struct {
	Days                      *int32  `xml:"Days,omitempty"`
	Date                      *string `xml:"Date,omitempty"`
	ExpiredObjectDeleteMarker *bool   `xml:"ExpiredObjectDeleteMarker,omitempty"`
}

type lifecycleTransitionXML struct {
	Date         *string `xml:"Date,omitempty"`
	Days         *int32  `xml:"Days,omitempty"`
	StorageClass *string `xml:"StorageClass,omitempty"`
}

type lifecycleNoncurrentVersionTransitionXML struct {
	NoncurrentDays          *int32  `xml:"NoncurrentDays,omitempty"`
	NewerNoncurrentVersions *int32  `xml:"NewerNoncurrentVersions,omitempty"`
	StorageClass            *string `xml:"StorageClass,omitempty"`
}

type lifecycleNoncurrentVersionExpirationXML struct {
	NoncurrentDays          *int32 `xml:"NoncurrentDays,omitempty"`
	NewerNoncurrentVersions *int32 `xml:"NewerNoncurrentVersions,omitempty"`
}

type lifecycleAbortIncompleteMultipartUploadXML struct {
	DaysAfterInitiation *int32 `xml:"DaysAfterInitiation,omitempty"`
}

type lifecycleRuleXML struct {
	ID                             *string                                     `xml:"ID,omitempty"`
	Status                         string                                      `xml:"Status"`
	Prefix                         *string                                     `xml:"Prefix,omitempty"`
	Filter                         *lifecycleFilterXML                         `xml:"Filter,omitempty"`
	Expiration                     *lifecycleExpirationXML                     `xml:"Expiration,omitempty"`
	Transition                     []lifecycleTransitionXML                    `xml:"Transition,omitempty"`
	NoncurrentVersionTransition    []lifecycleNoncurrentVersionTransitionXML   `xml:"NoncurrentVersionTransition,omitempty"`
	NoncurrentVersionExpiration    *lifecycleNoncurrentVersionExpirationXML    `xml:"NoncurrentVersionExpiration,omitempty"`
	AbortIncompleteMultipartUpload *lifecycleAbortIncompleteMultipartUploadXML `xml:"AbortIncompleteMultipartUpload,omitempty"`
}

type lifecycleConfigRespXML struct {
	XMLName xml.Name           `xml:"LifecycleConfiguration"`
	XMLNS   string             `xml:"xmlns,attr,omitempty"`
	Rules   []lifecycleRuleXML `xml:"Rule"`
}

func parseLifecycleDate(raw string) (*time.Time, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("empty lifecycle date")
	}
	formats := []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			utc := t.UTC()
			return &utc, nil
		}
	}
	return nil, errors.New("invalid lifecycle date")
}

func formatLifecycleDate(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format("2006-01-02T15:04:05.000Z")
	return &s
}

func parseTransitionStorageClass(v string) (types.TransitionStorageClass, error) {
	raw := strings.ToUpper(strings.TrimSpace(v))
	if raw == "" {
		return "", errors.New("missing storage class")
	}
	for _, allowed := range types.TransitionStorageClass("").Values() {
		if raw == string(allowed) {
			return allowed, nil
		}
	}
	return "", fmt.Errorf("unsupported storage class %q", raw)
}

func decodeLifecycleTag(x *lifecycleTagXML) (*types.Tag, error) {
	if x == nil {
		return nil, nil
	}
	key := strings.TrimSpace(x.Key)
	if key == "" {
		return nil, errors.New("missing lifecycle tag key")
	}
	val := strings.TrimSpace(x.Value)
	return &types.Tag{
		Key:   aws.String(key),
		Value: aws.String(val),
	}, nil
}

func encodeLifecycleTag(t *types.Tag) *lifecycleTagXML {
	if t == nil {
		return nil
	}
	return &lifecycleTagXML{
		Key:   aws.ToString(t.Key),
		Value: aws.ToString(t.Value),
	}
}

func decodeLifecycleAnd(x *lifecycleAndXML) (*types.LifecycleRuleAndOperator, error) {
	if x == nil {
		return nil, nil
	}
	out := &types.LifecycleRuleAndOperator{}
	var hasPred bool
	if x.Prefix != nil {
		out.Prefix = aws.String(strings.TrimSpace(*x.Prefix))
		hasPred = true
	}
	if x.ObjectSizeGreaterThan != nil {
		if *x.ObjectSizeGreaterThan < 0 {
			return nil, errors.New("invalid object size greater-than")
		}
		out.ObjectSizeGreaterThan = aws.Int64(*x.ObjectSizeGreaterThan)
		hasPred = true
	}
	if x.ObjectSizeLessThan != nil {
		if *x.ObjectSizeLessThan < 0 {
			return nil, errors.New("invalid object size less-than")
		}
		out.ObjectSizeLessThan = aws.Int64(*x.ObjectSizeLessThan)
		hasPred = true
	}
	if out.ObjectSizeGreaterThan != nil && out.ObjectSizeLessThan != nil &&
		aws.ToInt64(out.ObjectSizeGreaterThan) >= aws.ToInt64(out.ObjectSizeLessThan) {
		return nil, errors.New("object size greater-than must be less than object size less-than")
	}
	if len(x.Tag) > 0 {
		out.Tags = make([]types.Tag, 0, len(x.Tag))
		for _, xt := range x.Tag {
			tag, err := decodeLifecycleTag(&xt)
			if err != nil {
				return nil, err
			}
			out.Tags = append(out.Tags, *tag)
		}
		hasPred = true
	}
	if !hasPred {
		return nil, errors.New("empty And filter")
	}
	return out, nil
}

func encodeLifecycleAnd(a *types.LifecycleRuleAndOperator) *lifecycleAndXML {
	if a == nil {
		return nil
	}
	out := &lifecycleAndXML{}
	if a.Prefix != nil {
		out.Prefix = aws.String(aws.ToString(a.Prefix))
	}
	if a.ObjectSizeGreaterThan != nil {
		out.ObjectSizeGreaterThan = aws.Int64(aws.ToInt64(a.ObjectSizeGreaterThan))
	}
	if a.ObjectSizeLessThan != nil {
		out.ObjectSizeLessThan = aws.Int64(aws.ToInt64(a.ObjectSizeLessThan))
	}
	if len(a.Tags) > 0 {
		out.Tag = make([]lifecycleTagXML, 0, len(a.Tags))
		for _, t := range a.Tags {
			out.Tag = append(out.Tag, lifecycleTagXML{
				Key:   aws.ToString(t.Key),
				Value: aws.ToString(t.Value),
			})
		}
	}
	return out
}

func decodeLifecycleFilter(x *lifecycleFilterXML) (*types.LifecycleRuleFilter, error) {
	if x == nil {
		return nil, nil
	}
	out := &types.LifecycleRuleFilter{}
	var topLevelPredicates int
	if x.Prefix != nil {
		out.Prefix = aws.String(strings.TrimSpace(*x.Prefix))
		topLevelPredicates++
	}
	if x.Tag != nil {
		tag, err := decodeLifecycleTag(x.Tag)
		if err != nil {
			return nil, err
		}
		out.Tag = tag
		topLevelPredicates++
	}
	if x.And != nil {
		and, err := decodeLifecycleAnd(x.And)
		if err != nil {
			return nil, err
		}
		out.And = and
		topLevelPredicates++
	}
	if x.ObjectSizeGreaterThan != nil {
		if *x.ObjectSizeGreaterThan < 0 {
			return nil, errors.New("invalid object size greater-than")
		}
		out.ObjectSizeGreaterThan = aws.Int64(*x.ObjectSizeGreaterThan)
		topLevelPredicates++
	}
	if x.ObjectSizeLessThan != nil {
		if *x.ObjectSizeLessThan < 0 {
			return nil, errors.New("invalid object size less-than")
		}
		out.ObjectSizeLessThan = aws.Int64(*x.ObjectSizeLessThan)
		topLevelPredicates++
	}
	if topLevelPredicates > 1 {
		return nil, errors.New("filter must have exactly one top-level predicate")
	}
	return out, nil
}

func encodeLifecycleFilter(f *types.LifecycleRuleFilter) *lifecycleFilterXML {
	if f == nil {
		return nil
	}
	out := &lifecycleFilterXML{}
	if f.Prefix != nil {
		out.Prefix = aws.String(aws.ToString(f.Prefix))
	}
	if f.Tag != nil {
		out.Tag = encodeLifecycleTag(f.Tag)
	}
	if f.And != nil {
		out.And = encodeLifecycleAnd(f.And)
	}
	if f.ObjectSizeGreaterThan != nil {
		out.ObjectSizeGreaterThan = aws.Int64(aws.ToInt64(f.ObjectSizeGreaterThan))
	}
	if f.ObjectSizeLessThan != nil {
		out.ObjectSizeLessThan = aws.Int64(aws.ToInt64(f.ObjectSizeLessThan))
	}
	return out
}

func decodeLifecycleExpiration(x *lifecycleExpirationXML) (*types.LifecycleExpiration, error) {
	if x == nil {
		return nil, nil
	}
	out := &types.LifecycleExpiration{}
	var hasField bool
	if x.Days != nil {
		if *x.Days <= 0 {
			return nil, errors.New("invalid expiration days")
		}
		out.Days = aws.Int32(*x.Days)
		hasField = true
	}
	if x.Date != nil {
		d, err := parseLifecycleDate(*x.Date)
		if err != nil {
			return nil, err
		}
		out.Date = d
		hasField = true
	}
	if x.ExpiredObjectDeleteMarker != nil {
		out.ExpiredObjectDeleteMarker = aws.Bool(*x.ExpiredObjectDeleteMarker)
		hasField = true
	}
	if !hasField {
		return nil, errors.New("empty expiration")
	}
	if out.ExpiredObjectDeleteMarker != nil && (out.Days != nil || out.Date != nil) {
		return nil, errors.New("expired object delete marker cannot be combined with days/date")
	}
	return out, nil
}

func encodeLifecycleExpiration(exp *types.LifecycleExpiration) *lifecycleExpirationXML {
	if exp == nil {
		return nil
	}
	out := &lifecycleExpirationXML{}
	if exp.Days != nil {
		out.Days = aws.Int32(aws.ToInt32(exp.Days))
	}
	if exp.Date != nil {
		out.Date = formatLifecycleDate(exp.Date)
	}
	if exp.ExpiredObjectDeleteMarker != nil {
		out.ExpiredObjectDeleteMarker = aws.Bool(aws.ToBool(exp.ExpiredObjectDeleteMarker))
	}
	return out
}

func decodeLifecycleTransition(x lifecycleTransitionXML) (types.Transition, error) {
	var out types.Transition
	if x.Days != nil {
		if *x.Days < 0 {
			return out, errors.New("invalid transition days")
		}
		out.Days = aws.Int32(*x.Days)
	}
	if x.Date != nil {
		d, err := parseLifecycleDate(*x.Date)
		if err != nil {
			return out, err
		}
		out.Date = d
	}
	if out.Days != nil && out.Date != nil {
		return out, errors.New("transition cannot have both date and days")
	}
	if out.Days == nil && out.Date == nil {
		return out, errors.New("transition must have date or days")
	}
	if x.StorageClass == nil || strings.TrimSpace(*x.StorageClass) == "" {
		return out, errors.New("transition missing storage class")
	}
	sc, err := parseTransitionStorageClass(*x.StorageClass)
	if err != nil {
		return out, err
	}
	out.StorageClass = sc
	return out, nil
}

func encodeLifecycleTransition(t types.Transition) lifecycleTransitionXML {
	out := lifecycleTransitionXML{}
	if t.Date != nil {
		out.Date = formatLifecycleDate(t.Date)
	}
	if t.Days != nil {
		out.Days = aws.Int32(aws.ToInt32(t.Days))
	}
	if t.StorageClass != "" {
		sc := string(t.StorageClass)
		out.StorageClass = &sc
	}
	return out
}

func decodeLifecycleNoncurrentTransition(x lifecycleNoncurrentVersionTransitionXML) (types.NoncurrentVersionTransition, error) {
	var out types.NoncurrentVersionTransition
	if x.NoncurrentDays != nil {
		if *x.NoncurrentDays <= 0 {
			return out, errors.New("invalid noncurrent transition days")
		}
		out.NoncurrentDays = aws.Int32(*x.NoncurrentDays)
	}
	if x.NewerNoncurrentVersions != nil {
		if *x.NewerNoncurrentVersions <= 0 {
			return out, errors.New("invalid newer noncurrent versions")
		}
		out.NewerNoncurrentVersions = aws.Int32(*x.NewerNoncurrentVersions)
	}
	if out.NoncurrentDays == nil {
		return out, errors.New("noncurrent transition requires noncurrent days")
	}
	if x.StorageClass == nil || strings.TrimSpace(*x.StorageClass) == "" {
		return out, errors.New("noncurrent transition missing storage class")
	}
	sc, err := parseTransitionStorageClass(*x.StorageClass)
	if err != nil {
		return out, err
	}
	out.StorageClass = sc
	return out, nil
}

func encodeLifecycleNoncurrentTransition(t types.NoncurrentVersionTransition) lifecycleNoncurrentVersionTransitionXML {
	out := lifecycleNoncurrentVersionTransitionXML{}
	if t.NoncurrentDays != nil {
		out.NoncurrentDays = aws.Int32(aws.ToInt32(t.NoncurrentDays))
	}
	if t.NewerNoncurrentVersions != nil {
		out.NewerNoncurrentVersions = aws.Int32(aws.ToInt32(t.NewerNoncurrentVersions))
	}
	if t.StorageClass != "" {
		sc := string(t.StorageClass)
		out.StorageClass = &sc
	}
	return out
}

func decodeLifecycleNoncurrentExpiration(x *lifecycleNoncurrentVersionExpirationXML) (*types.NoncurrentVersionExpiration, error) {
	if x == nil {
		return nil, nil
	}
	out := &types.NoncurrentVersionExpiration{}
	var hasField bool
	if x.NoncurrentDays != nil {
		if *x.NoncurrentDays <= 0 {
			return nil, errors.New("invalid noncurrent expiration days")
		}
		out.NoncurrentDays = aws.Int32(*x.NoncurrentDays)
		hasField = true
	}
	if x.NewerNoncurrentVersions != nil {
		if *x.NewerNoncurrentVersions <= 0 {
			return nil, errors.New("invalid newer noncurrent versions")
		}
		out.NewerNoncurrentVersions = aws.Int32(*x.NewerNoncurrentVersions)
		hasField = true
	}
	if !hasField {
		return nil, errors.New("empty noncurrent expiration")
	}
	return out, nil
}

func encodeLifecycleNoncurrentExpiration(exp *types.NoncurrentVersionExpiration) *lifecycleNoncurrentVersionExpirationXML {
	if exp == nil {
		return nil
	}
	out := &lifecycleNoncurrentVersionExpirationXML{}
	if exp.NoncurrentDays != nil {
		out.NoncurrentDays = aws.Int32(aws.ToInt32(exp.NoncurrentDays))
	}
	if exp.NewerNoncurrentVersions != nil {
		out.NewerNoncurrentVersions = aws.Int32(aws.ToInt32(exp.NewerNoncurrentVersions))
	}
	return out
}

func decodeLifecycleAbortIncompleteMultipartUpload(x *lifecycleAbortIncompleteMultipartUploadXML) (*types.AbortIncompleteMultipartUpload, error) {
	if x == nil {
		return nil, nil
	}
	if x.DaysAfterInitiation == nil || *x.DaysAfterInitiation <= 0 {
		return nil, errors.New("invalid days after initiation")
	}
	return &types.AbortIncompleteMultipartUpload{
		DaysAfterInitiation: aws.Int32(*x.DaysAfterInitiation),
	}, nil
}

func encodeLifecycleAbortIncompleteMultipartUpload(a *types.AbortIncompleteMultipartUpload) *lifecycleAbortIncompleteMultipartUploadXML {
	if a == nil {
		return nil
	}
	out := &lifecycleAbortIncompleteMultipartUploadXML{}
	if a.DaysAfterInitiation != nil {
		out.DaysAfterInitiation = aws.Int32(aws.ToInt32(a.DaysAfterInitiation))
	}
	return out
}

func decodeLifecycleConfigXML(r io.Reader) (*types.BucketLifecycleConfiguration, error) {
	var in lifecycleConfigReqXML
	if err := xml.NewDecoder(r).Decode(&in); err != nil {
		return nil, err
	}
	if len(in.Rules) == 0 {
		return nil, errors.New("missing lifecycle rules")
	}

	rules := make([]types.LifecycleRule, 0, len(in.Rules))
	for i, xr := range in.Rules {
		var status types.ExpirationStatus
		switch strings.ToLower(strings.TrimSpace(xr.Status)) {
		case "enabled":
			status = types.ExpirationStatusEnabled
		case "disabled":
			status = types.ExpirationStatusDisabled
		default:
			return nil, fmt.Errorf("rule %d has invalid status", i)
		}

		rule := types.LifecycleRule{Status: status}
		if xr.ID != nil {
			id := strings.TrimSpace(*xr.ID)
			if id != "" {
				rule.ID = aws.String(id)
			}
		}
		if xr.Prefix != nil && xr.Filter != nil {
			return nil, fmt.Errorf("rule %d cannot contain both Prefix and Filter", i)
		}
		filter, err := decodeLifecycleFilter(xr.Filter)
		if err != nil {
			return nil, fmt.Errorf("rule %d has invalid filter: %w", i, err)
		}
		if xr.Prefix != nil {
			filter = &types.LifecycleRuleFilter{
				Prefix: aws.String(strings.TrimSpace(*xr.Prefix)),
			}
		}
		rule.Filter = filter
		exp, err := decodeLifecycleExpiration(xr.Expiration)
		if err != nil {
			return nil, fmt.Errorf("rule %d has invalid expiration: %w", i, err)
		}
		rule.Expiration = exp

		if len(xr.Transition) > 0 {
			rule.Transitions = make([]types.Transition, 0, len(xr.Transition))
			for j, xt := range xr.Transition {
				t, err := decodeLifecycleTransition(xt)
				if err != nil {
					return nil, fmt.Errorf("rule %d transition %d invalid: %w", i, j, err)
				}
				rule.Transitions = append(rule.Transitions, t)
			}
		}

		if len(xr.NoncurrentVersionTransition) > 0 {
			rule.NoncurrentVersionTransitions = make([]types.NoncurrentVersionTransition, 0, len(xr.NoncurrentVersionTransition))
			for j, xt := range xr.NoncurrentVersionTransition {
				t, err := decodeLifecycleNoncurrentTransition(xt)
				if err != nil {
					return nil, fmt.Errorf("rule %d noncurrent transition %d invalid: %w", i, j, err)
				}
				rule.NoncurrentVersionTransitions = append(rule.NoncurrentVersionTransitions, t)
			}
		}

		nce, err := decodeLifecycleNoncurrentExpiration(xr.NoncurrentVersionExpiration)
		if err != nil {
			return nil, fmt.Errorf("rule %d has invalid noncurrent expiration: %w", i, err)
		}
		rule.NoncurrentVersionExpiration = nce

		abort, err := decodeLifecycleAbortIncompleteMultipartUpload(xr.AbortIncompleteMultipartUpload)
		if err != nil {
			return nil, fmt.Errorf("rule %d has invalid abort multipart settings: %w", i, err)
		}
		rule.AbortIncompleteMultipartUpload = abort

		rules = append(rules, rule)
	}

	return &types.BucketLifecycleConfiguration{Rules: rules}, nil
}

func encodeLifecycleConfigXML(rules []types.LifecycleRule) ([]byte, error) {
	out := lifecycleConfigRespXML{
		XMLNS: "http://s3.amazonaws.com/doc/2006-03-01/",
		Rules: make([]lifecycleRuleXML, 0, len(rules)),
	}
	for _, r := range rules {
		xr := lifecycleRuleXML{
			ID:     r.ID,
			Status: string(r.Status),
		}
		filter := r.Filter
		if filter == nil {
			if legacyPrefix := lifecycleRuleLegacyPrefix(r); legacyPrefix != nil {
				filter = &types.LifecycleRuleFilter{
					Prefix: legacyPrefix,
				}
			}
		}
		xr.Filter = encodeLifecycleFilter(filter)
		xr.Expiration = encodeLifecycleExpiration(r.Expiration)
		if len(r.Transitions) > 0 {
			xr.Transition = make([]lifecycleTransitionXML, 0, len(r.Transitions))
			for _, t := range r.Transitions {
				xr.Transition = append(xr.Transition, encodeLifecycleTransition(t))
			}
		}
		if len(r.NoncurrentVersionTransitions) > 0 {
			xr.NoncurrentVersionTransition = make([]lifecycleNoncurrentVersionTransitionXML, 0, len(r.NoncurrentVersionTransitions))
			for _, t := range r.NoncurrentVersionTransitions {
				xr.NoncurrentVersionTransition = append(xr.NoncurrentVersionTransition, encodeLifecycleNoncurrentTransition(t))
			}
		}
		xr.NoncurrentVersionExpiration = encodeLifecycleNoncurrentExpiration(r.NoncurrentVersionExpiration)
		xr.AbortIncompleteMultipartUpload = encodeLifecycleAbortIncompleteMultipartUpload(r.AbortIncompleteMultipartUpload)
		out.Rules = append(out.Rules, xr)
	}
	body, err := xml.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), body...), nil
}

func lifecycleRuleLegacyPrefix(r types.LifecycleRule) *string {
	field := reflect.ValueOf(r).FieldByName("Prefix")
	if !field.IsValid() || field.Kind() != reflect.Pointer || field.IsNil() {
		return nil
	}
	legacy, ok := field.Interface().(*string)
	if !ok || legacy == nil {
		return nil
	}
	return aws.String(strings.TrimSpace(*legacy))
}

func (s *server) handlePutBucketLifecycleConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canCreateBucket(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	cfg, err := decodeLifecycleConfigXML(r.Body)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "Invalid lifecycle configuration")
		return
	}

	_, err = s.up.PutBucketLifecycleConfiguration(r.Context(), &s3.PutBucketLifecycleConfigurationInput{
		Bucket:                 &bucket,
		LifecycleConfiguration: cfg,
	})
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleGetBucketLifecycleConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	out, err := s.up.GetBucketLifecycleConfiguration(r.Context(), &s3.GetBucketLifecycleConfigurationInput{
		Bucket: &bucket,
	})
	if err != nil {
		writeUpstreamError(w, err)
		return
	}

	body, err := encodeLifecycleConfigXML(out.Rules)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body) // #nosec G705 -- body is generated by xml.Marshal, not user-controlled
}

func (s *server) handleDeleteBucketLifecycleConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canDeleteBucket(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	_, err := s.up.DeleteBucketLifecycle(r.Context(), &s3.DeleteBucketLifecycleInput{
		Bucket: &bucket,
	})
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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

func (s *server) handleListMultipartUploads(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
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
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid max-uploads")
			return
		}
		in.MaxUploads = aws.Int32(int32(n))
	}

	out, err := s.up.ListMultipartUploads(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}

	xw := beginXMLWriterResponse(w, http.StatusOK)
	defer flushXMLWriterResponse(xw)

	encodeS3RootStart(xw, "ListMultipartUploadsResult")
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
	encodeCommonPrefixes(xw, out.CommonPrefixes)
	for _, u := range out.Uploads {
		xw.Start("Upload")
		if u.Key != nil {
			xw.Elem("Key", *u.Key)
		}
		if u.UploadId != nil {
			xw.Elem("UploadId", *u.UploadId)
		}
		if u.Initiated != nil {
			xw.Elem("Initiated", formatS3Time(*u.Initiated))
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
		encodeOwnerDisplayNameThenID(xw, u.Owner)
		encodeInitiatorDisplayNameThenID(xw, u.Initiator)
		xw.End("Upload")
	}
	xw.End("ListMultipartUploadsResult")
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
		// Allow streaming io.Reader without Seek by using Unsigned Payload middleware. :contentReference[oaicite:10]{index=10}
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

// ---------- Multipart ----------

type completeMultipartUpload struct {
	XMLName xml.Name `xml:"CompleteMultipartUpload"`
	Parts   []struct {
		PartNumber int32  `xml:"PartNumber"`
		ETag       string `xml:"ETag"`
	} `xml:"Part"`
}

func (s *server) handleCreateMultipart(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
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
		writeUpstreamError(w, err)
		return
	}

	xw := beginXMLWriterResponse(w, http.StatusOK)
	defer flushXMLWriterResponse(xw)

	encodeS3RootStart(xw, "InitiateMultipartUploadResult")
	xw.Elem("Bucket", bucket)
	xw.Elem("Key", key)
	xw.Elem("UploadId", aws.ToString(out.UploadId))
	xw.End("InitiateMultipartUploadResult")
}

func (s *server) handleUploadPart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string, partNumber int32) {
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
	ssecAlgo, ssecKey, ssecMD5, hasSSEC, err := parseSSECustomerHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid SSE-C headers")
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
		// Allow streaming io.Reader without Seek. :contentReference[oaicite:11]{index=11}
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
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleListParts(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
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
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid part-number-marker")
			return
		}
		in.PartNumberMarker = aws.String(strconv.Itoa(pnm))
	}
	if mpStr := r.URL.Query().Get("max-parts"); mpStr != "" {
		mp, err := strconv.ParseInt(mpStr, 10, 32)
		if err != nil || mp <= 0 {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid max-parts")
			return
		}
		in.MaxParts = aws.Int32(int32(mp))
	}

	out, err := s.up.ListParts(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}

	xw := beginXMLWriterResponse(w, http.StatusOK)
	defer flushXMLWriterResponse(xw)

	encodeS3RootStart(xw, "ListPartsResult")
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
			xw.Elem("LastModified", formatS3Time(*p.LastModified))
		}
		if p.ETag != nil {
			xw.Elem("ETag", *p.ETag)
		}
		xw.ElemInt("Size", aws.ToInt64(p.Size))
		xw.End("Part")
	}
	xw.End("ListPartsResult")
}

// CompleteMultipartUpload requires PartNumber + ETag for each part. :contentReference[oaicite:12]{index=12}
func (s *server) handleCompleteMultipart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	var cmu completeMultipartUpload
	if err := xml.NewDecoder(r.Body).Decode(&cmu); err != nil {
		writeXMLError(w, http.StatusBadRequest, "MalformedXML", "Invalid XML")
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
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "No parts provided")
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
		writeUpstreamError(w, err)
		return
	}

	xw := beginXMLWriterResponse(w, http.StatusOK)
	defer flushXMLWriterResponse(xw)

	encodeS3RootStart(xw, "CompleteMultipartUploadResult")
	xw.Elem("Bucket", bucket)
	xw.Elem("Key", key)
	if out.ETag != nil {
		xw.Start("ETag")
		xw.RawString(`"` + xmlEscape(strings.Trim(*out.ETag, `"`)) + `"`)
		xw.End("ETag")
	}
	xw.End("CompleteMultipartUploadResult")
}

func (s *server) handleAbortMultipart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}
	_, err := s.up.AbortMultipartUpload(r.Context(), &s3.AbortMultipartUploadInput{
		Bucket:   &bucket,
		Key:      &key,
		UploadId: &uploadID,
	})
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

