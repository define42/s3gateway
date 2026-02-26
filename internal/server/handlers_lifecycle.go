package server

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	authz "github.com/define42/s3gateway/internal/authz"
	"github.com/define42/s3gateway/internal/xmlhelper"
)

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

func (s *Server) handlePutBucketLifecycleConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromCtx(r)
	if !authz.CanCreateBucket(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	cfg, err := decodeLifecycleConfigXML(r.Body)
	if err != nil {
		xmlhelper.WriteXMLError(w, http.StatusBadRequest, "InvalidRequest", "Invalid lifecycle configuration")
		return
	}

	_, err = s.up.PutBucketLifecycleConfiguration(r.Context(), &s3.PutBucketLifecycleConfigurationInput{
		Bucket:                 &bucket,
		LifecycleConfiguration: cfg,
	})
	if err != nil {
		xmlhelper.WriteUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleGetBucketLifecycleConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromCtx(r)
	if !authz.CanRead(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	out, err := s.up.GetBucketLifecycleConfiguration(r.Context(), &s3.GetBucketLifecycleConfigurationInput{
		Bucket: &bucket,
	})
	if err != nil {
		xmlhelper.WriteUpstreamError(w, err)
		return
	}

	body, err := encodeLifecycleConfigXML(out.Rules)
	if err != nil {
		xmlhelper.WriteUpstreamError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body) // #nosec G705 -- body is generated by xml.Marshal, not user-controlled
}

func (s *Server) handleDeleteBucketLifecycleConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromCtx(r)
	if !authz.CanDeleteBucket(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	_, err := s.up.DeleteBucketLifecycle(r.Context(), &s3.DeleteBucketLifecycleInput{
		Bucket: &bucket,
	})
	if err != nil {
		xmlhelper.WriteUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
