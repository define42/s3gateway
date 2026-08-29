package s3xml

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	maxVersioningBodyBytes  = int64(16 * 1024)
	maxVersioningFieldBytes = 32

	maxObjectTags         = 10
	maxBucketTags         = 50
	maxObjectTaggingBytes = int64(64 * 1024)
	maxBucketTaggingBytes = int64(256 * 1024)
	maxTagKeyRunes        = 128
	maxTagValueRunes      = 256
	maxTagKeyBytes        = maxTagKeyRunes * utf8.UTFMax
	maxTagValueBytes      = maxTagValueRunes * utf8.UTFMax
)

var versioningDecodeLimits = DecodeLimits{
	MaxBodyBytes:      maxVersioningBodyBytes,
	MaxDepth:          4,
	MaxElements:       16,
	MaxAttributes:     4,
	MaxAttributeBytes: 2048,
	ElementLimits: map[string]int{
		"VersioningConfiguration": 1,
		"Status":                  1,
		"MfaDelete":               1,
	},
	FieldByteLimits: map[string]int{
		"Status":    maxVersioningFieldBytes,
		"MfaDelete": maxVersioningFieldBytes,
	},
}

type versioningConfigXML struct {
	XMLName   xml.Name `xml:"VersioningConfiguration"`
	XMLNS     string   `xml:"xmlns,attr,omitempty"`
	Status    *string  `xml:"Status,omitempty"`
	MFADelete *string  `xml:"MfaDelete,omitempty"`
}

// DecodeVersioningConfig decodes a bucket versioning request and normalizes
// recognized status values case-insensitively. Unknown Status or MFADelete
// values return an error.
func DecodeVersioningConfig(r io.Reader) (*types.VersioningConfiguration, error) {
	var in versioningConfigXML
	if err := DecodeLimited(r, &in, versioningDecodeLimits); err != nil {
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

// EncodeVersioningConfig returns a complete S3 versioning XML document. Empty
// status values are omitted; non-empty values are encoded without validation.
func EncodeVersioningConfig(status types.BucketVersioningStatus, mfaDelete types.MFADeleteStatus) ([]byte, error) {
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

// DecodeTagging decodes object tagging with S3's ten-tag limit. New call sites
// should use DecodeObjectTagging or DecodeBucketTagging to make the operation's
// distinct limit explicit.
func DecodeTagging(r io.Reader) (*types.Tagging, error) {
	return DecodeObjectTagging(r)
}

// DecodeObjectTagging decodes an object Tagging document with S3's ten-tag
// limit.
func DecodeObjectTagging(r io.Reader) (*types.Tagging, error) {
	return decodeTagging(r, maxObjectTaggingBytes, maxObjectTags)
}

// DecodeBucketTagging decodes a bucket Tagging document with S3's fifty-tag
// limit.
func DecodeBucketTagging(r io.Reader) (*types.Tagging, error) {
	return decodeTagging(r, maxBucketTaggingBytes, maxBucketTags)
}

func decodeTagging(r io.Reader, maxBodyBytes int64, maxTags int) (*types.Tagging, error) {
	var in taggingXML
	limits := DecodeLimits{
		MaxBodyBytes:      maxBodyBytes,
		MaxDepth:          6,
		MaxElements:       4 + 3*maxTags,
		MaxAttributes:     4,
		MaxAttributeBytes: 2048,
		ElementLimits: map[string]int{
			"Tagging": 1,
			"TagSet":  1,
			"Tag":     maxTags,
			"Key":     maxTags,
			"Value":   maxTags,
		},
		FieldByteLimits: map[string]int{
			"Key":   maxTagKeyBytes,
			"Value": maxTagValueBytes,
		},
	}
	if err := DecodeLimited(r, &in, limits); err != nil {
		return nil, err
	}
	if len(in.TagSet) > maxTags {
		return nil, fmt.Errorf("tag set exceeds %d tags", maxTags)
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
		if utf8.RuneCountInString(key) > maxTagKeyRunes {
			return nil, fmt.Errorf("tag[%d] key exceeds %d characters", i, maxTagKeyRunes)
		}
		if utf8.RuneCountInString(value) > maxTagValueRunes {
			return nil, fmt.Errorf("tag[%d] value exceeds %d characters", i, maxTagValueRunes)
		}
		out.TagSet = append(out.TagSet, types.Tag{
			Key:   aws.String(key),
			Value: aws.String(value),
		})
	}
	return out, nil
}

// WriteTaggingResponse writes an S3 Tagging document, omitting nil tag fields.
// Response-write errors cannot be returned to the caller.
func WriteTaggingResponse(w http.ResponseWriter, status int, tagSet []types.Tag) {
	xw := BeginResponse(w, status)
	defer FlushResponse(xw)

	EncodeRootStart(xw, "Tagging")
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
