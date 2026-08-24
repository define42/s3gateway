package s3xml

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type versioningConfigXML struct {
	XMLName   xml.Name `xml:"VersioningConfiguration"`
	XMLNS     string   `xml:"xmlns,attr,omitempty"`
	Status    *string  `xml:"Status,omitempty"`
	MFADelete *string  `xml:"MfaDelete,omitempty"`
}

func DecodeVersioningConfig(r io.Reader) (*types.VersioningConfiguration, error) {
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

func DecodeTagging(r io.Reader) (*types.Tagging, error) {
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
