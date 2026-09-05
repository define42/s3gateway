package s3xml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	maxCreateBucketBodyBytes     = int64(16 * 1024)
	maxCreateBucketLocationBytes = 256
)

// DecodeCreateBucketConfig decodes the supported general-purpose bucket
// configuration. An empty body returns nil; an empty configuration root is
// accepted. LocationConstraint is preserved without region normalization.
// Unsupported XML fields are rejected, and successful decoding reads through
// EOF so callers can validate a digest of the original request body.
func DecodeCreateBucketConfig(r io.Reader) (*types.CreateBucketConfiguration, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxCreateBucketBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxCreateBucketBodyBytes {
		return nil, ErrXMLBodyTooLarge
	}
	if len(body) == 0 {
		return nil, nil
	}
	if err := validateCreateBucketProlog(body); err != nil {
		return nil, err
	}

	var config createBucketConfigXML
	err = DecodeLimited(bytes.NewReader(body), &config, DecodeLimits{
		MaxBodyBytes:      maxCreateBucketBodyBytes,
		MaxDepth:          2,
		MaxElements:       2,
		MaxAttributes:     4,
		MaxAttributeBytes: 2048,
		ElementLimits: map[string]int{
			"CreateBucketConfiguration": 1,
			"LocationConstraint":        1,
		},
		FieldByteLimits: map[string]int{
			"LocationConstraint": maxCreateBucketLocationBytes,
		},
	})
	if err != nil {
		return nil, err
	}
	return &types.CreateBucketConfiguration{LocationConstraint: config.location}, nil
}

func validateCreateBucketProlog(body []byte) error {
	// encoding/xml.Decode skips text preceding the root, even if that text is
	// not whitespace. Reject such malformed input before decoding the document.
	decoder := xml.NewDecoder(bytes.NewReader(body))
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch token := token.(type) {
		case xml.StartElement:
			return nil
		case xml.CharData:
			if len(bytes.TrimSpace(token)) != 0 {
				return errors.New("unexpected text before CreateBucketConfiguration")
			}
		case xml.Comment, xml.ProcInst:
		default:
			return errors.New("unsupported content before CreateBucketConfiguration")
		}
	}
}

type createBucketConfigXML struct {
	location types.BucketLocationConstraint
}

func (c *createBucketConfigXML) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	if start.Name.Local != "CreateBucketConfiguration" {
		return errors.New("expected CreateBucketConfiguration root")
	}
	if err := validateCreateBucketElement(start); err != nil {
		return err
	}

	var location strings.Builder
	var inLocation, seenLocation bool
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch token := token.(type) {
		case xml.StartElement:
			if inLocation || token.Name.Local != "LocationConstraint" {
				return fmt.Errorf("unsupported CreateBucketConfiguration element %s", token.Name.Local)
			}
			if seenLocation {
				return errors.New("duplicate LocationConstraint")
			}
			if err := validateCreateBucketElement(token); err != nil {
				return err
			}
			inLocation, seenLocation = true, true
		case xml.EndElement:
			if inLocation {
				inLocation = false
				continue
			}
			c.location = types.BucketLocationConstraint(location.String())
			return nil
		case xml.CharData:
			if inLocation {
				location.Write(token)
			} else if strings.TrimSpace(string(token)) != "" {
				return errors.New("unexpected text in CreateBucketConfiguration")
			}
		case xml.Comment, xml.ProcInst:
			// Comments and processing instructions do not change field values.
		default:
			return errors.New("unsupported content in CreateBucketConfiguration")
		}
	}
}

func validateCreateBucketElement(start xml.StartElement) error {
	if start.Name.Space != "" && start.Name.Space != s3XMLNamespace {
		return fmt.Errorf("unsupported namespace for %s", start.Name.Local)
	}
	for _, attr := range start.Attr {
		if attr.Name.Local == "xmlns" && attr.Name.Space == "" || attr.Name.Space == "xmlns" {
			continue
		}
		return fmt.Errorf("unsupported attribute %s on %s", attr.Name.Local, start.Name.Local)
	}
	return nil
}
