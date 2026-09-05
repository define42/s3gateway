package server

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// Unknown fields must not disappear when the gateway rebuilds a completion
// manifest: they may request checksum validation unsupported by the gateway.
type unsupportedCompleteMultipartElement struct{}

func (*unsupportedCompleteMultipartElement) UnmarshalXML(_ *xml.Decoder, start xml.StartElement) error {
	return fmt.Errorf("unsupported multipart completion element %q", start.Name.Local)
}

type completeMultipartChecksum struct {
	value *string
}

func (c *completeMultipartChecksum) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	if c.value != nil {
		return fmt.Errorf("duplicate multipart checksum %s", start.Name.Local)
	}
	value, err := decodeCompleteMultipartText(decoder, start)
	if err != nil {
		return err
	}
	c.value = aws.String(value)
	return nil
}

type completeMultipartETag string

func (e *completeMultipartETag) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	value, err := decodeCompleteMultipartText(decoder, start)
	if err != nil {
		return err
	}
	*e = completeMultipartETag(value)
	return nil
}

type completeMultipartPartNumber int32

func (p *completeMultipartPartNumber) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	value, err := decodeCompleteMultipartText(decoder, start)
	if err != nil {
		return err
	}
	number, err := strconv.ParseInt(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return err
	}
	*p = completeMultipartPartNumber(number)
	return nil
}

func decodeCompleteMultipartText(decoder *xml.Decoder, start xml.StartElement) (string, error) {
	var element struct {
		Value       string                              `xml:",chardata"`
		Unsupported unsupportedCompleteMultipartElement `xml:",any"`
	}
	if err := decoder.DecodeElement(&element, &start); err != nil {
		return "", err
	}
	if strings.TrimSpace(element.Value) == "" {
		return "", errors.New("multipart completion field must not be empty")
	}
	return element.Value, nil
}
