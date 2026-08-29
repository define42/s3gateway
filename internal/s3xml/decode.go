package s3xml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrXMLBodyTooLarge indicates that an XML request exceeded its operation's
	// byte limit.
	ErrXMLBodyTooLarge = errors.New("XML body exceeds size limit")
	// ErrXMLElementLimit indicates that an XML request exceeded its operation's
	// total or per-element count limit.
	ErrXMLElementLimit = errors.New("XML element count exceeds limit")
	// ErrXMLFieldTooLong indicates that text in a recognized XML field exceeded
	// its operation-specific byte limit.
	ErrXMLFieldTooLong = errors.New("XML field exceeds length limit")
)

// DecodeLimits bounds the work and memory used while decoding an XML request.
// ElementLimits and FieldByteLimits use local element names, independent of
// an optional XML namespace.
type DecodeLimits struct {
	MaxBodyBytes      int64
	MaxDepth          int
	MaxElements       int
	MaxAttributes     int
	MaxAttributeBytes int
	ElementLimits     map[string]int
	FieldByteLimits   map[string]int
}

// DecodeLimited decodes one XML document while enforcing limits before the
// standard decoder can append excess elements to slices or accumulate excess
// character data into strings. It also rejects non-whitespace content after
// the root document.
func DecodeLimited(r io.Reader, out any, limits DecodeLimits) error {
	if limits.MaxBodyBytes <= 0 {
		return errors.New("XML body limit must be positive")
	}

	lr := &io.LimitedReader{R: r, N: limits.MaxBodyBytes + 1}
	tokens := &limitedXMLTokenReader{
		decoder: xml.NewDecoder(lr),
		limits:  limits,
		counts:  make(map[string]int, len(limits.ElementLimits)),
	}
	decoder := xml.NewTokenDecoder(tokens)
	if err := decoder.Decode(out); err != nil {
		if lr.N == 0 {
			return ErrXMLBodyTooLarge
		}
		return err
	}
	if lr.N == 0 {
		return ErrXMLBodyTooLarge
	}

	for {
		token, err := decoder.Token()
		if lr.N == 0 {
			return ErrXMLBodyTooLarge
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch token := token.(type) {
		case xml.CharData:
			if len(bytes.TrimSpace(token)) != 0 {
				return errors.New("unexpected content after XML document")
			}
		case xml.Comment, xml.ProcInst:
			// XML permits comments and processing instructions after the root.
		default:
			return errors.New("multiple XML documents are not allowed")
		}
	}
}

type limitedXMLField struct {
	name     string
	bytes    int
	maxBytes int
}

type limitedXMLTokenReader struct {
	decoder    *xml.Decoder
	limits     DecodeLimits
	counts     map[string]int
	fields     []limitedXMLField
	elements   int
	attributes int
}

func (r *limitedXMLTokenReader) Token() (xml.Token, error) {
	token, err := r.decoder.Token()
	if err != nil {
		return nil, err
	}

	switch token := token.(type) {
	case xml.StartElement:
		r.elements++
		if r.limits.MaxElements > 0 && r.elements > r.limits.MaxElements {
			return nil, fmt.Errorf("%w: more than %d total elements", ErrXMLElementLimit, r.limits.MaxElements)
		}
		name := token.Name.Local
		if max := r.limits.ElementLimits[name]; max > 0 {
			r.counts[name]++
			if r.counts[name] > max {
				return nil, fmt.Errorf("%w: more than %d %s elements", ErrXMLElementLimit, max, name)
			}
		}
		if r.limits.MaxAttributes > 0 && len(token.Attr) > r.limits.MaxAttributes-r.attributes {
			return nil, fmt.Errorf("%w: more than %d attributes", ErrXMLElementLimit, r.limits.MaxAttributes)
		}
		r.attributes += len(token.Attr)
		if r.limits.MaxAttributeBytes > 0 {
			for _, attr := range token.Attr {
				if len(attr.Value) > r.limits.MaxAttributeBytes {
					return nil, fmt.Errorf("%w: attribute %s exceeds %d bytes", ErrXMLFieldTooLong, attr.Name.Local, r.limits.MaxAttributeBytes)
				}
			}
		}
		r.fields = append(r.fields, limitedXMLField{
			name:     name,
			maxBytes: r.limits.FieldByteLimits[name],
		})
		if r.limits.MaxDepth > 0 && len(r.fields) > r.limits.MaxDepth {
			return nil, fmt.Errorf("%w: nesting depth exceeds %d", ErrXMLElementLimit, r.limits.MaxDepth)
		}
	case xml.CharData:
		for i := range r.fields {
			field := &r.fields[i]
			if field.maxBytes <= 0 {
				continue
			}
			if len(token) > field.maxBytes-field.bytes {
				return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrXMLFieldTooLong, field.name, field.maxBytes)
			}
			field.bytes += len(token)
		}
	case xml.EndElement:
		if len(r.fields) > 0 {
			r.fields = r.fields[:len(r.fields)-1]
		}
	}
	return token, nil
}
