package server

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// Each entry lists the permitted children. True means a child may repeat;
// omitted entries are text-only fields. Validate before decoding into structs
// so discarded XML cannot turn a restricted expiration rule into a wider one.
var lifecycleXMLChildren = map[string]map[string]bool{
	"LifecycleConfiguration": {"Rule": true},
	"Rule": {
		"ID": false, "Status": false, "Prefix": false, "Filter": false,
		"Expiration": false, "Transition": true, "NoncurrentVersionTransition": true,
		"NoncurrentVersionExpiration": false, "AbortIncompleteMultipartUpload": false,
	},
	"Filter": {
		"Prefix": false, "Tag": false, "And": false,
		"ObjectSizeGreaterThan": false, "ObjectSizeLessThan": false,
	},
	"And": {
		"Prefix": false, "Tag": true,
		"ObjectSizeGreaterThan": false, "ObjectSizeLessThan": false,
	},
	"Tag":        {"Key": false, "Value": false},
	"Expiration": {"Days": false, "Date": false, "ExpiredObjectDeleteMarker": false},
	"Transition": {"Days": false, "Date": false, "StorageClass": false},
	"NoncurrentVersionTransition": {
		"NoncurrentDays": false, "NewerNoncurrentVersions": false, "StorageClass": false,
	},
	"NoncurrentVersionExpiration": {
		"NoncurrentDays": false, "NewerNoncurrentVersions": false,
	},
	"AbortIncompleteMultipartUpload": {"DaysAfterInitiation": false},
}

func (c *lifecycleConfigReqXML) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	// The alias avoids recursively calling this method. Both decoders stream
	// through the existing DecodeLimited reader, retaining its resource limits.
	type document lifecycleConfigReqXML
	tokens := &lifecycleXMLTokenReader{decoder: decoder, start: &start, namespace: start.Name.Space}
	return xml.NewTokenDecoder(tokens).Decode((*document)(c))
}

type lifecycleXMLElement struct {
	name string
	seen map[string]bool
}

type lifecycleXMLTokenReader struct {
	decoder   *xml.Decoder
	start     *xml.StartElement
	namespace string
	elements  []lifecycleXMLElement
	done      bool
}

func (r *lifecycleXMLTokenReader) Token() (xml.Token, error) {
	if r.done {
		return nil, io.EOF
	}
	var token xml.Token
	if r.start != nil {
		token = *r.start
		r.start = nil
	} else {
		var err error
		token, err = r.decoder.Token()
		if err != nil {
			return nil, err
		}
	}

	switch token := token.(type) {
	case xml.StartElement:
		if err := r.beginElement(token); err != nil {
			return nil, err
		}
	case xml.EndElement:
		parent := r.elements[len(r.elements)-1]
		if parent.name == "Tag" && (!parent.seen["Key"] || !parent.seen["Value"]) {
			return nil, fmt.Errorf("lifecycle tags require Key and Value elements")
		}
		r.elements = r.elements[:len(r.elements)-1]
		r.done = len(r.elements) == 0
	case xml.CharData:
		parent := r.elements[len(r.elements)-1]
		if lifecycleXMLChildren[parent.name] != nil && strings.TrimSpace(string(token)) != "" {
			return nil, fmt.Errorf("unexpected text in lifecycle element %q", parent.name)
		}
	case xml.Directive:
		return nil, fmt.Errorf("XML directives are not supported in lifecycle configurations")
	}
	return token, nil
}

func (r *lifecycleXMLTokenReader) beginElement(start xml.StartElement) error {
	name := start.Name.Local
	if start.Name.Space != r.namespace || (r.namespace != "" && r.namespace != "http://s3.amazonaws.com/doc/2006-03-01/") {
		return fmt.Errorf("unsupported namespace for lifecycle element %q", name)
	}
	for _, attr := range start.Attr {
		if attr.Name.Space != "xmlns" && (attr.Name.Space != "" || attr.Name.Local != "xmlns") {
			return fmt.Errorf("unsupported attribute %q on lifecycle element %q", attr.Name.Local, name)
		}
	}
	if len(r.elements) > 0 {
		parent := &r.elements[len(r.elements)-1]
		repeatable, allowed := lifecycleXMLChildren[parent.name][name]
		if !allowed {
			return fmt.Errorf("unsupported lifecycle element %q in %q", name, parent.name)
		}
		if parent.seen[name] && !repeatable {
			return fmt.Errorf("duplicate lifecycle element %q in %q", name, parent.name)
		}
		parent.seen[name] = true
	}
	r.elements = append(r.elements, lifecycleXMLElement{name: name, seen: make(map[string]bool)})
	return nil
}
