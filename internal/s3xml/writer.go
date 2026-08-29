// Package s3xml encodes and decodes S3 XML payloads.
package s3xml

import (
	"encoding/xml"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	s3XMLNamespace     = "http://s3.amazonaws.com/doc/2006-03-01/"
	s3TimeMillisFormat = "2006-01-02T15:04:05.000Z"
	xmlDeclaration     = `<?xml version="1.0" encoding="UTF-8"?>`
)

var xmlEscaper = strings.NewReplacer(
	`&`, "&amp;",
	`<`, "&lt;",
	`>`, "&gt;",
	`"`, "&quot;",
	`'`, "&apos;",
)

// Escape replaces the five XML special characters with entity references.
func Escape(s string) string {
	return xmlEscaper.Replace(s)
}

// FormatTime renders t in UTC with the millisecond precision used by S3 XML
// responses.
func FormatTime(t time.Time) string {
	return t.UTC().Format(s3TimeMillisFormat)
}

// BoolString returns the lowercase XML representation of a boolean.
func BoolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// WriteError writes an S3 Error document with the supplied HTTP status. XML
// encoding and response-write errors cannot be returned to the caller.
func WriteError(w http.ResponseWriter, status int, code, msg string) {
	xw := BeginResponse(w, status)
	xw.Start("Error")
	xw.Elem("Code", code)
	xw.Elem("Message", msg)
	xw.End("Error")
	_ = xw.Flush()
}

func beginXMLResponse(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
}

// Writer incrementally emits S3 XML and retains the first encoding or write
// error. After an error, token-writing methods become no-ops until Flush
// returns that error.
type Writer struct {
	enc *xml.Encoder
	out io.Writer
	err error
}

// BeginResponse commits an application/xml response with status, writes the
// XML declaration, and returns a streaming writer for the document body.
func BeginResponse(w http.ResponseWriter, status int) *Writer {
	beginXMLResponse(w, status)
	xw := &Writer{enc: xml.NewEncoder(w), out: w}
	_, err := io.WriteString(w, xmlDeclaration)
	xw.setErr(err)
	return xw
}

// FlushResponse flushes a streaming response and discards any error. It is
// intended for deferred cleanup where the HTTP status has already been sent.
func FlushResponse(xw *Writer) {
	_ = xw.Flush()
}

func (xw *Writer) setErr(err error) {
	if xw.err == nil {
		xw.err = err
	}
}

// Start writes an opening element with optional attributes.
func (xw *Writer) Start(name string, attrs ...xml.Attr) {
	if xw.err != nil {
		return
	}
	xw.setErr(xw.enc.EncodeToken(xml.StartElement{Name: xml.Name{Local: name}, Attr: attrs}))
}

// End writes a closing element. name must match the most recent open element.
func (xw *Writer) End(name string) {
	if xw.err != nil {
		return
	}
	xw.setErr(xw.enc.EncodeToken(xml.EndElement{Name: xml.Name{Local: name}}))
}

// Elem writes one escaped text element.
func (xw *Writer) Elem(name, value string) {
	if xw.err != nil {
		return
	}
	xw.setErr(xw.enc.EncodeElement(value, xml.StartElement{Name: xml.Name{Local: name}}))
}

// RawString writes pre-encoded XML without escaping it. Callers must ensure
// value is trusted, well-formed XML that preserves the encoder's element stack.
func (xw *Writer) RawString(value string) {
	if xw.err != nil {
		return
	}
	if err := xw.enc.Flush(); err != nil {
		xw.setErr(err)
		return
	}
	_, err := io.WriteString(xw.out, value)
	xw.setErr(err)
}

// ElemInt writes a base-10 integer element.
func (xw *Writer) ElemInt(name string, value int64) {
	xw.Elem(name, strconv.FormatInt(value, 10))
}

// ElemBool writes a lowercase boolean element.
func (xw *Writer) ElemBool(name string, value bool) {
	xw.Elem(name, BoolString(value))
}

// Flush emits buffered XML and returns the first error observed by the writer.
func (xw *Writer) Flush() error {
	if xw.err != nil {
		return xw.err
	}
	if err := xw.enc.Flush(); err != nil {
		xw.setErr(err)
	}
	return xw.err
}

// EncodeRootStart opens a root element in the S3 XML namespace.
func EncodeRootStart(xw *Writer, name string) {
	xw.Start(name, xml.Attr{
		Name:  xml.Name{Local: "xmlns"},
		Value: s3XMLNamespace,
	})
}

// EncodeCommonPrefixes writes each non-nil common prefix in SDK order.
func EncodeCommonPrefixes(xw *Writer, prefixes []types.CommonPrefix) {
	for _, cp := range prefixes {
		if cp.Prefix == nil {
			continue
		}
		xw.Start("CommonPrefixes")
		xw.Elem("Prefix", *cp.Prefix)
		xw.End("CommonPrefixes")
	}
}

// EncodeOwnerIDThenDisplayName writes an Owner element with ID before
// DisplayName. A nil owner produces no output.
func EncodeOwnerIDThenDisplayName(xw *Writer, owner *types.Owner) {
	if owner == nil {
		return
	}
	xw.Start("Owner")
	if owner.ID != nil {
		xw.Elem("ID", *owner.ID)
	}
	if owner.DisplayName != nil {
		xw.Elem("DisplayName", *owner.DisplayName)
	}
	xw.End("Owner")
}

// EncodeOwnerDisplayNameThenID writes an Owner element with DisplayName before
// ID. A nil owner produces no output.
func EncodeOwnerDisplayNameThenID(xw *Writer, owner *types.Owner) {
	if owner == nil {
		return
	}
	xw.Start("Owner")
	if owner.DisplayName != nil {
		xw.Elem("DisplayName", *owner.DisplayName)
	}
	if owner.ID != nil {
		xw.Elem("ID", *owner.ID)
	}
	xw.End("Owner")
}

// EncodeInitiatorDisplayNameThenID writes an Initiator element with DisplayName
// before ID. A nil initiator produces no output.
func EncodeInitiatorDisplayNameThenID(xw *Writer, initiator *types.Initiator) {
	if initiator == nil {
		return
	}
	xw.Start("Initiator")
	if initiator.DisplayName != nil {
		xw.Elem("DisplayName", *initiator.DisplayName)
	}
	if initiator.ID != nil {
		xw.Elem("ID", *initiator.ID)
	}
	xw.End("Initiator")
}

// EncodeRestoreStatus writes the populated fields of an S3 RestoreStatus
// element. A nil status produces no output.
func EncodeRestoreStatus(xw *Writer, restore *types.RestoreStatus) {
	if restore == nil {
		return
	}
	xw.Start("RestoreStatus")
	if restore.IsRestoreInProgress != nil {
		xw.ElemBool("IsRestoreInProgress", *restore.IsRestoreInProgress)
	}
	if restore.RestoreExpiryDate != nil {
		xw.Elem("RestoreExpiryDate", FormatTime(*restore.RestoreExpiryDate))
	}
	xw.End("RestoreStatus")
}
