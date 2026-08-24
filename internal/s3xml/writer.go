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

// ==================== XML helpers ====================
func Escape(s string) string {
	return xmlEscaper.Replace(s)
}

func FormatTime(t time.Time) string {
	return t.UTC().Format(s3TimeMillisFormat)
}

func BoolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

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

type Writer struct {
	enc *xml.Encoder
	out io.Writer
	err error
}

func BeginResponse(w http.ResponseWriter, status int) *Writer {
	beginXMLResponse(w, status)
	xw := &Writer{enc: xml.NewEncoder(w), out: w}
	_, err := io.WriteString(w, xmlDeclaration)
	xw.setErr(err)
	return xw
}

func FlushResponse(xw *Writer) {
	_ = xw.Flush()
}

func (xw *Writer) setErr(err error) {
	if xw.err == nil {
		xw.err = err
	}
}

func (xw *Writer) Start(name string, attrs ...xml.Attr) {
	if xw.err != nil {
		return
	}
	xw.setErr(xw.enc.EncodeToken(xml.StartElement{Name: xml.Name{Local: name}, Attr: attrs}))
}

func (xw *Writer) End(name string) {
	if xw.err != nil {
		return
	}
	xw.setErr(xw.enc.EncodeToken(xml.EndElement{Name: xml.Name{Local: name}}))
}

func (xw *Writer) Elem(name, value string) {
	if xw.err != nil {
		return
	}
	xw.setErr(xw.enc.EncodeElement(value, xml.StartElement{Name: xml.Name{Local: name}}))
}

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

func (xw *Writer) ElemInt(name string, value int64) {
	xw.Elem(name, strconv.FormatInt(value, 10))
}

func (xw *Writer) ElemBool(name string, value bool) {
	xw.Elem(name, BoolString(value))
}

func (xw *Writer) Flush() error {
	if xw.err != nil {
		return xw.err
	}
	if err := xw.enc.Flush(); err != nil {
		xw.setErr(err)
	}
	return xw.err
}

func EncodeRootStart(xw *Writer, name string) {
	xw.Start(name, xml.Attr{
		Name:  xml.Name{Local: "xmlns"},
		Value: s3XMLNamespace,
	})
}

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
