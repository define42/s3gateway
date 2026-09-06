package server

import (
	"bytes"
	"crypto/md5" // #nosec G501 -- S3 Content-MD5 requires this digest algorithm.
	"encoding/base64"
	"hash"
	"io"
	"net/http"
	"strings"

	"github.com/define42/s3gateway/internal/s3xml"
)

// decodeXMLWithChecksums validates integrity claims against the complete original
// XML. The SDK must compute its own checksum after serializing the decoded fields.
func decodeXMLWithChecksums[T any](
	w http.ResponseWriter,
	r *http.Request,
	decode func(io.Reader) (T, error),
	malformedMessage string,
) (T, bool) {
	var zero T
	if rejectXMLRequestTrailers(w, r) {
		return zero, false
	}
	checksum, ok := parseXMLRequestChecksum(w, r.Header)
	if !ok {
		return zero, false
	}
	decodeBody := func(body io.Reader) (T, error) {
		if checksum != nil {
			body = io.TeeReader(body, checksum.digest)
		}
		return decode(body)
	}
	decoded, ok := decodeXMLWithContentMD5(w, r, decodeBody, malformedMessage)
	if !ok {
		return zero, false
	}
	// Reading through EOF can reveal HTTP trailers that were not declared.
	if rejectXMLRequestTrailers(w, r) {
		return zero, false
	}
	if checksum != nil && !bytes.Equal(checksum.digest.Sum(nil), checksum.expected) {
		s3xml.WriteError(w, http.StatusBadRequest, "BadDigest", "The checksum does not match the request body")
		return zero, false
	}
	return decoded, true
}

// decodeXMLWithContentMD5 validates the original bytes before the SDK serializes
// a new XML body. decode must enforce a body limit and read through EOF on success.
// The caller must leave the SDK's ContentMD5 unset so its required checksum
// middleware computes a fresh checksum over the serialized body.
func decodeXMLWithContentMD5[T any](
	w http.ResponseWriter,
	r *http.Request,
	decode func(io.Reader) (T, error),
	malformedMessage string,
) (T, bool) {
	var zero T
	var expected []byte
	var digest hash.Hash
	var body io.Reader = r.Body
	if values := r.Header.Values("Content-MD5"); len(values) > 0 {
		if len(values) != 1 || len(strings.TrimSpace(values[0])) != base64.StdEncoding.EncodedLen(md5.Size) {
			s3xml.WriteError(w, http.StatusBadRequest, "InvalidDigest", "Content-MD5 must contain one base64-encoded MD5 digest")
			return zero, false
		}
		value := strings.TrimSpace(values[0])
		var err error
		expected, err = base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(expected) != md5.Size {
			s3xml.WriteError(w, http.StatusBadRequest, "InvalidDigest", "Content-MD5 must contain one base64-encoded MD5 digest")
			return zero, false
		}
		digest = md5.New() // #nosec G401 -- Verify the S3 Content-MD5 integrity header.
		body = io.TeeReader(body, digest)
	}

	decoded, err := decode(body)
	if err != nil {
		s3xml.WriteError(w, http.StatusBadRequest, "MalformedXML", malformedMessage)
		return zero, false
	}
	if digest != nil && !bytes.Equal(digest.Sum(nil), expected) {
		s3xml.WriteError(w, http.StatusBadRequest, "BadDigest", "The Content-MD5 digest does not match the request body")
		return zero, false
	}
	return decoded, true
}
