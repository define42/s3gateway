package server

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- S3 request-integrity checksum, not authentication.
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"net/http"
	"strings"

	"github.com/define42/s3gateway/internal/s3http"
	"github.com/define42/s3gateway/internal/s3xml"
)

type deleteObjectsChecksum struct {
	digest   hash.Hash
	expected []byte
}

// preserveDeleteObjectsTrailers keeps late HTTP/1 trailers visible across the
// shallow request copies made by authentication and audit middleware.
func preserveDeleteObjectsTrailers(r *http.Request) {
	if r.Method == http.MethodPost && r.Trailer == nil && r.URL.Query().Has("delete") {
		r.Trailer = make(http.Header)
	}
}

func rejectDeleteObjectsTrailers(w http.ResponseWriter, r *http.Request) bool {
	if len(r.Trailer) == 0 && len(r.Header.Values("Trailer")) == 0 && len(r.Header.Values("x-amz-trailer")) == 0 {
		return false
	}
	s3xml.WriteError(w, http.StatusBadRequest, "InvalidRequest", "Trailers are not supported for DeleteObjects; provide checksum headers")
	return true
}

func decodeDeleteObjectsWithChecksums(w http.ResponseWriter, r *http.Request) (deleteObjectsReqXML, bool) {
	var zero deleteObjectsReqXML
	if rejectDeleteObjectsTrailers(w, r) {
		return zero, false
	}
	checksum, ok := parseDeleteObjectsChecksum(w, r.Header)
	if !ok {
		return zero, false
	}
	decode := func(body io.Reader) (deleteObjectsReqXML, error) {
		if checksum != nil {
			body = io.TeeReader(body, checksum.digest)
		}
		return decodeDeleteObjectsRequest(body)
	}
	decoded, ok := decodeXMLWithContentMD5(w, r, decode, "Invalid DeleteObjects payload")
	if !ok {
		return zero, false
	}
	// The bounded XML decoder reads through EOF, which can reveal late trailers.
	if rejectDeleteObjectsTrailers(w, r) {
		return zero, false
	}
	if checksum != nil && !bytes.Equal(checksum.digest.Sum(nil), checksum.expected) {
		s3xml.WriteError(w, http.StatusBadRequest, "BadDigest", "The checksum does not match the request body")
		return zero, false
	}
	// Forward only decoded fields. The SDK must checksum its newly serialized XML.
	return decoded, true
}

func parseDeleteObjectsChecksum(w http.ResponseWriter, headers http.Header) (*deleteObjectsChecksum, bool) {
	reject := func(code, message string) (*deleteObjectsChecksum, bool) {
		s3xml.WriteError(w, http.StatusBadRequest, code, message)
		return nil, false
	}
	for _, name := range []string{"x-amz-checksum-algorithm", "x-amz-sdk-checksum-algorithm"} {
		values := headers.Values(name)
		if len(values) > 1 || (len(values) == 1 && strings.TrimSpace(values[0]) == "") {
			return reject("InvalidRequest", "Checksum algorithm headers must contain one supported algorithm")
		}
	}

	var checksum *deleteObjectsChecksum
	for name, values := range headers {
		name = strings.ToLower(name)
		if !strings.HasPrefix(name, "x-amz-checksum-") || name == "x-amz-checksum-algorithm" {
			continue
		}
		var digest hash.Hash
		switch name {
		case "x-amz-checksum-crc32":
			digest = crc32.NewIEEE()
		case "x-amz-checksum-crc32c":
			digest = crc32.New(crc32.MakeTable(crc32.Castagnoli))
		case "x-amz-checksum-crc64nvme":
			digest = crc64.New(crc64.MakeTable(0x9a6c9329ac4bc9b5))
		case "x-amz-checksum-sha1":
			digest = sha1.New() // #nosec G401 -- S3 checksum compatibility.
		case "x-amz-checksum-sha256":
			digest = sha256.New()
		default:
			return reject("InvalidRequest", "Unsupported checksum header for DeleteObjects")
		}
		if checksum != nil {
			return reject("InvalidRequest", "Multiple checksum value headers are not supported")
		}
		if len(values) != 1 {
			return reject("InvalidDigest", "Checksum headers must contain one base64-encoded digest")
		}
		value := strings.TrimSpace(values[0])
		if len(value) != base64.StdEncoding.EncodedLen(digest.Size()) {
			return reject("InvalidDigest", "Invalid checksum digest length")
		}
		expected, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(expected) != digest.Size() {
			return reject("InvalidDigest", "Invalid base64-encoded checksum digest")
		}
		checksum = &deleteObjectsChecksum{digest: digest, expected: expected}
	}
	selection, err := s3http.ParseChecksumWriteHeaders(headers)
	if err != nil {
		return reject("InvalidRequest", "Invalid or conflicting checksum algorithm selection")
	}
	if selection.ChecksumAlgorithm != "" && checksum == nil {
		return reject("InvalidRequest", "Checksum algorithm selection requires a matching checksum value")
	}
	return checksum, true
}
