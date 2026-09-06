package server

import (
	"crypto/sha1" // #nosec G505 -- S3 request-integrity checksum, not authentication.
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"net/http"
	"strings"

	"github.com/define42/s3gateway/internal/s3http"
	"github.com/define42/s3gateway/internal/s3xml"
)

type xmlRequestChecksum struct {
	digest   hash.Hash
	expected []byte
}

// preserveXMLRequestTrailers keeps late HTTP trailers visible across shallow
// request copies made by the transfer, authentication, and audit middleware.
func preserveXMLRequestTrailers(r *http.Request) {
	if r.Trailer != nil {
		return
	}
	q := r.URL.Query()
	if (r.Method == http.MethodPost && q.Has("delete")) ||
		(r.Method == http.MethodPut && (q.Has("tagging") || q.Has("versioning") || q.Has("lifecycle"))) {
		r.Trailer = make(http.Header)
	}
}

func rejectXMLRequestTrailers(w http.ResponseWriter, r *http.Request) bool {
	trailerPresent := len(r.Trailer) > 0
	for name := range r.Header {
		if strings.EqualFold(name, "Trailer") || strings.EqualFold(name, "x-amz-trailer") {
			trailerPresent = true
		}
	}
	if trailerPresent {
		s3xml.WriteError(w, http.StatusBadRequest, "InvalidRequest", "Trailers are not supported for XML configuration writes; provide checksum headers")
	}
	return trailerPresent
}

func parseXMLRequestChecksum(w http.ResponseWriter, headers http.Header) (*xmlRequestChecksum, bool) {
	reject := func(code, message string) (*xmlRequestChecksum, bool) {
		s3xml.WriteError(w, http.StatusBadRequest, code, message)
		return nil, false
	}
	var checksum *xmlRequestChecksum
	var selectors []string
	seen := make(map[string]bool)
	for name, values := range headers {
		name = strings.ToLower(name)
		if !strings.HasPrefix(name, "x-amz-checksum-") && name != "x-amz-sdk-checksum-algorithm" {
			continue
		}
		selector := name == "x-amz-checksum-algorithm" || name == "x-amz-sdk-checksum-algorithm"
		if selector {
			if seen[name] || len(values) != 1 || strings.TrimSpace(values[0]) == "" {
				return reject("InvalidRequest", "Checksum algorithm headers must contain one nonempty value")
			}
			seen[name] = true
			selectors = append(selectors, strings.TrimSpace(values[0]))
			continue
		}
		digest := xmlChecksumHash(name)
		if digest == nil {
			return reject("InvalidRequest", "Unsupported checksum header for XML configuration writes")
		}
		if seen[name] || len(values) != 1 {
			return reject("InvalidDigest", "Checksum headers must contain one base64-encoded digest")
		}
		seen[name] = true
		if checksum != nil {
			return reject("InvalidRequest", "Multiple checksum value headers are not supported")
		}
		value := strings.TrimSpace(values[0])
		if len(value) != base64.StdEncoding.EncodedLen(digest.Size()) {
			return reject("InvalidDigest", "Invalid checksum digest length")
		}
		expected, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(expected) != digest.Size() {
			return reject("InvalidDigest", "Invalid base64-encoded checksum digest")
		}
		checksum = &xmlRequestChecksum{digest: digest, expected: expected}
	}
	// An individual checksum overrides algorithm selection, as in the S3 API.
	if checksum != nil {
		return checksum, true
	}
	for _, selector := range selectors {
		if _, err := s3http.ParseChecksumAlgorithmHeader(selector); err != nil {
			return reject("InvalidRequest", "Unsupported checksum algorithm for XML configuration writes")
		}
	}
	if len(selectors) > 0 {
		return reject("InvalidRequest", "Checksum algorithm selection requires a checksum value")
	}
	return nil, true
}

func xmlChecksumHash(name string) hash.Hash {
	switch name {
	case "x-amz-checksum-crc32":
		return crc32.NewIEEE()
	case "x-amz-checksum-crc32c":
		return crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case "x-amz-checksum-crc64nvme":
		return crc64.New(crc64.MakeTable(0x9a6c9329ac4bc9b5))
	case "x-amz-checksum-sha1":
		return sha1.New() // #nosec G401 -- S3 request-integrity checksum.
	case "x-amz-checksum-sha256":
		return sha256.New()
	default:
		return nil
	}
}
