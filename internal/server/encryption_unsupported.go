package server

import (
	"net/http"
	"strings"

	"github.com/define42/s3gateway/internal/s3xml"
)

// Reject explicit encryption options before dispatch: silently dropping them
// could store data without the protection the caller requested. Header presence
// matters even when its value is empty. Upstream defaults still apply.
func requireNoEncryptionRequestHeaders(w http.ResponseWriter, r *http.Request) bool {
	if hasEncryptionRequestHeaders(r) {
		s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "S3 encryption request options are not supported")
		return false
	}
	return true
}

func hasEncryptionRequestHeaders(r *http.Request) bool {
	for name, values := range r.Header {
		if isEncryptionRequestHeader(name) {
			return true
		}
		// Check declarations before reading the body, including aws-chunked
		// trailers that the streaming decoder would otherwise ignore.
		if strings.EqualFold(name, "Trailer") || strings.EqualFold(name, "x-amz-trailer") {
			for _, value := range values {
				for declared := range strings.SplitSeq(value, ",") {
					if isEncryptionRequestHeader(strings.TrimSpace(declared)) {
						return true
					}
				}
			}
		}
	}
	// net/http moves HTTP Trailer declarations out of Header into Trailer.
	for name := range r.Trailer {
		if isEncryptionRequestHeader(name) {
			return true
		}
	}
	return false
}

func isEncryptionRequestHeader(name string) bool {
	name = strings.ToLower(name)
	for _, prefix := range []string{
		"x-amz-server-side-encryption",
		"x-amz-copy-source-server-side-encryption",
	} {
		if name == prefix || strings.HasPrefix(name, prefix+"-") {
			return true
		}
	}
	return false
}
