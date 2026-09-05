package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/define42/s3gateway/internal/s3http"
	"github.com/define42/s3gateway/internal/s3xml"
	"github.com/define42/s3gateway/internal/sigv4"
)

// requireSupportedUploadProperties rejects unsupported protection and append
// requests by header presence, so even an empty value cannot be ignored.
func requireSupportedUploadProperties(w http.ResponseWriter, r *http.Request) bool {
	for name := range r.Header {
		name = strings.ToLower(name)
		if strings.HasPrefix(name, "x-amz-object-lock-") || name == "x-amz-write-offset-bytes" {
			s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Unsupported upload header: "+name)
			return false
		}
	}
	return true
}

type uploadProperties struct {
	CacheControl            *string
	ContentDisposition      *string
	ContentEncoding         *string
	ContentLanguage         *string
	Tagging                 *string
	StorageClass            types.StorageClass
	WebsiteRedirectLocation *string
}

func parseUploadProperties(r *http.Request) (uploadProperties, error) {
	var properties uploadProperties
	for _, field := range []struct {
		name string
		dst  **string
	}{
		{name: "Content-Disposition", dst: &properties.ContentDisposition},
		{name: "x-amz-tagging", dst: &properties.Tagging},
		{name: "x-amz-website-redirect-location", dst: &properties.WebsiteRedirectLocation},
	} {
		values := r.Header.Values(field.name)
		if len(values) > 1 {
			return properties, fmt.Errorf("multiple %s headers are not supported", field.name)
		}
		if len(values) == 1 {
			*field.dst = aws.String(values[0])
		}
	}
	if values := r.Header.Values("Cache-Control"); len(values) > 0 {
		properties.CacheControl = aws.String(strings.Join(values, ","))
	}
	if values := r.Header.Values("Content-Language"); len(values) > 0 {
		properties.ContentLanguage = aws.String(strings.Join(values, ","))
	}
	var encodings []string
	for _, value := range r.Header.Values("Content-Encoding") {
		for encoding := range strings.SplitSeq(value, ",") {
			encoding = strings.TrimSpace(encoding)
			if encoding == "" {
				continue
			}
			if strings.EqualFold(encoding, "aws-chunked") {
				if !sigv4.IsAWSChunkedPayload(r.Header) {
					return properties, fmt.Errorf("aws-chunked content encoding requires a streaming payload")
				}
				// The gateway decodes this transport encoding; other encodings
				// describe the stored object and must survive forwarding.
				continue
			}
			encodings = append(encodings, encoding)
		}
	}
	if len(encodings) > 0 {
		properties.ContentEncoding = aws.String(strings.Join(encodings, ","))
	}
	if values := r.Header.Values("x-amz-storage-class"); len(values) > 0 {
		if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
			return properties, fmt.Errorf("invalid x-amz-storage-class header")
		}
		storageClass, err := s3http.ParseStorageClass(values[0])
		if err != nil {
			return properties, err
		}
		properties.StorageClass = storageClass
	}
	return properties, nil
}
