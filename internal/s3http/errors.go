// Package s3http translates S3 HTTP requests and upstream responses.
package s3http

import (
	"errors"
	"net/http"
	"strings"

	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/define42/s3gateway/internal/s3xml"
)

type upstreamErrorInfo struct {
	status  int
	code    string
	message string
	headers http.Header
}

func extractUpstreamErrorInfo(err error) upstreamErrorInfo {
	info := upstreamErrorInfo{
		status:  http.StatusBadGateway,
		code:    "BadGateway",
		message: "Upstream error",
		headers: make(http.Header),
	}

	if apiErr, ok := errors.AsType[smithy.APIError](err); ok {
		if c := strings.TrimSpace(apiErr.ErrorCode()); c != "" {
			info.code = c
		}
		if m := strings.TrimSpace(apiErr.ErrorMessage()); m != "" {
			info.message = m
		}
		if info.status == http.StatusBadGateway && apiErr.ErrorFault() == smithy.FaultClient {
			info.status = http.StatusBadRequest
		}
	}

	if respErr, ok := errors.AsType[*smithyhttp.ResponseError](err); ok {
		// A successful HTTP status can still wrap an SDK deserialization error
		// or an embedded S3 API error. Keep the failure classification above
		// unless the upstream supplied a final redirect or error status.
		if sc := respErr.HTTPStatusCode(); sc >= http.StatusMultipleChoices && sc < 600 {
			info.status = sc
		}
		if hr := respErr.HTTPResponse(); hr != nil {
			for k, vals := range hr.Header {
				kl := strings.ToLower(k)
				if strings.HasPrefix(kl, "x-amz-") || kl == "retry-after" {
					for _, v := range vals {
						info.headers.Add(k, v)
					}
				}
			}
		}
	}
	return info
}

// WriteUpstreamError translates an AWS SDK error into an S3 XML error response.
// It preserves upstream 3xx–5xx statuses, API codes and messages, x-amz-* headers,
// and Retry-After. Errors attached to successful upstream statuses retain a
// failure status: BadRequest for client API faults and BadGateway otherwise.
func WriteUpstreamError(w http.ResponseWriter, err error) {
	info := extractUpstreamErrorInfo(err)
	for k, vals := range info.headers {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	if info.status == http.StatusNotModified {
		w.WriteHeader(info.status)
		return
	}
	s3xml.WriteError(w, info.status, info.code, info.message)
}

// WriteUpstreamHeadError writes only the translated upstream status and
// forwarding-safe headers, as required for HEAD responses.
func WriteUpstreamHeadError(w http.ResponseWriter, err error) {
	info := extractUpstreamErrorInfo(err)
	for k, vals := range info.headers {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(info.status)
}
