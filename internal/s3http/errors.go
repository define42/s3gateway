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

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
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

	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		if sc := respErr.HTTPStatusCode(); sc > 0 {
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

func WriteUpstreamError(w http.ResponseWriter, err error) {
	info := extractUpstreamErrorInfo(err)
	for k, vals := range info.headers {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	s3xml.WriteError(w, info.status, info.code, info.message)
}

func WriteUpstreamHeadError(w http.ResponseWriter, err error) {
	info := extractUpstreamErrorInfo(err)
	for k, vals := range info.headers {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(info.status)
}
