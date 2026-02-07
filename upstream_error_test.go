package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

type stubAPIError struct {
	code    string
	message string
	fault   smithy.ErrorFault
}

func (e stubAPIError) Error() string {
	return e.code + ": " + e.message
}

func (e stubAPIError) ErrorCode() string {
	return e.code
}

func (e stubAPIError) ErrorMessage() string {
	return e.message
}

func (e stubAPIError) ErrorFault() smithy.ErrorFault {
	return e.fault
}

func TestWriteUpstreamHeadError(t *testing.T) {
	tests := []struct {
		name              string
		err               error
		wantStatus        int
		wantHeader        map[string]string
		unwantedHeaderKey []string
	}{
		{
			name: "propagates upstream status and allowed headers",
			err: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{
					Response: &http.Response{
						StatusCode: http.StatusNotFound,
						Header: http.Header{
							"x-amz-request-id": {"req-123"},
							"x-amz-id-2":       {"id2-abc"},
							"Retry-After":      {"7"},
							"Content-Type":     {"application/xml"},
						},
					},
				},
				Err: stubAPIError{
					code:    "NoSuchKey",
					message: "missing",
					fault:   smithy.FaultClient,
				},
			},
			wantStatus: http.StatusNotFound,
			wantHeader: map[string]string{
				"x-amz-request-id": "req-123",
				"x-amz-id-2":       "id2-abc",
				"Retry-After":      "7",
			},
			unwantedHeaderKey: []string{"Content-Type"},
		},
		{
			name: "propagates upstream not-modified status",
			err: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{
					Response: &http.Response{
						StatusCode: http.StatusNotModified,
						Header: http.Header{
							"x-amz-request-id": {"req-304"},
						},
					},
				},
				Err: stubAPIError{
					code:    "NotModified",
					message: "not modified",
					fault:   smithy.FaultClient,
				},
			},
			wantStatus: http.StatusNotModified,
			wantHeader: map[string]string{
				"x-amz-request-id": "req-304",
			},
		},
		{
			name: "client fault without upstream response maps to 400",
			err: stubAPIError{
				code:    "AccessDenied",
				message: "forbidden",
				fault:   smithy.FaultClient,
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "non-smithy error maps to 502",
			err:        errors.New("boom"),
			wantStatus: http.StatusBadGateway,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeUpstreamHeadError(rr, tc.err)

			if rr.Code != tc.wantStatus {
				t.Fatalf("status mismatch: got=%d want=%d", rr.Code, tc.wantStatus)
			}
			for key, want := range tc.wantHeader {
				if got := rr.Header().Get(key); got != want {
					t.Fatalf("header %q mismatch: got=%q want=%q", key, got, want)
				}
			}
			for _, key := range tc.unwantedHeaderKey {
				if got := rr.Header().Get(key); got != "" {
					t.Fatalf("unexpected header %q: got=%q", key, got)
				}
			}
			if rr.Body.Len() != 0 {
				t.Fatalf("head error response should not include body, got=%q", rr.Body.String())
			}
		})
	}
}
