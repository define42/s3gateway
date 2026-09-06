package s3http_test

import (
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/define42/s3gateway/internal/s3http"
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
			s3http.WriteUpstreamHeadError(rr, tc.err)

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

func TestWriteUpstreamErrorStatuses(t *testing.T) {
	deserializationError := &smithy.DeserializationError{Err: errors.New("unexpected EOF")}
	for _, tc := range []struct {
		name       string
		status     int
		err        error
		wantStatus int
		wantCode   string
		wantMsg    string
	}{
		{name: "malformed 200", status: 200, err: deserializationError, wantStatus: 502, wantCode: "BadGateway", wantMsg: "Upstream error"},
		{name: "malformed 201", status: 201, err: deserializationError, wantStatus: 502, wantCode: "BadGateway", wantMsg: "Upstream error"},
		{name: "malformed 204", status: 204, err: deserializationError, wantStatus: 502, wantCode: "BadGateway", wantMsg: "Upstream error"},
		{name: "malformed 206", status: 206, err: deserializationError, wantStatus: 502, wantCode: "BadGateway", wantMsg: "Upstream error"},
		{name: "malformed 299", status: 299, err: deserializationError, wantStatus: 502, wantCode: "BadGateway", wantMsg: "Upstream error"},
		{name: "embedded client error", status: 200, err: stubAPIError{"InvalidPart", "part missing", smithy.FaultClient}, wantStatus: 400, wantCode: "InvalidPart", wantMsg: "part missing"},
		{name: "embedded server error", status: 200, err: stubAPIError{"InternalError", "try again", smithy.FaultServer}, wantStatus: 502, wantCode: "InternalError", wantMsg: "try again"},
		{name: "embedded unknown error", status: 200, err: stubAPIError{"ServiceError", "try again", smithy.FaultUnknown}, wantStatus: 502, wantCode: "ServiceError", wantMsg: "try again"},
		{name: "not modified", status: 304, err: stubAPIError{"NotModified", "unchanged", smithy.FaultClient}, wantStatus: 304, wantCode: "NotModified", wantMsg: "unchanged"},
		{name: "permanent redirect", status: 301, err: stubAPIError{"PermanentRedirect", "wrong endpoint", smithy.FaultClient}, wantStatus: 301, wantCode: "PermanentRedirect", wantMsg: "wrong endpoint"},
		{name: "temporary redirect", status: 307, err: stubAPIError{"TemporaryRedirect", "temporary endpoint", smithy.FaultServer}, wantStatus: 307, wantCode: "TemporaryRedirect", wantMsg: "temporary endpoint"},
		{name: "access denied", status: 403, err: stubAPIError{"AccessDenied", "forbidden", smithy.FaultClient}, wantStatus: 403, wantCode: "AccessDenied", wantMsg: "forbidden"},
		{name: "not found", status: 404, err: stubAPIError{"NoSuchKey", "missing", smithy.FaultClient}, wantStatus: 404, wantCode: "NoSuchKey", wantMsg: "missing"},
		{name: "rate limited", status: 429, err: stubAPIError{"SlowDown", "slow down", smithy.FaultClient}, wantStatus: 429, wantCode: "SlowDown", wantMsg: "slow down"},
		{name: "service unavailable", status: 503, err: stubAPIError{"SlowDown", "slow down", smithy.FaultServer}, wantStatus: 503, wantCode: "SlowDown", wantMsg: "slow down"},
		{name: "malformed error response", status: 500, err: deserializationError, wantStatus: 500, wantCode: "BadGateway", wantMsg: "Upstream error"},
		{name: "missing status", err: deserializationError, wantStatus: 502, wantCode: "BadGateway", wantMsg: "Upstream error"},
		{name: "informational status", status: 100, err: deserializationError, wantStatus: 502, wantCode: "BadGateway", wantMsg: "Upstream error"},
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				err := &smithy.OperationError{
					ServiceID:     "S3",
					OperationName: "ListObjectsV2",
					Err: &smithyhttp.ResponseError{
						Response: &smithyhttp.Response{Response: &http.Response{
							StatusCode: tc.status,
							Header: http.Header{
								"X-Amz-Request-Id": {"request-id"},
								"X-Amz-Id-2":       {"extended-id"},
								"Retry-After":      {"3"},
								"Content-Length":   {"999"},
								"Set-Cookie":       {"upstream=private"},
								"Connection":       {"close"},
							},
						}},
						Err: tc.err,
					},
				}
				recorder := httptest.NewRecorder()
				if method == http.MethodHead {
					s3http.WriteUpstreamHeadError(recorder, err)
				} else {
					s3http.WriteUpstreamError(recorder, err)
				}
				if recorder.Code != tc.wantStatus {
					t.Fatalf("status=%d, want %d", recorder.Code, tc.wantStatus)
				}
				for key, want := range map[string]string{"X-Amz-Request-Id": "request-id", "X-Amz-Id-2": "extended-id", "Retry-After": "3"} {
					if got := recorder.Header().Get(key); got != want {
						t.Errorf("header %q=%q, want %q", key, got, want)
					}
				}
				for _, key := range []string{"Content-Length", "Set-Cookie", "Connection"} {
					if value := recorder.Header().Get(key); value != "" {
						t.Errorf("unexpected forwarded header %s=%q", key, value)
					}
				}
				if method == http.MethodHead || tc.wantStatus == http.StatusNotModified {
					if recorder.Body.Len() != 0 {
						t.Fatalf("bodyless response has body %q", recorder.Body.String())
					}
					return
				}
				var body struct{ Code, Message string }
				if err := xml.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body.Code != tc.wantCode || body.Message != tc.wantMsg {
					t.Fatalf("error response=%+v, want %s: %s", body, tc.wantCode, tc.wantMsg)
				}
			})
		}
	}
}
