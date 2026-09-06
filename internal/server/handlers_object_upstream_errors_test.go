package server

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

func TestListObjectsV2SDKRejectsUpstreamDeserializationErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response string
		valid    bool
	}{
		{name: "truncated listing", response: `<ListBucketResult><Contents><Key>present-object`},
		{name: "mismatched XML tags", response: `<ListBucketResult><Contents></ListBucketResult>`},
		{name: "valid listing", response: `<ListBucketResult><Name>team2-bucket</Name><KeyCount>1</KeyCount><IsTruncated>false</IsTruncated><Contents><Key>present-object</Key><Size>7</Size></Contents></ListBucketResult>`, valid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gateway, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/team2-bucket" || r.URL.Query().Get("list-type") != "2" {
					t.Errorf("unexpected upstream request: %s %s", r.Method, r.URL)
				}
				w.Header().Set("Content-Type", "application/xml")
				w.Header().Set("x-amz-request-id", "upstream-request-id")
				w.Header().Set("x-amz-id-2", "upstream-extended-id")
				w.Header().Set("Retry-After", "3")
				w.Header().Set("Set-Cookie", "upstream=private")
				_, _ = io.WriteString(w, tc.response)
			})
			t.Cleanup(cleanup)

			var gatewayStatus int
			var gatewayHeaders http.Header
			client := s3.New(s3.Options{
				Region:           "us-east-1",
				BaseEndpoint:     aws.String("https://gateway.example"),
				UsePathStyle:     true,
				Credentials:      credentials.NewStaticCredentialsProvider("test-access", "test-secret", ""),
				RetryMaxAttempts: 1,
				HTTPClient: multipartProgressHTTPClient(func(request *http.Request) (*http.Response, error) {
					recorder := httptest.NewRecorder()
					gateway.ServeHTTP(recorder, reqWithRules(request, fullTeam2Rule()))
					gatewayStatus = recorder.Code
					gatewayHeaders = recorder.Header().Clone()
					return recorder.Result(), nil
				}),
			})
			output, err := client.ListObjectsV2(t.Context(), &s3.ListObjectsV2Input{Bucket: aws.String("team2-bucket")})
			if tc.valid {
				if err != nil || gatewayStatus != http.StatusOK || len(output.Contents) != 1 || aws.ToString(output.Contents[0].Key) != "present-object" {
					t.Fatalf("valid listing failed: status=%d output=%+v error=%v", gatewayStatus, output, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("SDK accepted invalid upstream XML as a successful listing: status=%d output=%+v", gatewayStatus, output)
			}
			responseError, ok := errors.AsType[*smithyhttp.ResponseError](err)
			if gatewayStatus != http.StatusBadGateway || !ok || responseError.HTTPStatusCode() != http.StatusBadGateway {
				t.Fatalf("invalid listing status=%d error=%v, want 502", gatewayStatus, err)
			}
			apiError, ok := errors.AsType[smithy.APIError](err)
			if !ok || apiError.ErrorCode() != "BadGateway" {
				t.Fatalf("invalid listing API error=%v, want BadGateway", err)
			}
			for key, want := range map[string]string{"x-amz-request-id": "upstream-request-id", "x-amz-id-2": "upstream-extended-id", "Retry-After": "3"} {
				if got := gatewayHeaders.Get(key); got != want {
					t.Errorf("header %s=%q, want %q", key, got, want)
				}
			}
			if value := gatewayHeaders.Get("Set-Cookie"); value != "" {
				t.Errorf("unexpected upstream cookie %q", value)
			}
		})
	}
}
