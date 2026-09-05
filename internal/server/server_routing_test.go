package server

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

func TestAWSSDKObjectAnnotationsRejected(t *testing.T) {
	var upstreamCalls atomic.Int32
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	defer cleanup()
	gw.gcache.Set("testuser", "dogood", map[string]struct{}{"team2-rwcdb": {}})
	accessKey, secretKey := mustGatewayCredentials(t, gw, "testuser", "dogood")
	classifications := make(chan string, 1)
	authenticated := gw.WithAuth(gw, nil)
	front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case classifications <- classifyS3Request(r).action:
		default:
		}
		authenticated.ServeHTTP(w, r)
	}))
	defer front.Close()
	client := s3.NewFromConfig(aws.Config{
		Region:                     "us-east-1",
		Credentials:                credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
		HTTPClient:                 front.Client(),
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
	}, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(front.URL)
		options.UsePathStyle = true
	})

	for _, tc := range []struct {
		name string
		call func(*testing.T) error
	}{
		{
			name: "delete annotation preserves parent object",
			call: func(t *testing.T) error {
				t.Helper()
				_, err := client.DeleteObjectAnnotation(t.Context(), &s3.DeleteObjectAnnotationInput{
					Bucket:         aws.String("team2-bucket"),
					Key:            aws.String("important-object"),
					AnnotationName: aws.String("notes"),
					VersionId:      aws.String("original-version"),
				})
				return err
			},
		},
		{
			name: "put annotation preserves parent object",
			call: func(t *testing.T) error {
				t.Helper()
				_, err := client.PutObjectAnnotation(t.Context(), &s3.PutObjectAnnotationInput{
					Bucket:            aws.String("team2-bucket"),
					Key:               aws.String("important-object"),
					AnnotationName:    aws.String("notes"),
					AnnotationPayload: strings.NewReader("annotation text must not replace the object"),
				})
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call(t)
			select {
			case action := <-classifications:
				if action != unsupportedS3Action {
					t.Errorf("audit action = %q, want UnsupportedOperation", action)
				}
			default:
				t.Error("SDK request did not reach the gateway classifier")
			}
			if calls := upstreamCalls.Swap(0); calls != 0 {
				t.Errorf("unsupported annotation caused %d upstream calls, want zero", calls)
			}
			apiErr, ok := errors.AsType[smithy.APIError](err)
			if !ok || apiErr.ErrorCode() != "NotImplemented" {
				t.Fatalf("SDK error = %v, want NotImplemented", err)
			}
			responseErr, ok := errors.AsType[*smithyhttp.ResponseError](err)
			if !ok || responseErr.HTTPStatusCode() != http.StatusNotImplemented {
				t.Fatalf("SDK error = %v, want HTTP 501", err)
			}
		})
	}
}

func TestGatewayRejectsMalformedMultipartQueries(t *testing.T) {
	var upstreamCalls atomic.Int32
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	})
	defer cleanup()

	queries := []struct {
		name  string
		query string
	}{
		{name: "empty upload ID", query: "uploadId="},
		{name: "bare upload ID", query: "uploadId"},
		{name: "space upload ID", query: "uploadId=%20"},
		{name: "tab upload ID", query: "uploadId=%09"},
		{name: "duplicate upload IDs", query: "uploadId=first&uploadId=second"},
		{name: "duplicate identical upload IDs", query: "uploadId=first&uploadId=first"},
		{name: "empty first upload ID", query: "uploadId=&uploadId=second"},
		{name: "empty second upload ID", query: "uploadId=first&uploadId="},
		{name: "invalid percent escape", query: "uploadId=%zz"},
		{name: "incomplete percent escape", query: "uploadId=%"},
		{name: "semicolon separator", query: "uploadId=first;partNumber=1"},
	}
	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPost, http.MethodGet} {
		t.Run(method, func(t *testing.T) {
			for _, tc := range queries {
				t.Run(tc.name, func(t *testing.T) {
					body := "replacement object bytes"
					if method == http.MethodPost {
						body = `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>etag</ETag></Part></CompleteMultipartUpload>`
					}
					req := httptest.NewRequest(method, "/team2-bucket/important-object", strings.NewReader(body))
					req.URL.RawQuery = tc.query
					if method == http.MethodPut {
						req.URL.RawQuery += "&partNumber=1"
					}
					if action := classifyS3Request(req).action; action != unsupportedS3Action {
						t.Errorf("audit action = %q, want UnsupportedOperation", action)
					}
					rr := httptest.NewRecorder()
					gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
					if calls := upstreamCalls.Swap(0); calls != 0 {
						t.Errorf("malformed query caused %d upstream calls, want zero", calls)
					}
					if rr.Code != http.StatusBadRequest {
						t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
					}
				})
			}
		})
	}
}

func TestGatewayRejectsUnknownOperationSelectors(t *testing.T) {
	var upstreamCalls atomic.Int32
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	})
	defer cleanup()

	for _, tc := range []struct {
		name   string
		method string
		target string
	}{
		{name: "future object delete", method: http.MethodDelete, target: "/team2-bucket/key?future-operation"},
		{name: "future object write", method: http.MethodPut, target: "/team2-bucket/key?future-operation=enabled"},
		{name: "future bucket delete", method: http.MethodDelete, target: "/team2-bucket?future-operation"},
		{name: "future root operation", method: http.MethodGet, target: "/?future-operation"},
		{name: "annotation selector", method: http.MethodGet, target: "/team2-bucket/key?annotation&annotationName=notes"},
		{name: "unsupported selector with multipart ID", method: http.MethodDelete, target: "/team2-bucket/key?future-operation&uploadId=valid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader("replacement"))
			if action := classifyS3Request(req).action; action != unsupportedS3Action {
				t.Errorf("audit action = %q, want UnsupportedOperation", action)
			}
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if calls := upstreamCalls.Swap(0); calls != 0 {
				t.Errorf("unsupported selector caused %d upstream calls, want zero", calls)
			}
			if rr.Code != http.StatusNotImplemented || !strings.Contains(rr.Body.String(), "<Code>NotImplemented</Code>") {
				t.Fatalf("status = %d, body=%s; want 501 NotImplemented", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestGatewayRejectsConflictingOperationQueries(t *testing.T) {
	var upstreamCalls atomic.Int32
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	})
	defer cleanup()

	for _, tc := range []struct {
		name       string
		method     string
		target     string
		wantStatus int
	}{
		{name: "upload ID on bucket", method: http.MethodDelete, target: "/team2-bucket?uploadId=valid", wantStatus: http.StatusBadRequest},
		{name: "upload ID on bucket trailing slash", method: http.MethodPut, target: "/team2-bucket/?uploadId=valid&partNumber=1", wantStatus: http.StatusBadRequest},
		{name: "upload ID on root", method: http.MethodGet, target: "/?uploadId=valid", wantStatus: http.StatusBadRequest},
		{name: "part number on bucket", method: http.MethodGet, target: "/team2-bucket?partNumber=1", wantStatus: http.StatusBadRequest},
		{name: "part number on root", method: http.MethodGet, target: "/?partNumber=1", wantStatus: http.StatusBadRequest},
		{name: "attributes on bucket", method: http.MethodGet, target: "/team2-bucket?attributes", wantStatus: http.StatusBadRequest},
		{name: "attributes on root", method: http.MethodGet, target: "/?attributes", wantStatus: http.StatusBadRequest},
		{name: "part PUT without upload ID", method: http.MethodPut, target: "/team2-bucket/key?partNumber=1", wantStatus: http.StatusBadRequest},
		{name: "part DELETE without upload ID", method: http.MethodDelete, target: "/team2-bucket/key?partNumber=1", wantStatus: http.StatusBadRequest},
		{name: "part POST without upload ID", method: http.MethodPost, target: "/team2-bucket/key?partNumber=1", wantStatus: http.StatusBadRequest},
		{name: "upload ID with tagging", method: http.MethodDelete, target: "/team2-bucket/key?uploadId=valid&tagging", wantStatus: http.StatusBadRequest},
		{name: "upload ID with initiation", method: http.MethodPost, target: "/team2-bucket/key?uploadId=valid&uploads", wantStatus: http.StatusBadRequest},
		{name: "empty query name", method: http.MethodDelete, target: "/team2-bucket/key?=value", wantStatus: http.StatusBadRequest},
		{name: "empty name cannot hide annotation", method: http.MethodDelete, target: "/team2-bucket/key?=value&annotation&tagging", wantStatus: http.StatusBadRequest},
		{name: "empty part number", method: http.MethodPut, target: "/team2-bucket/key?uploadId=valid&partNumber=", wantStatus: http.StatusBadRequest},
		{name: "duplicate part number", method: http.MethodPut, target: "/team2-bucket/key?uploadId=valid&partNumber=1&partNumber=2", wantStatus: http.StatusBadRequest},
		{name: "version on bucket deletion", method: http.MethodDelete, target: "/team2-bucket?versionId=v", wantStatus: http.StatusNotImplemented},
		{name: "prefix on object write", method: http.MethodPut, target: "/team2-bucket/key?prefix=x", wantStatus: http.StatusNotImplemented},
		{name: "delimiter on bucket creation", method: http.MethodPut, target: "/team2-bucket?delimiter=x", wantStatus: http.StatusNotImplemented},
		{name: "part listing modifier on object deletion", method: http.MethodDelete, target: "/team2-bucket/key?max-parts=1", wantStatus: http.StatusNotImplemented},
		{name: "version on object write", method: http.MethodPut, target: "/team2-bucket/key?versionId=v", wantStatus: http.StatusNotImplemented},
		{name: "MinIO read modifier on object deletion", method: http.MethodDelete, target: "/team2-bucket/key?withUpdatedAt=true", wantStatus: http.StatusNotImplemented},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader("replacement"))
			if action := classifyS3Request(req).action; action != unsupportedS3Action {
				t.Errorf("audit action = %q, want UnsupportedOperation", action)
			}
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if calls := upstreamCalls.Swap(0); calls != 0 {
				t.Errorf("conflicting operation query caused %d upstream calls, want zero", calls)
			}
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, body=%s; want %d", rr.Code, rr.Body.String(), tc.wantStatus)
			}
		})
	}
}

func TestGatewayPreservesMinIOLifecycleRead(t *testing.T) {
	const lifecycle = `<LifecycleConfiguration><Rule><ID>expiry</ID><Status>Enabled</Status><Filter><Prefix>logs/</Prefix></Filter><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>`
	var upstreamCalls atomic.Int32
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/team2-bucket" || !r.URL.Query().Has("lifecycle") {
			t.Errorf("unexpected upstream lifecycle request: %s %s", r.Method, r.URL)
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, lifecycle)
	})
	defer cleanup()
	req := httptest.NewRequest(http.MethodGet, "/team2-bucket?lifecycle&withUpdatedAt=true", nil)
	if action := classifyS3Request(req).action; action != "GetBucketLifecycleConfiguration" {
		t.Errorf("audit action = %q, want GetBucketLifecycleConfiguration", action)
	}
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
	if rr.Code != http.StatusOK || upstreamCalls.Load() != 1 || !strings.Contains(rr.Body.String(), "<ID>expiry</ID>") {
		t.Fatalf("status=%d calls=%d body=%s; want lifecycle response", rr.Code, upstreamCalls.Load(), rr.Body.String())
	}
}

func TestGatewayPreservesObjectQueryModifiers(t *testing.T) {
	for _, tc := range []struct {
		name       string
		method     string
		query      string
		wantAction string
		wantStatus int
	}{
		{name: "GET part", method: http.MethodGet, query: "partNumber=1&versionId=v&x-id=GetObject", wantAction: "GetObject", wantStatus: http.StatusOK},
		{name: "HEAD part", method: http.MethodHead, query: "partNumber=1&versionId=v", wantAction: "HeadObject", wantStatus: http.StatusOK},
		{name: "DELETE version", method: http.MethodDelete, query: "versionId=v&x-id=DeleteObject", wantAction: "DeleteObject", wantStatus: http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			requests := make(chan *http.Request, 1)
			gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				select {
				case requests <- r.Clone(t.Context()):
				default:
				}
				w.WriteHeader(tc.wantStatus)
			})
			defer cleanup()
			req := httptest.NewRequest(tc.method, "/team2-bucket/key?"+tc.query, nil)
			if action := classifyS3Request(req).action; action != tc.wantAction {
				t.Errorf("audit action = %q, want %q", action, tc.wantAction)
			}
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != tc.wantStatus || upstreamCalls.Load() != 1 {
				t.Fatalf("status=%d calls=%d body=%s; want status=%d and one upstream call", rr.Code, upstreamCalls.Load(), rr.Body.String(), tc.wantStatus)
			}
			upstreamReq := <-requests
			query := upstreamReq.URL.Query()
			if upstreamReq.Method != tc.method || query.Get("versionId") != "v" {
				t.Fatalf("upstream request = %s %s; expected method and version preserved", upstreamReq.Method, upstreamReq.URL)
			}
			if tc.method != http.MethodDelete && query.Get("partNumber") != "1" {
				t.Fatalf("part number missing from upstream request: %s", upstreamReq.URL)
			}
		})
	}
}

func TestGatewayValidMultipartRoutes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		method     string
		query      string
		body       string
		response   string
		wantStatus int
	}{
		{name: "initiate", method: http.MethodPost, query: "uploads", response: `<InitiateMultipartUploadResult><UploadId>valid-upload</UploadId></InitiateMultipartUploadResult>`, wantStatus: http.StatusOK},
		{name: "upload part", method: http.MethodPut, query: "uploadId=valid-upload&partNumber=1&x-id=UploadPart", body: "part bytes", wantStatus: http.StatusOK},
		{name: "list parts", method: http.MethodGet, query: "uploadId=valid-upload&part-number-marker=0&max-parts=2&x-id=ListParts", response: `<ListPartsResult><UploadId>valid-upload</UploadId></ListPartsResult>`, wantStatus: http.StatusOK},
		{name: "complete", method: http.MethodPost, query: "uploadId=valid-upload", body: `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>etag</ETag></Part></CompleteMultipartUpload>`, response: `<CompleteMultipartUploadResult><ETag>etag</ETag></CompleteMultipartUploadResult>`, wantStatus: http.StatusOK},
		{name: "abort", method: http.MethodDelete, query: "uploadId=valid-upload&x-id=AbortMultipartUpload", wantStatus: http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			requests := make(chan *http.Request, 1)
			gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				select {
				case requests <- r.Clone(t.Context()):
				default:
				}
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/xml")
				w.Header().Set("ETag", `"etag"`)
				w.WriteHeader(tc.wantStatus)
				_, _ = io.WriteString(w, tc.response)
			})
			defer cleanup()
			req := httptest.NewRequest(tc.method, "/team2-bucket/key?"+tc.query, strings.NewReader(tc.body))
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != tc.wantStatus || upstreamCalls.Load() != 1 {
				t.Fatalf("status=%d calls=%d body=%s; want status=%d and one upstream call", rr.Code, upstreamCalls.Load(), rr.Body.String(), tc.wantStatus)
			}
			upstreamReq := <-requests
			if upstreamReq.Method != tc.method || upstreamReq.URL.Path != "/team2-bucket/key" {
				t.Fatalf("upstream route = %s %s, want %s /team2-bucket/key", upstreamReq.Method, upstreamReq.URL.Path, tc.method)
			}
			query := upstreamReq.URL.Query()
			if tc.name == "initiate" {
				if !query.Has("uploads") {
					t.Fatalf("missing upstream multipart initiation selector: %s", upstreamReq.URL)
				}
			} else if query.Get("uploadId") != "valid-upload" {
				t.Fatalf("lost multipart upload ID: %s", upstreamReq.URL)
			}
			if tc.method == http.MethodPut && query.Get("partNumber") != "1" {
				t.Fatalf("lost part number: %s", upstreamReq.URL)
			}
		})
	}
}
