package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/define42/s3gateway/internal/config"
)

const testAuditHashKey = "1234567890abcdef1234567890abcdef"

func TestClassifyS3RequestActions(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		target     string
		copySource string
		want       string
	}{
		{name: "list buckets", method: http.MethodGet, target: "/", want: "ListBuckets"},
		{name: "create bucket", method: http.MethodPut, target: "/bucket", want: "CreateBucket"},
		{name: "delete bucket", method: http.MethodDelete, target: "/bucket", want: "DeleteBucket"},
		{name: "head bucket", method: http.MethodHead, target: "/bucket", want: "HeadBucket"},
		{name: "list objects", method: http.MethodGet, target: "/bucket", want: "ListObjects"},
		{name: "list objects trailing slash", method: http.MethodGet, target: "/bucket/", want: "ListObjects"},
		{name: "list objects v2", method: http.MethodGet, target: "/bucket?list-type=2", want: "ListObjectsV2"},
		{name: "invalid list objects v2", method: http.MethodGet, target: "/bucket?list-type=1", want: "ListObjectsV2"},
		{name: "put lifecycle", method: http.MethodPut, target: "/bucket?lifecycle", want: "PutBucketLifecycleConfiguration"},
		{name: "get lifecycle", method: http.MethodGet, target: "/bucket?lifecycle", want: "GetBucketLifecycleConfiguration"},
		{name: "delete lifecycle", method: http.MethodDelete, target: "/bucket?lifecycle", want: "DeleteBucketLifecycleConfiguration"},
		{name: "put versioning", method: http.MethodPut, target: "/bucket?versioning", want: "PutBucketVersioning"},
		{name: "get versioning", method: http.MethodGet, target: "/bucket?versioning", want: "GetBucketVersioning"},
		{name: "put bucket tagging", method: http.MethodPut, target: "/bucket?tagging", want: "PutBucketTagging"},
		{name: "get bucket tagging", method: http.MethodGet, target: "/bucket?tagging", want: "GetBucketTagging"},
		{name: "delete bucket tagging", method: http.MethodDelete, target: "/bucket?tagging", want: "DeleteBucketTagging"},
		{name: "get bucket ACL", method: http.MethodGet, target: "/bucket?acl", want: "GetBucketAcl"},
		{name: "put bucket ACL", method: http.MethodPut, target: "/bucket?acl", want: "PutBucketAcl"},
		{name: "put bucket encryption", method: http.MethodPut, target: "/bucket?encryption", want: "PutBucketEncryption"},
		{name: "get bucket encryption", method: http.MethodGet, target: "/bucket?encryption", want: "GetBucketEncryption"},
		{name: "delete bucket encryption", method: http.MethodDelete, target: "/bucket?encryption", want: "DeleteBucketEncryption"},
		{name: "get bucket policy", method: http.MethodGet, target: "/bucket?policy", want: "GetBucketPolicy"},
		{name: "get bucket policy status", method: http.MethodGet, target: "/bucket?policyStatus", want: "GetBucketPolicyStatus"},
		{name: "get bucket CORS", method: http.MethodGet, target: "/bucket?cors", want: "GetBucketCors"},
		{name: "get bucket website", method: http.MethodGet, target: "/bucket?website", want: "GetBucketWebsite"},
		{name: "get bucket replication", method: http.MethodGet, target: "/bucket?replication", want: "GetBucketReplication"},
		{name: "get bucket logging", method: http.MethodGet, target: "/bucket?logging", want: "GetBucketLogging"},
		{name: "get bucket notification", method: http.MethodGet, target: "/bucket?notification", want: "GetBucketNotificationConfiguration"},
		{name: "get bucket request payment", method: http.MethodGet, target: "/bucket?requestPayment", want: "GetBucketRequestPayment"},
		{name: "get bucket acceleration", method: http.MethodGet, target: "/bucket?accelerate", want: "GetBucketAccelerateConfiguration"},
		{name: "get public access block", method: http.MethodGet, target: "/bucket?publicAccessBlock", want: "GetPublicAccessBlock"},
		{name: "delete objects", method: http.MethodPost, target: "/bucket?delete", want: "DeleteObjects"},
		{name: "get bucket location", method: http.MethodGet, target: "/bucket?location", want: "GetBucketLocation"},
		{name: "list object versions", method: http.MethodGet, target: "/bucket?versions", want: "ListObjectVersions"},
		{name: "list multipart uploads", method: http.MethodGet, target: "/bucket?uploads", want: "ListMultipartUploads"},
		{name: "get object ACL", method: http.MethodGet, target: "/bucket/key?acl", want: "GetObjectAcl"},
		{name: "put object ACL", method: http.MethodPut, target: "/bucket/key?acl", want: "PutObjectAcl"},
		{name: "put object tagging", method: http.MethodPut, target: "/bucket/key?tagging", want: "PutObjectTagging"},
		{name: "get object tagging", method: http.MethodGet, target: "/bucket/key?tagging", want: "GetObjectTagging"},
		{name: "delete object tagging", method: http.MethodDelete, target: "/bucket/key?tagging", want: "DeleteObjectTagging"},
		{name: "create multipart upload", method: http.MethodPost, target: "/bucket/key?uploads", want: "CreateMultipartUpload"},
		{name: "get object attributes", method: http.MethodGet, target: "/bucket/key?attributes", want: "GetObjectAttributes"},
		{name: "list parts", method: http.MethodGet, target: "/bucket/key?uploadId=id", want: "ListParts"},
		{name: "upload part", method: http.MethodPut, target: "/bucket/key?partNumber=1&uploadId=id", want: "UploadPart"},
		{name: "upload part copy", method: http.MethodPut, target: "/bucket/key?partNumber=1&uploadId=id", copySource: "/source/key", want: "UploadPartCopy"},
		{name: "complete multipart upload", method: http.MethodPost, target: "/bucket/key?uploadId=id", want: "CompleteMultipartUpload"},
		{name: "abort multipart upload", method: http.MethodDelete, target: "/bucket/key?uploadId=id", want: "AbortMultipartUpload"},
		{name: "get object", method: http.MethodGet, target: "/bucket/nested/key", want: "GetObject"},
		{name: "head object", method: http.MethodHead, target: "/bucket/key", want: "HeadObject"},
		{name: "put object", method: http.MethodPut, target: "/bucket/key", want: "PutObject"},
		{name: "copy object", method: http.MethodPut, target: "/bucket/key", copySource: "/source/key", want: "CopyObject"},
		{name: "delete object", method: http.MethodDelete, target: "/bucket/key", want: "DeleteObject"},
		{name: "pop bucket object with POST", method: http.MethodPost, target: "/api/pop/bucket/scanner", want: "PopObject"},
		{name: "pop global object with GET", method: http.MethodGet, target: "/api/pop/_all/archive", want: "PopObject"},
		{name: "pop method unsupported", method: http.MethodPatch, target: "/api/pop/bucket/scanner", want: unsupportedS3Action},
		{name: "unsupported global subresource", method: http.MethodGet, target: "/bucket/key?retention", want: unsupportedS3Action},
		{name: "bucket subresource on object", method: http.MethodGet, target: "/bucket/key?policy", want: unsupportedS3Action},
		{name: "unsupported method", method: http.MethodPatch, target: "/bucket/key", want: unsupportedS3Action},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, tt.target, nil)
			if tt.copySource != "" {
				r.Header.Set("x-amz-copy-source", tt.copySource)
			}
			if got := classifyS3Request(r).action; got != tt.want {
				t.Fatalf("action mismatch: got=%q want=%q", got, tt.want)
			}
		})
	}
}

func TestS3AuditEventIsCompleteAndRedacted(t *testing.T) {
	var logs bytes.Buffer
	s := newAuditTestServer(&logs)
	principal := "alice.secret@example.com"

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.setS3AuditPrincipal(r, principal)
		markS3AuditAuthenticated(r)
		w.Header().Set("x-amz-request-id", "request-123")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "ok")
	})
	r := httptest.NewRequest(
		http.MethodPut,
		"/private-bucket/private/object.txt?partNumber=7&uploadId=private-upload&x-id=private-credential",
		nil,
	)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 private-signature")
	r.Header.Set("x-amz-copy-source", "/private-source/private-key")
	w := httptest.NewRecorder()

	s.WithS3Audit(next).ServeHTTP(w, r)

	event := decodeSingleAuditEvent(t, logs.Bytes())
	assertAuditString(t, event, "msg", s3AuditMessage)
	assertAuditString(t, event, "event_kind", s3AuditEventKind)
	assertAuditString(t, event, "action", "UploadPartCopy")
	assertAuditString(t, event, "method", http.MethodPut)
	assertAuditNumber(t, event, "status", http.StatusCreated)
	assertAuditString(t, event, "outcome", "success")
	assertAuditNumber(t, event, "response_bytes", 2)
	assertAuditBool(t, event, "authenticated", true)
	assertAuditBool(t, event, "handler_completed", true)
	assertAuditString(t, event, "principal_hash", s.auditHash(auditPrincipalScope, principal))
	assertAuditString(t, event, "bucket_hash", s.auditHash(auditBucketScope, "private-bucket"))
	assertAuditString(
		t,
		event,
		"object_key_hash",
		s.auditHash(auditObjectKeyScope, "private/object.txt"),
	)
	assertAuditString(t, event, "request_id", "request-123")

	for _, secret := range []string{
		principal,
		"private-bucket",
		"private/object.txt",
		"private-upload",
		"private-credential",
		"private-signature",
		"private-source",
		"private-key",
	} {
		if bytes.Contains(logs.Bytes(), []byte(secret)) {
			t.Errorf("audit log exposed sensitive value %q: %s", secret, logs.Bytes())
		}
	}
}

func TestS3AuditWrapsAuthenticationFailures(t *testing.T) {
	var logs bytes.Buffer
	s := newAuditTestServer(&logs)
	adminHandler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("admin handler must not receive an S3 request")
	})
	r := httptest.NewRequest(http.MethodGet, "/private-bucket/private-key", nil)
	w := httptest.NewRecorder()

	s.WithS3Audit(s.WithAuth(s, adminHandler)).ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status mismatch: got=%d want=%d", w.Code, http.StatusUnauthorized)
	}
	event := decodeSingleAuditEvent(t, logs.Bytes())
	assertAuditString(t, event, "action", "GetObject")
	assertAuditString(t, event, "outcome", "client_error")
	assertAuditNumber(t, event, "status", http.StatusUnauthorized)
	assertAuditBool(t, event, "authenticated", false)
	assertAuditString(t, event, "principal_hash", "")
}

func TestS3AuditRecordsPanickingHandler(t *testing.T) {
	var logs bytes.Buffer
	s := newAuditTestServer(&logs)
	handler := s.WithS3Audit(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("test panic")
	}))

	func() {
		defer func() {
			if recovered := recover(); recovered == nil {
				t.Error("expected handler panic")
			}
		}()
		handler.ServeHTTP(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/bucket/key", nil),
		)
	}()

	event := decodeSingleAuditEvent(t, logs.Bytes())
	assertAuditString(t, event, "outcome", "server_error")
	assertAuditNumber(t, event, "status", http.StatusInternalServerError)
	assertAuditBool(t, event, "handler_completed", false)
}

func TestS3AuditExcludesNonS3Traffic(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		browser bool
	}{
		{name: "health", target: "/healthz"},
		{name: "readiness", target: "/readyz"},
		{name: "browser login", target: "/login", browser: true},
		{name: "browser root", target: "/", browser: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			s := newAuditTestServer(&logs)
			called := false
			handler := s.WithS3Audit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			r := httptest.NewRequest(http.MethodGet, tt.target, nil)
			if tt.browser {
				r.Header.Set("Accept", "text/html")
				r.Header.Set("User-Agent", "Mozilla/5.0")
			}

			handler.ServeHTTP(httptest.NewRecorder(), r)

			if !called {
				t.Fatal("next handler was not called")
			}
			if logs.Len() != 0 {
				t.Fatalf("non-S3 traffic produced audit log: %s", logs.Bytes())
			}
		})
	}
}

func TestS3AuditResponseWriterPreservesStreamingCapabilities(t *testing.T) {
	underlying := newAuditCapabilityWriter()
	w := &s3AuditResponseWriter{ResponseWriter: underlying}
	source := struct{ io.Reader }{Reader: strings.NewReader("streamed")}

	n, err := io.Copy(w, source)
	if err != nil {
		t.Fatalf("copy through audit response writer: %v", err)
	}
	if n != 8 || w.BytesWritten() != 8 || underlying.body.String() != "streamed" {
		t.Fatalf(
			"stream copy mismatch: copied=%d audited=%d body=%q",
			n,
			w.BytesWritten(),
			underlying.body.String(),
		)
	}
	if !underlying.readFromCalled {
		t.Fatal("underlying io.ReaderFrom fast path was not used")
	}
	if w.Status() != http.StatusOK || underlying.status != http.StatusOK {
		t.Fatalf("implicit status mismatch: audit=%d underlying=%d", w.Status(), underlying.status)
	}

	w.Flush()
	if !underlying.flushCalled {
		t.Fatal("flush was not forwarded")
	}
	if err := w.Push("/asset", nil); err != nil || !underlying.pushCalled {
		t.Fatalf("push was not forwarded: err=%v called=%t", err, underlying.pushCalled)
	}
	if _, _, err := w.Hijack(); !errors.Is(err, errAuditHijack) || !underlying.hijackCalled {
		t.Fatalf("hijack was not forwarded: err=%v called=%t", err, underlying.hijackCalled)
	}
	if w.Unwrap() != underlying {
		t.Fatal("unwrap did not return the underlying response writer")
	}
}

func TestS3AuditInputNormalization(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "standard method", got: auditMethod(http.MethodGet), want: http.MethodGet},
		{name: "invalid method", got: auditMethod("GET\nforged"), want: "OTHER"},
		{name: "empty method", got: auditMethod(""), want: "OTHER"},
		{name: "success", got: s3AuditOutcome(http.StatusNotModified, true), want: "success"},
		{name: "client error", got: s3AuditOutcome(http.StatusForbidden, true), want: "client_error"},
		{name: "server error", got: s3AuditOutcome(http.StatusBadGateway, true), want: "server_error"},
		{name: "panic", got: s3AuditOutcome(http.StatusOK, false), want: "server_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("value mismatch: got=%q want=%q", tt.got, tt.want)
			}
		})
	}

	header := make(http.Header)
	header.Set("x-amz-request-id", "safe-request-id")
	if got := auditRequestID(header); got != "safe-request-id" {
		t.Fatalf("safe request ID mismatch: got=%q", got)
	}
	header.Set("x-amz-request-id", "forged\nvalue")
	if got := auditRequestID(header); got != "" {
		t.Fatalf("unsafe request ID was retained: %q", got)
	}
	header.Set("x-amz-request-id", strings.Repeat("x", maxAuditRequestIDLen+1))
	if got := auditRequestID(header); got != "" {
		t.Fatalf("oversized request ID was retained: %q", got)
	}
}

func TestS3AuditHashesAreStableAndDomainSeparated(t *testing.T) {
	first := New(config.Config{S3AuditHashKey: testAuditHashKey}, nil)
	second := New(config.Config{S3AuditHashKey: testAuditHashKey}, nil)
	value := "same-sensitive-value"

	principalHash := first.auditHash(auditPrincipalScope, value)
	if principalHash == "" {
		t.Fatal("configured audit key produced an empty pseudonym")
	}
	if got := second.auditHash(auditPrincipalScope, value); got != principalHash {
		t.Fatalf("configured audit pseudonym is not stable: first=%q second=%q", principalHash, got)
	}
	if got := first.auditHash(auditBucketScope, value); got == principalHash {
		t.Fatal("principal and bucket pseudonyms must be domain-separated")
	}
	if got := first.auditHash(auditObjectKeyScope, value); got == principalHash {
		t.Fatal("principal and object-key pseudonyms must be domain-separated")
	}
}

func newAuditTestServer(logs io.Writer) *Server {
	s := New(config.Config{S3AuditHashKey: testAuditHashKey}, nil)
	s.logger = slog.New(slog.NewJSONHandler(logs, nil))
	return s
}

func decodeSingleAuditEvent(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var event map[string]any
	if err := decoder.Decode(&event); err != nil {
		t.Fatalf("decode audit event: %v; raw=%s", err, raw)
	}
	var extra map[string]any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("expected exactly one audit event: err=%v extra=%v raw=%s", err, extra, raw)
	}
	return event
}

func assertAuditString(t *testing.T, event map[string]any, key, want string) {
	t.Helper()
	got, ok := event[key].(string)
	if !ok || got != want {
		t.Fatalf("audit field %q mismatch: got=%v want=%q", key, event[key], want)
	}
}

func assertAuditNumber(t *testing.T, event map[string]any, key string, want int) {
	t.Helper()
	got, ok := event[key].(float64)
	if !ok || int(got) != want {
		t.Fatalf("audit field %q mismatch: got=%v want=%d", key, event[key], want)
	}
}

func assertAuditBool(t *testing.T, event map[string]any, key string, want bool) {
	t.Helper()
	got, ok := event[key].(bool)
	if !ok || got != want {
		t.Fatalf("audit field %q mismatch: got=%v want=%t", key, event[key], want)
	}
}

var errAuditHijack = errors.New("test hijack")

type auditCapabilityWriter struct {
	header         http.Header
	body           bytes.Buffer
	status         int
	readFromCalled bool
	flushCalled    bool
	hijackCalled   bool
	pushCalled     bool
}

func newAuditCapabilityWriter() *auditCapabilityWriter {
	return &auditCapabilityWriter{header: make(http.Header)}
}

func (w *auditCapabilityWriter) Header() http.Header {
	return w.header
}

func (w *auditCapabilityWriter) WriteHeader(status int) {
	w.status = status
}

func (w *auditCapabilityWriter) Write(p []byte) (int, error) {
	return w.body.Write(p)
}

func (w *auditCapabilityWriter) ReadFrom(r io.Reader) (int64, error) {
	w.readFromCalled = true
	return w.body.ReadFrom(r)
}

func (w *auditCapabilityWriter) Flush() {
	w.flushCalled = true
}

func (w *auditCapabilityWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijackCalled = true
	return nil, nil, errAuditHijack
}

func (w *auditCapabilityWriter) Push(string, *http.PushOptions) error {
	w.pushCalled = true
	return nil
}
