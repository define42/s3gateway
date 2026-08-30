package server

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/define42/s3gateway/internal/adminpage"
)

const (
	s3AuditMessage       = "S3 request completed"
	s3AuditEventKind     = "s3_audit"
	unknownS3Action      = "UnknownOperation"
	unsupportedS3Action  = "UnsupportedOperation"
	maxAuditRequestIDLen = 128
)

type auditHashScope uint8

const (
	auditPrincipalScope auditHashScope = iota
	auditBucketScope
	auditObjectKeyScope
	auditHashScopeCount
)

var auditHashScopeLabels = [auditHashScopeCount]string{
	"principal",
	"bucket",
	"object_key",
}

type s3AuditContextKey struct{}

type s3AuditState struct {
	principalHash string
	authenticated bool
	started       time.Time
	completed     bool
}

type s3AuditRequest struct {
	action string
	bucket string
	key    string
}

func newAuditHashKeys(configured string) ([auditHashScopeCount][sha256.Size]byte, bool) {
	masterKey, ok := newAuditMasterKey(configured)
	if !ok {
		return [auditHashScopeCount][sha256.Size]byte{}, false
	}

	var keys [auditHashScopeCount][sha256.Size]byte
	for scope, label := range auditHashScopeLabels {
		mac := hmac.New(sha256.New, masterKey[:])
		_, _ = io.WriteString(mac, label)
		copy(keys[scope][:], mac.Sum(nil))
	}
	return keys, true
}

func newAuditMasterKey(configured string) ([sha256.Size]byte, bool) {
	if configured != "" {
		key := sha256.Sum256([]byte("s3gateway/s3-audit/v1\x00" + configured))
		return key, true
	}

	var key [sha256.Size]byte
	if _, err := rand.Read(key[:]); err != nil {
		return key, false
	}
	return key, true
}

// WithS3Audit records exactly one structured event for every S3 request,
// including requests rejected by authentication. Health and browser-admin
// traffic are not S3 operations and are passed through without audit events.
func (s *Server) WithS3Audit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isS3AuditExcluded(r) {
			next.ServeHTTP(w, r)
			return
		}

		logger := s.auditLogger()
		if !logger.Enabled(r.Context(), slog.LevelInfo) {
			next.ServeHTTP(w, r)
			return
		}

		state := &s3AuditState{started: time.Now()}
		ctx := context.WithValue(r.Context(), s3AuditContextKey{}, state)
		auditWriter := &s3AuditResponseWriter{ResponseWriter: w}
		defer s.logS3Audit(r, auditWriter, state)

		next.ServeHTTP(auditWriter, r.WithContext(ctx))
		state.completed = true
	})
}

func (s *Server) logS3Audit(
	r *http.Request,
	w *s3AuditResponseWriter,
	state *s3AuditState,
) {
	request := classifyS3Request(r)
	status := w.Status()
	if !state.completed && w.status == 0 {
		status = http.StatusInternalServerError
	}
	s.auditLogger().LogAttrs(
		context.WithoutCancel(r.Context()),
		slog.LevelInfo,
		s3AuditMessage,
		slog.String("event_kind", s3AuditEventKind),
		slog.String("action", request.action),
		slog.String("method", auditMethod(r.Method)),
		slog.Int("status", status),
		slog.String("outcome", s3AuditOutcome(status, state.completed)),
		slog.Int64("duration_us", time.Since(state.started).Microseconds()),
		slog.Int64("response_bytes", w.BytesWritten()),
		slog.Bool("authenticated", state.authenticated),
		slog.Bool("handler_completed", state.completed),
		slog.String("principal_hash", state.principalHash),
		slog.String("bucket_hash", s.auditHash(auditBucketScope, request.bucket)),
		slog.String("object_key_hash", s.auditHash(auditObjectKeyScope, request.key)),
		slog.String("request_id", auditRequestID(w.Header())),
	)
}

func (s *Server) auditLogger() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return slog.Default()
}

func isS3AuditExcluded(r *http.Request) bool {
	if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
		return true
	}
	return adminpage.IsBrowser(r) && adminpage.IsAdminRoute(r.URL.Path)
}

func (s *Server) setS3AuditPrincipal(r *http.Request, principal string) {
	state, _ := r.Context().Value(s3AuditContextKey{}).(*s3AuditState)
	if state != nil {
		state.principalHash = s.auditHash(auditPrincipalScope, strings.TrimSpace(principal))
	}
}

func markS3AuditAuthenticated(r *http.Request) {
	state, _ := r.Context().Value(s3AuditContextKey{}).(*s3AuditState)
	if state != nil {
		state.authenticated = true
	}
}

func (s *Server) auditHash(scope auditHashScope, value string) string {
	if value == "" || !s.auditHashReady || scope >= auditHashScopeCount {
		return ""
	}
	mac := hmac.New(sha256.New, s.auditHashKeys[scope][:])
	_, _ = io.WriteString(mac, value)
	return hex.EncodeToString(mac.Sum(nil))
}

func auditMethod(method string) string {
	if len(method) == 0 || len(method) > 32 {
		return "OTHER"
	}
	for i := range len(method) {
		if method[i] < 'A' || method[i] > 'Z' {
			return "OTHER"
		}
	}
	return method
}

func auditRequestID(header http.Header) string {
	requestID := strings.TrimSpace(header.Get("x-amz-request-id"))
	if requestID == "" || len(requestID) > maxAuditRequestIDLen {
		return ""
	}
	for i := range len(requestID) {
		if requestID[i] < 0x21 || requestID[i] > 0x7e {
			return ""
		}
	}
	return requestID
}

func s3AuditOutcome(status int, completed bool) string {
	switch {
	case !completed:
		return "server_error"
	case status < http.StatusBadRequest:
		return "success"
	case status < http.StatusInternalServerError:
		return "client_error"
	default:
		return "server_error"
	}
}

func classifyS3Request(r *http.Request) s3AuditRequest {
	// Keep operation precedence aligned with ServeHTTP so malformed and
	// unsupported requests are attributed to the route they actually reach.
	p := r.URL.Path
	if p == "" {
		p = "/"
	}
	if scope, _, ok := parsePopAPIPath(p); ok {
		request := s3AuditRequest{action: "PopObject"}
		if scope != popGlobalScope {
			request.bucket = scope
		}
		if !isPopAPIMethod(r.Method) {
			request.action = unsupportedS3Action
		}
		return request
	}

	request := s3AuditResource(p)
	var q url.Values
	if r.URL.RawQuery != "" {
		q = r.URL.Query()
	}
	if firstUnsupportedSubresource(q) != "" {
		request.action = unsupportedS3Action
		return request
	}
	if p == "/" {
		if r.Method == http.MethodGet {
			request.action = "ListBuckets"
		} else {
			request.action = unsupportedS3Action
		}
		return request
	}
	if request.bucket == "" {
		return request
	}
	if request.key == "" {
		request.action = classifyBucketAction(r.Method, q)
		return request
	}
	request.action = classifyObjectAction(r.Method, r.Header, q)
	return request
}

func s3AuditResource(path string) s3AuditRequest {
	rest := strings.TrimPrefix(path, "/")
	if rest == "" {
		return s3AuditRequest{action: unknownS3Action}
	}
	parts := strings.SplitN(rest, "/", 2)
	request := s3AuditRequest{
		action: unknownS3Action,
		bucket: parts[0],
	}
	if len(parts) == 2 {
		request.key = parts[1]
	}
	return request
}

func classifyBucketAction(method string, q url.Values) string {
	if q.Has("lifecycle") {
		switch method {
		case http.MethodPut:
			return "PutBucketLifecycleConfiguration"
		case http.MethodGet:
			return "GetBucketLifecycleConfiguration"
		case http.MethodDelete:
			return "DeleteBucketLifecycleConfiguration"
		default:
			return unsupportedS3Action
		}
	}
	if q.Has("versioning") {
		switch method {
		case http.MethodPut:
			return "PutBucketVersioning"
		case http.MethodGet:
			return "GetBucketVersioning"
		default:
			return unsupportedS3Action
		}
	}
	if q.Has("tagging") {
		switch method {
		case http.MethodPut:
			return "PutBucketTagging"
		case http.MethodGet:
			return "GetBucketTagging"
		case http.MethodDelete:
			return "DeleteBucketTagging"
		default:
			return unsupportedS3Action
		}
	}
	if q.Has("acl") {
		switch method {
		case http.MethodGet:
			return "GetBucketAcl"
		case http.MethodPut:
			return "PutBucketAcl"
		default:
			return unsupportedS3Action
		}
	}
	if q.Has("encryption") {
		switch method {
		case http.MethodPut:
			return "PutBucketEncryption"
		case http.MethodGet:
			return "GetBucketEncryption"
		case http.MethodDelete:
			return "DeleteBucketEncryption"
		default:
			return unsupportedS3Action
		}
	}
	for _, key := range bucketConfigReadKeys {
		if !q.Has(key) {
			continue
		}
		if method != http.MethodGet {
			return unsupportedS3Action
		}
		return bucketConfigReadAction(key)
	}
	if q.Has("delete") {
		if method == http.MethodPost {
			return "DeleteObjects"
		}
		return unsupportedS3Action
	}
	if q.Has("location") {
		if method == http.MethodGet {
			return "GetBucketLocation"
		}
		return unsupportedS3Action
	}
	if q.Has("versions") {
		if method == http.MethodGet {
			return "ListObjectVersions"
		}
		return unsupportedS3Action
	}
	if q.Has("uploads") {
		if method == http.MethodGet {
			return "ListMultipartUploads"
		}
		return unsupportedS3Action
	}

	switch method {
	case http.MethodPut:
		return "CreateBucket"
	case http.MethodDelete:
		return "DeleteBucket"
	case http.MethodHead:
		return "HeadBucket"
	case http.MethodGet:
		if q.Get("list-type") != "" {
			return "ListObjectsV2"
		}
		return "ListObjects"
	default:
		return unsupportedS3Action
	}
}

func bucketConfigReadAction(key string) string {
	switch key {
	case "policy":
		return "GetBucketPolicy"
	case "policyStatus":
		return "GetBucketPolicyStatus"
	case "cors":
		return "GetBucketCors"
	case "website":
		return "GetBucketWebsite"
	case "replication":
		return "GetBucketReplication"
	case "logging":
		return "GetBucketLogging"
	case "notification":
		return "GetBucketNotificationConfiguration"
	case "requestPayment":
		return "GetBucketRequestPayment"
	case "accelerate":
		return "GetBucketAccelerateConfiguration"
	case "publicAccessBlock":
		return "GetPublicAccessBlock"
	default:
		return unknownS3Action
	}
}

func classifyObjectAction(method string, header http.Header, q url.Values) string {
	for subresource := range q {
		if _, ok := bucketOnlySubresources[subresource]; ok {
			return unsupportedS3Action
		}
	}
	if q.Has("acl") {
		switch method {
		case http.MethodGet:
			return "GetObjectAcl"
		case http.MethodPut:
			return "PutObjectAcl"
		default:
			return unsupportedS3Action
		}
	}
	if q.Has("tagging") {
		switch method {
		case http.MethodPut:
			return "PutObjectTagging"
		case http.MethodGet:
			return "GetObjectTagging"
		case http.MethodDelete:
			return "DeleteObjectTagging"
		default:
			return unsupportedS3Action
		}
	}
	if q.Has("uploads") {
		if method == http.MethodPost {
			return "CreateMultipartUpload"
		}
		return unsupportedS3Action
	}
	if q.Has("attributes") {
		if method == http.MethodGet {
			return "GetObjectAttributes"
		}
		return unsupportedS3Action
	}
	if q.Get("uploadId") != "" {
		switch method {
		case http.MethodGet:
			return "ListParts"
		case http.MethodPut:
			if strings.TrimSpace(header.Get("x-amz-copy-source")) != "" {
				return "UploadPartCopy"
			}
			return "UploadPart"
		case http.MethodPost:
			return "CompleteMultipartUpload"
		case http.MethodDelete:
			return "AbortMultipartUpload"
		default:
			return unsupportedS3Action
		}
	}

	switch method {
	case http.MethodGet:
		return "GetObject"
	case http.MethodHead:
		return "HeadObject"
	case http.MethodPut:
		if strings.TrimSpace(header.Get("x-amz-copy-source")) != "" {
			return "CopyObject"
		}
		return "PutObject"
	case http.MethodDelete:
		return "DeleteObject"
	default:
		return unsupportedS3Action
	}
}

type s3AuditResponseWriter struct {
	http.ResponseWriter
	status       int
	bytesWritten int64
}

func (w *s3AuditResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *s3AuditResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytesWritten += int64(n)
	return n, err
}

func (w *s3AuditResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if readerFrom, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err := readerFrom.ReadFrom(r)
		w.bytesWritten += n
		return n, err
	}
	return io.Copy(struct{ io.Writer }{w}, r)
}

func (w *s3AuditResponseWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *s3AuditResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijacking")
	}
	return hijacker.Hijack()
}

func (w *s3AuditResponseWriter) Push(target string, opts *http.PushOptions) error {
	pusher, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, opts)
}

func (w *s3AuditResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *s3AuditResponseWriter) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *s3AuditResponseWriter) BytesWritten() int64 {
	return w.bytesWritten
}
