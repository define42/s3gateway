package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	authz "github.com/define42/s3gateway/internal/authz"
	"github.com/define42/s3gateway/internal/config"
	"github.com/define42/s3gateway/internal/s3credentials"
	"github.com/define42/s3gateway/internal/testutil"
	"github.com/define42/s3gateway/internal/upstream"
)

func newGatewayWithStubUpstream(t *testing.T, h http.HandlerFunc) (*Server, func()) {
	t.Helper()

	upstreamSrv := httptest.NewServer(h)
	ctx := context.Background()
	// A custom CA bundle cannot be installed into the production factory's
	// plain *http.Client; it is irrelevant for the local stub anyway.
	t.Setenv("AWS_CA_BUNDLE", "")
	// Use the production upstream client factory so unit tests exercise the
	// same client configuration (e.g. request checksums only when required,
	// which non-seekable proxied bodies depend on).
	upstreamClient, err := upstream.New(ctx, config.Config{
		UpstreamEndpoint:       upstreamSrv.URL,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "upstream-ak",
		UpstreamSecretKey:      "upstream-sk",
		UpstreamForcePathStyle: true,
	})
	if err != nil {
		upstreamSrv.Close()
		t.Fatalf("init stub upstream client: %v", err)
	}
	gw := New(config.Config{}, upstreamClient)

	return gw, func() {
		upstreamSrv.Close()
	}
}

func fullTeam2Rule() []authz.Rule {
	return []authz.Rule{{
		BucketPrefix: "team2",
		Perm:         authz.PermRead | authz.PermWrite | authz.PermCreateBucket | authz.PermDeleteObject | authz.PermDeleteBucket,
	}}
}

func TestS3ClientUpload100MBThroughGateway(t *testing.T) {
	const uploadSize = int64(100 * 1024 * 1024)

	var uploadedBytes int64
	var uploadedBy string

	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/team2-large/objects/100mb.bin" {
			t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		uploadedBy = r.Header.Get("x-amz-meta-uploaded-by")
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			t.Fatalf("read upstream put body: %v", err)
		}
		uploadedBytes = n
		w.Header().Set("ETag", `"etag-100mb"`)
		w.WriteHeader(http.StatusOK)
	})
	defer cleanup()

	gw.gcache.Set("testuser", "dogood", map[string]struct{}{
		"team2-rw": {},
	})

	gwSrv := httptest.NewServer(gw.WithAuth(gw, adminWebpageHandler(gw)))
	defer gwSrv.Close()

	accessKey, secretKey, err := s3credentials.GenerateKeysBase64Encoded("testuser", "dogood")
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	client := testutil.NewS3Client(t, context.Background(), gwSrv.URL, "us-east-1", accessKey, secretKey)

	tmpFile, err := os.CreateTemp(t.TempDir(), "gateway-upload-100mb-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer tmpFile.Close()
	if err := tmpFile.Truncate(uploadSize); err != nil {
		t.Fatalf("truncate temp file to %d bytes: %v", uploadSize, err)
	}
	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek temp file start: %v", err)
	}

	if _, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket:        aws.String("team2-large"),
		Key:           aws.String("objects/100mb.bin"),
		Body:          tmpFile,
		ContentLength: aws.Int64(uploadSize),
		ContentType:   aws.String("application/octet-stream"),
	}); err != nil {
		t.Fatalf("put object 100MB via gateway client: %v", err)
	}

	if uploadedBytes != uploadSize {
		t.Fatalf("uploaded bytes mismatch: got=%d want=%d", uploadedBytes, uploadSize)
	}
	if uploadedBy != "testuser" {
		t.Fatalf("uploaded-by metadata mismatch: got=%q want=%q", uploadedBy, "testuser")
	}
}

func TestGatewayGetAndHeadObjectRichHeaderMatrix(t *testing.T) {
	lastModified := time.Now().UTC().Truncate(time.Second)
	expires := lastModified.Add(2 * time.Hour).Format(http.TimeFormat)
	retainUntil := lastModified.Add(24 * time.Hour).Format(time.RFC3339)

	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/team2-rich/object.txt" {
			t.Fatalf("unexpected upstream path: %s", r.URL.Path)
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			w.Header().Set("Accept-Ranges", "bytes")
			w.Header().Set("ETag", "\"etag-rich\"")
			w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", "11")
			w.Header().Set("Content-Range", "bytes 0-10/11")
			w.Header().Set("Cache-Control", "max-age=60")
			w.Header().Set("Content-Disposition", "inline")
			w.Header().Set("Content-Encoding", "identity")
			w.Header().Set("Content-Language", "en-US")
			w.Header().Set("Expires", expires)
			w.Header().Set("x-amz-version-id", "v-rich")
			w.Header().Set("x-amz-delete-marker", "true")
			w.Header().Set("x-amz-storage-class", "STANDARD")
			w.Header().Set("x-amz-server-side-encryption", "AES256")
			w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", "kms-rich")
			w.Header().Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
			w.Header().Set("x-amz-server-side-encryption-customer-key-md5", "md5-rich")
			w.Header().Set("x-amz-server-side-encryption-bucket-key-enabled", "true")
			w.Header().Set("x-amz-expiration", `expiry-date="2030-01-01T00:00:00Z", rule-id="rule-1"`)
			w.Header().Set("x-amz-restore", `ongoing-request="false"`)
			w.Header().Set("x-amz-website-redirect-location", "/redirect")
			w.Header().Set("x-amz-replication-status", "COMPLETED")
			w.Header().Set("x-amz-tagging-count", "2")
			w.Header().Set("x-amz-mp-parts-count", "3")
			w.Header().Set("x-amz-missing-meta", "1")
			w.Header().Set("x-amz-object-lock-mode", "GOVERNANCE")
			w.Header().Set("x-amz-object-lock-legal-hold", "ON")
			w.Header().Set("x-amz-object-lock-retain-until-date", retainUntil)
			w.Header().Set("x-amz-request-charged", "requester")
			w.Header().Set("x-amz-checksum-crc32", "AAAAAA==")
			w.Header().Set("x-amz-checksum-crc32c", "BBBBBB==")
			w.Header().Set("x-amz-checksum-crc64nvme", "CCCCCC==")
			w.Header().Set("x-amz-checksum-sha1", "DDDDDD==")
			w.Header().Set("x-amz-checksum-sha256", "EEEEEE==")
			w.Header().Set("x-amz-checksum-type", "FULL_OBJECT")
			w.Header().Set("x-amz-meta-k1", "v1")
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte("hello world"))
			}
		default:
			t.Fatalf("unexpected upstream method: %s", r.Method)
		}
	})
	defer cleanup()

	responseExpires := url.QueryEscape(lastModified.Add(1 * time.Hour).Format(http.TimeFormat))
	commonQuery := "versionId=v-rich&partNumber=1&response-cache-control=no-cache&response-content-disposition=attachment&response-content-encoding=gzip&response-content-language=en&response-content-type=text/plain&response-expires=" + responseExpires
	commonHeaders := map[string]string{
		"Range":               "bytes=0-10",
		"If-Match":            "\"etag-rich\"",
		"If-None-Match":       "\"etag-other\"",
		"If-Modified-Since":   lastModified.Add(-1 * time.Hour).Format(http.TimeFormat),
		"If-Unmodified-Since": lastModified.Add(1 * time.Hour).Format(http.TimeFormat),
		"x-amz-checksum-mode": "ENABLED",
		"x-amz-server-side-encryption-customer-algorithm": "AES256",
		"x-amz-server-side-encryption-customer-key":       "Zm9v",
		"x-amz-server-side-encryption-customer-key-md5":   "YmFy",
		"x-amz-expected-bucket-owner":                     "123456789012",
		"x-amz-request-payer":                             "requester",
	}

	getReq := httptest.NewRequest(http.MethodGet, "/team2-rich/object.txt?"+commonQuery, nil)
	for k, v := range commonHeaders {
		getReq.Header.Set(k, v)
	}
	getReq = getReq.WithContext(authz.WithRules(getReq.Context(), fullTeam2Rule()))
	getRR := httptest.NewRecorder()
	gw.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusPartialContent {
		t.Fatalf("get object status mismatch: got=%d body=%s", getRR.Code, getRR.Body.String())
	}
	if getRR.Header().Get("x-amz-checksum-type") != "FULL_OBJECT" {
		t.Fatalf("get object checksum type mismatch: got=%q", getRR.Header().Get("x-amz-checksum-type"))
	}
	if getRR.Header().Get("x-amz-meta-k1") != "v1" {
		t.Fatalf("get object metadata header mismatch: got=%q", getRR.Header().Get("x-amz-meta-k1"))
	}
	if body := getRR.Body.String(); body != "hello world" {
		t.Fatalf("get object body mismatch: got=%q", body)
	}

	headReq := httptest.NewRequest(http.MethodHead, "/team2-rich/object.txt?"+commonQuery, nil)
	for k, v := range commonHeaders {
		headReq.Header.Set(k, v)
	}
	headReq = headReq.WithContext(authz.WithRules(headReq.Context(), fullTeam2Rule()))
	headRR := httptest.NewRecorder()
	gw.ServeHTTP(headRR, headReq)
	if headRR.Code != http.StatusOK {
		t.Fatalf("head object status mismatch: got=%d", headRR.Code)
	}
	if headRR.Header().Get("x-amz-object-lock-mode") != "GOVERNANCE" {
		t.Fatalf("head object lock mode mismatch: got=%q", headRR.Header().Get("x-amz-object-lock-mode"))
	}
	if headRR.Header().Get("x-amz-checksum-sha256") != "EEEEEE==" {
		t.Fatalf("head object checksum mismatch: got=%q", headRR.Header().Get("x-amz-checksum-sha256"))
	}
}

func TestGatewayWriteCopyAndDeleteHandlerMatrix(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/team2-rich/object-put.txt" && r.URL.Query().Get("uploadId") == "" && r.Header.Get("x-amz-copy-source") == "":
			w.Header().Set("ETag", "\"put-etag\"")
			w.Header().Set("x-amz-version-id", "v-put")
			w.Header().Set("x-amz-server-side-encryption", "AES256")
			w.Header().Set("x-amz-checksum-sha256", "ZZZZZZ==")
			w.Header().Set("x-amz-checksum-type", "FULL_OBJECT")
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut && r.URL.Path == "/team2-rich/object-put.txt" && r.URL.Query().Get("uploadId") == "u1" && r.Header.Get("x-amz-copy-source") == "":
			w.Header().Set("ETag", "\"part-etag\"")
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut && r.URL.Path == "/team2-rich/copied.txt" && r.URL.Query().Get("uploadId") == "" && r.Header.Get("x-amz-copy-source") != "":
			w.Header().Set("x-amz-version-id", "v-copy")
			w.Header().Set("x-amz-request-charged", "requester")
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<CopyObjectResult>
  <LastModified>2026-02-07T01:02:03.000Z</LastModified>
  <ETag>"copy-etag"</ETag>
  <ChecksumCRC32>AAAAAA==</ChecksumCRC32>
  <ChecksumType>FULL_OBJECT</ChecksumType>
</CopyObjectResult>`))
		case r.Method == http.MethodPut && r.URL.Path == "/team2-rich/copied.txt" && r.URL.Query().Get("uploadId") == "u1" && r.Header.Get("x-amz-copy-source") != "":
			w.Header().Set("x-amz-copy-source-version-id", "src-v1")
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<CopyPartResult>
  <LastModified>2026-02-07T01:02:03.000Z</LastModified>
  <ETag>"copy-part-etag"</ETag>
  <ChecksumCRC32>BBBBBB==</ChecksumCRC32>
</CopyPartResult>`))
		case r.Method == http.MethodDelete && r.URL.Path == "/team2-rich/copied.txt" && r.URL.Query().Get("uploadId") == "":
			w.Header().Set("x-amz-delete-marker", "true")
			w.Header().Set("x-amz-version-id", "v-del")
			w.Header().Set("x-amz-request-charged", "requester")
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/team2-rich" && strings.Contains(r.URL.RawQuery, "delete"):
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult>
  <Deleted><Key>copied.txt</Key></Deleted>
</DeleteResult>`))
		default:
			t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
	})
	defer cleanup()

	permCtx := authz.WithRules(context.Background(), fullTeam2Rule())

	putReq := httptest.NewRequest(http.MethodPut, "/team2-rich/object-put.txt", bytes.NewReader([]byte("payload")))
	putReq = putReq.WithContext(permCtx)
	putReq.Header.Set("Content-Type", "text/plain")
	putReq.Header.Set("Expires", time.Now().Add(1*time.Hour).UTC().Format(http.TimeFormat))
	putReq.Header.Set("If-Match", "\"put-etag\"")
	putReq.Header.Set("x-amz-request-payer", "requester")
	putReq.Header.Set("x-amz-checksum-algorithm", "SHA256")
	putReq.Header.Set("x-amz-checksum-sha256", "ZZZZZZ==")
	putRR := httptest.NewRecorder()
	gw.ServeHTTP(putRR, putReq)
	if putRR.Code != http.StatusOK {
		t.Fatalf("put object status mismatch: got=%d body=%s", putRR.Code, putRR.Body.String())
	}

	putInvalidReq := httptest.NewRequest(http.MethodPut, "/team2-rich/object-put.txt", bytes.NewReader([]byte("payload")))
	putInvalidReq = putInvalidReq.WithContext(permCtx)
	putInvalidReq.Header.Set("If-Match", "\"a\"")
	putInvalidReq.Header.Set("If-None-Match", "\"b\"")
	putInvalidRR := httptest.NewRecorder()
	gw.ServeHTTP(putInvalidRR, putInvalidReq)
	if putInvalidRR.Code != http.StatusBadRequest {
		t.Fatalf("put object invalid condition status mismatch: got=%d", putInvalidRR.Code)
	}

	uploadPartReq := httptest.NewRequest(http.MethodPut, "/team2-rich/object-put.txt?partNumber=1&uploadId=u1", bytes.NewReader([]byte("part-body")))
	uploadPartReq = uploadPartReq.WithContext(permCtx)
	uploadPartReq.Header.Set("x-amz-checksum-algorithm", "SHA256")
	uploadPartReq.Header.Set("x-amz-checksum-sha256", "YYYYYY==")
	uploadPartRR := httptest.NewRecorder()
	gw.ServeHTTP(uploadPartRR, uploadPartReq)
	if uploadPartRR.Code != http.StatusOK {
		t.Fatalf("upload part status mismatch: got=%d body=%s", uploadPartRR.Code, uploadPartRR.Body.String())
	}

	uploadPartInvalidReq := httptest.NewRequest(http.MethodPut, "/team2-rich/object-put.txt?partNumber=1&uploadId=u1", bytes.NewReader([]byte("part-body")))
	uploadPartInvalidReq = uploadPartInvalidReq.WithContext(permCtx)
	uploadPartInvalidReq.Header.Set("Content-MD5", "abc")
	uploadPartInvalidReq.Header.Set("x-amz-checksum-algorithm", "SHA256")
	uploadPartInvalidRR := httptest.NewRecorder()
	gw.ServeHTTP(uploadPartInvalidRR, uploadPartInvalidReq)
	if uploadPartInvalidRR.Code != http.StatusBadRequest {
		t.Fatalf("upload part invalid headers status mismatch: got=%d", uploadPartInvalidRR.Code)
	}

	copyReq := httptest.NewRequest(http.MethodPut, "/team2-rich/copied.txt", nil)
	copyReq = copyReq.WithContext(permCtx)
	copyReq.Header.Set("x-amz-copy-source", "/team2-rich/source.txt")
	copyReq.Header.Set("If-Match", "\"copy-etag\"")
	copyReq.Header.Set("x-amz-copy-source-if-match", "\"source-etag\"")
	copyReq.Header.Set("x-amz-metadata-directive", "REPLACE")
	copyReq.Header.Set("x-amz-tagging-directive", "REPLACE")
	copyReq.Header.Set("x-amz-storage-class", "STANDARD")
	copyReq.Header.Set("x-amz-acl", "private")
	copyReq.Header.Set("x-amz-request-payer", "requester")
	copyReq.Header.Set("x-amz-checksum-algorithm", "SHA256")
	copyRR := httptest.NewRecorder()
	gw.ServeHTTP(copyRR, copyReq)
	if copyRR.Code != http.StatusOK {
		t.Fatalf("copy object status mismatch: got=%d body=%s", copyRR.Code, copyRR.Body.String())
	}
	if !strings.Contains(copyRR.Body.String(), "<ChecksumCRC32>AAAAAA==</ChecksumCRC32>") {
		t.Fatalf("copy object checksum missing: body=%s", copyRR.Body.String())
	}

	copyPartReq := httptest.NewRequest(http.MethodPut, "/team2-rich/copied.txt?partNumber=1&uploadId=u1", nil)
	copyPartReq = copyPartReq.WithContext(permCtx)
	copyPartReq.Header.Set("x-amz-copy-source", "/team2-rich/source.txt")
	copyPartReq.Header.Set("x-amz-copy-source-range", "bytes=0-5")
	copyPartRR := httptest.NewRecorder()
	gw.ServeHTTP(copyPartRR, copyPartReq)
	if copyPartRR.Code != http.StatusOK {
		t.Fatalf("upload part copy status mismatch: got=%d body=%s", copyPartRR.Code, copyPartRR.Body.String())
	}
	if !strings.Contains(copyPartRR.Body.String(), "<ChecksumCRC32>BBBBBB==</ChecksumCRC32>") {
		t.Fatalf("upload part copy checksum missing: body=%s", copyPartRR.Body.String())
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/team2-rich/copied.txt?versionId=v1", nil)
	delReq = delReq.WithContext(permCtx)
	delReq.Header.Set("If-Match", "\"copy-etag\"")
	delReq.Header.Set("x-amz-bypass-governance-retention", "true")
	delReq.Header.Set("x-amz-request-payer", "requester")
	delRR := httptest.NewRecorder()
	gw.ServeHTTP(delRR, delReq)
	if delRR.Code != http.StatusNoContent {
		t.Fatalf("delete object status mismatch: got=%d body=%s", delRR.Code, delRR.Body.String())
	}

	delObjsReqBody := `<?xml version="1.0" encoding="UTF-8"?><Delete><Object><Key>copied.txt</Key></Object></Delete>`
	delObjsReq := httptest.NewRequest(http.MethodPost, "/team2-rich?delete", strings.NewReader(delObjsReqBody))
	delObjsReq = delObjsReq.WithContext(permCtx)
	delObjsReq.Header.Set("Content-Type", "application/xml")
	delObjsReq.Header.Set("x-amz-request-payer", "requester")
	delObjsRR := httptest.NewRecorder()
	gw.ServeHTTP(delObjsRR, delObjsReq)
	if delObjsRR.Code != http.StatusOK {
		t.Fatalf("delete objects status mismatch: got=%d body=%s", delObjsRR.Code, delObjsRR.Body.String())
	}
}

func TestGatewayBucketHeadVersioningAndCreateDelete(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/team2-bucket" && strings.Contains(r.URL.RawQuery, "versioning"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/team2-bucket" && strings.Contains(r.URL.RawQuery, "versioning"):
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status><MfaDelete>Enabled</MfaDelete></VersioningConfiguration>`))
		case r.Method == http.MethodPut && r.URL.Path == "/team2-bucket":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodHead && r.URL.Path == "/team2-bucket":
			w.Header().Set("x-amz-bucket-region", "us-east-1")
			w.Header().Set("x-amz-bucket-arn", "arn:aws:s3:::team2-bucket")
			w.Header().Set("x-amz-bucket-location-name", "us-east-1")
			w.Header().Set("x-amz-bucket-location-type", "AvailabilityZone")
			w.Header().Set("x-amz-access-point-alias", "true")
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && r.URL.Path == "/team2-bucket":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
	})
	defer cleanup()

	fullPerm := authz.WithRules(context.Background(), fullTeam2Rule())

	createReq := httptest.NewRequest(http.MethodPut, "/team2-bucket", nil).WithContext(fullPerm)
	createRR := httptest.NewRecorder()
	gw.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusOK {
		t.Fatalf("create bucket status mismatch: got=%d body=%s", createRR.Code, createRR.Body.String())
	}

	headReq := httptest.NewRequest(http.MethodHead, "/team2-bucket", nil).WithContext(fullPerm)
	headRR := httptest.NewRecorder()
	gw.ServeHTTP(headRR, headReq)
	if headRR.Code != http.StatusOK {
		t.Fatalf("head bucket status mismatch: got=%d", headRR.Code)
	}
	if headRR.Header().Get("x-amz-bucket-region") != "us-east-1" {
		t.Fatalf("head bucket region mismatch: got=%q", headRR.Header().Get("x-amz-bucket-region"))
	}

	putVersioningBody := `<?xml version="1.0" encoding="UTF-8"?><VersioningConfiguration><Status>Enabled</Status><MfaDelete>Enabled</MfaDelete></VersioningConfiguration>`
	putVersioningReq := httptest.NewRequest(http.MethodPut, "/team2-bucket?versioning", strings.NewReader(putVersioningBody)).WithContext(fullPerm)
	putVersioningReq.Header.Set("Content-Type", "application/xml")
	putVersioningReq.Header.Set("x-amz-mfa", "device 123456")
	putVersioningRR := httptest.NewRecorder()
	gw.ServeHTTP(putVersioningRR, putVersioningReq)
	if putVersioningRR.Code != http.StatusOK {
		t.Fatalf("put bucket versioning status mismatch: got=%d body=%s", putVersioningRR.Code, putVersioningRR.Body.String())
	}

	getVersioningReq := httptest.NewRequest(http.MethodGet, "/team2-bucket?versioning", nil).WithContext(fullPerm)
	getVersioningRR := httptest.NewRecorder()
	gw.ServeHTTP(getVersioningRR, getVersioningReq)
	if getVersioningRR.Code != http.StatusOK {
		t.Fatalf("get bucket versioning status mismatch: got=%d body=%s", getVersioningRR.Code, getVersioningRR.Body.String())
	}
	if !strings.Contains(getVersioningRR.Body.String(), "<MfaDelete>Enabled</MfaDelete>") {
		t.Fatalf("get bucket versioning body missing mfa delete: %s", getVersioningRR.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/team2-bucket", nil).WithContext(fullPerm)
	deleteRR := httptest.NewRecorder()
	gw.ServeHTTP(deleteRR, deleteReq)
	if deleteRR.Code != http.StatusNoContent {
		t.Fatalf("delete bucket status mismatch: got=%d body=%s", deleteRR.Code, deleteRR.Body.String())
	}
}

func TestGatewayBucketAndObjectTaggingRoutes(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/team2-bucket" && strings.Contains(r.URL.RawQuery, "tagging"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/team2-bucket" && strings.Contains(r.URL.RawQuery, "tagging"):
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet><Tag><Key>bk</Key><Value>bv</Value></Tag></TagSet></Tagging>`))
		case r.Method == http.MethodDelete && r.URL.Path == "/team2-bucket" && strings.Contains(r.URL.RawQuery, "tagging"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && r.URL.Path == "/team2-bucket/object.txt" && strings.Contains(r.URL.RawQuery, "tagging"):
			w.Header().Set("x-amz-version-id", "v-put")
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/team2-bucket/object.txt" && strings.Contains(r.URL.RawQuery, "tagging"):
			w.Header().Set("x-amz-version-id", "v-get")
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet><Tag><Key>ok</Key><Value>ov</Value></Tag></TagSet></Tagging>`))
		case r.Method == http.MethodDelete && r.URL.Path == "/team2-bucket/object.txt" && strings.Contains(r.URL.RawQuery, "tagging"):
			w.Header().Set("x-amz-version-id", "v-del")
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
	})
	defer cleanup()

	fullPerm := authz.WithRules(context.Background(), fullTeam2Rule())
	bucketTaggingPayload := `<?xml version="1.0" encoding="UTF-8"?><Tagging><TagSet><Tag><Key>bk</Key><Value>bv</Value></Tag></TagSet></Tagging>`
	objectTaggingPayload := `<?xml version="1.0" encoding="UTF-8"?><Tagging><TagSet><Tag><Key>ok</Key><Value>ov</Value></Tag></TagSet></Tagging>`

	putBucketReq := httptest.NewRequest(http.MethodPut, "/team2-bucket?tagging", strings.NewReader(bucketTaggingPayload)).WithContext(fullPerm)
	putBucketRR := httptest.NewRecorder()
	gw.ServeHTTP(putBucketRR, putBucketReq)
	if putBucketRR.Code != http.StatusOK {
		t.Fatalf("put bucket tagging status mismatch: got=%d body=%s", putBucketRR.Code, putBucketRR.Body.String())
	}

	getBucketReq := httptest.NewRequest(http.MethodGet, "/team2-bucket?tagging", nil).WithContext(fullPerm)
	getBucketRR := httptest.NewRecorder()
	gw.ServeHTTP(getBucketRR, getBucketReq)
	if getBucketRR.Code != http.StatusOK {
		t.Fatalf("get bucket tagging status mismatch: got=%d body=%s", getBucketRR.Code, getBucketRR.Body.String())
	}
	if !strings.Contains(getBucketRR.Body.String(), "<Key>bk</Key>") {
		t.Fatalf("missing bucket tagging key in response body: %s", getBucketRR.Body.String())
	}

	deleteBucketReq := httptest.NewRequest(http.MethodDelete, "/team2-bucket?tagging", nil).WithContext(fullPerm)
	deleteBucketRR := httptest.NewRecorder()
	gw.ServeHTTP(deleteBucketRR, deleteBucketReq)
	if deleteBucketRR.Code != http.StatusNoContent {
		t.Fatalf("delete bucket tagging status mismatch: got=%d body=%s", deleteBucketRR.Code, deleteBucketRR.Body.String())
	}

	putObjectReq := httptest.NewRequest(http.MethodPut, "/team2-bucket/object.txt?tagging&versionId=v1", strings.NewReader(objectTaggingPayload)).WithContext(fullPerm)
	putObjectReq.Header.Set("x-amz-request-payer", "requester")
	putObjectRR := httptest.NewRecorder()
	gw.ServeHTTP(putObjectRR, putObjectReq)
	if putObjectRR.Code != http.StatusOK {
		t.Fatalf("put object tagging status mismatch: got=%d body=%s", putObjectRR.Code, putObjectRR.Body.String())
	}
	if putObjectRR.Header().Get("x-amz-version-id") != "v-put" {
		t.Fatalf("put object tagging version mismatch: got=%q", putObjectRR.Header().Get("x-amz-version-id"))
	}

	getObjectReq := httptest.NewRequest(http.MethodGet, "/team2-bucket/object.txt?tagging&versionId=v1", nil).WithContext(fullPerm)
	getObjectReq.Header.Set("x-amz-request-payer", "requester")
	getObjectRR := httptest.NewRecorder()
	gw.ServeHTTP(getObjectRR, getObjectReq)
	if getObjectRR.Code != http.StatusOK {
		t.Fatalf("get object tagging status mismatch: got=%d body=%s", getObjectRR.Code, getObjectRR.Body.String())
	}
	if getObjectRR.Header().Get("x-amz-version-id") != "v-get" {
		t.Fatalf("get object tagging version mismatch: got=%q", getObjectRR.Header().Get("x-amz-version-id"))
	}
	if !strings.Contains(getObjectRR.Body.String(), "<Key>ok</Key>") {
		t.Fatalf("missing object tagging key in response body: %s", getObjectRR.Body.String())
	}

	deleteObjectReq := httptest.NewRequest(http.MethodDelete, "/team2-bucket/object.txt?tagging&versionId=v1", nil).WithContext(fullPerm)
	deleteObjectRR := httptest.NewRecorder()
	gw.ServeHTTP(deleteObjectRR, deleteObjectReq)
	if deleteObjectRR.Code != http.StatusNoContent {
		t.Fatalf("delete object tagging status mismatch: got=%d body=%s", deleteObjectRR.Code, deleteObjectRR.Body.String())
	}
	if deleteObjectRR.Header().Get("x-amz-version-id") != "v-del" {
		t.Fatalf("delete object tagging version mismatch: got=%q", deleteObjectRR.Header().Get("x-amz-version-id"))
	}
}

func TestCoverageHelpersLifecycleAndShutdown(t *testing.T) {
	if got := encodeLifecycleTag(nil); got != nil {
		t.Fatalf("encodeLifecycleTag(nil) = %+v, want nil", got)
	}
	tagOut := encodeLifecycleTag(&types.Tag{Key: aws.String("k"), Value: aws.String("v")})
	if tagOut == nil || tagOut.Key != "k" || tagOut.Value != "v" {
		t.Fatalf("encodeLifecycleTag mismatch: %+v", tagOut)
	}

	if got := lifecycleRuleLegacyPrefix(types.LifecycleRule{}); got != nil {
		t.Fatalf("lifecycleRuleLegacyPrefix(zero) = %v, want nil", got)
	}

	if got := EffectiveShutdownTimeout(config.Config{}); got <= 0 {
		t.Fatalf("EffectiveShutdownTimeout() should apply defaults, got=%s", got)
	}
}
