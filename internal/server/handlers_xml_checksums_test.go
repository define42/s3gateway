package server

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/define42/s3gateway/internal/s3xml"
)

var xmlConfigurationChecksumRoutes = []struct{ name, target, body string }{
	{name: "object tagging", target: "/team2-bucket/key?tagging", body: "<!-- original formatting -->\n<Tagging><TagSet><Tag><Key>team</Key><Value>blue</Value></Tag></TagSet></Tagging>\n  "},
	{name: "bucket tagging", target: "/team2-bucket?tagging", body: "<!-- original formatting -->\n<Tagging><TagSet><Tag><Key>team</Key><Value>blue</Value></Tag></TagSet></Tagging>\n  "},
	{name: "versioning", target: "/team2-bucket?versioning", body: "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>\n  "},
	{name: "lifecycle", target: "/team2-bucket?lifecycle", body: "<LifecycleConfiguration><Rule><ID>expire</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>\n  "},
}

func TestXMLConfigurationAlternateChecksums(t *testing.T) {
	for _, route := range xmlConfigurationChecksumRoutes {
		t.Run(route.name, func(t *testing.T) {
			var calls atomic.Int32
			gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read upstream XML: %v", err)
				}
				if string(body) == route.body {
					t.Error("test did not exercise XML reserialization")
				}
				if r.Header.Get("x-amz-checksum-crc32") != deleteObjectsTestChecksum("CRC32", string(body)) {
					t.Error("upstream checksum does not cover the rebuilt XML")
				}
				if md5 := r.Header.Get("Content-MD5"); md5 != "" && md5 != xmlBodyMD5(string(body)) {
					t.Error("upstream MD5 does not cover the rebuilt XML")
				}
				w.WriteHeader(http.StatusOK)
			})
			t.Cleanup(cleanup)
			for _, algorithm := range []string{"CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256"} {
				t.Run(algorithm, func(t *testing.T) {
					for _, tc := range []struct{ name, checksummedBody, code string }{
						{name: "valid", checksummedBody: route.body},
						{name: "different XML", checksummedBody: "different configuration", code: "BadDigest"},
						{name: "missing trailing whitespace", checksummedBody: strings.TrimSpace(route.body), code: "BadDigest"},
					} {
						t.Run(tc.name, func(t *testing.T) {
							req := httptest.NewRequest(http.MethodPut, route.target, strings.NewReader(route.body))
							req.Header.Set("x-amz-checksum-"+strings.ToLower(algorithm), deleteObjectsTestChecksum(algorithm, tc.checksummedBody))
							rr := httptest.NewRecorder()
							before := calls.Load()
							gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
							assertXMLChecksumResult(t, rr, calls.Load()-before, tc.code)
						})
					}
				})
			}
		})
	}
}

func TestXMLConfigurationChecksumClaims(t *testing.T) {
	for _, route := range xmlConfigurationChecksumRoutes {
		t.Run(route.name, func(t *testing.T) {
			var calls atomic.Int32
			gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(http.StatusOK)
			})
			t.Cleanup(cleanup)
			crc32 := deleteObjectsTestChecksum("CRC32", route.body)
			sha256 := deleteObjectsTestChecksum("SHA256", route.body)
			for _, tc := range []struct {
				name   string
				header http.Header
				code   string
			}{
				{name: "no claims"},
				{name: "SDK selector", header: http.Header{"x-amz-sdk-checksum-algorithm": {"CRC32"}, "x-amz-checksum-crc32": {crc32}}},
				{name: "legacy selector", header: http.Header{"x-amz-checksum-algorithm": {"CRC32"}, "x-amz-checksum-crc32": {crc32}}},
				{name: "individual overrides selector", header: http.Header{"x-amz-sdk-checksum-algorithm": {"SHA256"}, "x-amz-checksum-crc32": {crc32}}},
				{name: "individual overrides unknown selector", header: http.Header{"x-amz-sdk-checksum-algorithm": {"SHA512"}, "x-amz-checksum-crc32": {crc32}}},
				{name: "both selectors overridden", header: http.Header{"x-amz-sdk-checksum-algorithm": {"CRC32"}, "x-amz-checksum-algorithm": {"SHA1"}, "x-amz-checksum-sha256": {sha256}}},
				{name: "MD5 and alternate digest", header: http.Header{"Content-Md5": {xmlBodyMD5(route.body)}, "x-amz-checksum-crc32": {crc32}}},
				{name: "bad MD5 with valid alternate digest", header: http.Header{"Content-Md5": {xmlBodyMD5("wrong")}, "x-amz-checksum-crc32": {crc32}}, code: "BadDigest"},
				{name: "valid MD5 with bad alternate digest", header: http.Header{"Content-Md5": {xmlBodyMD5(route.body)}, "x-amz-checksum-crc32": {deleteObjectsTestChecksum("CRC32", "wrong")}}, code: "BadDigest"},
				{name: "nil digest", header: http.Header{"x-amz-checksum-crc32": nil}, code: "InvalidDigest"},
				{name: "empty digest", header: http.Header{"x-amz-checksum-crc32": {""}}, code: "InvalidDigest"},
				{name: "malformed base64", header: http.Header{"x-amz-checksum-sha256": {strings.Repeat("!", 44)}}, code: "InvalidDigest"},
				{name: "invalid padding bits", header: http.Header{"x-amz-checksum-crc32": {"AAAAAB=="}}, code: "InvalidDigest"},
				{name: "wrong digest length", header: http.Header{"x-amz-checksum-crc32": {base64.StdEncoding.EncodeToString([]byte("short"))}}, code: "InvalidDigest"},
				{name: "duplicate digest", header: http.Header{"x-amz-checksum-crc32": {crc32, crc32}}, code: "InvalidDigest"},
				{name: "duplicate noncanonical names", header: http.Header{"x-amz-checksum-crc32": {crc32}, "X-Amz-Checksum-Crc32": {crc32}}, code: "InvalidDigest"},
				{name: "multiple value algorithms", header: http.Header{"x-amz-checksum-crc32": {crc32}, "x-amz-checksum-sha256": {sha256}}, code: "InvalidRequest"},
				{name: "SDK selector without digest", header: http.Header{"x-amz-sdk-checksum-algorithm": {"CRC32"}}, code: "InvalidRequest"},
				{name: "legacy selector without digest", header: http.Header{"x-amz-checksum-algorithm": {"CRC32"}}, code: "InvalidRequest"},
				{name: "MD5 does not satisfy alternate selector", header: http.Header{"Content-Md5": {xmlBodyMD5(route.body)}, "x-amz-sdk-checksum-algorithm": {"CRC32"}}, code: "InvalidRequest"},
				{name: "empty selector", header: http.Header{"x-amz-sdk-checksum-algorithm": {""}, "x-amz-checksum-crc32": {crc32}}, code: "InvalidRequest"},
				{name: "nil selector", header: http.Header{"x-amz-sdk-checksum-algorithm": nil}, code: "InvalidRequest"},
				{name: "duplicate selector", header: http.Header{"x-amz-sdk-checksum-algorithm": {"CRC32", "CRC32"}}, code: "InvalidRequest"},
				{name: "duplicate selector names", header: http.Header{"x-amz-sdk-checksum-algorithm": {"CRC32"}, "X-Amz-Sdk-Checksum-Algorithm": {"CRC32"}}, code: "InvalidRequest"},
				{name: "unsupported selector", header: http.Header{"x-amz-sdk-checksum-algorithm": {"SHA512"}}, code: "InvalidRequest"},
				{name: "unsupported SHA512 digest", header: http.Header{"x-amz-checksum-sha512": {sha256}}, code: "InvalidRequest"},
				{name: "unsupported MD5 alternate digest", header: http.Header{"x-amz-checksum-md5": {xmlBodyMD5(route.body)}}, code: "InvalidRequest"},
				{name: "unsupported XXHash digest", header: http.Header{"x-amz-checksum-xxhash64": {crc32}}, code: "InvalidRequest"},
				{name: "checksum type", header: http.Header{"x-amz-checksum-type": {"FULL_OBJECT"}}, code: "InvalidRequest"},
				{name: "AWS trailer declaration", header: http.Header{"x-amz-trailer": {"x-amz-checksum-crc32"}}, code: "InvalidRequest"},
				{name: "HTTP trailer declaration", header: http.Header{"Trailer": {"x-amz-checksum-crc32"}}, code: "InvalidRequest"},
				{name: "empty mixed-case declaration", header: http.Header{"X-aMz-TrAiLeR": nil}, code: "InvalidRequest"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					req := httptest.NewRequest(http.MethodPut, route.target, strings.NewReader(route.body))
					req.Header = tc.header.Clone()
					rr := httptest.NewRecorder()
					before := calls.Load()
					gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
					assertXMLChecksumResult(t, rr, calls.Load()-before, tc.code)
				})
			}
		})
	}
}

func assertXMLChecksumResult(t *testing.T, rr *httptest.ResponseRecorder, calls int32, code string) {
	t.Helper()
	if code == "" {
		if rr.Code != http.StatusOK || calls != 1 {
			t.Fatalf("status=%d calls=%d body=%s, want 200 and one upstream write", rr.Code, calls, rr.Body.String())
		}
		return
	}
	if rr.Code != http.StatusBadRequest || calls != 0 || !strings.Contains(rr.Body.String(), "<Code>"+code+"</Code>") {
		t.Fatalf("status=%d calls=%d body=%s, want 400 %s and no upstream writes", rr.Code, calls, rr.Body.String(), code)
	}
}

func TestXMLConfigurationHTTPChecksumTrailers(t *testing.T) {
	for _, route := range xmlConfigurationChecksumRoutes {
		t.Run(route.name, func(t *testing.T) {
			var calls atomic.Int32
			gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(http.StatusOK)
			})
			t.Cleanup(cleanup)
			gw.gcache.Set("testuser", "dogood", map[string]struct{}{"team2-rwcdb": {}})
			access, secret := mustGatewayCredentials(t, gw, "testuser", "dogood")
			handler := NewHTTPServer(gw.cfg, gw.WithS3Audit(gw.WithAuth(gw, nil))).Handler
			front := httptest.NewTLSServer(handler)
			t.Cleanup(front.Close)
			for _, tc := range []struct {
				name, payloadHash string
				declare, trailer  bool
			}{
				{name: "undeclared trailer", payloadHash: "UNSIGNED-PAYLOAD", trailer: true},
				{name: "declared trailer", payloadHash: "UNSIGNED-PAYLOAD", declare: true, trailer: true},
				{name: "ordinary HTTP chunks", payloadHash: "UNSIGNED-PAYLOAD"},
				{name: "body hash still validated", payloadHash: strings.Repeat("0", 64)},
			} {
				t.Run(tc.name, func(t *testing.T) {
					req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, front.URL+route.target, nil)
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("x-amz-content-sha256", tc.payloadHash)
					req.Header.Set("x-amz-checksum-crc32", deleteObjectsTestChecksum("CRC32", route.body))
					if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: access, SecretAccessKey: secret}, req, tc.payloadHash, "s3", "us-east-1", time.Now()); err != nil {
						t.Fatal(err)
					}
					if tc.declare {
						req.Header.Set("Trailer", "x-amz-checksum-sha256")
					}
					footer := ""
					if tc.trailer {
						footer = "X-Amz-Checksum-Sha256: " + deleteObjectsTestChecksum("SHA256", route.body) + "\r\n"
					}
					before := calls.Load()
					status, body := rawChunkedXMLRequest(t, front, req, route.body, footer)
					if tc.trailer || tc.payloadHash != "UNSIGNED-PAYLOAD" {
						if status != http.StatusBadRequest || calls.Load() != before {
							t.Fatalf("status=%d calls=%d body=%s, want rejection before upstream", status, calls.Load()-before, body)
						}
					} else if status != http.StatusOK || calls.Load()-before != 1 {
						t.Fatalf("ordinary chunked XML: status=%d body=%s", status, body)
					}
				})
			}
		})
	}
}

func TestSDKBucketTaggingRejectsChangedBodyChecksum(t *testing.T) {
	var calls atomic.Int32
	gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream XML: %v", err)
		}
		if !bytes.Contains(body, []byte("<Value>blue</Value>")) {
			t.Errorf("changed tagging reached upstream: %s", body)
		}
		if r.Header.Get("x-amz-checksum-crc32") != deleteObjectsTestChecksum("CRC32", string(body)) {
			s3xml.WriteError(w, http.StatusBadRequest, "BadDigest", "Invalid upstream checksum")
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	t.Cleanup(cleanup)
	gw.gcache.Set("testuser", "dogood", map[string]struct{}{"team2-c": {}})
	access, secret := mustGatewayCredentials(t, gw, "testuser", "dogood")
	var corrupt atomic.Bool
	handler := NewHTTPServer(gw.cfg, gw.WithS3Audit(gw.WithAuth(gw, nil))).Handler
	front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if corrupt.Load() {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read client XML: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = r.Body.Close()
			changed := bytes.Replace(body, []byte("<Value>blue</Value>"), []byte("<Value>evil</Value>"), 1)
			if bytes.Equal(body, changed) || r.Header.Get("x-amz-checksum-crc32") == "" || r.Header.Get("x-amz-content-sha256") != "UNSIGNED-PAYLOAD" {
				t.Error("test did not change an SDK request protected by its alternate checksum")
			}
			r.Body = io.NopCloser(bytes.NewReader(changed))
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	client := s3.New(s3.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(front.URL), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider(access, secret, ""),
		HTTPClient:  front.Client(), RetryMaxAttempts: 1,
	})
	for _, changed := range []bool{false, true} {
		corrupt.Store(changed)
		before := calls.Load()
		_, err := client.PutBucketTagging(t.Context(), &s3.PutBucketTaggingInput{
			Bucket: aws.String("team2-bucket"), ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
			Tagging: &types.Tagging{TagSet: []types.Tag{{Key: aws.String("team"), Value: aws.String("blue")}}},
		}, s3.WithAPIOptions(v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware))
		if changed {
			var apiErr smithy.APIError
			if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "BadDigest" || calls.Load() != before {
				t.Fatalf("changed SDK request: err=%v upstream calls=%d, want BadDigest and no write", err, calls.Load()-before)
			}
		} else if err != nil || calls.Load()-before != 1 {
			t.Fatalf("unchanged SDK request: err=%v upstream calls=%d", err, calls.Load()-before)
		}
	}
}
