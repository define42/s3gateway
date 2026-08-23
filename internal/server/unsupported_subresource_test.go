package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awscredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	authz "github.com/define42/s3gateway/internal/authz"
	"github.com/define42/s3gateway/internal/s3credentials"
	sigv4 "github.com/define42/s3gateway/internal/sigv4"
)

func writeOnlyTeam2Rule() []authz.Rule {
	return []authz.Rule{{BucketPrefix: "team2", Perm: authz.PermWrite}}
}

// TestAWSSDKClientDefaultTrailerUpload uploads through the full gateway stack
// (SigV4 auth included) with a real AWS SDK client over TLS and a non-seekable
// body — the combination that makes current SDKs send their default
// STREAMING-UNSIGNED-PAYLOAD-TRAILER aws-chunked encoding, which the gateway
// previously rejected with 400.
func TestAWSSDKClientDefaultTrailerUpload(t *testing.T) {
	payload := bytes.Repeat([]byte("aws sdk trailer default "), 8192) // ~192 KiB, spans SDK chunk sizes

	var upstreamBody []byte
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/team2-sdk/trailer.bin" {
			t.Errorf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		upstreamBody = b
		w.Header().Set("ETag", `"etag-sdk-trailer"`)
		w.WriteHeader(http.StatusOK)
	})
	defer cleanup()

	gw.gcache.Set("testuser", "dogood", map[string]struct{}{"team2-rw": {}})

	var gotContentSHA256 string
	recording := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			gotContentSHA256 = r.Header.Get("x-amz-content-sha256")
		}
		gw.WithAuth(gw, adminWebpageHandler(gw)).ServeHTTP(w, r)
	})
	gwSrv := httptest.NewTLSServer(recording)
	defer gwSrv.Close()

	accessKey, secretKey, err := s3credentials.GenerateKeysBase64Encoded("testuser", "dogood")
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithBaseEndpoint(gwSrv.URL),
		awsconfig.WithCredentialsProvider(awscredentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		awsconfig.WithHTTPClient(gwSrv.Client()),
	)
	if err != nil {
		t.Fatalf("load aws config: %v", err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) { o.UsePathStyle = true })

	// bytes.Buffer is deliberately non-seekable: over TLS that makes the SDK
	// use its aws-chunked unsigned-trailer encoding with a CRC32 trailer.
	if _, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket:        aws.String("team2-sdk"),
		Key:           aws.String("trailer.bin"),
		Body:          bytes.NewBuffer(payload),
		ContentLength: aws.Int64(int64(len(payload))),
	}); err != nil {
		t.Fatalf("put object via aws sdk over TLS: %v", err)
	}

	if gotContentSHA256 != sigv4.StreamingUnsignedPayloadTrailer {
		t.Fatalf("expected SDK to send %s, got %q (SDK behavior changed; test no longer exercises the trailer path)",
			sigv4.StreamingUnsignedPayloadTrailer, gotContentSHA256)
	}
	if !bytes.Equal(upstreamBody, payload) {
		t.Fatalf("upstream body mismatch: got len=%d want len=%d", len(upstreamBody), len(payload))
	}
}

// TestUnsupportedSubresourcesAreRejected ensures requests for unimplemented
// S3 sub-resource operations return NotImplemented instead of falling through
// to the plain bucket/object handlers (e.g. PutObjectAcl must never execute as
// a PutObject that overwrites the object, and DeleteBucketPolicy must never
// execute as DeleteBucket).
func TestUnsupportedSubresourcesAreRejected(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be called for unsupported sub-resources: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
	})
	defer cleanup()

	cases := []struct {
		method string
		target string
	}{
		// Real operations that previously fell through to destructive handlers.
		{http.MethodPut, "/team2-bucket/key.txt?acl"},                   // PutObjectAcl -> was PutObject overwrite
		{http.MethodPut, "/team2-bucket/key.txt?retention"},             // PutObjectRetention -> was PutObject overwrite
		{http.MethodPut, "/team2-bucket/key.txt?legal-hold"},            // PutObjectLegalHold -> was PutObject overwrite
		{http.MethodGet, "/team2-bucket/key.txt?acl"},                   // GetObjectAcl -> was GetObject body
		{http.MethodGet, "/team2-bucket/key.txt?torrent"},               // GetObjectTorrent -> was GetObject body
		{http.MethodPost, "/team2-bucket/key.txt?restore"},              // RestoreObject
		{http.MethodPost, "/team2-bucket/key.txt?select&select-type=2"}, // SelectObjectContent
		{http.MethodDelete, "/team2-bucket?policy"},                     // DeleteBucketPolicy -> was DeleteBucket
		{http.MethodDelete, "/team2-bucket?cors"},                       // DeleteBucketCors -> was DeleteBucket
		{http.MethodDelete, "/team2-bucket?encryption"},                 // DeleteBucketEncryption -> was DeleteBucket
		{http.MethodDelete, "/team2-bucket?replication"},                // DeleteBucketReplication -> was DeleteBucket
		{http.MethodDelete, "/team2-bucket?website"},                    // DeleteBucketWebsite -> was DeleteBucket
		{http.MethodPut, "/team2-bucket?acl"},                           // PutBucketAcl -> was CreateBucket
		{http.MethodPut, "/team2-bucket?policy"},                        // PutBucketPolicy -> was CreateBucket
		{http.MethodPut, "/team2-bucket?object-lock"},                   // PutObjectLockConfiguration
		{http.MethodGet, "/team2-bucket?acl"},
		{http.MethodGet, "/team2-bucket?policy"},
		{http.MethodGet, "/team2-bucket?policyStatus"},
		{http.MethodGet, "/team2-bucket?publicAccessBlock"},
		{http.MethodGet, "/team2-bucket?ownershipControls"},
		{http.MethodGet, "/team2-bucket?logging"},
		{http.MethodGet, "/team2-bucket?notification"},
		{http.MethodGet, "/team2-bucket?requestPayment"},
		{http.MethodGet, "/team2-bucket?accelerate"},
		{http.MethodGet, "/team2-bucket?intelligent-tiering"},
		{http.MethodGet, "/team2-bucket?inventory"},
		{http.MethodGet, "/team2-bucket?metrics"},
		{http.MethodGet, "/team2-bucket?analytics"},
		{http.MethodGet, "/?session"}, // S3 Express CreateSession
	}

	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.target, strings.NewReader("<Payload/>"))
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotImplemented {
			t.Fatalf("%s %s: status=%d want=%d body=%s", tc.method, tc.target, rr.Code, http.StatusNotImplemented, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "NotImplemented") {
			t.Fatalf("%s %s: body missing NotImplemented code: %s", tc.method, tc.target, rr.Body.String())
		}
	}
}

func TestListObjectsV1RoutingAndResponse(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/team2-bucket" {
			t.Errorf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("marker") != "start-key" || q.Get("prefix") != "logs/" || q.Get("delimiter") != "/" || q.Get("max-keys") != "50" {
			t.Errorf("upstream query mismatch: %s", r.URL.RawQuery)
		}
		if _, ok := q["list-type"]; ok {
			t.Errorf("v1 listing must not send list-type upstream: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>team2-bucket</Name>
  <Prefix>logs/</Prefix>
  <Marker>start-key</Marker>
  <NextMarker>logs/next</NextMarker>
  <MaxKeys>50</MaxKeys>
  <Delimiter>/</Delimiter>
  <IsTruncated>true</IsTruncated>
  <Contents>
    <Key>logs/a.txt</Key>
    <LastModified>2026-02-07T01:02:03.000Z</LastModified>
    <ETag>&quot;etag-a&quot;</ETag>
    <Size>42</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <CommonPrefixes><Prefix>logs/sub/</Prefix></CommonPrefixes>
</ListBucketResult>`))
	})
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/team2-bucket?marker=start-key&prefix=logs%2F&delimiter=%2F&max-keys=50", nil)
	req = reqWithRules(req, fullTeam2Rule())
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		"<ListBucketResult", "<Name>team2-bucket</Name>", "<Marker>start-key</Marker>",
		"<NextMarker>logs/next</NextMarker>", "<Key>logs/a.txt</Key>",
		"<IsTruncated>true</IsTruncated>", "<Prefix>logs/sub/</Prefix>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %q: %s", want, body)
		}
	}

	t.Run("forbidden without read permission", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/team2-bucket", nil)
		req = reqWithRules(req, nil)
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
		}
	})

	t.Run("invalid max-keys", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/team2-bucket?max-keys=abc", nil)
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusBadRequest, rr.Body.String())
		}
	})
}

func TestGetBucketLocationRoutingAndResponse(t *testing.T) {
	t.Run("region returned", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/team2-bucket" {
				t.Errorf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
			}
			if _, ok := r.URL.Query()["location"]; !ok {
				t.Errorf("expected location sub-resource in upstream query: %s", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">eu-central-1</LocationConstraint>`))
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/team2-bucket?location", nil)
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), ">eu-central-1</LocationConstraint>") {
			t.Fatalf("response missing region: %s", rr.Body.String())
		}
	})

	t.Run("us-east-1 renders empty element", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`))
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/team2-bucket?location", nil)
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`) {
			t.Fatalf("expected empty LocationConstraint element: %s", rr.Body.String())
		}
	})

	t.Run("write-only permission is sufficient", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-west-2</LocationConstraint>`))
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/team2-bucket?location", nil)
		req = reqWithRules(req, writeOnlyTeam2Rule())
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("no permission is forbidden", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("upstream must not be called without permission")
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/team2-bucket?location", nil)
		req = reqWithRules(req, nil)
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
		}
	})
}

// TestPutObjectUnsignedTrailerStreaming drives an STREAMING-UNSIGNED-PAYLOAD-TRAILER
// upload through the full router and verifies the upstream receives the decoded
// payload, plus the BadDigest mapping for a corrupted trailing checksum.
func TestPutObjectUnsignedTrailerStreaming(t *testing.T) {
	payload := strings.Repeat("unsigned trailer streaming ", 1000)
	sum := crc32.ChecksumIEEE([]byte(payload))
	checksum := base64.StdEncoding.EncodeToString([]byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)})

	encode := func(trailerValue string) string {
		return fmt.Sprintf("%x\r\n%s\r\n0\r\nx-amz-checksum-crc32:%s\r\n\r\n", len(payload), payload, trailerValue)
	}

	newStreamReq := func(body string) *http.Request {
		req := httptest.NewRequest(http.MethodPut, "/team2-bucket/streamed.bin", strings.NewReader(body))
		req.Header.Set("x-amz-content-sha256", sigv4.StreamingUnsignedPayloadTrailer)
		req.Header.Set("x-amz-decoded-content-length", fmt.Sprintf("%d", len(payload)))
		req.Header.Set("x-amz-trailer", "x-amz-checksum-crc32")
		req.Header.Set("Content-Encoding", "aws-chunked")
		return reqWithRules(req, fullTeam2Rule())
	}

	t.Run("valid upload decodes payload", func(t *testing.T) {
		var upstreamBody []byte
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut || r.URL.Path != "/team2-bucket/streamed.bin" {
				t.Errorf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
			}
			b, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read upstream body: %v", err)
			}
			upstreamBody = b
			w.Header().Set("ETag", `"etag-streamed"`)
			w.WriteHeader(http.StatusOK)
		})
		defer cleanup()

		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, newStreamReq(encode(checksum)))
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		if string(upstreamBody) != payload {
			t.Fatalf("upstream body mismatch: got len=%d want len=%d", len(upstreamBody), len(payload))
		}
	})

	t.Run("corrupted trailing checksum is BadDigest", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			// The body read fails mid-stream; the SDK surfaces the reader error.
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		})
		defer cleanup()

		bad := base64.StdEncoding.EncodeToString([]byte{9, 9, 9, 9})
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, newStreamReq(encode(bad)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusBadRequest, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "BadDigest") {
			t.Fatalf("expected BadDigest error code, got: %s", rr.Body.String())
		}
	})
}

// TestPutObjectSignedTrailerStreaming drives the signed-trailer mode through
// the router with sigv4 context injected.
func TestPutObjectSignedTrailerStreaming(t *testing.T) {
	auth := &sigv4.Auth{
		AccessKey:     "test-access-key",
		Date:          "20260207",
		Region:        "us-east-1",
		Service:       "s3",
		SignedHeaders: []string{"host", "x-amz-date"},
		SignatureHex:  strings.Repeat("0", 64),
		AmzDate:       "20260207T010203Z",
	}
	const secret = "secret"
	payload := "signed trailer through handler"

	signingKey := sigv4.DeriveSigningKey(secret, auth.Date, auth.Region, auth.Service)
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", auth.Date, auth.Region, auth.Service)
	emptyHash := sha256.Sum256(nil)
	signChunk := func(prevSig string, chunk []byte) string {
		chunkHash := sha256.Sum256(chunk)
		return sigv4.HmacSHA256Hex(signingKey, []byte(strings.Join([]string{
			"AWS4-HMAC-SHA256-PAYLOAD", auth.AmzDate, scope, prevSig,
			fmt.Sprintf("%x", emptyHash[:]), fmt.Sprintf("%x", chunkHash[:]),
		}, "\n")))
	}

	sum := crc32.ChecksumIEEE([]byte(payload))
	checksum := base64.StdEncoding.EncodeToString([]byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)})
	chunkSig := signChunk(strings.ToLower(auth.SignatureHex), []byte(payload))
	finalSig := signChunk(chunkSig, nil)
	trailerBlock := "x-amz-checksum-crc32:" + checksum + "\n"
	blockHash := sha256.Sum256([]byte(trailerBlock))
	trailerSig := sigv4.HmacSHA256Hex(signingKey, []byte(strings.Join([]string{
		"AWS4-HMAC-SHA256-TRAILER", auth.AmzDate, scope, finalSig,
		fmt.Sprintf("%x", blockHash[:]),
	}, "\n")))

	body := fmt.Sprintf("%x;chunk-signature=%s\r\n%s\r\n", len(payload), chunkSig, payload) +
		"0;chunk-signature=" + finalSig + "\r\n" +
		trailerBlock + "\r\n" +
		"x-amz-trailer-signature:" + trailerSig + "\r\n\r\n"

	var upstreamBody []byte
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		upstreamBody = b
		w.Header().Set("ETag", `"etag-signed-trailer"`)
		w.WriteHeader(http.StatusOK)
	})
	defer cleanup()

	req := httptest.NewRequest(http.MethodPut, "/team2-bucket/signed-trailer.bin", strings.NewReader(body))
	req.Header.Set("x-amz-content-sha256", sigv4.StreamingSignedPayloadTrailer)
	req.Header.Set("x-amz-decoded-content-length", fmt.Sprintf("%d", len(payload)))
	req.Header.Set("x-amz-trailer", "x-amz-checksum-crc32")
	req = reqWithRulesAndSigV4(req, fullTeam2Rule(), auth)

	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if string(upstreamBody) != payload {
		t.Fatalf("upstream body mismatch: got=%q want=%q", string(upstreamBody), payload)
	}
}
