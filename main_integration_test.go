package main_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	s3gateway "github.com/define42/s3gateway"
)

func TestBootS3GatewayFullIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ldapCfgPath := s3gateway.WriteGatewayGlauthConfig(t)
	ldapURL, stopLDAP := s3gateway.StartGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	defer stopLDAP()

	minioURL, stopMinio := s3gateway.StartMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	t.Setenv("LISTEN_ADDR", "127.0.0.1:0")
	t.Setenv("LDAP_URL", ldapURL)
	t.Setenv("LDAP_BASE_DN", "dc=glauth,dc=com")
	t.Setenv("LDAP_GROUP_TTL", "45s")
	t.Setenv("LDAP_GROUP_CACHE_MAX_ENTRIES", "256")
	t.Setenv("S3_ENDPOINT", minioURL)
	t.Setenv("S3_REGION", "us-east-1")
	t.Setenv("S3_ACCESS_KEY", "minioadmin")
	t.Setenv("S3_SECRET_KEY", "minioadmin")
	t.Setenv("S3_FORCE_PATH_STYLE", "true")
	t.Setenv("SIGV4_SECRET", "password")
	t.Setenv("SIGV4_SERVICE", "s3")
	t.Setenv("SIGV4_MAX_SKEW", "20m")
	t.Setenv("HTTP_READ_HEADER_TIMEOUT", "3s")
	t.Setenv("HTTP_IDLE_TIMEOUT", "11s")
	t.Setenv("HTTP_SHUTDOWN_TIMEOUT", "13s")
	t.Setenv("HTTP_MAX_HEADER_BYTES", "65536")

	httpSrv, cfg, err := s3gateway.BootS3Gateway()
	if err != nil {
		t.Fatalf("bootS3Gateway returned error: %v", err)
	}

	if cfg.LDAPURL != ldapURL {
		t.Fatalf("cfg.LDAPURL mismatch: got=%q want=%q", cfg.LDAPURL, ldapURL)
	}
	if cfg.UpstreamEndpoint != minioURL {
		t.Fatalf("cfg.UpstreamEndpoint mismatch: got=%q want=%q", cfg.UpstreamEndpoint, minioURL)
	}
	if cfg.GroupCacheMaxEntries != 256 {
		t.Fatalf("cfg.GroupCacheMaxEntries mismatch: got=%d want=256", cfg.GroupCacheMaxEntries)
	}
	if cfg.SigV4MaxSkew != 20*time.Minute {
		t.Fatalf("cfg.SigV4MaxSkew mismatch: got=%s want=20m", cfg.SigV4MaxSkew)
	}
	if cfg.ReadHeaderTimeout != 3*time.Second {
		t.Fatalf("cfg.ReadHeaderTimeout mismatch: got=%s want=3s", cfg.ReadHeaderTimeout)
	}
	if cfg.IdleTimeout != 11*time.Second {
		t.Fatalf("cfg.IdleTimeout mismatch: got=%s want=11s", cfg.IdleTimeout)
	}
	if cfg.ShutdownTimeout != 13*time.Second {
		t.Fatalf("cfg.ShutdownTimeout mismatch: got=%s want=13s", cfg.ShutdownTimeout)
	}
	if cfg.MaxHeaderBytes != 65536 {
		t.Fatalf("cfg.MaxHeaderBytes mismatch: got=%d want=65536", cfg.MaxHeaderBytes)
	}
	if httpSrv.Handler == nil {
		t.Fatalf("booted server handler should not be nil")
	}
	if httpSrv.ReadHeaderTimeout != cfg.ReadHeaderTimeout {
		t.Fatalf("http server read header timeout mismatch: got=%s want=%s", httpSrv.ReadHeaderTimeout, cfg.ReadHeaderTimeout)
	}
	if httpSrv.IdleTimeout != cfg.IdleTimeout {
		t.Fatalf("http server idle timeout mismatch: got=%s want=%s", httpSrv.IdleTimeout, cfg.IdleTimeout)
	}
	if httpSrv.MaxHeaderBytes != cfg.MaxHeaderBytes {
		t.Fatalf("http server max header bytes mismatch: got=%d want=%d", httpSrv.MaxHeaderBytes, cfg.MaxHeaderBytes)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for booted gateway: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- httpSrv.Serve(ln)
	}()
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("shutdown booted gateway: %v", err)
		}
		select {
		case err := <-serveErr:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("booted gateway serve error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("timeout waiting for booted gateway to stop")
		}
	})

	gatewayURL := "http://" + ln.Addr().String()
	waitForGatewayReady(t, gatewayURL)

	rwAccessKey := base64.StdEncoding.EncodeToString([]byte("testuser@example.com:dogood"))
	roAccessKey := base64.StdEncoding.EncodeToString([]byte("readonly@example.com:dogood"))

	rwClient := s3gateway.NewS3Client(t, ctx, gatewayURL, "us-east-1", rwAccessKey, cfg.SigV4Secret)
	roClient := s3gateway.NewS3Client(t, ctx, gatewayURL, "us-east-1", roAccessKey, cfg.SigV4Secret)
	upstreamClient := s3gateway.NewS3Client(t, ctx, minioURL, "us-east-1", cfg.UpstreamAccessKey, cfg.UpstreamSecretKey)

	bucket := fmt.Sprintf("team2-boot-%d", time.Now().UnixNano())
	key := "boot/object.txt"
	payload := []byte("bootS3Gateway integration payload")

	if _, err := rwClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("create bucket through booted gateway: %v", err)
	}
	t.Cleanup(func() {
		_, _ = rwClient.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		_, _ = rwClient.DeleteBucket(ctx, &s3.DeleteBucketInput{
			Bucket: aws.String(bucket),
		})
	})

	if _, err := roClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(fmt.Sprintf("team2-boot-ro-%d", time.Now().UnixNano())),
	}); err == nil {
		t.Fatalf("expected readonly CreateBucket to fail")
	} else {
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("expected smithy api error for readonly create bucket, got: %v", err)
		}
		if apiErr.ErrorCode() != "AccessDenied" {
			t.Fatalf("readonly CreateBucket error code mismatch: got=%q want=%q", apiErr.ErrorCode(), "AccessDenied")
		}
	}

	if _, err := rwClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))),
		ContentType:   aws.String("text/plain"),
	}); err != nil {
		t.Fatalf("put object through booted gateway: %v", err)
	}

	newListInputWithOptionalAttrs := func() *s3.ListObjectsV2Input {
		return &s3.ListObjectsV2Input{
			Bucket: aws.String(bucket),
			Prefix: aws.String("boot/"),
			OptionalObjectAttributes: []s3types.OptionalObjectAttributes{
				s3types.OptionalObjectAttributesRestoreStatus,
			},
		}
	}
	upstreamListWithOptionalAttrs, upstreamListWithOptionalAttrsErr := upstreamClient.ListObjectsV2(ctx, newListInputWithOptionalAttrs())
	gatewayListWithOptionalAttrs, gatewayListWithOptionalAttrsErr := rwClient.ListObjectsV2(ctx, newListInputWithOptionalAttrs())
	if (upstreamListWithOptionalAttrsErr != nil) != (gatewayListWithOptionalAttrsErr != nil) {
		t.Fatalf("list objects v2 with optional-object-attributes error mismatch: gatewayErr=%v upstreamErr=%v", gatewayListWithOptionalAttrsErr, upstreamListWithOptionalAttrsErr)
	}
	if upstreamListWithOptionalAttrsErr != nil {
		var upstreamAPIErr smithy.APIError
		var gatewayAPIErr smithy.APIError
		if !errors.As(upstreamListWithOptionalAttrsErr, &upstreamAPIErr) || !errors.As(gatewayListWithOptionalAttrsErr, &gatewayAPIErr) {
			t.Fatalf("list objects v2 with optional-object-attributes expected smithy errors: gatewayErr=%v upstreamErr=%v", gatewayListWithOptionalAttrsErr, upstreamListWithOptionalAttrsErr)
		}
		if gatewayAPIErr.ErrorCode() != upstreamAPIErr.ErrorCode() {
			t.Fatalf("list objects v2 with optional-object-attributes error code mismatch: gateway=%q upstream=%q", gatewayAPIErr.ErrorCode(), upstreamAPIErr.ErrorCode())
		}
	} else {
		makeObjectSigs := func(objs []s3types.Object) []string {
			out := make([]string, 0, len(objs))
			for _, o := range objs {
				restoreInProgress := "<nil>"
				restoreExpiry := "<nil>"
				if o.RestoreStatus != nil {
					if o.RestoreStatus.IsRestoreInProgress != nil {
						restoreInProgress = fmt.Sprintf("%t", aws.ToBool(o.RestoreStatus.IsRestoreInProgress))
					}
					if o.RestoreStatus.RestoreExpiryDate != nil {
						restoreExpiry = o.RestoreStatus.RestoreExpiryDate.UTC().Format(time.RFC3339Nano)
					}
				}
				out = append(out, fmt.Sprintf(
					"%s|%d|%s|%s",
					aws.ToString(o.Key),
					aws.ToInt64(o.Size),
					restoreInProgress,
					restoreExpiry,
				))
			}
			sort.Strings(out)
			return out
		}
		if got, want := fmt.Sprintf(
			"%v|%v|%v",
			makeObjectSigs(gatewayListWithOptionalAttrs.Contents),
			aws.ToInt32(gatewayListWithOptionalAttrs.KeyCount),
			aws.ToBool(gatewayListWithOptionalAttrs.IsTruncated),
		), fmt.Sprintf(
			"%v|%v|%v",
			makeObjectSigs(upstreamListWithOptionalAttrs.Contents),
			aws.ToInt32(upstreamListWithOptionalAttrs.KeyCount),
			aws.ToBool(upstreamListWithOptionalAttrs.IsTruncated),
		); got != want {
			t.Fatalf("list objects v2 with optional-object-attributes mismatch: gateway=%q upstream=%q", got, want)
		}
	}

	roObj, err := roClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("readonly get object through booted gateway: %v", err)
	}
	defer roObj.Body.Close()
	roBody, err := io.ReadAll(roObj.Body)
	if err != nil {
		t.Fatalf("read readonly object body: %v", err)
	}
	if !bytes.Equal(roBody, payload) {
		t.Fatalf("readonly object body mismatch: got=%q want=%q", string(roBody), string(payload))
	}

	upObj, err := upstreamClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("get object from upstream after gateway write: %v", err)
	}
	defer upObj.Body.Close()
	upBody, err := io.ReadAll(upObj.Body)
	if err != nil {
		t.Fatalf("read upstream object body: %v", err)
	}
	if !bytes.Equal(upBody, payload) {
		t.Fatalf("upstream object body mismatch: got=%q want=%q", string(upBody), string(payload))
	}
}

func waitForGatewayReady(t *testing.T, gatewayURL string) {
	t.Helper()

	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(10 * time.Second)
	for {
		req, err := http.NewRequest(http.MethodGet, gatewayURL+"/", nil)
		if err != nil {
			t.Fatalf("build readiness request: %v", err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway did not become ready in time: lastErr=%v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
