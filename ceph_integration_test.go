package main_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3gateway "github.com/define42/s3gateway"
	"github.com/define42/s3gateway/internal/s3credentials"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
)

func startCephRGW(ctx context.Context, t *testing.T) (endpoint string, container testcontainers.Container, terminate func()) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "ceph/daemon:latest",
		Privileged:   true,
		ExposedPorts: []string{"7480/tcp"},
		Env: map[string]string{
			"CEPH_DAEMON":         "demo", // start an in-container demo cluster
			"NETWORK_AUTO_DETECT": "4",
			"CEPH_ARGS":           "--mon-data-avail-crit 1",
			"CEPH_DEMO_UID":       "demo",
			"DEMO_DAEMONS":        "osd,rgw",
			"RGW_NAME":            "localhost",
			"RGW_FRONTEND_PORT":   "7480",
		},
		WaitingFor: wait.
			ForHTTP("/").
			WithPort("7480/tcp").
			WithForcedIPv4LocalHost().
			WithStatusCodeMatcher(func(status int) bool {
				return status == http.StatusOK || status == http.StatusForbidden
			}).
			WithStartupTimeout(3 * time.Minute),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start ceph: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}

	port, err := container.MappedPort(ctx, "7480/tcp")
	if err != nil {
		t.Fatal(err)
	}

	endpoint = fmt.Sprintf("http://%s:%s", host, port.Port())

	terminate = func() {
		_ = container.Terminate(ctx)
	}

	return endpoint, container, terminate
}

func cephDemoUserCredentials(ctx context.Context, t *testing.T, c testcontainers.Container) (accessKey, secretKey string) {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	var lastOut string
	var lastErr error
	for {
		exitCode, out, err := c.Exec(ctx, []string{"radosgw-admin", "user", "info", "--uid=demo"}, tcexec.Multiplexed())
		outBytes, readErr := io.ReadAll(out)
		if readErr != nil {
			t.Fatalf("read ceph demo credential output: %v", readErr)
		}
		lastOut = string(outBytes)
		if err == nil && exitCode == 0 {
			var userResp struct {
				Keys []struct {
					AccessKey string `json:"access_key"`
					SecretKey string `json:"secret_key"`
				} `json:"keys"`
			}
			if err := json.Unmarshal(outBytes, &userResp); err != nil {
				lastErr = fmt.Errorf("parse demo user info: %w", err)
			} else if len(userResp.Keys) > 0 {
				accessKey = strings.TrimSpace(userResp.Keys[0].AccessKey)
				secretKey = strings.TrimSpace(userResp.Keys[0].SecretKey)
				if accessKey != "" && secretKey != "" {
					return accessKey, secretKey
				}
				lastErr = fmt.Errorf("demo user info returned empty credentials")
			} else {
				lastErr = fmt.Errorf("demo user info returned no keys")
			}
		} else {
			lastErr = fmt.Errorf("radosgw-admin user info failed: %v (exit=%d)", err, exitCode)
		}
		if time.Now().After(deadline) {
			t.Fatalf("read ceph demo credentials timed out: %v\n%s", lastErr, lastOut)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func createCephBucketViaS3cmd(ctx context.Context, t *testing.T, c testcontainers.Container, bucket string) {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	cmd := []string{"bash", "-lc", "s3cmd mb s3://" + bucket}
	var lastOut string
	var lastErr error
	for {
		exitCode, out, err := c.Exec(ctx, cmd, tcexec.Multiplexed())
		outBytes, readErr := io.ReadAll(out)
		if readErr != nil {
			t.Fatalf("read s3cmd create bucket output: %v", readErr)
		}
		lastOut = string(outBytes)
		if err == nil && exitCode == 0 || strings.Contains(lastOut, "already exists") || strings.Contains(lastOut, "BucketAlreadyOwnedByYou") {
			listExitCode, listOut, listErr := c.Exec(ctx, []string{"radosgw-admin", "bucket", "list"}, tcexec.Multiplexed())
			listOutBytes, listReadErr := io.ReadAll(listOut)
			if listReadErr != nil {
				t.Fatalf("read radosgw-admin bucket list output: %v", listReadErr)
			}
			if listErr == nil && listExitCode == 0 && strings.Contains(string(listOutBytes), `"`+bucket+`"`) {
				return
			}
			lastErr = fmt.Errorf("bucket not present in admin list yet: %v (exit=%d)", listErr, listExitCode)
			lastOut = string(listOutBytes)
		} else {
			lastErr = fmt.Errorf("s3cmd mb failed: %v (exit=%d)", err, exitCode)
		}
		if time.Now().After(deadline) {
			t.Fatalf("create ceph bucket via s3cmd timed out: %v\n%s", lastErr, lastOut)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func TestCephS3_full_s3gatewaytest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if err := dockerAvailable(); err != nil {
		t.Skipf("skipping integration test because Docker is unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	cephEndpoint, container, terminate := startCephRGW(ctx, t)
	defer terminate()

	upstreamAccessKey, upstreamSecretKey := cephDemoUserCredentials(ctx, t, container)
	bucket := fmt.Sprintf("team2-cephgw-%d", time.Now().UnixNano())
	createCephBucketViaS3cmd(ctx, t, container, bucket)

	ldapCfgPath := s3gateway.WriteGatewayGlauthConfig(t)
	ldapURL, stopLDAP := s3gateway.StartGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	defer stopLDAP()

	t.Setenv("LISTEN_ADDR", "127.0.0.1:0")
	t.Setenv("LDAP_URL", ldapURL)
	t.Setenv("LDAP_BASE_DN", "dc=glauth,dc=com")
	t.Setenv("LDAP_DOMAIN", "example.com")
	t.Setenv("S3_ENDPOINT", cephEndpoint)
	t.Setenv("S3_REGION", "us-east-1")
	t.Setenv("S3_ACCESS_KEY", upstreamAccessKey)
	t.Setenv("S3_SECRET_KEY", upstreamSecretKey)
	t.Setenv("S3_FORCE_PATH_STYLE", "true")

	httpSrv, _, err := s3gateway.BootS3Gateway()
	if err != nil {
		t.Fatalf("boot s3gateway with ceph upstream: %v", err)
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

	rwAccessKey, rwSecretKey, err := s3credentials.GenerateKeysBase64Encoded("testuser", "dogood")
	if err != nil {
		t.Fatalf("generate gateway rw credentials: %v", err)
	}
	gatewayClient := s3gateway.NewS3Client(t, ctx, gatewayURL, "us-east-1", rwAccessKey, rwSecretKey)

	createdBucket := fmt.Sprintf("team2-cephgw-created-%d", time.Now().UnixNano())
	if _, err := gatewayClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(createdBucket),
	}); err != nil {
		t.Fatalf("create bucket via s3gateway: %v", err)
	}
	t.Cleanup(func() {
		_, _ = gatewayClient.DeleteBucket(ctx, &s3.DeleteBucketInput{
			Bucket: aws.String(createdBucket),
		})
	})

	listOut, err := gatewayClient.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		t.Fatalf("list buckets via s3gateway: %v", err)
	}
	foundCreatedBucket := false
	for _, b := range listOut.Buckets {
		if aws.ToString(b.Name) == createdBucket {
			foundCreatedBucket = true
			break
		}
	}
	if !foundCreatedBucket {
		t.Fatalf("created bucket %q not returned by list buckets", createdBucket)
	}

	key := fmt.Sprintf("cephgw/smoke-%d.txt", time.Now().UnixNano())
	payload := []byte("hello through s3gateway to ceph")

	t.Cleanup(func() {
		_, _ = gatewayClient.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
	})

	if _, err := gatewayClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))),
		ContentType:   aws.String("text/plain"),
	}); err != nil {
		t.Fatalf("put object via s3gateway: %v", err)
	}

	gwObj, err := gatewayClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("get object via s3gateway: %v", err)
	}
	defer gwObj.Body.Close()
	gwBody, err := io.ReadAll(gwObj.Body)
	if err != nil {
		t.Fatalf("read gateway object body: %v", err)
	}
	if !bytes.Equal(gwBody, payload) {
		t.Fatalf("gateway object body mismatch: got=%q want=%q", string(gwBody), string(payload))
	}

}

func dockerAvailable() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		return err
	}
	_, err = client.Ping(ctx)
	return err
}
