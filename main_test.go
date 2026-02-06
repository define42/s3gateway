package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestLdapS3upstreamWithClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ldapCfgPath := writeGatewayGlauthConfig(t)
	ldapURL, stopLDAP := startGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	defer stopLDAP()

	minioURL, stopMinio := startMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	cfg := Config{
		LDAPURL:                ldapURL,
		BaseDN:                 "dc=glauth,dc=com",
		GroupTTL:               30 * time.Second,
		UpstreamEndpoint:       minioURL,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "minioadmin",
		UpstreamSecretKey:      "minioadmin",
		UpstreamForcePathStyle: true,
		SigV4Secret:            "password",
		SigV4Service:           "s3",
	}

	// Sanity-check LDAP bind + group mapping used by gateway authz.
	grps, err := fetchGroupsUPN(cfg, "testuser@example.com", "dogood")
	if err != nil {
		t.Fatalf("ldap auth/group lookup failed: %v", err)
	}
	if !canWrite(rulesFromGroups(grps), "team2-integration-check") {
		t.Fatalf("expected team2-rw write permission, got groups: %v", mapKeys(grps))
	}

	up, err := newUpstreamS3(ctx, cfg)
	if err != nil {
		t.Fatalf("init upstream s3: %v", err)
	}

	gw := &server{
		cfg:    cfg,
		up:     up,
		gcache: newGroupCache(cfg.GroupTTL),
	}
	gwSrv := httptest.NewServer(gw.withAuth(gw))
	defer gwSrv.Close()

	gatewayAccessKey := base64.StdEncoding.EncodeToString([]byte("testuser@example.com:dogood"))
	gatewayClient := newS3Client(t, ctx, gwSrv.URL, "us-east-1", gatewayAccessKey, cfg.SigV4Secret)
	upstreamClient := newS3Client(t, ctx, minioURL, "us-east-1", cfg.UpstreamAccessKey, cfg.UpstreamSecretKey)

	bucket := fmt.Sprintf("team2-integration-%d", time.Now().UnixNano())
	key := "smoke/hello.txt"
	wantBody := []byte("hello through s3gateway")

	if _, err := gatewayClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("create bucket via gateway: %v", err)
	}

	if _, err := gatewayClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(wantBody),
		ContentLength: aws.Int64(int64(len(wantBody))),
		ContentType:   aws.String("text/plain"),
	}); err != nil {
		t.Fatalf("put object via gateway: %v", err)
	}

	gotObj, err := upstreamClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("get object from upstream minio: %v", err)
	}
	defer gotObj.Body.Close()

	gotBody, err := io.ReadAll(gotObj.Body)
	if err != nil {
		t.Fatalf("read upstream object body: %v", err)
	}
	if !bytes.Equal(gotBody, wantBody) {
		t.Fatalf("upstream object mismatch: got %q want %q", string(gotBody), string(wantBody))
	}

	if _, err := gatewayClient.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}); err != nil {
		t.Fatalf("delete object via gateway: %v", err)
	}

	if _, err := upstreamClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}); err == nil {
		t.Fatalf("expected upstream object to be deleted, but get object succeeded")
	}
}

func startGlauthWithConfig(ctx context.Context, t *testing.T, cfg string, scheme string) (string, func()) {
	t.Helper()

	cert := pathRelative(t, "testldap", "cert.pem")
	key := pathRelative(t, "testldap", "key.pem")
	waitLog := "LDAPS server listening"
	if strings.EqualFold(scheme, "ldap") {
		waitLog = "LDAP server listening"
	}

	req := testcontainers.ContainerRequest{
		Image:        "glauth/glauth:latest",
		ExposedPorts: []string{"389/tcp"},
		Env: map[string]string{
			"GLAUTH_CONFIG": "/app/config/config.cfg",
		},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: cfg, ContainerFilePath: "/app/config/config.cfg", FileMode: 0o644},
			{HostFilePath: cert, ContainerFilePath: "/app/config/cert.pem", FileMode: 0o644},
			{HostFilePath: key, ContainerFilePath: "/app/config/key.pem", FileMode: 0o600},
		},
		Networks:       nil,
		NetworkAliases: nil,
		WaitingFor: wait.ForLog(waitLog).
			WithStartupTimeout(1 * time.Minute).
			WithPollInterval(2 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start glauth container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("get host: %v", err)
	}
	port, err := container.MappedPort(ctx, "389/tcp")
	if err != nil {
		t.Fatalf("get mapped port: %v", err)
	}

	url := fmt.Sprintf("%s://%s:%s", scheme, host, port.Port())

	return url, func() {
		_ = container.Terminate(context.Background())
	}
}

func writeGatewayGlauthConfig(t *testing.T) string {
	t.Helper()

	const cfg = `
debug = true

[ldap]
  enabled = true
  listen = "0.0.0.0:389"
  tls = false

[ldaps]
  enabled = false

[backend]
  datastore = "config"
  baseDN = "dc=glauth,dc=com"
  nameformat = "userPrincipalName"
  groupformat = "cn"

[behaviors]
  IgnoreCapabilities = true

[[users]]
  name = "testuser"
  mail = "testuser@example.com"
  primarygroup = 5506
  othergroups = [5506]
  passsha256 = "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a" # dogood
    [[users.capabilities]]
    action = "search"
    object = "*"

[[groups]]
  name = "team2-rw"
  gidnumber = 5506
`

	cfgPath := filepath.Join(t.TempDir(), "glauth-integration.cfg")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write glauth config: %v", err)
	}
	return cfgPath
}

func mapKeys(in map[string]struct{}) []string {
	out := make([]string, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	return out
}

func newS3Client(t *testing.T, ctx context.Context, endpoint, region, accessKey, secretKey string) *s3.Client {
	t.Helper()

	resolver := aws.EndpointResolverWithOptionsFunc(
		func(service, _ string, _ ...interface{}) (aws.Endpoint, error) {
			if service == s3.ServiceID {
				return aws.Endpoint{URL: endpoint, HostnameImmutable: true}, nil
			}
			return aws.Endpoint{}, &aws.EndpointNotFoundError{}
		},
	)

	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithEndpointResolverWithOptions(resolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		t.Fatalf("load aws config for %s: %v", endpoint, err)
	}

	return s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})
}

func pathRelative(t *testing.T, elems ...string) string {
	t.Helper()
	p := filepath.Join(elems...)
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	return abs
}

func startMinio(ctx context.Context, t *testing.T, accessKey string, secretKey string) (string, func()) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "minio/minio:latest",
		ExposedPorts: []string{"9000/tcp"},
		Env: map[string]string{
			"MINIO_ROOT_USER":     accessKey,
			"MINIO_ROOT_PASSWORD": secretKey,
		},
		Cmd: []string{
			"server",
			"/data",
			"--address",
			":9000",
		},
		WaitingFor: wait.ForHTTP("/minio/health/ready").
			WithPort("9000/tcp").
			WithStartupTimeout(1 * time.Minute),
	}

	container, err := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		},
	)
	if err != nil {
		t.Fatalf("failed to start minio container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("get host: %v", err)
	}

	port, err := container.MappedPort(ctx, "9000/tcp")
	if err != nil {
		t.Fatalf("get mapped port: %v", err)
	}

	endpoint := fmt.Sprintf("http://%s:%s", host, port.Port())

	return endpoint, func() {
		_ = container.Terminate(context.Background())
	}
}
