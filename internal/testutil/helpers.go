// Package testutil provides shared test helpers used across multiple test packages.
package testutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/redpanda"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	glauthTestImage   = "glauth/glauth@sha256:b3efd79fc32ac626ad1b18e36ab42fac2e2ac662454582fdfa21cc82efab786b"
	minioTestImage    = "minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"
	redpandaTestImage = "docker.redpanda.com/redpandadata/redpanda:v25.2.4"
)

// ModuleRoot returns the absolute path of the module root directory,
// derived from the compile-time location of this source file
// (<moduleRoot>/internal/testutil/helpers.go).
func ModuleRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}

// PathRelative resolves elems relative to the module root.
func PathRelative(tb testing.TB, elems ...string) string {
	tb.Helper()
	return filepath.Join(append([]string{ModuleRoot()}, elems...)...)
}

// WriteGatewayGlauthConfig writes a glauth config file to a temp directory
// and returns its path.
func WriteGatewayGlauthConfig(tb testing.TB) string {
	tb.Helper()
	return writeGatewayGlauthConfig(tb, false)
}

// WriteGatewayGlauthConfigWithAllBucketsRead writes the standard integration
// LDAP fixture with s3gateway-all-r assigned to testuser.
func WriteGatewayGlauthConfigWithAllBucketsRead(tb testing.TB) string {
	tb.Helper()
	return writeGatewayGlauthConfig(tb, true)
}

func writeGatewayGlauthConfig(tb testing.TB, hasAllBucketsRead bool) string {
	tb.Helper()

	otherGroups := "5506"
	allBucketsReadGroup := ""
	if hasAllBucketsRead {
		otherGroups += ", 5508"
		allBucketsReadGroup = `
[[groups]]
  name = "s3gateway-all-r"
  gidnumber = 5508
`
	}

	const cfgTemplate = `
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
  othergroups = [%s]
  passsha256 = "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a" # dogood
    [[users.capabilities]]
    action = "search"
    object = "*"

[[users]]
  name = "readonly"
  mail = "readonly@example.com"
  primarygroup = 5507
  othergroups = [5507]
  passsha256 = "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a" # dogood
    [[users.capabilities]]
    action = "search"
    object = "*"

[[groups]]
  name = "team2-rwcdb"
  gidnumber = 5506

[[groups]]
  name = "team2-r"
  gidnumber = 5507
%s
`
	cfg := fmt.Sprintf(cfgTemplate, otherGroups, allBucketsReadGroup)

	cfgPath := filepath.Join(tb.TempDir(), "glauth-integration.cfg")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		tb.Fatalf("write glauth config: %v", err)
	}
	return cfgPath
}

// StartGlauthWithConfig starts a glauth container with the given config file
// and returns the LDAP URL plus a cleanup function.
func StartGlauthWithConfig(ctx context.Context, tb testing.TB, cfg string, scheme string) (string, func()) {
	tb.Helper()

	cert := PathRelative(tb, "testldap", "cert.pem")
	key := PathRelative(tb, "testldap", "key.pem")
	waitLog := "LDAPS server listening"
	if strings.EqualFold(scheme, "ldap") {
		waitLog = "LDAP server listening"
	}

	req := testcontainers.ContainerRequest{
		Image:        glauthTestImage,
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
		tb.Fatalf("failed to start glauth container: %v", err)
	}
	cleanup := sync.OnceFunc(func() {
		_ = container.Terminate(context.Background())
	})
	tb.Cleanup(cleanup)

	host, err := container.Host(ctx)
	if err != nil {
		tb.Fatalf("get host: %v", err)
	}
	port, err := container.MappedPort(ctx, "389/tcp")
	if err != nil {
		tb.Fatalf("get mapped port: %v", err)
	}

	url := fmt.Sprintf("%s://%s:%s", scheme, host, port.Port())

	return url, cleanup
}

// StartMinio starts MinIO with HTTPS, adds its generated certificate to the
// test's AWS_CA_BUNDLE, and returns its endpoint URL plus a cleanup function.
func StartMinio(ctx context.Context, tb testing.TB, accessKey string, secretKey string) (string, func()) {
	tb.Helper()

	provider, err := testcontainers.NewDockerProvider()
	if err != nil {
		tb.Fatalf("create Docker provider: %v", err)
	}
	defer func() { _ = provider.Close() }()
	dockerHost, err := provider.DaemonHost(ctx)
	if err != nil {
		tb.Fatalf("get Docker host for test certificate: %v", err)
	}
	certificatePath, keyPath, certificate := writeTestTLSCertificate(tb, dockerHost)
	TrustTLSCertificate(tb, certificate)
	roots := x509.NewCertPool()
	roots.AddCert(certificate)

	req := testcontainers.ContainerRequest{
		Image:        minioTestImage,
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
			"--certs-dir",
			"/certs",
		},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: certificatePath, ContainerFilePath: "/certs/public.crt", FileMode: 0o644},
			{HostFilePath: keyPath, ContainerFilePath: "/certs/private.key", FileMode: 0o600},
		},
		WaitingFor: wait.ForHTTP("/minio/health/ready").
			WithPort("9000/tcp").
			WithTLS(true, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}).
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
		tb.Fatalf("failed to start minio container: %v", err)
	}
	cleanup := sync.OnceFunc(func() {
		_ = container.Terminate(context.Background())
	})
	tb.Cleanup(cleanup)

	host, err := container.Host(ctx)
	if err != nil {
		tb.Fatalf("get host: %v", err)
	}

	port, err := container.MappedPort(ctx, "9000/tcp")
	if err != nil {
		tb.Fatalf("get mapped port: %v", err)
	}

	endpoint := fmt.Sprintf("https://%s:%s", host, port.Port())

	return endpoint, cleanup
}

// StartRedpanda starts a single-node Redpanda container with automatic topic
// creation enabled and returns its host-accessible Kafka seed broker.
func StartRedpanda(ctx context.Context, tb testing.TB) (string, func()) {
	tb.Helper()

	container, err := redpanda.Run(
		ctx,
		redpandaTestImage,
		redpanda.WithAutoCreateTopics(),
	)
	if err != nil {
		if container != nil {
			_ = testcontainers.TerminateContainer(container)
		}
		tb.Fatalf("failed to start redpanda container: %v", err)
	}
	cleanup := sync.OnceFunc(func() {
		_ = testcontainers.TerminateContainer(container)
	})
	tb.Cleanup(cleanup)

	broker, err := container.KafkaSeedBroker(ctx)
	if err != nil {
		tb.Fatalf("get redpanda kafka seed broker: %v", err)
	}

	return broker, cleanup
}

// NewS3Client creates a new AWS S3 client configured to talk to the given endpoint.
func NewS3Client(tb testing.TB, ctx context.Context, endpoint, region, accessKey, secretKey string) *s3.Client {
	tb.Helper()

	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithBaseEndpoint(endpoint),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		config.WithResponseChecksumValidation(aws.ResponseChecksumValidationWhenRequired),
	)
	if err != nil {
		tb.Fatalf("load aws config for %s: %v", endpoint, err)
	}

	return s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})
}
