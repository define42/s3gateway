// Package testutil provides shared test helpers used across multiple test packages.
package testutil

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

const redpandaTestImage = "docker.redpanda.com/redpandadata/redpanda:v25.2.4"

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
`

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
		tb.Fatalf("failed to start glauth container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		tb.Fatalf("get host: %v", err)
	}
	port, err := container.MappedPort(ctx, "389/tcp")
	if err != nil {
		tb.Fatalf("get mapped port: %v", err)
	}

	url := fmt.Sprintf("%s://%s:%s", scheme, host, port.Port())

	return url, func() {
		_ = container.Terminate(context.Background())
	}
}

// StartMinio starts a MinIO container and returns its endpoint URL plus a cleanup function.
func StartMinio(ctx context.Context, tb testing.TB, accessKey string, secretKey string) (string, func()) {
	tb.Helper()

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
		tb.Fatalf("failed to start minio container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		tb.Fatalf("get host: %v", err)
	}

	port, err := container.MappedPort(ctx, "9000/tcp")
	if err != nil {
		tb.Fatalf("get mapped port: %v", err)
	}

	endpoint := fmt.Sprintf("http://%s:%s", host, port.Port())

	return endpoint, func() {
		_ = container.Terminate(context.Background())
	}
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

	broker, err := container.KafkaSeedBroker(ctx)
	if err != nil {
		_ = testcontainers.TerminateContainer(container)
		tb.Fatalf("get redpanda kafka seed broker: %v", err)
	}

	return broker, func() {
		_ = testcontainers.TerminateContainer(container)
	}
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
