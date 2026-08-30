package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/define42/s3gateway/internal/config"
	"github.com/define42/s3gateway/internal/s3credentials"
	"github.com/define42/s3gateway/internal/testutil"
	"github.com/define42/s3gateway/internal/uploadnotify"
)

func TestBootRedpandaGlobalPopIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	ldapConfig := testutil.WriteGatewayGlauthConfig(t)
	ldapURL, stopLDAP := testutil.StartGlauthWithConfig(ctx, t, ldapConfig, "ldap")
	t.Cleanup(stopLDAP)

	minioURL, stopMinio := testutil.StartMinio(ctx, t, "minioadmin", "minioadmin")
	t.Cleanup(stopMinio)

	kafkaBroker, stopRedpanda := testutil.StartRedpanda(ctx, t)
	t.Cleanup(stopRedpanda)

	privateKeyHex, publicKey, err := s3credentials.GenerateX25519TestKeys()
	if err != nil {
		t.Fatalf("generate X25519 test keys: %v", err)
	}
	privateKey, err := s3credentials.X25519PrivateKeyFromHex(privateKeyHex)
	if err != nil {
		t.Fatalf("parse X25519 private key: %v", err)
	}

	httpServer, cleanup, err := boot(config.Config{
		LDAPURL:                   ldapURL,
		BaseDN:                    "dc=glauth,dc=com",
		LDAPDomain:                "example.com",
		GroupCacheMaxEntries:      256,
		UpstreamEndpoint:          minioURL,
		UpstreamRegion:            "us-east-1",
		UpstreamAccessKey:         "minioadmin",
		UpstreamSecretKey:         "minioadmin",
		UpstreamForcePathStyle:    true,
		KafkaBrokers:              []string{kafkaBroker},
		KafkaGlobalTopic:          "_all",
		KafkaNotificationTimeout:  15 * time.Second,
		KafkaPopTimeout:           15 * time.Second,
		KafkaPopMaxConsumers:      10,
		S3GatewayPrivateX25519Key: privateKey,
	})
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatalf("boot gateway with redpanda: %v", err)
	}

	gateway := httptest.NewServer(httpServer.Handler)
	t.Cleanup(gateway.Close)

	accessKey, secretKey, err := s3credentials.GenerateKeysX25519(
		"testuser",
		"dogood",
		publicKey,
	)
	if err != nil {
		t.Fatalf("generate gateway credentials: %v", err)
	}
	gatewayS3 := testutil.NewS3Client(
		t,
		ctx,
		gateway.URL,
		"us-east-1",
		accessKey,
		secretKey,
	)

	bucket := fmt.Sprintf("team2-redpanda-pop-%d", time.Now().UnixNano())
	key := "incoming/evidence.txt"
	payload := []byte("redpanda global pop integration payload")
	if _, err := gatewayS3.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("create bucket through gateway: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = gatewayS3.DeleteObject(cleanupCtx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		_, _ = gatewayS3.DeleteBucket(cleanupCtx, &s3.DeleteBucketInput{
			Bucket: aws.String(bucket),
		})
	})

	if _, err := gatewayS3.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))),
		ContentType:   aws.String("text/plain"),
	}); err != nil {
		t.Fatalf("put object through gateway: %v", err)
	}

	popRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		gateway.URL+"/api/pop/_all/integration",
		nil,
	)
	if err != nil {
		t.Fatalf("build global pop request: %v", err)
	}
	popRequest.SetBasicAuth("testuser", "dogood")
	popResponse, err := gateway.Client().Do(popRequest)
	if err != nil {
		t.Fatalf("execute global pop request: %v", err)
	}
	defer popResponse.Body.Close()

	gotPayload, err := io.ReadAll(popResponse.Body)
	if err != nil {
		t.Fatalf("read global pop response: %v", err)
	}
	if popResponse.StatusCode != http.StatusOK {
		t.Fatalf(
			"global pop status = %d, want %d; body=%q",
			popResponse.StatusCode,
			http.StatusOK,
			string(gotPayload),
		)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("global pop body = %q, want %q", gotPayload, payload)
	}
	if got := popResponse.Header.Get("X-S3Gateway-Bucket"); got != bucket {
		t.Fatalf("global pop bucket header = %q, want %q", got, bucket)
	}
	if got := popResponse.Header.Get("X-S3Gateway-Object-Key"); got != "incoming%2Fevidence.txt" {
		t.Fatalf("global pop object key header = %q", got)
	}
	if got := popResponse.Header.Get("X-S3Gateway-Event-Name"); got != string(uploadnotify.EventObjectCreatedPut) {
		t.Fatalf("global pop event name header = %q", got)
	}
	if got := popResponse.Header.Get("X-S3Gateway-Event-ID"); got == "" {
		t.Fatal("global pop response is missing event id header")
	}
}
