//go:build integration

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/define42/s3gateway/internal/config"
	"github.com/define42/s3gateway/internal/s3credentials"
	"github.com/define42/s3gateway/internal/testutil"
	"github.com/define42/s3gateway/internal/uploadnotify"
	"github.com/twmb/franz-go/pkg/kgo"
)

func TestShutdownPreservesInFlightUploadNotificationIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	ldapConfig := testutil.WriteGatewayGlauthConfig(t)
	ldapURL, stopLDAP := testutil.StartGlauthWithConfig(ctx, t, ldapConfig, "ldap")
	t.Cleanup(stopLDAP)
	minioURL, stopMinio := testutil.StartMinio(ctx, t, "minioadmin", "minioadmin")
	t.Cleanup(stopMinio)
	kafkaBroker, stopRedpanda := testutil.StartRedpanda(ctx, t)
	t.Cleanup(stopRedpanda)

	const bucket = "team2-shutdown"
	const key = "pending.txt"
	const topic = "shutdown-events"
	payload := []byte("upload accepted before shutdown must still publish its event")
	uploadStarted := make(chan struct{})
	uploadReleased := make(chan struct{})
	signalUploadStarted := sync.OnceFunc(func() { close(uploadStarted) })
	releaseUpload := sync.OnceFunc(func() { close(uploadReleased) })
	defer releaseUpload()

	minioEndpoint, err := url.Parse(minioURL)
	if err != nil {
		t.Fatalf("parse MinIO endpoint: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(minioEndpoint)
	proxy.Transport = testutil.NewHTTPClient(t).Transport
	upstreamGate := testutil.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/"+bucket+"/"+key {
			signalUploadStarted()
			select {
			case <-uploadReleased:
			case <-r.Context().Done():
				return
			case <-ctx.Done():
				return
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(upstreamGate.Close)

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
		LDAPGroupBaseDN:           "ou=groups,dc=glauth,dc=com",
		LDAPDomain:                "example.com",
		UpstreamEndpoint:          upstreamGate.URL,
		UpstreamRegion:            "us-east-1",
		UpstreamAccessKey:         "minioadmin",
		UpstreamSecretKey:         "minioadmin",
		UpstreamForcePathStyle:    true,
		KafkaBrokers:              []string{kafkaBroker},
		KafkaGlobalTopic:          topic,
		KafkaNotificationTimeout:  10 * time.Second,
		S3GatewayPrivateX25519Key: privateKey,
	})
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatalf("boot gateway: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for gateway: %v", err)
	}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- httpServer.Serve(listener)
		close(serveDone)
	}()
	t.Cleanup(func() {
		releaseUpload()
		_ = httpServer.Close()
		select {
		case err := <-serveDone:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("gateway serve: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("gateway did not stop")
		}
	})

	accessKey, secretKey, err := s3credentials.GenerateKeysX25519("testuser", "dogood", publicKey)
	if err != nil {
		t.Fatalf("generate gateway credentials: %v", err)
	}
	gatewayS3 := testutil.NewS3Client(t, ctx, "http://"+listener.Addr().String(), "us-east-1", accessKey, secretKey)
	if _, err := gatewayS3.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	putObject := func(objectKey string) error {
		_, err := gatewayS3.PutObject(ctx, &s3.PutObjectInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(objectKey),
			Body:          bytes.NewReader(payload),
			ContentLength: aws.Int64(int64(len(payload))),
		})
		return err
	}

	// Establish the producer connection and verify the broker before testing
	// shutdown, so a missing final event cannot be mistaken for startup failure.
	if err := putObject("warmup.txt"); err != nil {
		t.Fatalf("upload warmup object: %v", err)
	}
	consumer, err := kgo.NewClient(
		kgo.SeedBrokers(kafkaBroker),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if err != nil {
		t.Fatalf("create Kafka consumer: %v", err)
	}
	t.Cleanup(consumer.Close)
	readEvent := func() uploadnotify.Event {
		t.Helper()
		readCtx, readCancel := context.WithTimeout(ctx, 10*time.Second)
		defer readCancel()
		fetches := consumer.PollRecords(readCtx, 1)
		if errs := fetches.Errors(); len(errs) != 0 {
			t.Fatalf("read upload event from Kafka: %v", errs)
		}
		records := fetches.Records()
		if len(records) != 1 {
			t.Fatalf("read upload event from Kafka: records=%d, context error=%v", len(records), readCtx.Err())
		}
		var event uploadnotify.Event
		if err := json.Unmarshal(records[0].Value, &event); err != nil {
			t.Fatalf("decode upload event: %v", err)
		}
		return event
	}
	if event := readEvent(); event.Key != "warmup.txt" {
		t.Fatalf("warmup event key = %q", event.Key)
	}

	uploadDone := make(chan error, 1)
	go func() { uploadDone <- putObject(key) }()
	select {
	case <-uploadStarted:
	case err := <-uploadDone:
		t.Fatalf("upload finished before reaching the upstream gate: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("upload did not reach the upstream gate")
	}

	shutdownStarted := make(chan struct{})
	httpServer.RegisterOnShutdown(func() { close(shutdownStarted) })
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 30*time.Second)
	defer shutdownCancel()
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- httpServer.Shutdown(shutdownCtx) }()
	select {
	case <-shutdownStarted:
	case <-shutdownCtx.Done():
		t.Fatal("shutdown did not start")
	}
	select {
	case err := <-serveDone:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("gateway serve during shutdown: %v", err)
		}
	case <-shutdownCtx.Done():
		t.Fatal("shutdown did not close the listener")
	}
	select {
	case err := <-shutdownDone:
		t.Fatalf("shutdown returned while the upload was still blocked: %v", err)
	default:
	}
	releaseUpload()
	select {
	case err := <-uploadDone:
		if err != nil {
			t.Fatalf("in-flight upload failed during shutdown: %v", err)
		}
	case <-shutdownCtx.Done():
		t.Fatal("in-flight upload did not finish during shutdown")
	}
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("graceful shutdown: %v", err)
		}
	case <-shutdownCtx.Done():
		t.Fatal("shutdown did not finish after the upload")
	}

	event := readEvent()
	if event.Bucket != bucket || event.Key != key || event.EventName != uploadnotify.EventObjectCreatedPut || event.Uploader != "testuser" {
		t.Fatalf("unexpected event for upload completed during shutdown: %+v", event)
	}
	upstreamS3 := testutil.NewS3Client(t, ctx, minioURL, "us-east-1", "minioadmin", "minioadmin")
	object, err := upstreamS3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		t.Fatalf("read uploaded object: %v", err)
	}
	defer object.Body.Close()
	stored, err := io.ReadAll(object.Body)
	if err != nil || !bytes.Equal(stored, payload) {
		t.Fatalf("uploaded object = %q, error = %v", stored, err)
	}
	cleanup()
}
