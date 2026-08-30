package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
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
	uiKey := "ui/incoming.txt"
	payload := []byte("redpanda global pop integration payload")
	if _, err := gatewayS3.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("create bucket through gateway: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		for _, objectKey := range []string{key, uiKey} {
			_, _ = gatewayS3.DeleteObject(cleanupCtx, &s3.DeleteObjectInput{
				Bucket: aws.String(bucket),
				Key:    aws.String(objectKey),
			})
		}
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

	type popResult struct {
		status int
		header http.Header
		body   []byte
	}
	popGlobal := func(method string) popResult {
		t.Helper()
		popRequest, requestErr := http.NewRequestWithContext(
			ctx,
			method,
			gateway.URL+"/api/pop/_all/integration",
			nil,
		)
		if requestErr != nil {
			t.Fatalf("build global pop request: %v", requestErr)
		}
		popRequest.SetBasicAuth("testuser", "dogood")
		popResponse, requestErr := gateway.Client().Do(popRequest)
		if requestErr != nil {
			t.Fatalf("execute global pop request: %v", requestErr)
		}
		defer popResponse.Body.Close()

		body, readErr := io.ReadAll(popResponse.Body)
		if readErr != nil {
			t.Fatalf("read global pop response: %v", readErr)
		}
		return popResult{
			status: popResponse.StatusCode,
			header: popResponse.Header.Clone(),
			body:   body,
		}
	}

	s3Pop := popGlobal(http.MethodGet)
	if s3Pop.status != http.StatusOK {
		t.Fatalf(
			"global pop status = %d, want %d; body=%q",
			s3Pop.status,
			http.StatusOK,
			string(s3Pop.body),
		)
	}
	if !bytes.Equal(s3Pop.body, payload) {
		t.Fatalf("global pop body = %q, want %q", s3Pop.body, payload)
	}
	if got := s3Pop.header.Get("X-S3Gateway-Bucket"); got != bucket {
		t.Fatalf("global pop bucket header = %q, want %q", got, bucket)
	}
	if got := s3Pop.header.Get("X-S3Gateway-Object-Key"); got != "incoming%2Fevidence.txt" {
		t.Fatalf("global pop object key header = %q", got)
	}
	if got := s3Pop.header.Get("X-S3Gateway-Event-Name"); got != string(uploadnotify.EventObjectCreatedPut) {
		t.Fatalf("global pop event name header = %q", got)
	}
	if got := s3Pop.header.Get("X-S3Gateway-Event-ID"); got == "" {
		t.Fatal("global pop response is missing event id header")
	}

	browserClient := *gateway.Client()
	browserClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	loginForm := url.Values{
		"username": {"testuser"},
		"password": {"dogood"},
	}
	loginRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		gateway.URL+"/login",
		strings.NewReader(loginForm.Encode()),
	)
	if err != nil {
		t.Fatalf("build browser login request: %v", err)
	}
	loginRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRequest.Header.Set("Accept", "text/html")
	loginRequest.Header.Set("User-Agent", "Mozilla/5.0")
	loginResponse, err := browserClient.Do(loginRequest)
	if err != nil {
		t.Fatalf("execute browser login request: %v", err)
	}
	_, _ = io.Copy(io.Discard, loginResponse.Body)
	_ = loginResponse.Body.Close()
	if loginResponse.StatusCode != http.StatusSeeOther {
		t.Fatalf("browser login status = %d, want %d", loginResponse.StatusCode, http.StatusSeeOther)
	}
	var sessionCookie *http.Cookie
	for _, cookie := range loginResponse.Cookies() {
		if cookie.Name == "s3gateway_admin_session" {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("browser login response is missing admin session cookie")
	}

	uiPayload := []byte("browser upload redpanda payload")
	var uploadBody bytes.Buffer
	uploadWriter := multipart.NewWriter(&uploadBody)
	for field, value := range map[string]string{
		"name":    bucket,
		"key":     uiKey,
		"cursor":  "",
		"history": "",
		"size":    strconv.Itoa(len(uiPayload)),
	} {
		if err := uploadWriter.WriteField(field, value); err != nil {
			t.Fatalf("write browser upload field %q: %v", field, err)
		}
	}
	filePart, err := uploadWriter.CreateFormFile("file", "incoming.txt")
	if err != nil {
		t.Fatalf("create browser upload file part: %v", err)
	}
	if _, err := filePart.Write(uiPayload); err != nil {
		t.Fatalf("write browser upload payload: %v", err)
	}
	if err := uploadWriter.Close(); err != nil {
		t.Fatalf("close browser upload payload: %v", err)
	}
	uploadRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		gateway.URL+"/admin/bucket/upload",
		&uploadBody,
	)
	if err != nil {
		t.Fatalf("build browser upload request: %v", err)
	}
	uploadRequest.Header.Set("Content-Type", uploadWriter.FormDataContentType())
	uploadRequest.Header.Set("Accept", "text/html")
	uploadRequest.Header.Set("User-Agent", "Mozilla/5.0")
	uploadRequest.Header.Set("Origin", gateway.URL)
	uploadRequest.AddCookie(sessionCookie)
	uploadResponse, err := browserClient.Do(uploadRequest)
	if err != nil {
		t.Fatalf("execute browser upload request: %v", err)
	}
	uploadResponseBody, readErr := io.ReadAll(uploadResponse.Body)
	_ = uploadResponse.Body.Close()
	if readErr != nil {
		t.Fatalf("read browser upload response: %v", readErr)
	}
	if uploadResponse.StatusCode != http.StatusSeeOther {
		t.Fatalf(
			"browser upload status = %d, want %d; body=%q",
			uploadResponse.StatusCode,
			http.StatusSeeOther,
			string(uploadResponseBody),
		)
	}

	uiPop := popGlobal(http.MethodPost)
	if uiPop.status != http.StatusOK {
		t.Fatalf(
			"UI global pop status = %d, want %d; body=%q",
			uiPop.status,
			http.StatusOK,
			string(uiPop.body),
		)
	}
	if !bytes.Equal(uiPop.body, uiPayload) {
		t.Fatalf("UI global pop body = %q, want %q", uiPop.body, uiPayload)
	}
	if got := uiPop.header.Get("X-S3Gateway-Bucket"); got != bucket {
		t.Fatalf("UI global pop bucket header = %q, want %q", got, bucket)
	}
	if got := uiPop.header.Get("X-S3Gateway-Object-Key"); got != "ui%2Fincoming.txt" {
		t.Fatalf("UI global pop object key header = %q", got)
	}
	if got := uiPop.header.Get("X-S3Gateway-Event-Name"); got != string(uploadnotify.EventObjectCreatedCompleteMultipartUpload) {
		t.Fatalf("UI global pop event name header = %q", got)
	}
	if got := uiPop.header.Get("X-S3Gateway-Event-ID"); got == "" {
		t.Fatal("UI global pop response is missing event id header")
	}

	topicsRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		gateway.URL+"/admin/kafka-topics",
		nil,
	)
	if err != nil {
		t.Fatalf("build Kafka topics page request: %v", err)
	}
	topicsRequest.Header.Set("Accept", "text/html")
	topicsRequest.Header.Set("User-Agent", "Mozilla/5.0")
	topicsRequest.AddCookie(sessionCookie)
	topicsResponse, err := browserClient.Do(topicsRequest)
	if err != nil {
		t.Fatalf("execute Kafka topics page request: %v", err)
	}
	topicsBody, readErr := io.ReadAll(topicsResponse.Body)
	_ = topicsResponse.Body.Close()
	if readErr != nil {
		t.Fatalf("read Kafka topics page response: %v", readErr)
	}
	if topicsResponse.StatusCode != http.StatusOK {
		t.Fatalf(
			"Kafka topics page status = %d, want %d; body=%q",
			topicsResponse.StatusCode,
			http.StatusOK,
			string(topicsBody),
		)
	}
	topicsHTML := string(topicsBody)
	topicIndex := strings.Index(topicsHTML, "<code>_all</code>")
	if topicIndex < 0 {
		t.Fatalf("Kafka topics page is missing _all topic: %q", topicsHTML)
	}
	rowEnd := strings.Index(topicsHTML[topicIndex:], "</tr>")
	if rowEnd < 0 {
		t.Fatalf("Kafka topics page has incomplete _all row: %q", topicsHTML[topicIndex:])
	}
	allTopicRow := topicsHTML[topicIndex : topicIndex+rowEnd]
	if !strings.Contains(allTopicRow, "<code>1</code>") {
		t.Fatalf("Kafka _all row is missing partition count 1: %q", allTopicRow)
	}
	if !strings.Contains(allTopicRow, "<code>2</code>") {
		t.Fatalf("Kafka _all row is missing element count 2: %q", allTopicRow)
	}
	groupIndex := strings.Index(topicsHTML[topicIndex:], "<code>testuser:integration</code>")
	if groupIndex < 0 {
		t.Fatalf("Kafka _all topic is missing consumer group testuser:integration: %q", topicsHTML[topicIndex:])
	}
	groupHTML := topicsHTML[topicIndex+groupIndex:]
	groupRow, _, found := strings.Cut(groupHTML, "</tr>")
	if !found {
		t.Fatalf("Kafka consumer group row is incomplete: %q", groupHTML)
	}
	if !strings.Contains(groupRow, "<code>2</code>") {
		t.Fatalf("Kafka consumer group row is missing current offset 2: %q", groupRow)
	}
}
