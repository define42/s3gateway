// Command s3demo demonstrates X25519-protected LDAP credentials with an S3
// client configured for the local s3gateway stack.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

const (
	defaultEndpoint         = "http://localhost:8080"
	defaultRegion           = "eu-west-1"
	defaultUsername         = "testuser"
	defaultReadonlyUsername = "readonly"
	demoBucket              = "team2-data"
	requestTimeout          = 2 * time.Minute
)

type demoConfig struct {
	endpoint         string
	region           string
	publicKeyHex     string
	username         string
	password         string
	readonlyUsername string
	readonlyPassword string
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := loadDemoConfig()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	client, err := newGatewayClient(ctx, cfg, cfg.username, cfg.password)
	if err != nil {
		return fmt.Errorf("create S3 client: %w", err)
	}
	if err := listBuckets(ctx, client); err != nil {
		return err
	}
	bucket, objectKey, content, err := createBucketAndUpload(ctx, client, cfg.region)
	if err != nil {
		return err
	}
	if err := checkBucketCreation(ctx, client, cfg.region, "donotexist-what"); err != nil {
		return err
	}
	if err := checkReadonlyAccess(ctx, cfg, bucket, objectKey, content); err != nil {
		return err
	}
	return nil
}

func loadDemoConfig() (demoConfig, error) {
	cfg := demoConfig{
		endpoint:         envOrDefault("S3GATEWAY_ENDPOINT_URL", defaultEndpoint),
		region:           envOrDefault("S3GATEWAY_REGION", defaultRegion),
		publicKeyHex:     strings.TrimSpace(os.Getenv("S3GATEWAY_PUBLIC_X25519_KEY")),
		username:         envOrDefault("S3GATEWAY_DEMO_USERNAME", defaultUsername),
		password:         os.Getenv("S3GATEWAY_DEMO_PASSWORD"),
		readonlyUsername: envOrDefault("S3GATEWAY_DEMO_READONLY_USERNAME", defaultReadonlyUsername),
		readonlyPassword: os.Getenv("S3GATEWAY_DEMO_READONLY_PASSWORD"),
	}

	if cfg.publicKeyHex == "" {
		return demoConfig{}, errors.New("S3GATEWAY_PUBLIC_X25519_KEY is required")
	}
	if cfg.password == "" {
		return demoConfig{}, errors.New("S3GATEWAY_DEMO_PASSWORD is required")
	}
	if cfg.readonlyPassword == "" {
		return demoConfig{}, errors.New("S3GATEWAY_DEMO_READONLY_PASSWORD is required")
	}
	endpoint, err := url.ParseRequestURI(cfg.endpoint)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") {
		return demoConfig{}, errors.New("S3GATEWAY_ENDPOINT_URL must be an absolute HTTP or HTTPS URL")
	}
	return cfg, nil
}

func envOrDefault(key, defaultValue string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return defaultValue
}

func newGatewayClient(
	ctx context.Context,
	cfg demoConfig,
	username string,
	password string,
) (*s3.Client, error) {
	accessKey, secretKey, err := generateGatewayKeys(username, password, cfg.publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("generate gateway credentials: %w", err)
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(
		ctx,
		awsconfig.WithRegion(cfg.region),
		awsconfig.WithBaseEndpoint(cfg.endpoint),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration: %w", err)
	}
	return s3.NewFromConfig(awsCfg, func(options *s3.Options) {
		options.UsePathStyle = true
	}), nil
}

func listBuckets(ctx context.Context, client *s3.Client) error {
	output, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return fmt.Errorf("list buckets: %w", err)
	}
	fmt.Println("S3 Buckets:")
	for _, bucket := range output.Buckets {
		fmt.Printf("- %s\n", aws.ToString(bucket.Name))
	}
	return nil
}

func createBucketAndUpload(
	ctx context.Context,
	client *s3.Client,
	region string,
) (string, string, string, error) {
	if err := createBucket(ctx, client, region, demoBucket); err != nil {
		code := apiErrorCode(err)
		if code != "BucketAlreadyOwnedByYou" && code != "BucketAlreadyExists" {
			return "", "", "", fmt.Errorf("create bucket %q: %w", demoBucket, err)
		}
		fmt.Printf("Bucket already exists: %s\n", demoBucket)
	} else {
		fmt.Printf("Created bucket: %s\n", demoBucket)
	}

	objectKey, err := randomObjectKey("team2-data-upload", ".txt")
	if err != nil {
		return "", "", "", err
	}
	content := fmt.Sprintf("Sample data uploaded by the Go client [%s]\n", objectKey)
	contentLength := int64(len(content))
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(demoBucket),
		Key:           aws.String(objectKey),
		Body:          bytes.NewReader([]byte(content)),
		ContentLength: aws.Int64(contentLength),
		ContentType:   aws.String("text/plain"),
	}); err != nil {
		return "", "", "", fmt.Errorf("upload s3://%s/%s: %w", demoBucket, objectKey, err)
	}
	fmt.Printf("Uploaded object to s3://%s/%s from memory\n", demoBucket, objectKey)

	downloaded, err := downloadObject(ctx, client, demoBucket, objectKey)
	if err != nil {
		return "", "", "", err
	}
	fmt.Printf("Downloaded s3://%s/%s into memory\n", demoBucket, objectKey)
	if downloaded != content {
		return "", "", "", errors.New("uploaded and downloaded content differ")
	}
	fmt.Println("Validation passed: uploaded and downloaded file contents are identical")

	objects, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(demoBucket),
	})
	if err != nil {
		return "", "", "", fmt.Errorf("list objects in %q: %w", demoBucket, err)
	}
	found := false
	fmt.Printf("Objects in bucket %q:\n", demoBucket)
	for _, object := range objects.Contents {
		key := aws.ToString(object.Key)
		fmt.Printf("- %s\n", key)
		if key == objectKey {
			found = true
		}
	}
	if !found {
		return "", "", "", fmt.Errorf("uploaded object %q not found in bucket listing", objectKey)
	}
	fmt.Printf("Validation passed: %q exists in bucket %q\n", objectKey, demoBucket)
	return demoBucket, objectKey, content, nil
}

func createBucket(ctx context.Context, client *s3.Client, region, bucket string) error {
	input := &s3.CreateBucketInput{Bucket: aws.String(bucket)}
	if region != "" && region != "us-east-1" {
		input.CreateBucketConfiguration = &s3types.CreateBucketConfiguration{
			LocationConstraint: s3types.BucketLocationConstraint(region),
		}
	}
	_, err := client.CreateBucket(ctx, input)
	return err
}

func checkBucketCreation(ctx context.Context, client *s3.Client, region, bucket string) error {
	if err := createBucket(ctx, client, region, bucket); err != nil {
		code := apiErrorCode(err)
		if code == "BucketAlreadyOwnedByYou" || code == "BucketAlreadyExists" || code == "AccessDenied" {
			fmt.Printf("Bucket creation check could not create %q: %s\n", bucket, code)
			return nil
		}
		return fmt.Errorf("bucket creation check: %w", err)
	}
	fmt.Printf("Bucket creation check passed: created %q\n", bucket)
	if _, err := client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); err != nil {
		return fmt.Errorf("delete probe bucket %q: %w", bucket, err)
	}
	fmt.Printf("Cleanup complete: deleted %q\n", bucket)
	return nil
}

func checkReadonlyAccess(
	ctx context.Context,
	cfg demoConfig,
	bucket string,
	objectKey string,
	expectedContent string,
) error {
	client, err := newGatewayClient(ctx, cfg, cfg.readonlyUsername, cfg.readonlyPassword)
	if err != nil {
		return fmt.Errorf("create readonly S3 client: %w", err)
	}

	buckets, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return fmt.Errorf("list buckets as readonly user: %w", err)
	}
	visible := false
	for _, candidate := range buckets.Buckets {
		if aws.ToString(candidate.Name) == bucket {
			visible = true
			break
		}
	}
	if !visible {
		return fmt.Errorf("readonly user cannot see bucket %q", bucket)
	}
	fmt.Printf("Readonly check passed: bucket %q is visible\n", bucket)

	downloaded, err := downloadObject(ctx, client, bucket, objectKey)
	if err != nil {
		return fmt.Errorf("download as readonly user: %w", err)
	}
	if downloaded != expectedContent {
		return errors.New("readonly downloaded content differs from uploaded content")
	}
	fmt.Println("Readonly check passed: downloaded content matches uploaded content")

	readonlyKey, err := randomObjectKey("readonly-upload-attempt", ".txt")
	if err != nil {
		return err
	}
	body := []byte("readonly upload should fail\n")
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(readonlyKey),
		Body:          bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
		ContentType:   aws.String("text/plain"),
	})
	if err == nil {
		return fmt.Errorf("readonly upload unexpectedly succeeded for s3://%s/%s", bucket, readonlyKey)
	}
	if code := apiErrorCode(err); code != "AccessDenied" {
		return fmt.Errorf("readonly upload returned %q instead of AccessDenied: %w", code, err)
	}
	fmt.Println("Readonly check passed: upload denied with AccessDenied")
	return nil
}

func downloadObject(ctx context.Context, client *s3.Client, bucket, key string) (string, error) {
	output, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return "", fmt.Errorf("get s3://%s/%s: %w", bucket, key, err)
	}
	body, readErr := io.ReadAll(output.Body)
	closeErr := output.Body.Close()
	if readErr != nil {
		return "", fmt.Errorf("read s3://%s/%s: %w", bucket, key, readErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close s3://%s/%s: %w", bucket, key, closeErr)
	}
	return string(body), nil
}

func randomObjectKey(prefix, suffix string) (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
		return "", fmt.Errorf("generate random object key: %w", err)
	}
	return prefix + "-" + hex.EncodeToString(randomBytes) + suffix, nil
}

func apiErrorCode(err error) string {
	if apiErr, ok := errors.AsType[smithy.APIError](err); ok {
		return apiErr.ErrorCode()
	}
	return ""
}
