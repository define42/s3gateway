package server

import (
	"bytes"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func BenchmarkFullIntegrationGatewayPutObject(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping full integration benchmark in short mode")
	}

	env := setupIntegrationEnv(b)
	payload := bytes.Repeat([]byte("bench-gateway-put-"), 8*1024) // ~128 KiB
	key := "bench/put.bin"
	bucket := fmt.Sprintf("team2-bench-put-%d", time.Now().UnixNano())

	if _, err := env.rwClient.CreateBucket(env.ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		b.Fatalf("create benchmark bucket: %v", err)
	}
	b.Cleanup(func() {
		_, _ = env.rwClient.DeleteObject(env.ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		_, _ = env.rwClient.DeleteBucket(env.ctx, &s3.DeleteBucketInput{
			Bucket: aws.String(bucket),
		})
	})

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := env.rwClient.PutObject(env.ctx, &s3.PutObjectInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(key),
			Body:          bytes.NewReader(payload),
			ContentLength: aws.Int64(int64(len(payload))),
			ContentType:   aws.String("application/octet-stream"),
		}); err != nil {
			b.Fatalf("put object via gateway: %v", err)
		}
	}
}

func BenchmarkFullIntegrationGatewayGetObject(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping full integration benchmark in short mode")
	}

	env := setupIntegrationEnv(b)
	payload := bytes.Repeat([]byte("bench-gateway-get-"), 8*1024) // ~128 KiB
	key := "bench/get.bin"
	bucket := fmt.Sprintf("team2-bench-get-%d", time.Now().UnixNano())

	if _, err := env.rwClient.CreateBucket(env.ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		b.Fatalf("create benchmark bucket: %v", err)
	}
	if _, err := env.rwClient.PutObject(env.ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))),
		ContentType:   aws.String("application/octet-stream"),
	}); err != nil {
		b.Fatalf("seed object for get benchmark: %v", err)
	}
	b.Cleanup(func() {
		_, _ = env.rwClient.DeleteObject(env.ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		_, _ = env.rwClient.DeleteBucket(env.ctx, &s3.DeleteBucketInput{
			Bucket: aws.String(bucket),
		})
	})

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := env.rwClient.GetObject(env.ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		if err != nil {
			b.Fatalf("get object via gateway: %v", err)
		}
		if _, err := io.Copy(io.Discard, out.Body); err != nil {
			_ = out.Body.Close()
			b.Fatalf("read object body: %v", err)
		}
		if err := out.Body.Close(); err != nil {
			b.Fatalf("close object body: %v", err)
		}
	}
}
