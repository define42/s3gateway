# s3gateway

An S3-compatible gateway that:

- Authenticates clients with AWS SigV4.
- Uses `AccessKey` as `base64("username:password")` (by design).
- Validates credentials against LDAP.
- Authorizes bucket access by LDAP group naming convention.
- Proxies allowed requests to an upstream S3-compatible backend (for example MinIO or AWS S3).

## Authentication Model (By Design)

- Client signs requests with SigV4.
- `AWS_ACCESS_KEY_ID` must be `base64("<upn-or-username>:<password>")`.
- `AWS_SECRET_ACCESS_KEY` must match `SIGV4_SECRET`.
- Gateway verifies SigV4 signature and request time window (`SIGV4_MAX_SKEW`).
- Gateway decodes access key to LDAP credentials and binds to LDAP.

Important:

- Base64 is not encryption. Always use TLS in production.
- Do not log/redact `Authorization` and credential-related headers at every layer.

## Authorization Model

LDAP groups define bucket prefix permissions:

- `<prefix>-r` -> read access
- `<prefix>-rw` -> read/write access

Gateway maps each group to bucket prefix `<prefix>-` and grants the strongest matching permission.

Examples:

- `team2-r` can read buckets like `team2-logs`, `team2-data`.
- `team2-rw` can read and write those buckets.

For copy operations (`CopyObject`, `UploadPartCopy`):

- Destination bucket requires write permission.
- Source bucket requires read permission.

## Supported Capabilities

Path-style S3 API is supported (`/<bucket>/<key>`). Virtual-hosted-style is not.

### Bucket-level

- `GET /` -> List buckets (filtered by read permission).
- `PUT /<bucket>` -> Create bucket.
- `HEAD /<bucket>` -> Head bucket.
- `DELETE /<bucket>` -> Delete bucket.
- `GET /<bucket>?list-type=2` -> List objects v2.
- `GET /<bucket>?versions` -> List object versions.
- `POST /<bucket>?delete` -> Multi-object delete.
- `PUT /<bucket>?versioning` -> Put bucket versioning.
- `GET /<bucket>?versioning` -> Get bucket versioning.
- `PUT /<bucket>?lifecycle` -> Put lifecycle configuration.
- `GET /<bucket>?lifecycle` -> Get lifecycle configuration.
- `DELETE /<bucket>?lifecycle` -> Delete lifecycle configuration.
- `GET /<bucket>?uploads` -> List multipart uploads.

### Object-level

- `GET /<bucket>/<key>` -> Get object.
- `HEAD /<bucket>/<key>` -> Head object.
- `PUT /<bucket>/<key>` -> Put object.
- `PUT /<bucket>/<key>` with `x-amz-copy-source` -> Copy object.
- `GET /<bucket>/<key>?attributes` -> Get object attributes.
- `DELETE /<bucket>/<key>` -> Delete object.

### Multipart upload

- `POST /<bucket>/<key>?uploads` -> Create multipart upload.
- `PUT /<bucket>/<key>?partNumber=N&uploadId=...` -> Upload part.
- `PUT /<bucket>/<key>?partNumber=N&uploadId=...` with `x-amz-copy-source` -> Upload part copy.
- `GET /<bucket>/<key>?uploadId=...` -> List parts.
- `POST /<bucket>/<key>?uploadId=...` -> Complete multipart upload.
- `DELETE /<bucket>/<key>?uploadId=...` -> Abort multipart upload.

### Streaming uploads

- Supports `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (`aws-chunked`).
- Verifies per-chunk signature chain.
- Requires `x-amz-decoded-content-length`.

## Notable Limits / Non-Goals

- Path-style requests only.
- Header-based SigV4 auth only (no presigned URL flow).
- Only implemented operations are supported; unsupported routes return `NotImplemented`.

## Configuration

### Required

- `LDAP_URL` (example: `ldaps://ldap.example.com:636`)
- `LDAP_BASE_DN` (example: `dc=example,dc=com`)
- `S3_ENDPOINT` (example: `http://minio:9000`)
- `S3_ACCESS_KEY`
- `S3_SECRET_KEY`

### Optional

- `LISTEN_ADDR` (default `:8080`)
- `LDAP_GROUP_TTL` (default `2m`)
- `LDAP_GROUP_CACHE_MAX_ENTRIES` (default `10000`)
- `S3_REGION` (default `us-east-1`)
- `S3_FORCE_PATH_STYLE` (default `true`)
- `SIGV4_SECRET` (default `password`, strongly recommended to override)
- `SIGV4_SERVICE` (default `s3`)
- `SIGV4_MAX_SKEW` (default `15m`)
- `HTTP_READ_HEADER_TIMEOUT` (default `10s`)
- `HTTP_READ_TIMEOUT` (default `0s`)
- `HTTP_WRITE_TIMEOUT` (default `0s`)
- `HTTP_IDLE_TIMEOUT` (default `120s`)
- `HTTP_SHUTDOWN_TIMEOUT` (default `20s`)
- `HTTP_MAX_HEADER_BYTES` (default `1048576`)

## Run

```bash
go run .
```

The server supports graceful shutdown on `SIGINT`/`SIGTERM`.

## Client Setup Example

```bash
# Designed credential mapping:
# AccessKey = base64("user@example.com:ldap-password")
export AWS_ACCESS_KEY_ID="$(printf 'user@example.com:ldap-password' | base64)"
export AWS_SECRET_ACCESS_KEY="your-sigv4-secret"
export AWS_REGION="us-east-1"

aws --endpoint-url http://127.0.0.1:8080 s3api list-buckets
```

## SDK Usage Example (Prefix + Delimiter)

```go
bucket := "my-bucket"
prefix := "my-folder/"
input := &s3.ListObjectsV2Input{
    Bucket:    &bucket,
    Prefix:    &prefix,
    Delimiter: aws.String("/"),
}
```

This is supported by the gateway and forwarded upstream.

## Testing

```bash
go test ./...
go test -race ./...
```

Integration tests use Docker via `testcontainers-go`.
