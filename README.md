# S3gateway

[![codecov](https://codecov.io/gh/define42/s3gateway/graph/badge.svg?token=GVN99Z1NQC)](https://codecov.io/gh/define42/s3gateway)

An S3-compatible gateway that:

- Authenticates clients with AWS SigV4.
- Uses `AccessKey` as `AD` + `base64("username:password")` (by design).
- Validates credentials against LDAP.
- Authorizes bucket access by LDAP group naming convention.
- Proxies allowed requests to an upstream S3-compatible backend (for example MinIO or AWS S3).

## Authentication Model (By Design)

- Client signs requests with SigV4.
- `AWS_ACCESS_KEY_ID` must be `AD` + `base64("<username>:<password>")` (literal `AD` prefix; username only, no `@domain`).
- `AWS_SECRET_ACCESS_KEY` must match `SIGV4_SECRET`.
- Gateway verifies SigV4 signature and request time window (`SIGV4_MAX_SKEW`).
- Gateway appends `@LDAP_DOMAIN` and binds to LDAP with `<username>@<LDAP_DOMAIN>`.

Important:

- Base64 is not encryption. Always use TLS in production.
- Do not log/redact `Authorization` and credential-related headers at every layer.

## Authorization Model

LDAP groups define bucket prefix permissions:

- `<prefix>-r` -> read access
- `<prefix>-w` -> write access
- `<prefix>-c` -> create bucket
- `<prefix>-d` -> delete object(s)
- `<prefix>-b` -> delete bucket

You can combine permission letters in one group, for example:

- `<prefix>-rwcdb` -> full access for this gateway's operations

Gateway maps each group to bucket prefix `<prefix>-` and combines matching permissions.

Examples:

- `team2-r` can read buckets like `team2-logs`, `team2-data`.
- `team2-rwcdb` can read, write, create buckets, delete objects, and delete buckets.
- `ListBuckets` shows buckets when you have `r` or `w` for the matching bucket prefix.

For copy operations (`CopyObject`, `UploadPartCopy`):

- Destination bucket requires write permission.
- Source bucket requires read permission.

## Supported Capabilities

Path-style S3 API is supported (`/<bucket>/<key>`). Virtual-hosted-style is not.

| Scope | Route / Request | Capability | Required group rule |
| --- | --- | --- | --- |
| Bucket | `GET /` | List buckets | Any permission on bucket prefix (`r`, `w`, `c`, `d`, or `b`); only matching buckets are returned |
| Bucket | `PUT /<bucket>` | Create bucket | `c` on target bucket prefix |
| Bucket | `HEAD /<bucket>` | Head bucket | `r` on target bucket prefix |
| Bucket | `DELETE /<bucket>` | Delete bucket | `b` on target bucket prefix |
| Bucket | `GET /<bucket>?list-type=2` | List objects v2 | `r` on target bucket prefix |
| Bucket | `GET /<bucket>?versions` | List object versions | `r` on target bucket prefix |
| Bucket | `POST /<bucket>?delete` | Multi-object delete | `d` on target bucket prefix |
| Bucket | `PUT /<bucket>?versioning` | Put bucket versioning | `w` on target bucket prefix |
| Bucket | `GET /<bucket>?versioning` | Get bucket versioning | `r` on target bucket prefix |
| Bucket | `PUT /<bucket>?lifecycle` | Put lifecycle configuration | `c` on target bucket prefix |
| Bucket | `GET /<bucket>?lifecycle` | Get lifecycle configuration | `r` on target bucket prefix |
| Bucket | `DELETE /<bucket>?lifecycle` | Delete lifecycle configuration | `b` on target bucket prefix |
| Bucket | `PUT /<bucket>?tagging` | Put bucket tagging | `w` on target bucket prefix |
| Bucket | `GET /<bucket>?tagging` | Get bucket tagging | `r` on target bucket prefix |
| Bucket | `DELETE /<bucket>?tagging` | Delete bucket tagging | `w` on target bucket prefix |
| Bucket | `GET /<bucket>?uploads` | List multipart uploads | `r` on target bucket prefix |
| Object | `GET /<bucket>/<key>` | Get object | `r` on target bucket prefix |
| Object | `HEAD /<bucket>/<key>` | Head object | `r` on target bucket prefix |
| Object | `PUT /<bucket>/<key>` | Put object | `w` on target bucket prefix; if `REQUIRED_UPLOAD_METADATA_KEYS` is set, all listed `x-amz-meta-*` keys must be present |
| Object | `PUT /<bucket>/<key>` with `x-amz-copy-source` | Copy object | Destination bucket: `w`; source bucket: `r` |
| Object | `GET /<bucket>/<key>?attributes` | Get object attributes | `r` on target bucket prefix |
| Object | `DELETE /<bucket>/<key>` | Delete object | `d` on target bucket prefix |
| Object | `PUT /<bucket>/<key>?tagging` | Put object tagging | `w` on target bucket prefix |
| Object | `GET /<bucket>/<key>?tagging` | Get object tagging | `r` on target bucket prefix |
| Object | `DELETE /<bucket>/<key>?tagging` | Delete object tagging | `w` on target bucket prefix |
| Multipart | `POST /<bucket>/<key>?uploads` | Create multipart upload | `w` on target bucket prefix; if `REQUIRED_UPLOAD_METADATA_KEYS` is set, all listed `x-amz-meta-*` keys must be present |
| Multipart | `PUT /<bucket>/<key>?partNumber=N&uploadId=...` | Upload part | `w` on target bucket prefix |
| Multipart | `PUT /<bucket>/<key>?partNumber=N&uploadId=...` with `x-amz-copy-source` | Upload part copy | Destination bucket: `w`; source bucket: `r` |
| Multipart | `GET /<bucket>/<key>?uploadId=...` | List parts | `r` on target bucket prefix |
| Multipart | `POST /<bucket>/<key>?uploadId=...` | Complete multipart upload | `w` on target bucket prefix |
| Multipart | `DELETE /<bucket>/<key>?uploadId=...` | Abort multipart upload | `w` on target bucket prefix |
| Streaming | `PUT` object/part with `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD` | `aws-chunked` streaming uploads | Same as underlying write route (`w`); requires `x-amz-decoded-content-length` and per-chunk signature chain |

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
- `LDAP_DOMAIN` (default `example.com`)
- `LDAP_GROUP_TTL` (default `2m`)
- `LDAP_GROUP_CACHE_MAX_ENTRIES` (default `10000`)
- `S3_REGION` (default `us-east-1`)
- `S3_FORCE_PATH_STYLE` (default `true`)
- `SIGV4_SECRET` (default `password`, strongly recommended to override)
- `SIGV4_SERVICE` (default `s3`)
- `SIGV4_MAX_SKEW` (default `15m`)
- `REQUIRED_UPLOAD_METADATA_KEYS` (default empty): comma-separated required upload metadata keys (for example `legal-ingest-timestamp,case-id`). Keys may be provided with or without `x-amz-meta-` prefix.
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

## Health Endpoints

- `GET /healthz` -> liveness endpoint. Returns `200 OK` when process is running.
- `GET /readyz` -> readiness endpoint. Returns `200 OK` only when both LDAP and upstream S3 are reachable; otherwise returns `503 Service Unavailable`.

Example Kubernetes probes:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080

readinessProbe:
  httpGet:
    path: /readyz
    port: 8080
```

## Client Setup Example

```bash
# Designed credential mapping:
# AccessKey = AD + base64("user:ldap-password")
# Gateway LDAP bind identity = "user@${LDAP_DOMAIN}"
export AWS_ACCESS_KEY_ID="AD$(printf 'user:ldap-password' | base64)"
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
