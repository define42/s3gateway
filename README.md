# S3gateway

[![codecov](https://codecov.io/gh/define42/s3gateway/graph/badge.svg?token=GVN99Z1NQC)](https://codecov.io/gh/define42/s3gateway)

An S3-compatible gateway that:

- Authenticates clients with AWS SigV4.
- Supports legacy and encrypted credential formats for `AccessKey`:
  - Legacy: `AD` + `base64("LdapUsername:LdapPassword")`
  - Encrypted: `GenerateKeysX25519(LdapUsername, LdapPassword, s3gateway-publicKey)` output (`X1...`)
- Validates credentials against LDAP.
- Authorizes bucket access by LDAP group naming convention.
- Proxies allowed requests to an upstream S3-compatible backend (for example MinIO, Ceph S3 or AWS S3).

## Authentication Model

- Client signs requests with SigV4.
- `AWS_ACCESS_KEY_ID` supports:
  - `AD` + `base64("<LdapUsername>:<LdapPassword>")` (legacy mode; literal `AD` prefix; username only, no `@domain`)
  - `GenerateKeysX25519(LdapUsername, LdapPassword, s3gateway-publicKey)` access key output (`X1...`, encrypted mode)
- `secretKey` is be derived from the same LDAP credentials by  `base64(sha256(LdapUsername:LdapPassword))`.
- Gateway verifies SigV4 signature and request time window (`SIGV4_MAX_SKEW`).
- In encrypted mode, gateway decrypts `AWS_ACCESS_KEY_ID` using `S3GATEWAY_PRIVATE_X25519_KEY` and extracts `<username>:<password>`.
- Gateway appends `@LDAP_DOMAIN` and binds to LDAP with `<username>@<LDAP_DOMAIN>`.

Important:

- Legacy base64 mode is not encryption. Always use TLS in production.
- `GenerateKeysX25519` encrypts LDAP `username:password` into `AccessKey` and also returns a token-derived `SecretKey` from the same LDAP credentials.

## Credential Derivation Details

For both credential modes, start from:

- `token = "<ldapUsername>:<ldapPassword>"`

`SecretKey` derivation (used as `AWS_SECRET_ACCESS_KEY`):

- `secretKey = base64url(sha256(token))`
- Encoding includes standard base64url padding (`=`), matching `EncodeSecretKey(...)` in this repo.

Legacy `AccessKey` (`AD...`) derivation:

- `accessKey = "AD" + base64(token)`

Encrypted `AccessKey` (`X1...`) derivation:

- `accessKey = "X1" + base64url_no_padding(payload)`
- `payload = ephemeralPublicKey(32) || nonce(12) || ciphertext`
- `ciphertext = ChaCha20-Poly1305(plaintext=token, key=X25519(ephemeralPrivateKey, gatewayPublicKeyHex), aad=nil)`

Notes:

- `X1...` access keys are non-deterministic (new ephemeral key + nonce each generation).
- `secretKey` is deterministic for the same `username:password` token.
- Gateway must have matching `S3GATEWAY_PRIVATE_X25519_KEY` for the public key used by the client.

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
- `SIGV4_SECRET` (default `password`): used to derive admin web-session cookie keys.
- `SIGV4_SERVICE` (default `s3`)
- `SIGV4_MAX_SKEW` (default `15m`)
- `S3GATEWAY_PRIVATE_X25519_KEY` (default empty): hex-encoded X25519 private key used to decrypt encrypted `AWS_ACCESS_KEY_ID` (`X1...`) values generated by `GenerateKeysX25519`.
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
# SecretKey = token-derived key from the same credentials (for example, GenerateKeysBase64Encoded output)
# Gateway LDAP bind identity = "user@${LDAP_DOMAIN}"
export AWS_ACCESS_KEY_ID="AD$(printf 'user:ldap-password' | base64)"
export AWS_SECRET_ACCESS_KEY="your-derived-secret-key"
export AWS_REGION="us-east-1"

aws --endpoint-url http://127.0.0.1:8080 s3api list-buckets
```

Encrypted credential option:

- Configure gateway env `S3GATEWAY_PRIVATE_X25519_KEY` with your X25519 private key (hex).
- On the client, call `GenerateKeysX25519(ldapUsername, ldapPassword, gatewayPublicKeyHex)`.
- Use returned `accessKey` (`X1...`) as `AWS_ACCESS_KEY_ID`.
- `GenerateKeysX25519` also returns `secretKey` derived from the same LDAP credentials.
- Set `AWS_SECRET_ACCESS_KEY` to that returned `secretKey` for request signing.

## Example Client Demos

Repository examples:

- Python legacy/base64 flow: `example_s3_client/python/s3demo.py`
- Python encrypted/X25519 flow: `example_s3_client/python/s3demo_x25519.py`
- Java legacy/base64 flow: `example_s3_client/java/src/main/java/S3Demo.java`

Python encrypted demo notes:

- `s3demo_x25519.py` generates both `accessKey` (`X1...`) and `secretKey` from username/password using X25519 + ChaCha20-Poly1305.
- It currently uses this gateway public key constant:
  - `b0b5d6c181c25c6d8d49aa68ecc85a9f8a0ab0f776680eca733ded24dd95ea31`
- Ensure the gateway private key is the matching pair (`S3GATEWAY_PRIVATE_X25519_KEY`), or auth will fail.
- Python dependencies for this demo include `boto3` and `cryptography`.

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
