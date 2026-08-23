# S3gateway

[![codecov](https://codecov.io/gh/define42/s3gateway/graph/badge.svg?token=GVN99Z1NQC)](https://codecov.io/gh/define42/s3gateway)

An S3-compatible gateway that:

- Authenticates clients with AWS SigV4.
- Supports two `AWS_ACCESS_KEY` credential formats:
  - Unencrypted (legacy): `AWS_ACCESS_KEY` = `AD` + `base64("LdapUsername:LdapPassword")`
  - Encrypted (recommended): `GenerateKeysX25519(LdapUsername, LdapPassword, s3gateway-publicKey)` output `AWS_ACCESS_KEY`
- Validates credentials against LDAP.
- Authorizes bucket access by LDAP group naming convention.
- Proxies allowed requests to an upstream S3-compatible backend (for example MinIO, Ceph S3 or AWS S3).

## Authentication Model (Two Modes)

S3gateway supports two ways to build `AWS_ACCESS_KEY`:

| Mode | `AWS_ACCESS_KEY` format | Encryption | Python demo |
| --- | --- | --- | --- |
| Unencrypted (legacy) | `AD` + `base64("username:password")` | No | `example_s3_client/python/s3demo.py` |
| Encrypted (X25519) | `X1` + `base64url(x25519(LdapUsername:LdapPassword, s3gatewayPub))` | Yes | `example_s3_client/python/s3demo_x25519.py` |

Both modes use the same `AWS_ACCESS_KEY` derivation:

- `secretKey = base64url(sha256("username:password"))`

Request flow:

- Client signs requests with SigV4.
- Gateway verifies SigV4 signature and request time window (`SIGV4_MAX_SKEW`).
- If `AWS_ACCESS_KEY` starts with `X1`, gateway decrypts it with `S3GATEWAY_PRIVATE_X25519_KEY`.
- Gateway appends `@LDAP_DOMAIN` and binds to LDAP with `<username>@<LDAP_DOMAIN>`.

Important:

- Legacy base64 mode is not encryption. Always use TLS in production.

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
| Bucket | `GET /<bucket>?location` | Get bucket location | Any permission on target bucket prefix |
| Bucket | `GET /<bucket>` | List objects (v1) | `r` on target bucket prefix |
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
| Streaming | `PUT` object/part with `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` | `aws-chunked` streaming uploads with signed trailing checksum | Same as `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, plus `x-amz-trailer-signature` verification and trailing `x-amz-checksum-*` validation |
| Streaming | `PUT` object/part with `x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER` | `aws-chunked` streaming uploads with unsigned trailing checksum (current AWS SDK/CLI default over TLS) | Same as underlying write route (`w`); requires `x-amz-decoded-content-length`; trailing `x-amz-checksum-*` (crc32, crc32c, crc64nvme, sha1, sha256) is validated against the payload |

## Notable Limits / Non-Goals

- Path-style requests only.
- Header-based SigV4 auth only (no presigned URL flow).
- Only implemented operations are supported; unsupported routes return `NotImplemented`.
- Requests carrying a sub-resource of an unimplemented operation (for example `?acl`, `?policy`, `?retention`) are rejected with `NotImplemented` before any bucket/object handler runs, so they can never be misinterpreted as a plain `GET`/`PUT`/`DELETE`.

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
- `SIGV4_MAX_SKEW` (default `15m`)
- `S3GATEWAY_PRIVATE_X25519_KEY` (default empty): hex-encoded X25519 private key used to decrypt encrypted `AWS_ACCESS_KEY` (`X1...`) values generated by `GenerateKeysX25519`.
- `REQUIRED_UPLOAD_METADATA_KEYS` (default empty): comma-separated required upload metadata keys (for example `legal-ingest-timestamp,case-id`). Keys may be provided with or without `x-amz-meta-` prefix.
- `COOKIE_SECRET` (default empty): secret seed used to sign and encrypt admin web-session cookies. When not set, ephemeral random keys are generated at startup and admin sessions are invalidated on every restart (and cannot be shared across multiple instances). **Set this to a strong random value (at least 16 characters) in production.**
- `HTTP_READ_HEADER_TIMEOUT` (default `10s`)
- `HTTP_READ_TIMEOUT` (default `0s`)
- `HTTP_WRITE_TIMEOUT` (default `0s`)
- `HTTP_IDLE_TIMEOUT` (default `120s`)
- `HTTP_SHUTDOWN_TIMEOUT` (default `20s`)
- `HTTP_MAX_HEADER_BYTES` (default `1048576`)
- `ACME_DOMAINS` (default empty): comma-separated domain list. When set, gateway enables automatic HTTPS certificate management via ACME/certmagic.
- `ACME_SERVER` (default `https://acme-v02.api.letsencrypt.org/directory`): ACME directory URL.
- `ACME_DATA_DIR` (default `./certs`): directory used to store ACME account and certificate data.
- `ACME_CA_DIR` (default empty): directory of PEM CA certificate file(s) trusted for TLS when connecting to the ACME server (useful for private ACME endpoints).

## Run

```bash
go run .
```

The server supports graceful shutdown on `SIGINT`/`SIGTERM`.

## ACME (Automatic HTTPS)

S3gateway supports automatic TLS certificates through ACME using `certmagic`.

Minimal setup:

```bash
export ACME_DOMAINS="s3gw.example.com"
go run .
```

Optional overrides:

```bash
export ACME_SERVER="https://acme-v02.api.letsencrypt.org/directory"
export ACME_DATA_DIR="./certs"
# For private ACME servers:
export ACME_CA_DIR="/etc/s3gateway/acme-ca"
```

Behavior:

- `ACME_DOMAINS` accepts comma-separated values and trims spaces.
- If `ACME_DOMAINS` is set, the gateway serves HTTPS using the ACME-managed listener.
- If `ACME_DOMAINS` is empty, the gateway serves plain HTTP on `LISTEN_ADDR`.
- For public ACME CAs, ensure each ACME domain resolves to the gateway host.

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

### 1) Unencrypted authentication (`AD...`) from `example_s3_client/python/s3demo.py`

```python
def generate_gateway_keys(user_upn, user_password):
    token = f"{user_upn}:{user_password}"
    access_key = "AD" + base64.b64encode(token.encode("utf-8")).decode("utf-8")
    secret_key = base64.urlsafe_b64encode(
        hashlib.sha256(token.encode("utf-8")).digest()
    ).decode("utf-8")
    return access_key, secret_key
```

### 2) Encrypted authentication (`X1...`) from `example_s3_client/python/s3demo_x25519.py`

```python
def generate_keys_x25519(user_upn, user_password, public_key_hex):
    receiver_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    token_bytes = f"{user_upn}:{user_password}".encode("utf-8")

    ephemeral_priv = X25519PrivateKey.generate()
    shared_secret = ephemeral_priv.exchange(receiver_pub)
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(shared_secret).encrypt(nonce, token_bytes, None)

    ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    payload = ephemeral_pub_bytes + nonce + ciphertext
    access_key = "X1" + base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")
    secret_key = base64.urlsafe_b64encode(hashlib.sha256(token_bytes).digest()).decode("utf-8")
    return access_key, secret_key
```

For encrypted mode, configure gateway env `S3GATEWAY_PRIVATE_X25519_KEY` with the private key matching the public key used by the client.

Repository demos:

- Python unencrypted flow: `example_s3_client/python/s3demo.py`
- Python encrypted flow: `example_s3_client/python/s3demo_x25519.py`
- Java unencrypted flow: `example_s3_client/java/src/main/java/S3Demo.java`


## Testing

```bash
go test ./...
go test -race ./...
```

Integration tests use Docker via `testcontainers-go`.
