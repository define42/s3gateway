# s3gateway

[![Go Version](https://img.shields.io/github/go-mod/go-version/define42/s3gateway)](https://go.dev/) [![Go](https://github.com/define42/s3gateway/actions/workflows/go.yml/badge.svg)](https://github.com/define42/s3gateway/actions/workflows/go.yml) [![CodeQL](https://github.com/define42/s3gateway/actions/workflows/codeql.yml/badge.svg)](https://github.com/define42/s3gateway/actions/workflows/codeql.yml) [![Codecov](https://codecov.io/gh/define42/s3gateway/graph/badge.svg?token=GVN99Z1NQC)](https://codecov.io/gh/define42/s3gateway) [![Release](https://img.shields.io/github/v/release/define42/s3gateway)](https://github.com/define42/s3gateway/releases/latest)

s3gateway is an authentication and authorization proxy that adds LDAP and
Active Directory (AD) support to S3, which does not provide this integration
natively. It carries a user's X25519-protected LDAP/AD username and password in
S3 credentials, allowing standard S3 clients to authenticate against LDAP/AD.
The gateway then derives and enforces bucket permissions from the user's
LDAP/AD group memberships before forwarding authorized requests to the
configured S3-compatible backend.

## Authentication

Both SigV4 credential fields are generated from the same LDAP username and
password:

```text
access key ID =
    "X1" + base64url(
        ephemeral_public_key || salt || nonce ||
        ChaCha20-Poly1305("username:password")
    )

secret access key =
    base64url(SHA-256("username:password"))
```

The `X1` prefix identifies the credential format. Each access key ID uses the
gateway's published X25519 public key together with a fresh client-side
ephemeral X25519 key pair, salt, and nonce. The gateway uses its private key and
the included ephemeral public key to derive the same encryption key and decrypt
the LDAP credentials. The version, ephemeral public key, and salt are bound to
the ciphertext as additional authenticated data.
`S3GATEWAY_PRIVATE_X25519_KEY` is therefore required when the gateway starts;
access key IDs using any other credential format are rejected. See the
[Python](example_s3_client/python/s3demo_x25519.py) and
[Go](example_s3_client/golang/) implementations.

LDAP usernames must be supplied without the domain suffix: the gateway appends
`@LDAP_DOMAIN` before binding and searching. Usernames cannot contain `:`
because that character separates the username and password in the credential
payload.

For each S3 request, the gateway:

1. Parses the SigV4 authorization data and validates the request timestamp.
2. Decrypts the access key ID and derives the SigV4 secret access key.
3. Verifies the SigV4 request signature, required signed headers, and any
   declared hexadecimal payload digest as the body is consumed.
4. Binds to LDAP as `<username>@<LDAP_DOMAIN>` and loads the user's groups.
5. Applies the group-derived bucket policy and proxies an allowed request.

Always use TLS in production.

Body-bearing requests that use `UNSIGNED-PAYLOAD` or
`STREAMING-UNSIGNED-PAYLOAD-TRAILER` are accepted only over TLS. Plaintext
requests must cryptographically bind their body to the SigV4 signature.

### Encrypted client setup

Generate an X25519 key pair. The gateway receives the private key; clients
receive only the public key:

```bash
eval "$(python3 example_s3_client/python/generate_x25519_keys.py)"
```

Start the local stack from the same shell so Compose passes the private key to
the gateway, then run either encrypted demo with the public key:

```bash
docker compose up --build -d

# Python
python3 example_s3_client/python/s3demo_x25519.py

# Go
export S3GATEWAY_DEMO_PASSWORD=dogood
export S3GATEWAY_DEMO_READONLY_PASSWORD=dogood
go run ./example_s3_client/golang
```

Store production private keys in a secret manager. Do not put them in files
committed to source control or bake them into container images.

## Authorization

Only LDAP groups directly inside the required `LDAP_GROUP_BASE_DN` container
can grant access. For example, with
`LDAP_GROUP_BASE_DN=OU=S3GatewayGroups,DC=example,DC=com`, membership in
`CN=team2-r,OU=S3GatewayGroups,DC=example,DC=com` grants namespace read access;
the same CN in another container or a nested OU is ignored. The gateway compares
parsed DNs case-insensitively before interpreting the group's CN. Malformed DNs
and group RDNs other than a single non-empty CN are ignored. This restriction
also applies to `s3gateway-all-r`, and covers S3, Pop, and browser administration.

Protect the container and its groups from untrusted creation, renaming, and
membership changes, including inherited directory permissions. `LDAP_BASE_DN`
is still the user-search base; it does not define trusted authorization groups.
The development Compose stack uses Glauth's `ou=groups,dc=glauth,dc=com` container.

When upgrading, set `LDAP_GROUP_BASE_DN` explicitly and place authorized groups
directly inside it before restarting every gateway instance. Restarting clears
cached groups and existing admin sessions. A missing, empty, or malformed group
container prevents startup; there is no fallback to unrestricted CN matching.

LDAP group names use `<namespace>-<permissions>`. The namespace is the part of
a bucket name before its first `-`; permissions are one or more letters:

| Letter | Permission |
| --- | --- |
| `r` | Read buckets and objects |
| `w` | Upload objects and set or delete object tags |
| `c` | Create buckets and put bucket configuration or ACLs |
| `d` | Delete objects |
| `b` | Delete buckets and bucket configuration |

For example, `team2-r` can read `team2-logs` and `team2-data`, while
`team2-rwcdb` grants every permission implemented by the gateway for the
`team2` namespace. Permissions from multiple groups for the same namespace are
combined. `ListBuckets` returns matching buckets when the user has any
permission for their namespace.

The reserved LDAP group `s3gateway-all-r` grants read access to every bucket
namespace. It does not grant upload, create, or delete permissions, but those
permissions can still be granted for individual namespaces through additional
groups.

Copy operations require `r` on the source bucket and `w` on the destination
bucket.

## S3 compatibility

Only path-style requests (`/<bucket>/<key>`) are supported. Virtual-hosted-style
requests are not.

| Scope | Route / request | Operation or behavior | Required permission |
| --- | --- | --- | --- |
| Bucket | `GET /` | ListBuckets; only matching buckets are returned | Any permission on the bucket namespace |
| Bucket | `PUT /<bucket>` | CreateBucket | `c` |
| Bucket | `HEAD /<bucket>` | HeadBucket | `r` |
| Bucket | `DELETE /<bucket>` | DeleteBucket | `b` |
| Bucket | `GET /<bucket>?location` | GetBucketLocation | Any permission |
| Bucket | `GET /<bucket>` | ListObjects v1 | `r` |
| Bucket | `GET /<bucket>?list-type=2` | ListObjectsV2 | `r` |
| Bucket | `GET /<bucket>?versions` | ListObjectVersions | `r` |
| Bucket | `POST /<bucket>?delete` | DeleteObjects | `d` |
| Bucket | `PUT /<bucket>?versioning` | PutBucketVersioning | `c` |
| Bucket | `GET /<bucket>?versioning` | GetBucketVersioning | `r` |
| Bucket | `PUT /<bucket>?lifecycle` | PutBucketLifecycleConfiguration | `c` |
| Bucket | `GET /<bucket>?lifecycle` | GetBucketLifecycleConfiguration | `r` |
| Bucket | `DELETE /<bucket>?lifecycle` | DeleteBucketLifecycleConfiguration | `b` |
| Bucket | `PUT /<bucket>?tagging` | PutBucketTagging | `c` |
| Bucket | `GET /<bucket>?tagging` | GetBucketTagging | `r` |
| Bucket | `DELETE /<bucket>?tagging` | DeleteBucketTagging | `b` |
| Bucket | `GET /<bucket>?uploads` | ListMultipartUploads | `r` |
| Bucket | `GET /<bucket>?acl` | Return a canned owner `FULL_CONTROL` ACL | `r` |
| Bucket | `PUT /<bucket>?acl` | Accept the `private` canned ACL as a no-op | `c` |
| Bucket | `PUT /<bucket>?encryption` | PutBucketEncryption | `c` |
| Bucket | `GET /<bucket>?encryption` | GetBucketEncryption | `r` |
| Bucket | `DELETE /<bucket>?encryption` | DeleteBucketEncryption | `b` |
| Bucket | `GET /<bucket>?policy`, `?policyStatus` | Return `NoSuchBucketPolicy`; the gateway has no bucket policies | `r` |
| Bucket | `GET /<bucket>?cors`, `?website`, `?replication` | Return the matching not-configured error | `r` |
| Bucket | `GET /<bucket>?logging`, `?notification`, `?accelerate` | Return an empty or disabled configuration | `r` |
| Bucket | `GET /<bucket>?requestPayment` | Return `BucketOwner` | `r` |
| Bucket | `GET /<bucket>?publicAccessBlock` | Return all public-access blocks enabled | `r` |
| Object | `GET /<bucket>/<key>?acl` | Return a canned owner `FULL_CONTROL` ACL | `r` |
| Object | `PUT /<bucket>/<key>?acl` | Accept `private`, `bucket-owner-read`, or `bucket-owner-full-control` as a no-op | `c` |
| Object | `GET /<bucket>/<key>` | GetObject | `r` |
| Object | `HEAD /<bucket>/<key>` | HeadObject | `r` |
| Object | `PUT /<bucket>/<key>` | PutObject | `w` |
| Object | `PUT /<bucket>/<key>` with `x-amz-copy-source` | CopyObject | Destination `w`; source `r` |
| Object | `GET /<bucket>/<key>?attributes` | GetObjectAttributes | `r` |
| Object | `DELETE /<bucket>/<key>` | DeleteObject | `d` |
| Object | `PUT /<bucket>/<key>?tagging` | PutObjectTagging | `w` |
| Object | `GET /<bucket>/<key>?tagging` | GetObjectTagging | `r` |
| Object | `DELETE /<bucket>/<key>?tagging` | DeleteObjectTagging | `w` |
| Multipart | `POST /<bucket>/<key>?uploads` | CreateMultipartUpload | `w` |
| Multipart | `PUT /<bucket>/<key>?partNumber=N&uploadId=...` | UploadPart | `w` |
| Multipart | `PUT /<bucket>/<key>?partNumber=N&uploadId=...` with `x-amz-copy-source` | UploadPartCopy | Destination `w`; source `r` |
| Multipart | `GET /<bucket>/<key>?uploadId=...` | ListParts | `r` |
| Multipart | `POST /<bucket>/<key>?uploadId=...` | CompleteMultipartUpload | `w` |
| Multipart | `DELETE /<bucket>/<key>?uploadId=...` | AbortMultipartUpload | `w` |
| Streaming | `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` | Verify the `aws-chunked` per-chunk signature chain | Permission required by the underlying write route |
| Streaming | `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` | Verify the chunk chain, signed trailer, and trailing checksum | Permission required by the underlying write route |
| Streaming | `STREAMING-UNSIGNED-PAYLOAD-TRAILER` | Over TLS, validate the trailing CRC32, CRC32C, CRC64NVME, SHA-1, or SHA-256 checksum | Permission required by the underlying write route |

Streaming writes require `x-amz-decoded-content-length`. Signed-trailer mode
also requires `x-amz-trailer-signature`.

## Demo

The included Python and Go clients create a bucket, upload and download an
object, list the result, and confirm that a read-only LDAP user cannot upload:

```console
$ python3 example_s3_client/python/s3demo_x25519.py
Created bucket: team2-data
Uploaded object to s3://team2-data/...
Validation passed: uploaded and downloaded file contents are identical
Readonly check passed: upload denied with AccessDenied
```

## Getting started

### Local Docker Compose stack

The local stack requires Docker with the Compose plugin and Python 3. It starts
MinIO, a test LDAP server, and s3gateway. Create a virtual environment and
generate the X25519 gateway key pair first:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install boto3 cryptography
eval "$(python3 example_s3_client/python/generate_x25519_keys.py)"
docker compose up --build -d
```

The services are available at:

| Service | URL | Credentials |
| --- | --- | --- |
| s3gateway S3 endpoint | `http://localhost:8080` | Generated from an LDAP username and password |
| s3gateway admin console | `http://localhost:8080/login` | `testuser` / `dogood` or `readonly` / `dogood` |
| MinIO console | `http://localhost:9001` | `minioadmin` / `minioadmin` |

`testuser` has full access to the `team2` and `team8` bucket namespaces.
`readonly` has read-only access to `team2`.

Run the encrypted credential demo from the same shell so the client receives
the matching public key. Choose either client:

```bash
# Python
python3 example_s3_client/python/s3demo_x25519.py

# Go
export S3GATEWAY_DEMO_PASSWORD=dogood
export S3GATEWAY_DEMO_READONLY_PASSWORD=dogood
go run ./example_s3_client/golang
```

Stop the stack when finished:

```bash
docker compose down
```

### Published container

Images are published to GitHub Container Registry. Create an environment file
containing at least the six required settings listed under
[Configuration](#configuration), then run:

```bash
docker pull ghcr.io/define42/s3gateway:latest
docker run --rm -p 8080:8080 \
  --env-file ./s3gateway.env \
  ghcr.io/define42/s3gateway:latest
```

Versioned images use the generated `v*` release tag; commit images use the full
Git commit SHA.

### From source

Building from source requires Go 1.27.0 or later and reachable LDAP and upstream
S3 services:

```bash
export LDAP_URL="ldaps://ldap.example.com:636"
export LDAP_BASE_DN="dc=example,dc=com"
export LDAP_GROUP_BASE_DN="ou=S3GatewayGroups,dc=example,dc=com"
export LDAP_DOMAIN="example.com"
export S3_ENDPOINT="https://s3.example.com"
export S3_ACCESS_KEY="upstream-access-key"
export S3_SECRET_KEY="upstream-secret-key"
export S3GATEWAY_PRIVATE_X25519_KEY="64-character-hex-private-key"

go run ./cmd/s3gateway
```

To install the binary first:

```bash
go install github.com/define42/s3gateway/cmd/s3gateway@latest
s3gateway
```

The process emits structured JSON logs and shuts down gracefully on `SIGINT`
or `SIGTERM`.

## Features and reference

- AWS SigV4 authentication backed by LDAP credentials.
- X25519-encrypted client credentials.
- LDAP-group authorization for bucket namespaces and individual operation types.
- Path-style bucket, object, multipart, versioning, lifecycle, tagging,
  encryption, and compatibility operations.
- Browser-based administration using the same LDAP groups.
- Required upload metadata and authenticated-uploader stamping.
- Structured S3 audit events with pseudonymized identifiers.
- Optional Kafka upload events and Splunk HEC log forwarding.
- Optional ACME-managed HTTPS and unauthenticated health endpoints.

### Admin console

Open `/login` in a browser and sign in with an LDAP username without the domain
suffix. The console lists permitted buckets and objects and supports bucket
creation plus object upload, download, and deletion according to the same LDAP
group permissions as the S3 API.

When Kafka is configured, the **Kafka topics** page shows retained element
counts and each topic's consumer groups with their committed offsets by
partition. Users see bucket-named topics only when their LDAP groups grant read
permission for the corresponding bucket namespace. Members of
`s3gateway-all-r` see every topic, including internal topics and the configured
global topic such as `_all`. A committed offset is the next record that group
will consume.

Admin sessions expire 30 minutes after login and are stored in process memory.
They are invalidated on restart and are not shared between gateway replicas.
Set `COOKIE_SECRET` to the same strong value on persistent deployments so the
cookie encryption keys do not change on every restart.

### Upload metadata

`PutObject`, `CreateMultipartUpload`, admin-console uploads, and `CopyObject`
with `x-amz-metadata-directive: REPLACE` stamp the authenticated LDAP username
as `x-amz-meta-uploaded-by`, replacing any client-supplied value.

Set `REQUIRED_UPLOAD_METADATA_KEYS` to a comma-separated list to require
additional `x-amz-meta-*` keys on those creation paths. A `CopyObject` request
using the default `COPY` directive inherits the source object's metadata and is
not revalidated.

### Configuration

Configuration is read from environment variables at startup. Duration values
use Go duration syntax such as `500ms`, `30s`, or `2m`.

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `LDAP_URL` | Yes | — | LDAP URL, for example `ldaps://ldap.example.com:636` |
| `LDAP_BASE_DN` | Yes | — | Search base, for example `dc=example,dc=com` |
| `LDAP_GROUP_BASE_DN` | Yes | — | Trusted group container, for example `ou=S3GatewayGroups,dc=example,dc=com`; only direct child groups grant permissions |
| `S3_ENDPOINT` | Yes | — | Upstream S3-compatible endpoint |
| `S3_ACCESS_KEY` | Yes | — | Upstream S3 access key; this is not a client gateway credential |
| `S3_SECRET_KEY` | Yes | — | Upstream S3 secret key |
| `LISTEN_ADDR` | No | `:8080` | Plain HTTP listen address when ACME is disabled |
| `LDAP_DOMAIN` | No | `example.com` | Domain appended to the client-supplied LDAP username |
| `LDAP_GROUP_TTL` | No | `2m` | Successful LDAP group and rejected-credential cache lifetime |
| `LDAP_GROUP_CACHE_MAX_ENTRIES` | No | `10000` | Maximum group-cache entries; also bounds in-memory admin sessions |
| `LDAP_OPERATION_TIMEOUT` | No | `10s` | Maximum duration of each LDAP dial, bind, or search operation |
| `AUTH_MAX_CONCURRENT` | No | `32` | Total concurrent LDAP authentication operations, including the reserve |
| `AUTH_RATE_PER_SECOND` | No | `20` | Total sustained LDAP authentication rate, including the reserve |
| `AUTH_RATE_BURST` | No | `40` | Total LDAP authentication burst, including the reserve |
| `AUTH_RESERVED_MAX_CONCURRENT` | No | `8` | Concurrent LDAP capacity reserved for credentials that authenticated successfully within `AUTH_TRUSTED_CREDENTIAL_TTL` |
| `AUTH_RESERVED_RATE_PER_SECOND` | No | `5` | Sustained LDAP rate reserved for recently successful credentials |
| `AUTH_RESERVED_BURST` | No | `10` | LDAP burst reserved for recently successful credentials |
| `AUTH_PER_IP_MAX_CONCURRENT` | No | `4` | Maximum concurrent LDAP authentication operations for one client IP |
| `AUTH_PER_IP_RATE_PER_SECOND` | No | `5` | Sustained LDAP authentication rate for one client IP |
| `AUTH_PER_IP_BURST` | No | `10` | LDAP authentication burst for one client IP |
| `AUTH_PER_PRINCIPAL_MAX_CONCURRENT` | No | `2` | Maximum concurrent LDAP authentication operations for one normalized username |
| `AUTH_PER_PRINCIPAL_RATE_PER_SECOND` | No | `2` | Sustained LDAP authentication rate for one normalized username |
| `AUTH_PER_PRINCIPAL_BURST` | No | `4` | LDAP authentication burst for one normalized username |
| `AUTH_INGRESS_PER_IP_RATE_PER_SECOND` | No | `5` | Early per-IP rate for authentication-bearing HTTP requests, before credential parsing or login-body reads; successful authentication restores the token |
| `AUTH_INGRESS_PER_IP_BURST` | No | `40` | Early per-IP burst for authentication-bearing HTTP requests; successful authentication restores the token |
| `AUTH_TRUSTED_CREDENTIAL_TTL` | No | `15m` | How long a successfully authenticated credential fingerprint may use reserved LDAP capacity |
| `TRUSTED_PROXY_CIDRS` | No | Empty | Proxy CIDRs allowed to supply `X-Forwarded-For` for authentication rate-limit attribution |
| `S3_REGION` | No | `us-east-1` | Upstream S3 signing region |
| `S3_FORCE_PATH_STYLE` | No | `true` | Use path-style requests to the upstream S3 service |
| `SIGV4_MAX_SKEW` | No | `15m` | Maximum allowed absolute age or clock skew of a client request |
| `S3GATEWAY_PRIVATE_X25519_KEY` | Yes | — | 64-character hex X25519 private key used to decrypt `X1...` access key IDs |
| `REQUIRED_UPLOAD_METADATA_KEYS` | No | Empty | Comma-separated metadata keys, with or without the `x-amz-meta-` prefix |
| `COOKIE_SECRET` | No | Ephemeral | Admin-cookie key seed; when set, it must contain at least 32 characters |
| `KAFKA_BROKERS` | No | Empty | Comma-separated Kafka bootstrap brokers; empty disables notifications |
| `ENABLE_KAFKA_BUCKET_TOPIC` | No | `false` | Publish each upload event to a topic whose name matches its bucket |
| `KAFKA_GLOBAL_TOPIC` | No | Empty | Optional global upload-event topic |
| `KAFKA_NOTIFICATION_TIMEOUT` | No | `5s` | Maximum total wait for all Kafka acknowledgements |
| `KAFKA_POP_TIMEOUT` | No | `30s` | Maximum individual wait for pop polling and offset commits |
| `KAFKA_POP_MAX_CONSUMERS` | No | `1000` | Maximum cached `{topic, group}` pop consumers; idle consumers are evicted |
| `SPLUNK_HEC_ENDPOINT` | No | Empty | Complete HEC JSON event URL; empty disables HEC forwarding |
| `SPLUNK_HEC_TOKEN` | With HEC | Empty | HEC authentication token |
| `SPLUNK_HEC_INDEX` | With HEC | Empty | Destination Splunk index |
| `SPLUNK_HEC_FLUSH_INTERVAL` | No | `30s` | Interval for batching HEC log events |
| `S3_AUDIT_HASH_KEY` | No | Ephemeral | HMAC seed for stable audit pseudonyms; when set, it must contain at least 32 characters |
| `HTTP_READ_HEADER_TIMEOUT` | No | `10s` | HTTP header-read timeout |
| `HTTP_READ_TIMEOUT` | No | `0s` | HTTP request-read timeout; `0s` disables it |
| `HTTP_WRITE_TIMEOUT` | No | `0s` | HTTP response-write timeout; `0s` disables it |
| `HTTP_IDLE_TIMEOUT` | No | `120s` | HTTP keep-alive idle timeout |
| `HTTP_SHUTDOWN_TIMEOUT` | No | `20s` | Graceful-shutdown timeout |
| `HTTP_MAX_HEADER_BYTES` | No | `1048576` | Maximum request-header size in bytes |
| `ADMIN_LOGIN_READ_TIMEOUT` | No | `10s` | Route-specific deadline for reading browser login POST bodies |
| `READINESS_CHECK_TIMEOUT` | No | `2s` | Maximum duration of a live LDAP and S3 readiness check |
| `READINESS_CACHE_TTL` | No | `5s` | Lifetime of cached readiness success or failure results |
| `READINESS_ALLOWED_CIDRS` | No | `127.0.0.0/8,::1/128` | Direct-client CIDRs allowed to access `/readyz`; forwarded client headers are ignored |
| `ACME_DOMAINS` | No | Empty | Comma-separated certificate domains; empty disables ACME HTTPS |
| `ACME_SERVER` | No | Let's Encrypt production | ACME directory URL |
| `ACME_DATA_DIR` | No | `./certs` | ACME account and certificate storage directory |
| `ACME_CA_DIR` | No | Empty | Directory containing PEM CA files trusted for a private ACME server |

When `COOKIE_SECRET` is empty, the gateway generates ephemeral cookie keys and
logs a warning. Set it to a strong secret in production, but remember that the
session records themselves remain local to each process.

Authentication limits are layered. An LDAP cache miss must pass both its
per-client-IP and per-principal limits before it can use the shared global
pool. The reserved portion of the global totals is available only to an exact
credential pair that authenticated successfully during
`AUTH_TRUSTED_CREDENTIAL_TTL`; a claimed username alone never unlocks it.
Limiter state is bounded by `LDAP_GROUP_CACHE_MAX_ENTRIES` and is process-local.

By default, client-IP attribution uses the direct TCP peer and ignores all
forwarding headers. Configure `TRUSTED_PROXY_CIDRS` only with addresses of
proxies that sanitize or append `X-Forwarded-For`. The gateway then walks the
header from right to left and selects the nearest untrusted address. Deploy an
edge or load-balancer rate limit as well when traffic is distributed across
gateway replicas, because application limiter state is not shared.

### Kafka upload notifications

When `KAFKA_BROKERS` is configured, the S3 API publishes a JSON event after the
upstream confirms `PutObject`, `CopyObject`, or `CompleteMultipartUpload`.
`CopyObject` publishes an `ObjectCreated:Copy` event. Multipart initiation and
individual `UploadPart` and `UploadPartCopy` operations do not produce events.
Admin-console uploads publish the same events as S3 uploads.

Enable bucket topics to publish each event to the topic whose name matches its
bucket:

```dotenv
KAFKA_BROKERS=kafka-1:9092,kafka-2:9092
ENABLE_KAFKA_BUCKET_TOPIC=true
```

Configure `KAFKA_GLOBAL_TOPIC` to publish every event to one global topic:

```dotenv
KAFKA_BROKERS=kafka-1:9092,kafka-2:9092
KAFKA_GLOBAL_TOPIC=_all
```

Set both options for dual delivery:

```dotenv
KAFKA_BROKERS=kafka-1:9092,kafka-2:9092
ENABLE_KAFKA_BUCKET_TOPIC=true
KAFKA_GLOBAL_TOPIC=_all
```

An upload to bucket `images` is then published to topics `images` and `_all`.
Both records contain the same payload and generated UUIDv7 `event_id`. When
`KAFKA_BROKERS` is set, at least one of `ENABLE_KAFKA_BUCKET_TOPIC` or
`KAFKA_GLOBAL_TOPIC` must enable a destination.

The producer requests automatic topic creation; the Kafka cluster must permit
it, or the topics must already exist. Records use `<bucket>/<key>` as the key
and an `application/json` value:

```json
{
  "schema_version": 1,
  "event_id": "019c0000-0000-7000-8000-000000000001",
  "event_name": "ObjectCreated:CompleteMultipartUpload",
  "bucket": "team2-evidence",
  "key": "cases/42/document.pdf",
  "etag": "98f13708210194c475687be6106a3b84-2",
  "version_id": "3Lg...",
  "upload_id": "VXBsb2FkIElE...",
  "uploader": "alice",
  "occurred_at": "2026-08-24T12:30:00Z"
}
```

Delivery is best effort and bounded by one shared
`KAFKA_NOTIFICATION_TIMEOUT`. In dual-topic mode, both records are submitted
before the gateway waits for their acknowledgements, but they are not published
as a Kafka transaction: one topic can succeed while the other fails. A Kafka
failure is logged but does not change the successful S3 response because the
object is already stored upstream. A timeout can leave delivery status unknown,
so consumers must tolerate duplicate events and can use `event_id` for
deduplication.

### Kafka object pop API

When Kafka notifications are configured, authenticated clients can consume an
upload event and stream its corresponding object with:

```http
GET /api/pop/{bucket}/{group}
GET /api/pop/_all/{group}
POST /api/pop/{bucket}/{group}
POST /api/pop/_all/{group}
```

The bucket route consumes the bucket-named topic, requires read access to that
bucket, and therefore requires `ENABLE_KAFKA_BUCKET_TOPIC=true`. The `_all`
route consumes the configured `KAFKA_GLOBAL_TOPIC` and requires membership in
the `s3gateway-all-r` LDAP group before polling. Both routes use HTTP Basic
authentication with the caller's LDAP username without the domain suffix and
password; the gateway appends `@LDAP_DOMAIN` during authentication. The event's
bucket is checked again before its object is read. SigV4 authentication is not
accepted for `/api/pop/*`; other S3 routes continue to require SigV4. The
authenticated username and requested group may each contain letters, digits,
`.`, `_`, and `-`, and must not be `.` or `..`. The gateway always prefixes the
username, so requesting group `scanner` as user `alice` uses the Kafka consumer
group `alice:scanner`.
The fully namespaced ID may be at most 249 bytes long. This prevents another
user from consuming through Alice's group; the same requested group name is
independent for every user.

`GET` and `POST` have identical consuming semantics: either method streams one
object and commits its Kafka offset after successful delivery. Consequently,
`GET` is state-changing and is not safe or idempotent. Do not expose these URLs
to link previewers, browser prefetchers, crawlers, or caches. Pop responses use
`Cache-Control: no-store`.

Basic credentials must be sent only over HTTPS because HTTP Basic encoding does
not encrypt them. For example:

```bash
curl --user 'user' \
  https://s3.example.com/api/pop/images/scanner
```

With the password omitted from `--user`, curl prompts for it instead of placing
it in the shell history.

The response body is the S3 object. `X-S3Gateway-Bucket` identifies its bucket,
and `X-S3Gateway-Object-Key` contains the URL-query-escaped object key. A
successful response uses `Content-Type: application/octet-stream`,
`Content-Disposition: attachment`, and `X-Content-Type-Options: nosniff` so
browsers download objects instead of rendering untrusted content on the admin
interface's origin. The object's original content type and disposition are not
forwarded; object bytes are unchanged. Available object headers such as
`Content-Length`, `ETag`, and `x-amz-version-id` are included. If no event is
available within `KAFKA_POP_TIMEOUT`, the gateway returns `204 No Content`.

Automatic acknowledgement occurs only after the complete object body has been
written and flushed successfully. The gateway then synchronously commits the
Kafka offset. An S3 read failure, short object body, client write failure, or
Kafka commit failure leaves the record unacknowledged and eligible for
redelivery. A successful body followed by an uncertain commit can therefore be
delivered again; clients must tolerate duplicates and may use
`X-S3Gateway-Event-ID` for deduplication.

### Splunk HEC logging

Set the endpoint, token, and index to enable forwarding:

```dotenv
SPLUNK_HEC_ENDPOINT=https://splunk.example:8088/services/collector/event
SPLUNK_HEC_TOKEN=<secret-token>
SPLUNK_HEC_INDEX=s3gateway
SPLUNK_HEC_FLUSH_INTERVAL=30s
```

The gateway continues to emit JSON logs on stdout while batching copies for
HEC. Failed batches remain buffered for the next interval, subject to a 64 MiB
in-memory limit, and pending logs are flushed during graceful shutdown. When
the buffer is full, stdout logging continues and dropped-event counts are
reported on stderr. A response lost after successful ingestion can cause a
retry, so duplicate HEC events are possible. Use HTTPS for the HEC endpoint in
production.

### S3 audit logs

Every S3 request produces one `INFO`-level structured log event named
`S3 request completed`, including requests rejected during authentication.
Health checks and browser-admin requests are excluded. Each event contains:

- `event_kind`, `action`, `method`, `status`, and `outcome`
- `duration_us` and `response_bytes`
- `authenticated` and `handler_completed`
- `request_id`, when the upstream returns a safe `x-amz-request-id`
- `principal_hash`, `bucket_hash`, and `object_key_hash`

The gateway does not put raw principals, bucket names, object keys,
authorization headers, or query values in these audit fields. Identifiers are
HMAC-SHA256 pseudonyms. When `S3_AUDIT_HASH_KEY` is empty, a random key is
generated at startup, so hashes cannot be correlated across restarts or
replicas. Set the same protected value of at least 32 characters on each
instance when stable correlation is required. Splunk HEC receives these events
when HEC forwarding is enabled.

### ACME HTTPS

After setting the required configuration, add one or more certificate domains:

```bash
export ACME_DOMAINS="s3gw.example.com"
go run ./cmd/s3gateway
```

Optional overrides:

```bash
export ACME_SERVER="https://acme-v02.api.letsencrypt.org/directory"
export ACME_DATA_DIR="./certs"
export ACME_CA_DIR="/etc/s3gateway/acme-ca" # private ACME server CA files
```

`ACME_DOMAINS` accepts comma-separated values and trims spaces. When it is set,
the gateway uses the ACME-managed HTTPS listener instead of `LISTEN_ADDR`.
Ensure every public ACME domain resolves to the gateway host and that the
required challenge and HTTPS ports are reachable.

### Health endpoints

Health endpoints do not require SigV4 or LDAP authentication:

| Endpoint | Meaning |
| --- | --- |
| `GET /healthz` | Returns `200 OK` while the process is serving requests |
| `GET /readyz` | Returns `200 OK` when LDAP can be reached and upstream `ListBuckets` succeeds; otherwise `503 Service Unavailable` |

Example Kubernetes probes for the default plain HTTP listener:

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

### Limits and non-goals

- Only header-based SigV4 authentication is supported; presigned URLs are not.
- Only the operations listed above are implemented. Other routes return
  `NotImplemented`.
- Unimplemented S3 subresources such as `?retention`, `?object-lock`, and
  `?select` are rejected before bucket or object dispatch.
- LDAP groups are the only source of authorization. Client-supplied ACLs are
  never forwarded upstream. ACL reads return canned owner `FULL_CONTROL`
  documents, and only owner-retaining canned ACLs are accepted as no-ops for
  client compatibility on bucket creation, object writes/copies, multipart
  initiation, and ACL subresources.
- LDAP `d` permission grants ordinary object deletion only. Requests to bypass
  governance retention are rejected and never forwarded upstream. The shared
  upstream identity should not be granted governance-retention bypass authority.
- For non-streaming signed payloads, the gateway verifies the declared
  `x-amz-content-sha256` digest while streaming and withholds the final byte
  until verification succeeds, so an invalid body cannot complete an upstream
  write.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for prerequisites, local development,
tests, benchmarks, and the pull-request checklist.

## Contributors

See the [GitHub contributors graph](https://github.com/define42/s3gateway/graphs/contributors).

## License

This repository does not currently include a license file. Add an explicit
license before redistributing or reusing the code.
