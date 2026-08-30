# Changelog

Notable user-visible changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Release versions and dates below come from this repository's Git tags.

## [Unreleased]

### Added

- Added a Go AWS SDK v2 client example using X25519-protected gateway credentials.

### Changed

- S3 authentication now accepts only X25519-encrypted `X1...` access key IDs, and `S3GATEWAY_PRIVATE_X25519_KEY` is required at startup.

### Removed

- Removed the reversible `AD...` Base64 credential format and its legacy Python and Java examples.

## [1.0.64] - 2026-08-28

### Added

- Added `POST /api/pop/{bucket}/{group}` and `POST /api/pop/_all/{group}` to consume Kafka upload events and stream the corresponding S3 object.
- Added bounded Kafka pop-consumer caching, configurable with `KAFKA_POP_TIMEOUT` and `KAFKA_POP_MAX_CONSUMERS`.
- Added at-least-once pop behavior: a Kafka offset is committed only after the complete object body is written and flushed successfully.

### Security

- Pop requests use LDAP-backed HTTP Basic authentication and enforce read permission on the event's bucket. These credentials require HTTPS in production.

## [1.0.63] - 2026-08-28

### Added

- Added simultaneous bucket-named and global Kafka upload-event destinations.
- Added a UUIDv7 `event_id` to upload events so consumers can deduplicate possible retries.

### Changed

- Replaced `KAFKA_TOPIC` with `ENABLE_KAFKA_BUCKET_TOPIC` and `KAFKA_GLOBAL_TOPIC`. Configuring `KAFKA_BROKERS` now requires at least one of those destinations.
- Dual-topic publication shares one `KAFKA_NOTIFICATION_TIMEOUT` and is not transactional; one destination may succeed while another fails.

## [1.0.62] - 2026-08-25

### Changed

- Updated the module, container build, CI, and documented source requirement to Go 1.26.6.

## [1.0.61] - 2026-08-25

### Added

- Added one structured `S3 request completed` audit event for every S3 request, including requests rejected during authentication.
- Added HMAC-SHA256 pseudonyms for principals, buckets, and object keys. `S3_AUDIT_HASH_KEY` enables stable correlation across restarts and replicas.

### Security

- Audit fields omit raw principals, bucket names, object keys, authorization headers, and query values.

## [1.0.60] - 2026-08-24

### Added

- Added optional batched forwarding of structured logs to Splunk HTTP Event Collector (HEC).
- Added HEC endpoint, token, index, and flush-interval configuration and graceful-shutdown flushing.

### Changed

- JSON logging continues on standard output when HEC forwarding is enabled. Failed HEC batches remain buffered up to the implementation's memory limit for retry.

## [1.0.59] - 2026-08-24

### Added

- Added optional Kafka notifications after successful `PutObject` and `CompleteMultipartUpload` operations.
- Added versioned JSON upload events containing the bucket, key, uploader, timestamps, and available S3 identifiers.

### Changed

- Kafka delivery is best effort: a publication failure is logged but does not replace an already-successful S3 response.

## [1.0.58] - 2026-08-24

### Fixed

- Updated the X25519 Python example to read the gateway public key from `S3GATEWAY_PUBLIC_X25519_KEY` instead of embedding a fixed key.
- Added the corresponding private-key pass-through to the local Docker Compose service.
- Corrected the documented X25519 payload framing, `COOKIE_SECRET` minimum length, required startup configuration, and local/container setup.

## [1.0.56] - 2026-08-24

### Changed

- Moved the executable entry point to `./cmd/s3gateway` and separated application composition and process lifecycle handling into `internal/app`.
- Updated the container build and source-run command for the new entry point.

## [1.0.55] - 2026-08-24

### Added

- Added ListObjects v1, GetBucketLocation, bucket encryption configuration, and compatibility responses for common bucket and object ACL/configuration requests.
- Added SigV4 streaming trailer support, including signed-trailer verification and trailing checksum validation.

### Fixed

- Unknown S3 subresources are rejected before bucket or object dispatch.
- Streaming trailer validation withholds the final decoded byte until the signed trailer has been verified.

## [1.0.50] - 2026-08-23

### Fixed

- Applied required-upload-metadata validation and authenticated-uploader stamping to browser-admin uploads.
- Applied the same metadata policy to `CopyObject` when `x-amz-metadata-directive` is `REPLACE`; the default `COPY` behavior continues to inherit source metadata.

## [1.0.49] - 2026-03-01

### Security

- Added security headers to admin responses.
- Increased the minimum configured `COOKIE_SECRET` length to 32 characters.

## [1.0.48] - 2026-03-01

### Security

- Rejected X25519 credential tokens that decrypt to an empty username or password.

## [1.0.46] - 2026-02-28

### Security

- Added HKDF-SHA256 with a random transmitted salt to X25519 shared-secret derivation.
- Bound the credential version, ephemeral public key, and salt to ChaCha20-Poly1305 ciphertext as additional authenticated data.

## [1.0.45] - 2026-02-28

### Fixed

- Corrected LDAP group parsing to split at the first hyphen and require an exact bucket-namespace match.
- Corrected permission selection so the most-specific matching namespace is used instead of combining overlapping prefixes.

## [1.0.0] - 2026-02-10

### Added

- Added the first 1.0-tagged path-style S3 gateway with header-based SigV4 authentication, LDAP credential validation, LDAP-group bucket permissions, and upstream S3 proxying.
- Included the browser administration console, liveness and readiness endpoints, multipart operations, object and bucket tagging, lifecycle configuration, versioning, and streaming SigV4 uploads.

### Security

- The initial 1.0 client credential format carried LDAP credentials in reversible base64 and therefore required TLS.

[Unreleased]: https://github.com/define42/s3gateway/compare/v1.0.64...HEAD
[1.0.64]: https://github.com/define42/s3gateway/releases/tag/v1.0.64
[1.0.63]: https://github.com/define42/s3gateway/releases/tag/v1.0.63
[1.0.62]: https://github.com/define42/s3gateway/releases/tag/v1.0.62
[1.0.61]: https://github.com/define42/s3gateway/releases/tag/v1.0.61
[1.0.60]: https://github.com/define42/s3gateway/releases/tag/v1.0.60
[1.0.59]: https://github.com/define42/s3gateway/releases/tag/v1.0.59
[1.0.58]: https://github.com/define42/s3gateway/releases/tag/v1.0.58
[1.0.56]: https://github.com/define42/s3gateway/releases/tag/v1.0.56
[1.0.55]: https://github.com/define42/s3gateway/releases/tag/v1.0.55
[1.0.50]: https://github.com/define42/s3gateway/releases/tag/v1.0.50
[1.0.49]: https://github.com/define42/s3gateway/releases/tag/v1.0.49
[1.0.48]: https://github.com/define42/s3gateway/releases/tag/v1.0.48
[1.0.46]: https://github.com/define42/s3gateway/releases/tag/v1.0.46
[1.0.45]: https://github.com/define42/s3gateway/releases/tag/v1.0.45
[1.0.0]: https://github.com/define42/s3gateway/releases/tag/v1.0.0
