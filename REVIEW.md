# Full Code Review — s3gateway

- **Date:** 2026-08-23
- **Reviewed revision:** `df494f9` (merge of PR #34) — full codebase, docs, tests, and CI
- **Scope:** all Go sources (~8.2k non-test LOC), admin templates, example clients, README/AGENTS, Dockerfile, docker-compose, GitHub workflows
- **Verification run for this review:** `go build ./...` ✅ · `go vet ./...` ✅ · `gofmt -l .` ⚠️ 8 files · unit-test packages (`adminpage`, `authz`, `certreader`, `config`, `s3credentials`, `upstream`) ✅ · Docker-based integration tests not runnable in the review environment

---

## 1. Overall assessment

The project is in good shape for its size. The architecture is clean (auth middleware → authz rules → thin proxy handlers → typed XML encoding), and several things are done notably well:

- SigV4 verification with constant-time signature comparison, plus **per-chunk signature-chain verification** for `aws-chunked` streaming uploads — many gateways skip this.
- The group cache stores a **SHA-256 credential hash, not the password**, uses `subtle.ConstantTimeCompare`, and LDAP lookups are deduplicated with `singleflight`.
- X25519 credential mode v1 uses ephemeral ECDH + **HKDF with random salt** + ChaCha20-Poly1305 with the header fields bound via AAD.
- User-controlled input into the LDAP search filter is escaped (`ldap.EscapeFilter`).
- Admin UI: server-side sessions with encrypted/signed cookie carrying only a random ID, `HttpOnly` + `SameSite=Lax`, Origin/Referer checks on state-changing POSTs, `html/template` with `urlquery` in URLs, security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control: no-store`), and `MaxBytesReader` on form bodies.
- Object bodies are streamed through (no buffering) in both directions; upstream client is tuned (connection pooling, timeouts).
- Good CI hygiene baseline: golangci-lint, gosec target, CodeQL, coverage gate, scheduled benchmarks, wide integration coverage (glauth LDAP, MinIO, Ceph, real `minio-go` client).

The findings below are ordered by severity. The most important items are two **authenticated memory-exhaustion DoS vectors** (F-1, F-2), a set of **policy-bypass inconsistencies** around required upload metadata / `uploaded-by` stamping (F-6), and **admin-session lifetime/cookie hardening** (F-3, F-4, F-5). None of the findings is an unauthenticated remote-compromise vector.

---

## 2. High severity

### F-1: Unbounded allocations in the aws-chunked reader — authenticated OOM DoS
`internal/sigv4/sigv4.go:516-520` — `beginChunk` trusts the client-supplied chunk size and buffers the whole chunk:

```go
if n > int64(^uint(0)>>1) { ... }   // on 64-bit this never triggers
chunk := make([]byte, int(n))
if _, err := io.ReadFull(r.br, chunk); err != nil { ... }
```

Any authenticated user with `w` on any prefix can send a single `PUT` with a chunk header claiming e.g. `0x200000000` (8 GiB); the gateway attempts the allocation before reading a single payload byte and is OOM-killed. Two more unbounded reads in the same reader:

- `internal/sigv4/sigv4.go:492` — `r.br.ReadString('\n')` for the chunk header line has no length cap; a request that streams gigabytes with no `\n` accumulates into memory.
- `internal/sigv4/sigv4.go:589-599` — `consumeTrailers` has the same unbounded `ReadString`.

**Recommendation:** reject chunk sizes above a sane cap (AWS SDK chunks are ≤ 1 MiB; 16–64 MiB is a generous limit), and read the header/trailer lines through a bounded reader (error out past e.g. 4 KiB). Also consider verifying that the decoded byte total matches `x-amz-decoded-content-length`.

### F-2: Unbounded XML request bodies on the S3 API — authenticated memory DoS
All XML-decoding S3 handlers pass `r.Body` straight to `xml.NewDecoder` with no size limit:

- `internal/server/handlers_object.go:167` (DeleteObjects — the 1..1000 objects check runs only *after* full decode)
- `internal/server/handlers_multipart.go:343` (CompleteMultipartUpload)
- `internal/server/handlers_lifecycle.go:502` (PutBucketLifecycleConfiguration)
- `internal/handler_bucket/handler_bucket.go:24,97` (versioning, bucket/object tagging)

A multi-gigabyte `<Delete>` document (or one huge `<Key>` element) is buffered into decoded strings before any limit applies. The admin UI already does this correctly (`maxAdminFormBodySize` 64 KiB, `adminpage.go:1025`); the S3 API should too.

**Recommendation:** wrap each XML body in `http.MaxBytesReader` (1 MiB is far above any legitimate payload for these operations; AWS itself caps DeleteObjects requests well below that).

---

## 3. Medium severity

### F-3: Admin session cookie is never `Secure` behind a TLS-terminating proxy
`internal/adminpage/adminpage.go:491,516` — `session.Options.Secure = r.TLS != nil`. When TLS is terminated at a load balancer / ingress (a very common deployment; the gateway itself often listens on plain HTTP), `r.TLS` is nil and the session cookie is issued **without** the `Secure` attribute, so the browser will also send it over `http://`.

**Recommendation:** add a config knob (`COOKIE_SECURE=true` or trust of `X-Forwarded-Proto`) and default to `Secure` whenever the deployment is HTTPS-fronted.

### F-4: Admin sessions slide forever and never re-check LDAP
`internal/adminpage/adminpage.go:288-296` — every `get` extends `Expires = now + ttl`, with no absolute cap, and the group set is a snapshot taken at login (`handleAdminLogin`). Consequences: a disabled/offboarded LDAP user, or one whose groups were revoked, keeps full admin-UI access (read/upload/delete objects, create buckets) indefinitely as long as they keep the tab active.

**Recommendation:** add an absolute session lifetime (e.g. 8–12 h) and/or refresh groups periodically. Note the S3 API path does not have this problem (`LDAP_GROUP_TTL`, default 2 min).

### F-5: Login form lacks the same-origin check the other admin POSTs have (login CSRF)
`internal/adminpage/adminpage.go:1004-1085` — `handleAdminLogin` accepts a cross-site form POST (`hasTrustedAdminOrigin` is enforced on create-bucket/upload/delete/logout, but not on login). `SameSite=Lax` does not help here because a login CSRF does not need an existing cookie: an attacker can silently log the victim's browser into an attacker-controlled LDAP account; anything the victim then uploads via the admin UI lands in attacker-visible buckets stamped `uploaded-by: attacker`.

**Recommendation:** apply `hasTrustedAdminOrigin` to the login POST as well.

### F-6: `REQUIRED_UPLOAD_METADATA_KEYS` / `uploaded-by` stamping can be bypassed
The policy is enforced on `PutObject` and `CreateMultipartUpload` (`handlers_object.go:1176-1180`, `handlers_multipart.go:130-135`), but not on the other paths that create objects:

1. **CopyObject** (`handlers_object.go:1323`): with `x-amz-metadata-directive: REPLACE` the caller fully controls the destination metadata — required keys were not checked and, unlike PutObject, `uploaded-by` was **not** overwritten, so it could be spoofed or omitted. Any user with `w` on a destination and `r` on any source could mint objects that violate the metadata policy. (UploadPartCopy is *not* affected — individual parts carry no object metadata; the policy applies at `CreateMultipartUpload`, which already enforces it.) **FIXED** in this PR: the copy handler now stamps `uploaded-by` and enforces `REQUIRED_UPLOAD_METADATA_KEYS` when the directive is `REPLACE`, with regression coverage in `internal/server/copy_metadata_policy_test.go`.
2. **Admin-UI upload** (`adminpage.go`): `uploaded-by` is stamped from the session (good), but required metadata keys were never checked, so the browser upload path silently bypassed the policy that the S3 API rejects with 400. **FIXED** in this PR: the required keys are threaded into the admin handler, the upload form renders a required input per key (`meta-<key>`), and `handleAdminBucketUpload` enforces them before starting the upload; coverage in `internal/adminpage/upload_required_metadata_test.go`.

**Recommendation:** ~~run `missingRequiredUploadMetadata` + `ensureUploadedByMetadata` on the copy path when the directive is `REPLACE`~~ (done); ~~enforce required keys on admin uploads~~ (done).

**Residual (accepted, not fixed):** the `COPY` directive inherits the source object's metadata verbatim, so a non-compliant *source* object (one written before the policy existed, or placed directly in the backend outside the gateway) can still be propagated by a copy. Closing this would require the gateway to `HEAD` the source and validate its metadata on every copy — a per-request latency/cost hit and a deviation from S3 semantics (AWS allows such copies). Since all *creation* paths through the gateway now enforce the policy, the practical exposure is limited to pre-existing/externally-written objects; strict enforcement is left as an opt-in follow-up rather than default behavior.

### F-7: SigV4 verification does not require critical headers to be signed, and never verifies the payload hash
`internal/sigv4/sigv4.go:129-166`:

- The gateway signs over whatever `SignedHeaders` the client lists; there is no check that `host` and all present `x-amz-*` headers are included (AWS rejects unsigned `x-amz-*` headers). `x-amz-date` and the *value* of `x-amz-content-sha256` are independently protected via `stringToSign`/canonical request, but headers like `x-amz-copy-source`, `x-amz-metadata-directive`, `x-amz-bypass-governance-retention`, `x-amz-meta-*` are only protected if the client chose to sign them.
- For non-streaming uploads the gateway never hashes the body to compare against a hex `x-amz-content-sha256` (real S3 returns `XAmzContentSHA256Mismatch`); `UNSIGNED-PAYLOAD` is accepted unconditionally.

Over TLS neither matters much; over the plain-HTTP listener this voids the integrity guarantees users assume SigV4 gives them (an on-path attacker can swap request bodies or redirect a copy source of a captured request within the 15-minute skew window — there is also no replay cache, which is inherent to SigV4).

**Recommendation:** enforce that `host` and every present `x-amz-*` header is in `SignedHeaders`; optionally verify the payload hash for non-streaming bodies (it streams through a hasher cheaply); document loudly that plain-HTTP deployments are only for closed networks.

### F-8: No throttling of authentication attempts; gateway is an LDAP password oracle
Every request with fresh credentials — S3 API (`server.go:136`) or admin login — triggers a live LDAP bind; failures are not negatively cached and there is no per-IP/per-UPN rate limit. The gateway can be used to spray passwords against the directory (constrained only by LDAP-side lockout), and doubles as a load amplifier toward LDAP. Related: unauthenticated `/readyz` performs an upstream `ListBuckets` **and** an LDAP dial per hit (`server.go:401-413`) and echoes internal error strings (`not ready: ldap: dial tcp 10.x.x.x:636 ...`) to anonymous callers (`server.go:423`).

**Recommendation:** add a small failed-auth negative cache (even 5–10 s) and basic per-IP rate limiting; cache the `/readyz` probe result for a couple of seconds and log details server-side instead of echoing them.

---

## 4. Low severity / hardening

- **F-9 — Legacy `AD` credentials cannot be disabled.** `internal/s3credentials/s3credentials.go:10-16`: even with `S3GATEWAY_PRIVATE_X25519_KEY` configured, plain-base64 credentials always remain accepted, so the encrypted mode adds no enforceable guarantee. Add e.g. `DISABLE_LEGACY_CREDENTIALS=true`.
- **F-10 — Auth errors use HTTP 401 + code `AccessDenied`** (`server.go:117-139`). Real S3 uses 403 with `AccessDenied` / `SignatureDoesNotMatch` / `InvalidAccessKeyId`; some SDK retry/error mapping branches on these. Prefer S3-conformant status/code pairs.
- **F-11 — Container runs as root.** `Dockerfile` (scratch stage) has no `USER` directive; add a non-root uid. `GOARCH=amd64` is also hardcoded — no arm64 image.
- **F-12 — No CSP on the admin pages.** `adminpage.go:1754-1757` sets nosniff/frame headers; the templates use inline CSS, so a nonce/`style-src` CSP would be the next step. Also `msg`/`err` query params render attacker-influenced (escaped) text on the dashboard — a minor phishing aid.
- **F-13 — `main.go` data race on `tlsLn`** (`main.go:59,109,150`): written by the server goroutine, read by `main` after a signal, no synchronization. Harmless in practice, but a `-race` CI run could flag it; hand the listener over via channel or mutex.
- **F-14 — `AdminSessionStore.save` ID-reuse branch** (`adminpage.go:238-249`) is unreachable from the login flow (a valid session redirects before save) but would re-bind an existing session ID to a new identity if ever reached. Always mint a fresh ID on (re)login.
- **F-15 — testldap private key in repo** (`testldap/key.pem`). Clearly a test fixture for glauth; fine, but worth an allowlist entry for secret scanners and a README note.

---

## 5. Correctness / S3-compatibility gaps

- **F-16 — PutObject / CreateMultipartUpload silently drop request attributes.** `handlers_object.go:1215-1258` forwards metadata/SSE/checksums but ignores `x-amz-tagging`, `x-amz-storage-class`, `x-amz-acl`, `Cache-Control`, `Content-Disposition`, `Content-Encoding`, `Content-Language`, `x-amz-website-redirect-location`, and object-lock headers — clients get 200 OK and the attributes are simply lost (CopyObject *does* forward most of them, which makes the asymmetry surprising). Forward them or reject requests carrying them.
- **F-17 — Trailer-based streaming modes are rejected.** Only `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` is accepted (`sigv4.go:427,604`). Since the 2025 "flexible checksums" defaults, current AWS SDKs/CLI send `STREAMING-UNSIGNED-PAYLOAD-TRAILER` (or the signed trailer variant) for uploads by default, which this gateway 400s. Either implement the trailer modes or document that clients must set `request_checksum_calculation = when_required` (README says only "requires per-chunk signature chain", which understates the interop impact).
- **F-18 — Metadata key double-strip.** `extractAmzMeta` (`handlers_object.go:1752-1768`) trims `x-amz-meta-`, then `NormalizeRequiredMetadataKey` trims the prefix *again*, so `x-amz-meta-x-amz-meta-foo` is stored as `foo`. Also only the first value of a repeated metadata header survives. Use a normalization that strips the prefix exactly once at this call site.
- **F-19 — CreateBucket ignores the request body** (`handlers_bucket.go:42-54`): `CreateBucketConfiguration`/`LocationConstraint`, `x-amz-acl`, and object-lock headers are dropped; response lacks the `Location` header. `CompleteMultipartUpload` likewise omits `Location` and silently discards malformed `<Part>` entries instead of returning 400 (`handlers_multipart.go:348-365`). `ListBuckets` output has no `CreationDate`/`Owner` and ignores `max-buckets`/`continuation-token`/`prefix`.
- **F-20 — `handleListMultipartUploads` casts `encoding-type` unvalidated** (`handlers_multipart.go:41-43`, `types.EncodingType(v)`) while every other handler goes through `ParseEncodingType`.
- **F-21 — Legacy credential decoding trims the token.** `S3CredentialsBase64Encoded` (`s3credentials_base64encoded.go:24`) runs `strings.TrimSpace` over `username:password` before deriving the secret, so passwords with leading/trailing whitespace can never authenticate (client derives the secret over the untrimmed token). Trim only the username.
- **F-22 — LDAP domain escaping is applied in the wrong context.** `ldap.go:36` filter-escapes the domain when building the *bind* UPN (bind names are not filters), and the same pre-escaped string is then escaped a second time inside the search filter (`ldap.go:42`). Works only because real domains contain no filter metacharacters; escape raw values exactly once, at the filter site. (User input is correctly escaped — good.)
- **F-23 — README ListBuckets rule contradiction.** README line 59 says listing needs "`r` or `w`"; the capability table (line 72) and the code (`handlers_bucket.go:32`, any permission bit) disagree. Align docs with code.

---

## 6. Documentation

- **F-24 — README X25519 example is stale and non-functional.** The embedded `generate_keys_x25519` snippet (README lines 214-232) shows the *pre-HKDF* format: no salt, raw ECDH shared secret used directly as the ChaCha key, no AAD, `payload = epub + nonce + ciphertext`. The server (since the HKDF change, PR #30) requires `epub + salt + nonce + ciphertext` with HKDF-SHA256 and AAD binding — which `example_s3_client/python/s3demo_x25519.py` correctly implements. Anyone implementing a client from the README will fail to authenticate. Replace the snippet with the current one (and fix the nearby wording: "Both modes use the same `AWS_ACCESS_KEY` derivation" then shows the *secret key* derivation).
- **F-25 — COOKIE_SECRET length mismatch.** README line 132 says "at least 16 characters"; `config.go:111` enforces ≥ 32.
- **F-26 — AGENTS.md is stale.** It still describes root-level `config.go`/`adminpage.go`, templates in `webtemplate/`, and "most tests at root", none of which matches the current `internal/` layout.
- **F-27 — Leftover AI-citation artifacts** in comments: `:contentReference[oaicite:8]{index=8}` (`sigv4.go:148`) and `:contentReference[oaicite:6]{index=6}` (`upstream.go:19`). Delete them.

---

## 7. Code quality

- **F-28 — gofmt drift with no formatting gate.** `gofmt -l` flags 8 files, including `internal/adminpage/adminpage.go`, `internal/config/config.go`, and `internal/sigv4/sigv4.go`. There is no `.golangci.yml`, and golangci-lint's default preset does not check formatting, so CI stays green while the repo drifts from the AGENTS.md rule. Run `gofmt -w .` and add `gofmt`/`gofumpt` to an explicit `.golangci.yml`.
- **F-29 — Reflection to read a deprecated SDK field.** `lifecycleRuleLegacyPrefix` (`handlers_lifecycle.go:630-640`) uses `reflect` to dodge the `LifecycleRule.Prefix` deprecation warning; if the SDK drops the field this silently returns nil. Access it directly with a `//nolint:staticcheck` and a comment.
- **F-30 — Dead/miswired admin plumbing.** `adminBucketView.ObjectKeys/ObjectsTruncated/ObjectListError` are never populated; `NewHandler`'s `maxSessions` is fed `cfg.GroupCacheMaxEntries` (an unrelated knob); the 30-minute admin TTL is hardcoded. Introduce dedicated config (e.g. `ADMIN_SESSION_TTL`, `ADMIN_MAX_SESSIONS`) and delete the dead fields.
- **F-31 — Massive duplicated header-copy blocks.** `handleGetObject`/`handleHeadObject` each hand-copy ~40 response headers (`handlers_object.go:650-758, 856-968`); a shared table-driven copier would halve the file and keep the two paths in sync.
- **F-32 — `envRequired`/`os.Exit` inside `LoadConfig`** (`config.go:125-131`) bypasses the error-return path `BootS3Gateway` already has, and makes missing-env behavior untestable. Return errors up to `main`.
- **F-33 — Minor sigv4 cleanups.** `constantTimeEq` re-implements `subtle.ConstantTimeCompare`/`hmac.Equal`; `canonicalQuery`'s `sort.Strings(vs)` (`sigv4.go:187`) is redundant given the later full `sort.Slice`.

---

## 8. Tests & CI

- **F-34 — Integration tests cannot be skipped.** Docker-backed tests (testcontainers) live in normal `_test.go` files with no `testing.Short()` guard, docker-availability check, or build tag; on a machine without Docker `go test ./...` fails outright (reproduced in this review). Add a guard (`-short` skip or `//go:build integration`).
- **F-35 — CI never runs the race detector**, although AGENTS.md demands it for auth/concurrency changes (and F-13 is exactly the kind of thing it catches). Add a `go test -race` job (unit packages only, if time-bound).
- **F-36 — No in-package tests for `sigv4`, `groupcache`, `ldap`, `xmlhelper`, `handler_bucket`.** They are exercised indirectly via `-coverpkg` from server/root tests, but the chunked-reader edge cases from F-1 (huge chunk header, missing CRLF, trailer handling) deserve direct unit tests.
- **F-37 — Codecov step breaks fork PRs.** `codecov-action@v4` with a secret token and `fail_ci_if_error: true` fails for external contributors whose runs cannot see `secrets.CODECOV_TOKEN`.
- **F-38 — Go version skew.** Dockerfile builds with `golang:1.24-alpine`, CI uses Go `1.25`, `go.mod` pins `toolchain go1.24.13`. Harmless today, but pick one source of truth.

---

## 9. Suggested priority order

| Priority | Items | Theme |
| --- | --- | --- |
| 1 | F-1, F-2 | Authenticated DoS: cap chunk sizes/lines, `MaxBytesReader` on XML bodies |
| 2 | F-6, F-3, F-4, F-5 | Policy bypasses + admin-session hardening |
| 3 | F-7, F-8, F-9, F-10 | SigV4 strictness, auth throttling, legacy-mode switch |
| 4 | F-16, F-17 | Client-visible correctness (dropped attributes, trailer streaming modes) |
| 5 | F-24 … F-27 | Documentation fixes (README X25519 snippet first — it actively misleads) |
| 6 | F-28 … F-38 | Formatting gate, cleanups, test/CI hygiene |

Items in priorities 1, 2, and 5 are all small, low-risk changes; the largest engineering effort in the list is F-17 (trailer-mode streaming support).
