# Go S3 client example

This example creates X25519-encrypted gateway credentials, configures AWS SDK
for Go v2 for path-style requests, uploads and downloads an object, and confirms
that the read-only test user cannot upload.

Start the local stack and export its public key as described in the repository
README, then set the LDAP test passwords and run the client:

```bash
export S3GATEWAY_DEMO_PASSWORD=dogood
export S3GATEWAY_DEMO_READONLY_PASSWORD=dogood
go run ./example_s3_client/golang
```

The example uses `testuser`, `readonly`, `http://localhost:8080`, and
`eu-west-1` by default. Override them with:

- `S3GATEWAY_DEMO_USERNAME`
- `S3GATEWAY_DEMO_READONLY_USERNAME`
- `S3GATEWAY_ENDPOINT_URL`
- `S3GATEWAY_REGION`

`S3GATEWAY_PUBLIC_X25519_KEY`, `S3GATEWAY_DEMO_PASSWORD`, and
`S3GATEWAY_DEMO_READONLY_PASSWORD` are required. Keep LDAP passwords out of
source control and shell history in production workflows.
