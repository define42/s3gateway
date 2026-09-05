FROM golang:1.27.0-alpine AS builder

WORKDIR /src

RUN apk add --no-cache ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/s3gateway ./cmd/s3gateway

# Non-root identity and a writable data directory for the scratch stage.
# UID/GID 65532 follows the distroless "nonroot" convention.
RUN mkdir -p /out/data /out/etc \
    && echo 's3gateway:x:65532:65532:s3gateway:/data:/sbin/nologin' > /out/etc/passwd \
    && echo 's3gateway:x:65532:' > /out/etc/group

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /out/etc/passwd /out/etc/group /etc/
COPY --from=builder --chown=65532:65532 /out/data /data
COPY --from=builder /out/s3gateway /s3gateway

# /data is the only writable path; the default ACME_DATA_DIR (./certs)
# resolves to /data/certs. ACME mode binds ports 80 and 443, which require
# net.ipv4.ip_unprivileged_port_start=0 when running as this user.
ENV HOME=/data
WORKDIR /data
USER 65532:65532

EXPOSE 8080

ENTRYPOINT ["/s3gateway"]
