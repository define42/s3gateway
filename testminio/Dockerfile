FROM alpine:3.23

RUN apk add --no-cache openssl

COPY generate-certs.sh /generate-certs.sh

ENTRYPOINT ["/bin/sh", "/generate-certs.sh"]
