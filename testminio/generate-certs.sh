#!/bin/sh
set -eu

mkdir -p /certs /ca
if [ ! -s /certs/private.key ] || [ ! -s /certs/public.crt ] ||
    ! openssl x509 -checkend 86400 -noout -in /certs/public.crt; then
    umask 077
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -keyout /certs/private.key -out /certs/public.crt \
        -subj '/CN=minio' \
        -addext 'subjectAltName=DNS:minio,DNS:localhost,IP:127.0.0.1' \
        -addext 'basicConstraints=critical,CA:TRUE' \
        -addext 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign' \
        -addext 'extendedKeyUsage=serverAuth'
fi
cp /certs/public.crt /ca/public.crt
chmod 644 /certs/public.crt /ca/public.crt
