#!/usr/bin/env python3

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


private_key = X25519PrivateKey.generate()
private_hex = private_key.private_bytes(
    Encoding.Raw,
    PrivateFormat.Raw,
    NoEncryption(),
).hex()
public_hex = private_key.public_key().public_bytes(
    Encoding.Raw,
    PublicFormat.Raw,
).hex()

print(f"export S3GATEWAY_PRIVATE_X25519_KEY={private_hex}")
print(f"export S3GATEWAY_PUBLIC_X25519_KEY={public_hex}")
