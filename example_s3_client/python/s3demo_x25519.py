#!/usr/bin/env python3

import boto3
import base64
import hashlib
import os
import uuid
from botocore.exceptions import NoCredentialsError, ClientError, EndpointConnectionError
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

S3_REGION = "eu-west-1"
S3_ENDPOINT_URL = "http://localhost:8080"
S3GATEWAY_PUBLIC_X25519_KEY = "b0b5d6c181c25c6d8d49aa68ecc85a9f8a0ab0f776680eca733ded24dd95ea31"

HKDF_INFO = b"s3gateway-x25519-v1"
HKDF_SALT_SIZE = 32


def derive_key(shared_secret: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=HKDF_INFO,
    ).derive(shared_secret)


def generate_keys_x25519(user_upn, user_password, public_key_hex):
    if ":" in user_upn:
        raise ValueError("ldap username cannot contain ':' character")

    public_key_bytes = bytes.fromhex(public_key_hex)
    if len(public_key_bytes) != 32:
        raise ValueError("X25519 public key must be 32 bytes")

    receiver_pub = X25519PublicKey.from_public_bytes(public_key_bytes)
    token = f"{user_upn}:{user_password}"
    token_bytes = token.encode("utf-8")

    ephemeral_priv = X25519PrivateKey.generate()
    shared_secret = ephemeral_priv.exchange(receiver_pub)
    ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    salt = os.urandom(HKDF_SALT_SIZE)
    key = derive_key(shared_secret, salt)
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = aead.encrypt(nonce, token_bytes, None)

    payload = ephemeral_pub_bytes + salt + nonce + ciphertext
    access_key = "X1" + base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")
    secret_key = base64.urlsafe_b64encode(
        hashlib.sha256(token_bytes).digest()
    ).decode("utf-8")
    return access_key, secret_key

def get_s3_client(user_upn, user_password):
    access_key, secret_key = generate_keys_x25519(
        user_upn, user_password, S3GATEWAY_PUBLIC_X25519_KEY
    )
    return boto3.client(
        "s3",
        aws_access_key_id=access_key,  # X1 + base64url(ephemeralPub || nonce || chacha20poly1305(token))
        aws_secret_access_key=secret_key,  # sha256("user:ldap-password"), base64url-encoded
        region_name=S3_REGION,
        endpoint_url=S3_ENDPOINT_URL,
    )

def list_s3_buckets(s3):
    try:
        response = s3.list_buckets()

        print("S3 Buckets:")
        for bucket in response.get("Buckets", []):
            print(f"- {bucket['Name']}")

    except NoCredentialsError:
        print("ERROR: Invalid or missing AWS credentials.")
    except EndpointConnectionError as e:
        print(f"ERROR: Could not connect to S3 endpoint: {e}")
    except ClientError as e:
        print(f"AWS Client error: {e.response['Error']['Message']}")
    except Exception as e:
        print(f"Unexpected error: {e}")

def create_bucket_and_upload_file(s3):
    bucket_name = "team2-data"
    object_key = f"team2-data-upload-{uuid.uuid4().hex}.txt"
    content = f"Sample data uploaded by s3demo.py [{object_key}]\n"

    try:
        create_bucket_args = {"Bucket": bucket_name}
        region = s3.meta.region_name
        if region and region != "us-east-1":
            create_bucket_args["CreateBucketConfiguration"] = {
                "LocationConstraint": region
            }
        s3.create_bucket(**create_bucket_args)
        print(f"Created bucket: {bucket_name}")
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
            print(f"Bucket already exists: {bucket_name}")
        else:
            raise

    uploaded_content = content
    s3.put_object(
        Bucket=bucket_name,
        Key=object_key,
        Body=uploaded_content.encode("utf-8"),
        ContentType="text/plain",
    )
    print(f"Uploaded object to s3://{bucket_name}/{object_key} from memory")
    downloaded_object = s3.get_object(Bucket=bucket_name, Key=object_key)
    try:
        downloaded_content = downloaded_object["Body"].read().decode("utf-8")
    finally:
        downloaded_object["Body"].close()
    print(f"Downloaded s3://{bucket_name}/{object_key} into memory")

    if uploaded_content != downloaded_content:
        raise ValueError("Uploaded and downloaded file contents do not match")
    print("Validation passed: uploaded and downloaded file contents are identical")

    objects_response = s3.list_objects_v2(Bucket=bucket_name)
    object_keys = [obj["Key"] for obj in objects_response.get("Contents", [])]
    print(f"Objects in bucket '{bucket_name}':")
    for key in object_keys:
        print(f"- {key}")

    if object_key not in object_keys:
        raise FileNotFoundError(f"Uploaded object '{object_key}' not found in bucket listing")
    print(f"Validation passed: '{object_key}' exists in bucket '{bucket_name}'")
    return bucket_name, object_key, uploaded_content

def check_bucket_name_creation(s3, bucket_name):
    try:
        create_bucket_args = {"Bucket": bucket_name}
        region = s3.meta.region_name
        if region and region != "us-east-1":
            create_bucket_args["CreateBucketConfiguration"] = {
                "LocationConstraint": region
            }
        s3.create_bucket(**create_bucket_args)
        print(f"Bucket creation check passed: created '{bucket_name}'")

        # Clean up the probe bucket so repeated runs do not leave extra state.
        s3.delete_bucket(Bucket=bucket_name)
        print(f"Cleanup complete: deleted '{bucket_name}'")
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in {
            "BucketAlreadyOwnedByYou",
            "BucketAlreadyExists",
            "AccessDenied",
        }:
            print(
                f"Bucket creation check could not create '{bucket_name}': "
                f"{error_code}"
            )
        else:
            raise

def check_readonly_access(bucket_name, object_key, expected_content):
    readonly_client = get_s3_client("readonly", "dogood")

    buckets_response = readonly_client.list_buckets()
    bucket_names = {bucket["Name"] for bucket in buckets_response.get("Buckets", [])}
    if bucket_name not in bucket_names:
        raise PermissionError(f"Readonly user cannot see bucket '{bucket_name}' in list_buckets")
    print(f"Readonly check passed: bucket '{bucket_name}' is visible")

    readonly_object = readonly_client.get_object(Bucket=bucket_name, Key=object_key)
    try:
        readonly_content = readonly_object["Body"].read().decode("utf-8")
    finally:
        readonly_object["Body"].close()
    print(f"Readonly check: downloaded s3://{bucket_name}/{object_key} into memory")

    if readonly_content != expected_content:
        raise ValueError("Readonly downloaded content does not match the uploaded content")
    print("Readonly check passed: downloaded content matches uploaded content")

    readonly_upload_key = f"readonly-upload-attempt-{uuid.uuid4().hex}.txt"
    try:
        readonly_client.put_object(
            Bucket=bucket_name,
            Key=readonly_upload_key,
            Body=b"readonly upload should fail\n",
            ContentType="text/plain",
        )
        raise PermissionError(
            f"Readonly upload unexpectedly succeeded for s3://{bucket_name}/{readonly_upload_key}"
        )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code != "AccessDenied":
            raise
        print(f"Readonly check passed: upload denied with {error_code}")

if __name__ == "__main__":
    s3_client = get_s3_client("testuser", "dogood")
    list_s3_buckets(s3_client)
    bucket_name, object_key, uploaded_content = create_bucket_and_upload_file(s3_client)
    check_bucket_name_creation(s3_client, "donotexist-what")
    check_readonly_access(bucket_name, object_key, uploaded_content)
