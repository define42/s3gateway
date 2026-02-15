import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.*;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class S3Demo {

    private static final String S3_REGION = "eu-west-1";
    private static final String S3_ENDPOINT_URL = "http://localhost:8080";

    private static class GatewayKeys {
        final String accessKey;
        final String secretKey;

        GatewayKeys(String accessKey, String secretKey) {
            this.accessKey = accessKey;
            this.secretKey = secretKey;
        }
    }

    private static GatewayKeys generateGatewayKeys(String userUpn, String userPassword) {
        String token = userUpn + ":" + userPassword;
        String accessKey = "AD" + Base64.getEncoder()
                .encodeToString(token.getBytes(StandardCharsets.UTF_8));

        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8));
            String secretKey = Base64.getUrlEncoder().encodeToString(hash);
            return new GatewayKeys(accessKey, secretKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private static S3Client getS3Client(String userUpn, String userPassword) {
        GatewayKeys keys = generateGatewayKeys(userUpn, userPassword);
        AwsBasicCredentials creds = AwsBasicCredentials.create(keys.accessKey, keys.secretKey);

        // For many local S3 implementations (MinIO, etc.) path-style is required.
        S3Configuration s3Config = S3Configuration.builder()
                .pathStyleAccessEnabled(true)
                .build();

        return S3Client.builder()
                .httpClient(UrlConnectionHttpClient.create())
                .credentialsProvider(StaticCredentialsProvider.create(creds))
                .region(Region.of(S3_REGION))
                .endpointOverride(URI.create(S3_ENDPOINT_URL))
                .serviceConfiguration(s3Config)
                .build();
    }

    private static void listS3Buckets(S3Client s3) {
        try {
            ListBucketsResponse resp = s3.listBuckets();
            System.out.println("S3 Buckets:");
            for (Bucket b : resp.buckets()) {
                System.out.println("- " + b.name());
            }
        } catch (S3Exception e) {
            System.out.println("AWS S3 error: " + safeAwsMessage(e));
        } catch (Exception e) {
            System.out.println("Unexpected error: " + e);
        }
    }

    private static class UploadResult {
        final String bucketName;
        final String objectKey;
        final String uploadedContent;

        UploadResult(String bucketName, String objectKey, String uploadedContent) {
            this.bucketName = bucketName;
            this.objectKey = objectKey;
            this.uploadedContent = uploadedContent;
        }
    }

    private static UploadResult createBucketAndUploadFile(S3Client s3) {
        String bucketName = "team2-data";
        String objectKey = "team2-data-upload-" + UUID.randomUUID().toString().replace("-", "") + ".txt";
        String content = "Sample data uploaded by s3demo.py [" + objectKey + "]\n";

        // Create bucket (ignore already-exists owned-by-you)
        try {
            CreateBucketRequest.Builder req = CreateBucketRequest.builder().bucket(bucketName);

            // Similar to boto3: set LocationConstraint if not us-east-1
            if (!"us-east-1".equalsIgnoreCase(S3_REGION)) {
                req.createBucketConfiguration(
                        CreateBucketConfiguration.builder()
                                .locationConstraint(S3_REGION)
                                .build()
                );
            }

            s3.createBucket(req.build());
            System.out.println("Created bucket: " + bucketName);
        } catch (S3Exception e) {
            String code = awsErrorCode(e);
            if ("BucketAlreadyOwnedByYou".equals(code) || "BucketAlreadyExists".equals(code)) {
                System.out.println("Bucket already exists: " + bucketName);
            } else {
                throw e;
            }
        }

        // Put object
        s3.putObject(
                PutObjectRequest.builder()
                        .bucket(bucketName)
                        .key(objectKey)
                        .contentType("text/plain")
                        .build(),
                RequestBody.fromBytes(content.getBytes(StandardCharsets.UTF_8))
        );
        System.out.println("Uploaded object to s3://" + bucketName + "/" + objectKey + " from memory");

        // Get object into memory
        ResponseBytes<GetObjectResponse> downloaded = s3.getObjectAsBytes(
                GetObjectRequest.builder()
                        .bucket(bucketName)
                        .key(objectKey)
                        .build()
        );
        String downloadedContent = downloaded.asString(StandardCharsets.UTF_8);
        System.out.println("Downloaded s3://" + bucketName + "/" + objectKey + " into memory");

        if (!content.equals(downloadedContent)) {
            throw new IllegalStateException("Uploaded and downloaded file contents do not match");
        }
        System.out.println("Validation passed: uploaded and downloaded file contents are identical");

        // List objects, verify key exists
        ListObjectsV2Response objects = s3.listObjectsV2(
                ListObjectsV2Request.builder()
                        .bucket(bucketName)
                        .build()
        );

        List<String> keys = objects.contents().stream().map(S3Object::key).collect(Collectors.toList());
        System.out.println("Objects in bucket '" + bucketName + "':");
        for (String k : keys) System.out.println("- " + k);

        if (!keys.contains(objectKey)) {
            throw new IllegalStateException("Uploaded object '" + objectKey + "' not found in bucket listing");
        }
        System.out.println("Validation passed: '" + objectKey + "' exists in bucket '" + bucketName + "'");

        return new UploadResult(bucketName, objectKey, content);
    }

    private static void checkBucketNameCreation(S3Client s3, String bucketName) {
        try {
            CreateBucketRequest.Builder req = CreateBucketRequest.builder().bucket(bucketName);
            if (!"us-east-1".equalsIgnoreCase(S3_REGION)) {
                req.createBucketConfiguration(
                        CreateBucketConfiguration.builder()
                                .locationConstraint(S3_REGION)
                                .build()
                );
            }

            s3.createBucket(req.build());
            System.out.println("Bucket creation check passed: created '" + bucketName + "'");

            // Cleanup
            s3.deleteBucket(DeleteBucketRequest.builder().bucket(bucketName).build());
            System.out.println("Cleanup complete: deleted '" + bucketName + "'");
        } catch (S3Exception e) {
            String code = awsErrorCode(e);
            if (Set.of("BucketAlreadyOwnedByYou", "BucketAlreadyExists", "AccessDenied").contains(code)
                    || isAccessDenied(e)) {
                String reason = code.isBlank() ? ("HTTP " + e.statusCode()) : code;
                System.out.println("Bucket creation check could not create '" + bucketName + "': " + reason);
            } else {
                throw e;
            }
        }
    }

    private static void checkReadonlyAccess(String bucketName, String objectKey, String expectedContent) {
        try (S3Client readonly = getS3Client("readonly", "dogood")) {
            ListBucketsResponse buckets = readonly.listBuckets();
            Set<String> names = buckets.buckets().stream().map(Bucket::name).collect(Collectors.toSet());
            if (!names.contains(bucketName)) {
                throw new SecurityException("Readonly user cannot see bucket '" + bucketName + "' in list_buckets");
            }
            System.out.println("Readonly check passed: bucket '" + bucketName + "' is visible");

            ResponseBytes<GetObjectResponse> downloaded = readonly.getObjectAsBytes(
                    GetObjectRequest.builder().bucket(bucketName).key(objectKey).build()
            );
            String readonlyContent = downloaded.asString(StandardCharsets.UTF_8);
            System.out.println("Readonly check: downloaded s3://" + bucketName + "/" + objectKey + " into memory");

            if (!expectedContent.equals(readonlyContent)) {
                throw new IllegalStateException("Readonly downloaded content does not match the uploaded content");
            }
            System.out.println("Readonly check passed: downloaded content matches uploaded content");

            String readonlyUploadKey = "readonly-upload-attempt-" + UUID.randomUUID().toString().replace("-", "") + ".txt";
            try {
                readonly.putObject(
                        PutObjectRequest.builder()
                                .bucket(bucketName)
                                .key(readonlyUploadKey)
                                .contentType("text/plain")
                                .build(),
                        RequestBody.fromString("readonly upload should fail\n")
                );
                throw new SecurityException("Readonly upload unexpectedly succeeded for s3://"
                        + bucketName + "/" + readonlyUploadKey);
            } catch (S3Exception e) {
                String code = awsErrorCode(e);
                if (!isAccessDenied(e)) {
                    throw e;
                }
                String reason = code.isBlank() ? ("HTTP " + e.statusCode()) : code;
                System.out.println("Readonly check passed: upload denied with " + reason);
            }
        }
    }

    private static boolean isAccessDenied(S3Exception e) {
        return "AccessDenied".equals(awsErrorCode(e)) || e.statusCode() == 403;
    }

    private static String awsErrorCode(S3Exception e) {
        if (e.awsErrorDetails() == null) return "";
        String code = e.awsErrorDetails().errorCode();
        return code == null ? "" : code;
    }

    private static String safeAwsMessage(S3Exception e) {
        if (e.awsErrorDetails() != null && e.awsErrorDetails().errorMessage() != null) {
            return e.awsErrorDetails().errorMessage();
        }
        return e.getMessage();
    }

    public static void main(String[] args) {
        try (S3Client s3 = getS3Client("testuser", "dogood")) {
            listS3Buckets(s3);

            UploadResult res = createBucketAndUploadFile(s3);

            checkBucketNameCreation(s3, "donotexist-what");

            checkReadonlyAccess(res.bucketName, res.objectKey, res.uploadedContent);
        }
    }
}
