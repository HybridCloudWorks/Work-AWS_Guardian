# audit-storage

Private, encrypted, lifecycle-bounded S3 bucket for append-only-shaped JSON
audit evidence (design §3.1). No credentials or secrets are ever written here;
redaction happens in the application layer before a record reaches the bucket.

## Controls

| Control | Resource / attribute | Value |
|---|---|---|
| Private bucket (no public ACLs) | `aws_s3_bucket_public_access_block` `block_public_acls` | `true` |
| Private bucket (no public policy) | `aws_s3_bucket_public_access_block` `block_public_policy` | `true` |
| Ignore public ACLs | `aws_s3_bucket_public_access_block` `ignore_public_acls` | `true` |
| Restrict public buckets | `aws_s3_bucket_public_access_block` `restrict_public_buckets` | `true` |
| Ownership (ACLs disabled) | `aws_s3_bucket_ownership_controls` `object_ownership` | `BucketOwnerEnforced` |
| Default encryption at rest | `aws_s3_bucket_server_side_encryption_configuration` `sse_algorithm` | `AES256` (AWS-managed, ADR 0003) |
| Versioning | `aws_s3_bucket_versioning` `status` | `Enabled` |
| Object expiration | `aws_s3_bucket_lifecycle_configuration` `expiration.days` | `var.audit_expiration_days` (30) |
| Noncurrent expiration | `aws_s3_bucket_lifecycle_configuration` `noncurrent_version_expiration.noncurrent_days` | `var.audit_expiration_days` (30) |
| Abort incomplete MPU | `aws_s3_bucket_lifecycle_configuration` `abort_incomplete_multipart_upload.days_after_initiation` | `7` |
| TLS required | bucket policy `DenyInsecureTransport` (`aws:SecureTransport = false`) | Deny |
| SSE header required | bucket policy `DenyUnencryptedObjectUploads` (`s3:x-amz-server-side-encryption` Null) | Deny |
| SSE algorithm pinned | bucket policy `DenyNonAes256ObjectUploads` (`StringNotEquals AES256`) | Deny |
| Server access logging | `aws_s3_bucket_logging` (self-logging, `log/` prefix) | `var.enable_access_logging` (true) |

## SSE pin — how the two deny statements combine

`StringNotEquals` only matches when the key is present, so it alone would let a
header-absent write through. `DenyUnencryptedObjectUploads` catches the
header-absent case (`Null = true`) and `DenyNonAes256ObjectUploads` catches any
present-but-wrong value. Together, every `PutObject` must carry exactly
`x-amz-server-side-encryption: AES256`.

## Access logging — POC decision

Server access logging targets the audit bucket itself under a `log/` prefix
(self-logging) rather than a second always-on log bucket, which the cost/POC
constraint forbids. The existing lifecycle rule expires `log/` objects on the
same 30-day schedule, so access logs do not accumulate cost. If a reviewer
prefers a dedicated log bucket, set `enable_access_logging = false` and
provision one behind its own feature flag.

## Teardown

1. Objects expire automatically at 30 days; for an immediate `terraform
   destroy`, empty the bucket first (including noncurrent versions and the
   `log/` prefix) because versioning is enabled.
2. Set `enable_access_logging = false` to detach the logging configuration if
   it blocks emptying.

## Variables

| Name | Type | Default | Purpose |
|---|---|---|---|
| `name_prefix` | string | — | Resource name prefix. |
| `audit_expiration_days` | number | — | Object expiration (root pins to 30). |
| `enable_access_logging` | bool | `true` | Toggle self-logging. |
