# Storage & retention control verification

Task 2.2 exit criterion: *storage controls are plan-visible, least privilege is
reviewed, and retention tests exist.*

Full `terraform plan` requires AWS credentials, which CI does not carry. This
document is the credential-free verification artifact: it lists each storage
control, the exact Terraform attribute that enforces it, and the expected
value. A reviewer confirms each row against `terraform plan` output from a
reviewed HCP run. The variable-validation subset is also machine-checked by
`tests/storage_retention.tftest.hcl` (Terraform native tests, 1.6+).

## S3 audit bucket — `modules/audit-storage`

| # | Control | Attribute (resource.field) | Expected value |
|---|---|---|---|
| S1 | Object expiration = 30 days | `aws_s3_bucket_lifecycle_configuration.audit.rule[0].expiration.days` | `30` |
| S2 | Noncurrent version expiration = 30 days | `aws_s3_bucket_lifecycle_configuration.audit.rule[0].noncurrent_version_expiration.noncurrent_days` | `30` |
| S3 | Abort incomplete MPU = 7 days | `aws_s3_bucket_lifecycle_configuration.audit.rule[0].abort_incomplete_multipart_upload.days_after_initiation` | `7` |
| S4 | Default SSE = AES256 | `aws_s3_bucket_server_side_encryption_configuration.audit.rule[0].apply_server_side_encryption_by_default.sse_algorithm` | `AES256` |
| S5 | Block public ACLs | `aws_s3_bucket_public_access_block.audit.block_public_acls` | `true` |
| S6 | Block public policy | `aws_s3_bucket_public_access_block.audit.block_public_policy` | `true` |
| S7 | Ignore public ACLs | `aws_s3_bucket_public_access_block.audit.ignore_public_acls` | `true` |
| S8 | Restrict public buckets | `aws_s3_bucket_public_access_block.audit.restrict_public_buckets` | `true` |
| S9 | Ownership = BucketOwnerEnforced | `aws_s3_bucket_ownership_controls.audit.rule.object_ownership` | `BucketOwnerEnforced` |
| S10 | Versioning enabled | `aws_s3_bucket_versioning.audit.versioning_configuration.status` | `Enabled` |
| S11 | TLS-only (deny insecure transport) | `aws_s3_bucket_policy.audit` → statement `DenyInsecureTransport` | `Deny` on `aws:SecureTransport = false` |
| S12 | SSE header required | `aws_s3_bucket_policy.audit` → statement `DenyUnencryptedObjectUploads` | `Deny` when `s3:x-amz-server-side-encryption` is Null |
| S13 | SSE algorithm pinned to AES256 | `aws_s3_bucket_policy.audit` → statement `DenyNonAes256ObjectUploads` | `Deny` on `StringNotEquals s3:x-amz-server-side-encryption = AES256` |
| S14 | Server access logging configured | `aws_s3_bucket_logging.audit[0].target_bucket` / `target_prefix` | self (`aws_s3_bucket.audit.id`) / `log/` |

## DynamoDB findings/idempotency table — `modules/findings-store`

| # | Control | Attribute (resource.field) | Expected value |
|---|---|---|---|
| D1 | On-demand (no provisioned capacity) | `aws_dynamodb_table.drift.billing_mode` | `PAY_PER_REQUEST` |
| D2 | Partition key | `aws_dynamodb_table.drift.hash_key` | `finding_id` |
| D3 | Encryption at rest | `aws_dynamodb_table.drift.server_side_encryption.enabled` | `true` |
| D4 | Point-in-time recovery | `aws_dynamodb_table.drift.point_in_time_recovery.enabled` | `true` |
| D5 | Deletion protection | `aws_dynamodb_table.drift.deletion_protection_enabled` | `true` (teardown flips false) |
| D6 | Idempotency TTL attribute | `aws_dynamodb_table.drift.ttl.attribute_name` / `enabled` | `ttl_epoch` / `true` |

## CloudWatch logs — `modules/observability`

| # | Control | Attribute (resource.field) | Expected value |
|---|---|---|---|
| C1 | Log retention = 7 days | `aws_cloudwatch_log_group.app.retention_in_days` | `7` |

## Variable-validation guards (root `variables.tf`)

These are enforced at `terraform validate`/`plan` time and are additionally
asserted by `tests/storage_retention.tftest.hcl`.

| # | Guard | Variable | Rule |
|---|---|---|---|
| V1 | 30-day S3 retention is not configurable away | `audit_expiration_days` | `== 30` or error |
| V2 | 7-day log retention is not configurable away | `log_retention_days` | `== 7` or error |
| V3 | Environment is sandbox only (no prod) | `environment` | `lower(...) == "sandbox"` or error |

## How to run the native test

```
terraform init -backend=false -input=false
terraform test
```

The `.tftest.hcl` uses `command = plan` with no provider calls for the
validation assertions, so it runs without AWS credentials.
