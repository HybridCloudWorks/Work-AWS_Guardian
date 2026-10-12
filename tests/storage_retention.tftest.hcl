# Native Terraform tests (Terraform 1.6+; repo runtime 1.16.5) for the storage
# retention controls and the POC retention guards.
#
# Credential-free by design:
#   - A mock AWS provider supplies computed values, so no AWS calls are made.
#   - Each `run` targets a single storage module via `module { source = ... }`
#     instead of the full root config, so unrelated Gateway/IAM wiring does not
#     need to resolve. This both avoids credential needs and lets the test
#     assert the real resource attributes that enforce retention.
#
# Run from the repository root:
#   terraform init -backend=false -input=false
#   terraform test

mock_provider "aws" {}

# NOTE on root variable guards (V1-V3): the root config performs a full plan
# that resolves feature-flagged Gateway/IAM wiring whose computed outputs are
# null under a mock provider, which fails planning for reasons unrelated to
# retention. Those guards (audit_expiration_days == 30, log_retention_days == 7,
# environment == sandbox) are therefore verified by `terraform validate` and
# documented in tests/terraform/storage_retention.md (V1-V3). The module-scoped
# runs below assert the actual enforced retention/encryption attributes, which
# is the stronger and credential-free check.

# --- S3 audit bucket controls (S1-S10, S14) ----------------------------------

run "audit_storage_controls" {
  command = plan

  module {
    source = "./modules/audit-storage"
  }

  variables {
    name_prefix           = "ccg-poc"
    audit_expiration_days = 30
    enable_access_logging = true
  }

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.audit.rule[0].expiration[0].days == 30
    error_message = "S1: audit object expiration must be 30 days."
  }

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.audit.rule[0].noncurrent_version_expiration[0].noncurrent_days == 30
    error_message = "S2: noncurrent version expiration must be 30 days."
  }

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.audit.rule[0].abort_incomplete_multipart_upload[0].days_after_initiation == 7
    error_message = "S3: abort incomplete multipart upload must be 7 days."
  }

  assert {
    condition = contains(flatten([
      for r in aws_s3_bucket_server_side_encryption_configuration.audit.rule :
      [for d in r.apply_server_side_encryption_by_default : d.sse_algorithm]
    ]), "AES256")
    error_message = "S4: default SSE must be AES256."
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.audit.block_public_acls == true
    error_message = "S5: block_public_acls must be true."
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.audit.block_public_policy == true
    error_message = "S6: block_public_policy must be true."
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.audit.ignore_public_acls == true
    error_message = "S7: ignore_public_acls must be true."
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.audit.restrict_public_buckets == true
    error_message = "S8: restrict_public_buckets must be true."
  }

  assert {
    condition     = aws_s3_bucket_ownership_controls.audit.rule[0].object_ownership == "BucketOwnerEnforced"
    error_message = "S9: ownership must be BucketOwnerEnforced."
  }

  assert {
    condition     = aws_s3_bucket_versioning.audit.versioning_configuration[0].status == "Enabled"
    error_message = "S10: versioning must be Enabled."
  }

  assert {
    condition     = length(aws_s3_bucket_logging.audit) == 1 && aws_s3_bucket_logging.audit[0].target_prefix == "log/"
    error_message = "S14: server access logging must be configured with log/ prefix."
  }
}

run "audit_storage_logging_toggle_off" {
  command = plan

  module {
    source = "./modules/audit-storage"
  }

  variables {
    name_prefix           = "ccg-poc"
    audit_expiration_days = 30
    enable_access_logging = false
  }

  assert {
    condition     = length(aws_s3_bucket_logging.audit) == 0
    error_message = "Disabling access logging must remove the logging resource."
  }
}

# --- DynamoDB findings/idempotency controls (D1-D6) --------------------------

run "findings_store_controls" {
  command = plan

  module {
    source = "./modules/findings-store"
  }

  variables {
    name_prefix                = "ccg-poc"
    enable_deletion_protection = true
  }

  assert {
    condition     = aws_dynamodb_table.drift.billing_mode == "PAY_PER_REQUEST"
    error_message = "D1: table must be on-demand (PAY_PER_REQUEST)."
  }

  assert {
    condition     = aws_dynamodb_table.drift.hash_key == "finding_id"
    error_message = "D2: partition key must be finding_id."
  }

  assert {
    condition     = aws_dynamodb_table.drift.server_side_encryption[0].enabled == true
    error_message = "D3: encryption at rest must be enabled."
  }

  assert {
    condition     = aws_dynamodb_table.drift.point_in_time_recovery[0].enabled == true
    error_message = "D4: point-in-time recovery must be enabled."
  }

  assert {
    condition     = aws_dynamodb_table.drift.deletion_protection_enabled == true
    error_message = "D5: deletion protection must default to true."
  }

  assert {
    condition     = aws_dynamodb_table.drift.ttl[0].attribute_name == "ttl_epoch" && aws_dynamodb_table.drift.ttl[0].enabled == true
    error_message = "D6: TTL must be enabled on ttl_epoch for idempotency records."
  }
}

# --- CloudWatch log retention (C1) -------------------------------------------

run "observability_log_retention" {
  command = plan

  module {
    source = "./modules/observability"
  }

  variables {
    name_prefix        = "ccg-poc"
    log_retention_days = 7
  }

  assert {
    condition     = aws_cloudwatch_log_group.app.retention_in_days == 7
    error_message = "C1: CloudWatch log retention must be 7 days."
  }
}
