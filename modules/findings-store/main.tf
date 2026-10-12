# Single on-demand table holding BOTH current finding state and operational
# idempotency metadata (design §3.1), kept to one table by the POC cost
# constraint (no second provisioned/always-on table).
#
# Item-type convention (single-table design, keyed on finding_id):
#   - Finding items:     finding_id = "FINDING#<deterministic-finding-id>"
#   - Idempotency items:  finding_id = "IDEMP#<sha256(tool|target_arn|
#                         sorted(params)|expected_finding_version)>"
#     Idempotency items carry: outcome ("APPLIED"|"NOOP"), correlation_id,
#     request_id, created_at, and a ttl_epoch attribute. Only terminal
#     success/no-op outcomes are cached; failures are never cached so a retry
#     re-evaluates (P1.1). Payload mismatch on a reused key is rejected by the
#     tool layer, not by the table schema.
#
# DynamoDB is schemaless beyond the key, so idempotency attributes need no
# schema declaration here. `ttl_epoch` is declared as the TTL attribute so
# idempotency records self-expire without a sweep job; finding items omit it
# and are therefore retained. The hash key stays a single partition key (no
# sort key) because every access is a point lookup by the prefixed id, which
# keeps the table on-demand and cheap.
resource "aws_dynamodb_table" "drift" {
  name         = "${var.name_prefix}-drift"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S"
  }

  # Time-to-live for self-expiring idempotency records (ttl_epoch is a Unix
  # epoch seconds attribute present only on IDEMP# items). Finding items omit
  # the attribute and are never auto-expired.
  ttl {
    attribute_name = "ttl_epoch"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }

  # Reliability/Security pillar: recover current-finding state from accidental
  # writes or deletes. PITR is on-demand priced and fits the POC budget.
  point_in_time_recovery {
    enabled = true
  }

  # Guard against accidental table deletion. Terraform destroy must clear this
  # explicitly, which is the documented teardown step for the POC.
  deletion_protection_enabled = var.enable_deletion_protection
}
