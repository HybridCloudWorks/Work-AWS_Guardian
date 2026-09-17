resource "aws_dynamodb_table" "drift" {
  name         = "${var.name_prefix}-drift"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S"
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
