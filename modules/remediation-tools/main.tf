# Remediation tool Lambda stubs.
#
# Design §3.3: Each tool target is a small Lambda with an explicit input/output
# schema and a separate least-privilege execution role. The target rechecks
# safety preconditions but cannot override a Gateway denial.
#
# Four approved tools (CCG-REQ-013 / design §3.3):
#   1. sg-correction   — restrict one approved sandbox SG ingress rule
#   2. s3-encryption   — enable approved encryption on an eligible sandbox bucket
#   3. tagging         — add/correct approved compliance tags
#   4. key-rotation    — rotate a specifically approved sandbox access key
#
# GATING: All resources are gated behind `enable_remediation_tools` (default false).
#
# PREREQUISITES (gate-0.2 before enabling):
#   - tool_execution_role_arn must reference the confirmed least-privilege role.
#   - Gateway ARN and tool target schema must be captured.
#   - Lambda deployment packages must be built (placeholder used here).
#
# NAMING: Functions are named `{prefix}-tool-*` so the Gateway execution role's
# wildcard ARN (`function:{prefix}-tool-*`) already covers these functions.

locals {
  # Shared environment variables passed to every tool Lambda.
  tool_env = {
    FINDINGS_TABLE_NAME = var.findings_table_name
    AUDIT_BUCKET_NAME   = var.audit_bucket_name
    LOG_GROUP_NAME      = var.log_group_name
  }
}

# --- 1. Security-group correction tool ----------------------------------------
resource "aws_lambda_function" "sg_correction" {
  count = var.enable_remediation_tools ? 1 : 0

  function_name = "${var.name_prefix}-tool-sg-correction"
  description   = "CCG: correct one approved sandbox SG ingress rule. Idempotent; rejects global-open ingress."

  runtime  = "python3.14"
  handler  = "ccg.tools.sg_correction_handler"
  role     = var.tool_execution_role_arn
  filename = "${path.module}/placeholder.zip"

  timeout     = var.lambda_timeout_seconds
  memory_size = var.lambda_memory_mb

  environment {
    variables = local.tool_env
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Component = "tool-sg-correction"
    CCGDemo   = "true"
  }
}

# --- 2. S3 encryption enablement tool ----------------------------------------
resource "aws_lambda_function" "s3_encryption" {
  count = var.enable_remediation_tools ? 1 : 0

  function_name = "${var.name_prefix}-tool-s3-encryption"
  description   = "CCG: enable approved SSE on an eligible sandbox bucket. Idempotent; never makes bucket public."

  runtime  = "python3.14"
  handler  = "ccg.tools.s3_encryption_handler"
  role     = var.tool_execution_role_arn
  filename = "${path.module}/placeholder.zip"

  timeout     = var.lambda_timeout_seconds
  memory_size = var.lambda_memory_mb

  environment {
    variables = local.tool_env
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Component = "tool-s3-encryption"
    CCGDemo   = "true"
  }
}

# --- 3. Compliant tagging tool -----------------------------------------------
resource "aws_lambda_function" "tagging" {
  count = var.enable_remediation_tools ? 1 : 0

  function_name = "${var.name_prefix}-tool-tagging"
  description   = "CCG: add/correct approved compliance tags on an eligible target. Never writes Environment=prod."

  runtime  = "python3.14"
  handler  = "ccg.tools.tagging_handler"
  role     = var.tool_execution_role_arn
  filename = "${path.module}/placeholder.zip"

  timeout     = var.lambda_timeout_seconds
  memory_size = var.lambda_memory_mb

  environment {
    variables = local.tool_env
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Component = "tool-tagging"
    CCGDemo   = "true"
  }
}

# --- 4. Access-key rotation workflow tool ------------------------------------
resource "aws_lambda_function" "key_rotation" {
  count = var.enable_remediation_tools ? 1 : 0

  function_name = "${var.name_prefix}-tool-key-rotation"
  description   = "CCG: rotate a specifically approved sandbox access key. Secret material never returned in logs or response."

  runtime  = "python3.14"
  handler  = "ccg.tools.key_rotation_handler"
  role     = var.tool_execution_role_arn
  filename = "${path.module}/placeholder.zip"

  timeout     = var.lambda_timeout_seconds
  memory_size = var.lambda_memory_mb

  environment {
    variables = local.tool_env
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Component = "tool-key-rotation"
    CCGDemo   = "true"
  }
}
