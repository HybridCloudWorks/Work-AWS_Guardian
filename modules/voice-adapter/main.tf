locals {
  # Use the built CCG package when provided; fall back to the committed
  # placeholder so the module still validates/plans before a real build.
  lambda_package = var.lambda_package_path != "" ? var.lambda_package_path : "${path.module}/placeholder.zip"
}

# Nova Sonic read-only voice adapter stub.
#
# Design §3.5 / CCG-REQ-030 through CCG-REQ-033:
#   - The Nova Sonic adapter is OPTIONAL and OFF by default.
#   - It provides READ-ONLY finding summaries and policy status. It does NOT
#     expose any remediation tool schema and cannot call the Gateway mutation
#     surface.
#   - It requires explicit feature enablement AND microphone consent.
#   - If the API, model, region, quota, or browser path is unavailable, the
#     adapter returns a safe "unavailable" result without weakening console
#     authorization.
#
# GATING: All resources are gated behind `enable_voice` (default false).
#
# PREREQUISITES (gate-0.3 before enabling):
#   - Nova Sonic model ID, region availability, bidirectional API, audio
#     formats, browser transport, interruption events, and authentication must
#     be verified.
#   - Voice adapter must have no mutation tool visibility or Gateway bypass.
#   - Microphone consent flow must be implemented in the Next.js console.
#
# IAM: The voice adapter Lambda reads DynamoDB findings (read-only) and writes
# structured logs. It has NO permissions to call the Gateway, invoke tool
# Lambdas, mutate S3, or call `bedrock-agentcore:*` APIs.

resource "aws_lambda_function" "voice_adapter" {
  count = var.enable_voice ? 1 : 0

  function_name = "${var.name_prefix}-voice-adapter"
  description   = "CCG POC read-only Nova Sonic voice adapter — finding summaries only; no mutation tools."

  runtime          = "python3.14"
  handler          = "ccg.voice_handler.lambda_handler"
  role             = aws_iam_role.voice_adapter[0].arn
  filename         = local.lambda_package
  source_code_hash = var.lambda_package_hash != "" ? var.lambda_package_hash : null

  timeout     = var.lambda_timeout_seconds
  memory_size = var.lambda_memory_mb

  environment {
    variables = {
      FINDINGS_TABLE_NAME = var.findings_table_name
      LOG_GROUP_NAME      = var.log_group_name
      # Nova Sonic model configuration is injected at runtime; NOT hardcoded
      # here to allow regional override if the model/quota changes.
      # Raw audio is NOT retained by default (CCG-REQ-035).
      RETAIN_AUDIO = "false"
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Component = "voice-adapter"
    CCGDemo   = "true"
  }
}

# --- Voice adapter IAM role (gated with the Lambda) --------------------------
# The role is gated so that it is only created when voice is intentionally
# enabled. It carries only read-only DynamoDB access and log writes.
resource "aws_iam_role" "voice_adapter" {
  count = var.enable_voice ? 1 : 0

  name        = "${var.name_prefix}-voice-adapter"
  description = "Read-only voice adapter execution role (DynamoDB read + log write only; no Gateway/tool permissions)."

  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = {
    Component = "voice-adapter"
    CCGDemo   = "true"
  }
}

resource "aws_iam_role_policy" "voice_adapter" {
  count = var.enable_voice ? 1 : 0

  name   = "${var.name_prefix}-voice-adapter"
  role   = aws_iam_role.voice_adapter[0].id
  policy = data.aws_iam_policy_document.voice_adapter_permissions.json
}

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    sid     = "LambdaAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

data "aws_iam_policy_document" "voice_adapter_permissions" {
  # Read-only findings access for summary generation.
  statement {
    sid    = "ReadFindings"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:Query",
      "dynamodb:Scan",
    ]
    resources = ["arn:aws:dynamodb:${var.region}:${var.account_id}:table/${var.name_prefix}-drift"]
  }

  statement {
    sid       = "WriteLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${var.log_group_arn}:*"]
  }

  # Explicit denies: the voice adapter MUST NOT call Gateway tools, invoke
  # remediation Lambdas, activate policies, or mutate any resource.
  statement {
    sid    = "DenyMutations"
    effect = "Deny"
    actions = [
      "bedrock-agentcore:*",
      "lambda:InvokeFunction",
      "ec2:*",
      "s3:Put*",
      "iam:*",
      "cloudtrail:*",
    ]
    resources = ["*"]
  }
}
