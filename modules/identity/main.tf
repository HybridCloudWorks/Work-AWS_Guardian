# IAM role creation for the CCG POC trust boundaries.
#
# Design §3 / §6 separate four execution identities:
#   discovery     — read-only sources + write evidence
#   tool          — narrow sandbox-gated remediation
#   control_plane — policy activation only
#   audit_reader  — read-only on the audit bucket
#
# GATING: All four roles are gated behind `enable_roles` (default false).
# Policy *documents* are produced by the iam-policies module and passed in
# as JSON; this module only creates the IAM roles and attaches those documents.
# No wildcard administrative policies or AWS managed policy attachments.
#
# PREREQUISITES (gate-0.2 before enabling):
#   - Discovery, tool, and control-plane trust policies require the Lambda
#     and BedrockAgentCore service principal ARNs confirmed in the target region.
#   - Tool role requires the exact Lambda ARN prefix from gateway-policy outputs.
#   - Threat-model review of T1 (confused-deputy) must confirm SourceAccount
#     conditions on every trust policy before any role is active.

# --- Discovery role -----------------------------------------------------------
resource "aws_iam_role" "discovery" {
  count = var.enable_roles ? 1 : 0

  name        = "${var.name_prefix}-discovery"
  description = "Read-only discovery execution role (Config/SecurityHub/CloudTrail + evidence writes)."

  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = {
    Component = "discovery"
    CCGDemo   = "true"
  }
}

resource "aws_iam_role_policy" "discovery" {
  count = var.enable_roles ? 1 : 0

  name   = "${var.name_prefix}-discovery"
  role   = aws_iam_role.discovery[0].id
  policy = var.discovery_policy_json
}

# --- Tool execution role ------------------------------------------------------
resource "aws_iam_role" "tool_execution" {
  count = var.enable_roles ? 1 : 0

  name        = "${var.name_prefix}-tool-exec"
  description = "Sandbox-gated tool-execution role (narrow remediation actions only)."

  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = {
    Component = "tool-execution"
    CCGDemo   = "true"
  }
}

resource "aws_iam_role_policy" "tool_execution" {
  count = var.enable_roles ? 1 : 0

  name   = "${var.name_prefix}-tool-exec"
  role   = aws_iam_role.tool_execution[0].id
  policy = var.tool_execution_policy_json
}

# --- Control-plane role -------------------------------------------------------
resource "aws_iam_role" "control_plane" {
  count = var.enable_roles ? 1 : 0

  name        = "${var.name_prefix}-ctrl-plane"
  description = "Policy-activation control-plane role (AgentCore UpdatePolicy + reconciliation reads only)."

  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = {
    Component = "control-plane"
    CCGDemo   = "true"
  }
}

resource "aws_iam_role_policy" "control_plane" {
  count = var.enable_roles ? 1 : 0

  name   = "${var.name_prefix}-ctrl-plane"
  role   = aws_iam_role.control_plane[0].id
  policy = var.control_plane_policy_json
}

# --- Audit-reader role --------------------------------------------------------
resource "aws_iam_role" "audit_reader" {
  count = var.enable_roles ? 1 : 0

  name        = "${var.name_prefix}-audit-reader"
  description = "Read-only audit bucket access role. Not used at runtime; reserved for investigation."

  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = {
    Component = "audit-reader"
    CCGDemo   = "true"
  }
}

resource "aws_iam_role_policy" "audit_reader" {
  count = var.enable_roles ? 1 : 0

  name   = "${var.name_prefix}-audit-reader"
  role   = aws_iam_role.audit_reader[0].id
  policy = var.audit_reader_policy_json
}

# --- Console/API role ---------------------------------------------------------
# Execution role for the console API Lambda (design §3.4 / §6). Reads findings
# and audit evidence and reaches activation only by assuming the control-plane
# role; it holds no remediation permissions and cannot invoke the tool Lambdas,
# so the console/API can never bypass the AgentCore Gateway.
resource "aws_iam_role" "api" {
  count = var.enable_roles ? 1 : 0

  name        = "${var.name_prefix}-api"
  description = "Console/API Lambda role: read findings/audit + assume control-plane for activation. No direct mutation or tool invocation."

  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = {
    Component = "console-api"
    CCGDemo   = "true"
  }
}

resource "aws_iam_role_policy" "api" {
  count = var.enable_roles ? 1 : 0

  name   = "${var.name_prefix}-api"
  role   = aws_iam_role.api[0].id
  policy = var.api_policy_json
}

# --- Shared trust policy: Lambda service principal ---------------------------
# SourceAccount condition added per threat-model T1 (confused-deputy).
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
