# AgentCore Gateway execution role + a feature-flagged Gateway skeleton.
#
# The IAM role is always created (safe, no runtime effect on its own). The
# Gateway itself is gated behind `enable_gateway` (default false) so that
# NOTHING is deployed to AgentCore until a reviewed HCP plan is explicitly
# approved for the minimal schema-capture step (see docs/THREAT_MODEL.md deploy
# gate). This lets the role and wiring be reviewed/merged now without creating
# any live Gateway.

# AgentCore name rules differ per resource (verified by provider validation):
#   - policy engine: ^[A-Za-z][A-Za-z0-9_]{0,47}$  → underscores only, no hyphens
#   - gateway:       ^([0-9a-zA-Z][-]?){1,100}$     → hyphens only, no underscores
# The repo's name_prefix is hyphenated, so derive an underscore-normalized
# prefix for the policy engine. The gateway and IAM role keep the hyphens.
locals {
  agentcore_name_prefix = replace(var.name_prefix, "-", "_")
}

resource "aws_iam_role" "gateway_execution" {
  name               = "${var.name_prefix}-gateway-exec"
  assume_role_policy = var.assume_role_policy_json
}

resource "aws_iam_role_policy" "gateway_execution" {
  name   = "${var.name_prefix}-gateway-exec"
  role   = aws_iam_role.gateway_execution.id
  policy = var.execution_policy_json
}

# --- Feature-flagged Policy Engine (count = 0 by default → not deployed) ------
#
# The Policy Engine is the external Cedar decision boundary the Gateway binds
# to. Verified against provider 6.64.0: only `name` is required;
# `encryption_key_arn` is optional and OMITTED here per the AWS-managed-keys
# decision (no CMK). Gated by the same enable_gateway flag so its `count`
# matches the Gateway's and cross-references resolve.
resource "aws_bedrockagentcore_policy_engine" "this" {
  count = var.enable_gateway ? 1 : 0

  # The provider restricts this name to [A-Za-z0-9_], must start with a letter,
  # max 48 chars. name_prefix is hyphenated elsewhere, so normalize hyphens to
  # underscores for AgentCore resource names.
  name        = "${local.agentcore_name_prefix}_policy_engine"
  description = "CCG POC Cedar policy engine"
}

# --- Feature-flagged Gateway (count = 0 by default → not deployed) ------------
#
# Argument names verified against the hashicorp/aws 6.64.0 provider schema
# (`terraform providers schema -json`): authorizer_type/name/role_arn are
# required; protocol_type is optional. For AWS_IAM authorization the
# authorizer_configuration block is omitted entirely (that block only models
# custom_jwt_authorizer).
#
# policy_engine_configuration binds the engine with mode = "LOG_ONLY".
#
# LOG_ONLY correctness (C1 / P0.1): LOG_ONLY means every policy is EVALUATED
# but NO decision is ENFORCED. Both permits and forbids merely produce log
# entries in this mode — a forbid in LOG_ONLY does NOT block a call. Therefore
# the capture-safety basis is NOT "forbids block"; it is that NO PERMIT EXISTS
# OR IS ACTIVE, so nothing can authorize a mutation regardless of mode. Do not
# describe LOG_ONLY as "fail-closed because forbids enforce" — that is false.
#
# Enforcement requires BOTH mode = "ENFORCE" AND an active default-deny permit
# set, flipped only via the audited control-plane UpdatePolicy flow
# (src/ccg/policy.py, task 4.3) — never via a Terraform apply. There is
# deliberately NO enforcement_mode = "ACTIVE" argument and NO permit-activation
# variable in this Terraform.
#
# Still gated: materializes only when enable_gateway = true, via a reviewed HCP
# plan per docs/THREAT_MODEL.md (CCGDemo-tagged, no active permits). Deploying is
# a real AWS mutation.
resource "aws_bedrockagentcore_gateway" "this" {
  count = var.enable_gateway ? 1 : 0

  # Gateway name rule differs from the policy engine's: it matches
  # ^([0-9a-zA-Z][-]?){1,100}$ — hyphens are allowed, underscores are NOT. So
  # the gateway keeps the hyphenated name_prefix (unlike the policy engine).
  name            = "${var.name_prefix}-gateway"
  role_arn        = aws_iam_role.gateway_execution.arn
  protocol_type   = "MCP"
  authorizer_type = "AWS_IAM"
  description     = "CCG POC schema-capture gateway (LOG_ONLY; no active permits)"

  policy_engine_configuration {
    arn  = aws_bedrockagentcore_policy_engine.this[0].policy_engine_arn
    mode = "LOG_ONLY"
  }
}
