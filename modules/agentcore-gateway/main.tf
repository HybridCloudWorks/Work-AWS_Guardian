# AgentCore Gateway execution role + a feature-flagged Gateway skeleton.
#
# The IAM role is always created (safe, no runtime effect on its own). The
# Gateway itself is gated behind `enable_gateway` (default false) so that
# NOTHING is deployed to AgentCore until a reviewed HCP plan is explicitly
# approved for the minimal schema-capture step (see docs/THREAT_MODEL.md deploy
# gate). This lets the role and wiring be reviewed/merged now without creating
# any live Gateway.

resource "aws_iam_role" "gateway_execution" {
  name               = "${var.name_prefix}-gateway-exec"
  assume_role_policy = var.assume_role_policy_json
}

resource "aws_iam_role_policy" "gateway_execution" {
  name   = "${var.name_prefix}-gateway-exec"
  role   = aws_iam_role.gateway_execution.id
  policy = var.execution_policy_json
}

# --- Feature-flagged Gateway (count = 0 by default → not deployed) ------------
#
# Argument names verified against the hashicorp/aws 6.64.0 provider schema
# (`terraform providers schema -json`): authorizer_type/name/role_arn are
# required; protocol_type is optional. For AWS_IAM authorization the
# authorizer_configuration block is omitted entirely (that block only models
# custom_jwt_authorizer). policy_engine_configuration is wired in a later change
# once a policy engine exists; keeping it out here means the Gateway defaults to
# no active permit path, consistent with the fail-closed posture.
#
# Still gated: this resource only materializes when enable_gateway = true, which
# must go through a reviewed HCP plan per docs/THREAT_MODEL.md (CCGDemo-tagged,
# permits inactive). Deploying the Gateway is a real AWS mutation.
resource "aws_bedrockagentcore_gateway" "this" {
  count = var.enable_gateway ? 1 : 0

  name            = "${var.name_prefix}-gateway"
  role_arn        = aws_iam_role.gateway_execution.arn
  protocol_type   = "MCP"
  authorizer_type = "AWS_IAM"
  description     = "CCG POC schema-capture gateway (permits inactive)"
}
