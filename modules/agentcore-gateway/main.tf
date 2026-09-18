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
# NOTE: argument names below follow the AgentCore CreateGateway API contract
# (name, protocolType=MCP, roleArn, authorizerType=AWS_IAM for the POC, optional
# policyEngineConfiguration). The EXACT Terraform provider (aws 6.64.0) argument
# spellings must be confirmed against the real `terraform plan` in HCP before
# enable_gateway is set true — do not assume these are provider-correct yet.
# They are intentionally inert while count = 0.
#
# resource "aws_bedrockagentcore_gateway" "this" {
#   count             = var.enable_gateway ? 1 : 0
#   name              = "${var.name_prefix}-gateway"
#   protocol_type     = "MCP"
#   role_arn          = aws_iam_role.gateway_execution.arn
#   authorizer_type   = "AWS_IAM"
#   # policy_engine_configuration { mode = "LOG_ONLY"  arn = ... }  # permits inactive
# }
#
# Kept commented until the argument names are HCP-plan-verified, so this module
# is valid and deployable (role only) today with zero AgentCore footprint.
