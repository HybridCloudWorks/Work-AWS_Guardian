# Native Terraform tests (Terraform 1.6+; repo runtime 1.16.5) for task 2.5:
# the AgentCore Gateway authorization boundary and its Cedar policy resources.
#
# Credential-free by design:
#   - A mock AWS provider supplies computed values, so no AWS calls are made.
#   - Each `run` targets a single module via `module { source = ... }` so the
#     unrelated root wiring need not resolve.
#
# These tests assert the external-policy-boundary posture a reviewer must be
# able to confirm from a plan:
#   - MCP + AWS_IAM gateway bound to the engine in LOG_ONLY (G1-G4)
#   - nothing created when the feature flag is off (G5, GP5)
#   - four tool targets + one policy resource when gateway-policy is on (GP1-GP4)
#   - deployed Cedar content comes from the reviewed files (GP6)
#
# Run from the repository root:
#   terraform init -backend=false -input=false
#   terraform test

# The mock provider returns arbitrary strings for computed attributes. Two
# overrides are needed:
#   - aws_iam_policy_document.json must be a JSON object (client-side validated
#     when it feeds aws_iam_role.assume_role_policy).
#   - aws_bedrockagentcore_policy_engine.policy_engine_arn is consumed by the
#     gateway's policy_engine_configuration.arn, so give it a concrete value.
mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_resource "aws_bedrockagentcore_policy_engine" {
    defaults = {
      policy_engine_arn = "arn:aws:bedrock-agentcore:us-east-1:111122223333:policy-engine/ccg_poc_policy_engine"
      policy_engine_id  = "engine-abc1234567"
    }
  }
}

# =============================================================================
# agentcore-gateway module
# =============================================================================

run "gateway_boundary_enabled" {
  command = plan

  module {
    source = "./modules/agentcore-gateway"
  }

  variables {
    name_prefix             = "ccg-poc"
    assume_role_policy_json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    execution_policy_json   = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    enable_gateway          = true
  }

  # G1 — gateway speaks MCP.
  assert {
    condition     = aws_bedrockagentcore_gateway.this[0].protocol_type == "MCP"
    error_message = "G1: gateway protocol_type must be MCP."
  }

  # G2 — AWS_IAM authorizer (no JWT authorizer block).
  assert {
    condition     = aws_bedrockagentcore_gateway.this[0].authorizer_type == "AWS_IAM"
    error_message = "G2: gateway authorizer_type must be AWS_IAM."
  }

  # G3 — engine binding is LOG_ONLY (evaluate-only, no enforcement at deploy).
  assert {
    condition     = aws_bedrockagentcore_gateway.this[0].policy_engine_configuration[0].mode == "LOG_ONLY"
    error_message = "G3: policy_engine_configuration.mode must be LOG_ONLY."
  }

  # G4 — exactly one engine and one gateway when enabled.
  assert {
    condition = (
      length(aws_bedrockagentcore_policy_engine.this) == 1 &&
      length(aws_bedrockagentcore_gateway.this) == 1
    )
    error_message = "G4: enabling must create exactly one policy engine and one gateway."
  }
}

run "gateway_boundary_disabled_by_default" {
  command = plan

  module {
    source = "./modules/agentcore-gateway"
  }

  variables {
    name_prefix             = "ccg-poc"
    assume_role_policy_json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    execution_policy_json   = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    # enable_gateway defaults to false
  }

  # G5 — no AgentCore resources exist when the flag is off.
  assert {
    condition = (
      length(aws_bedrockagentcore_gateway.this) == 0 &&
      length(aws_bedrockagentcore_policy_engine.this) == 0
    )
    error_message = "G5: no gateway/engine may exist when enable_gateway = false."
  }

  # G6 — the execution role is still created (safe, no runtime effect).
  assert {
    condition     = aws_iam_role.gateway_execution.name == "ccg-poc-gateway-exec"
    error_message = "G6: the gateway execution role must still be created when disabled."
  }
}

# =============================================================================
# gateway-policy module
# =============================================================================

run "gateway_policy_enabled" {
  command = plan

  module {
    source = "./modules/gateway-policy"
  }

  variables {
    name_prefix              = "ccg-poc"
    gateway_id               = "gw-ccgpoc000000000"
    policy_engine_id         = "engine-abc1234567"
    sg_correction_lambda_arn = "arn:aws:lambda:us-east-1:111122223333:function:ccg-poc-tool-sg-correction"
    s3_encryption_lambda_arn = "arn:aws:lambda:us-east-1:111122223333:function:ccg-poc-tool-s3-encryption"
    tagging_lambda_arn       = "arn:aws:lambda:us-east-1:111122223333:function:ccg-poc-tool-tagging"
    key_rotation_lambda_arn  = "arn:aws:lambda:us-east-1:111122223333:function:ccg-poc-tool-key-rotation"
    enable_gateway_policy    = true
  }

  # GP1 — four tool targets, one per approved remediation Lambda.
  assert {
    condition = (
      length(aws_bedrockagentcore_gateway_target.sg_correction) == 1 &&
      length(aws_bedrockagentcore_gateway_target.s3_encryption) == 1 &&
      length(aws_bedrockagentcore_gateway_target.tagging) == 1 &&
      length(aws_bedrockagentcore_gateway_target.key_rotation) == 1
    )
    error_message = "GP1: four gateway tool targets must be created when enabled."
  }

  # GP2 — each target is wired to its own tool Lambda (sole-ingress targets).
  assert {
    condition     = aws_bedrockagentcore_gateway_target.sg_correction[0].target_configuration[0].mcp[0].lambda[0].lambda_arn == "arn:aws:lambda:us-east-1:111122223333:function:ccg-poc-tool-sg-correction"
    error_message = "GP2: sg-correction target must point at the sg-correction tool Lambda."
  }

  # GP3 — exactly one Cedar policy resource.
  assert {
    condition     = length(aws_bedrockagentcore_policy.ccg) == 1
    error_message = "GP3: exactly one Cedar policy resource must be created when enabled."
  }

  # GP4 — the policy binds to the supplied policy engine.
  assert {
    condition     = aws_bedrockagentcore_policy.ccg[0].policy_engine_id == "engine-abc1234567"
    error_message = "GP4: policy must bind to the provided policy_engine_id."
  }

  # GP6 — deployed Cedar content is the reviewed, concatenated files, with the
  # forbids ahead of the permits (documented order) and no inline placeholder.
  assert {
    condition = (
      strcontains(aws_bedrockagentcore_policy.ccg[0].definition[0].cedar[0].statement, "RemediationTarget___security_group_correction") &&
      strcontains(aws_bedrockagentcore_policy.ccg[0].definition[0].cedar[0].statement, "guardrails.cedar") &&
      strcontains(aws_bedrockagentcore_policy.ccg[0].definition[0].cedar[0].statement, "remediation-permits.cedar")
    )
    error_message = "GP6: deployed Cedar must be the concatenated reviewed guardrails + permits files."
  }
}

run "gateway_policy_disabled_by_default" {
  command = plan

  module {
    source = "./modules/gateway-policy"
  }

  variables {
    name_prefix = "ccg-poc"
    # enable_gateway_policy defaults to false
  }

  # GP5 — no targets and no policy exist when the flag is off.
  assert {
    condition = (
      length(aws_bedrockagentcore_gateway_target.sg_correction) == 0 &&
      length(aws_bedrockagentcore_gateway_target.s3_encryption) == 0 &&
      length(aws_bedrockagentcore_gateway_target.tagging) == 0 &&
      length(aws_bedrockagentcore_gateway_target.key_rotation) == 0 &&
      length(aws_bedrockagentcore_policy.ccg) == 0
    )
    error_message = "GP5: no targets or policy may exist when enable_gateway_policy = false."
  }
}
