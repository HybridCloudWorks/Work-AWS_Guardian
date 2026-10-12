# AgentCore Gateway Target, Policy, and policy attachment stubs.
#
# Design §3.2: The Gateway is the ONLY mutation ingress. This module extends
# the agentcore-gateway module with:
#   - Lambda-backed tool targets (one per approved remediation tool)
#   - A Cedar Policy resource with the four narrow per-tool permit policies and
#     always-on forbids
#
# GATING: All resources are gated behind `enable_gateway_policy` (default false).
# The agentcore-gateway module must be enabled first (its outputs feed this module).
#
# PREREQUISITES (gate-0.2 before enabling):
#   - Exact AgentCore action IDs, entity/context attribute names, and policy
#     analyzer output must be captured from the live Gateway schema.
#   - Cedar policy files must be adapted from intent to the real schema
#     (guardrails.cedar / remediation-permits.cedar are intent, not deployable).
#   - Remediation Lambda ARNs must be known (from remediation-tools module).
#   - Threat-model T2 (forged context) must be resolved before enabling ENFORCE.
#
# ACTIVATION:
#   - Initial deploy uses the Policy Engine's LOG_ONLY mode (set in the
#     agentcore-gateway module). Switching to "ENFORCE" is a separate audited
#     control-plane activation — never a Terraform `apply`. See design §3.2 and
#     task 4.3.
#
# SCHEMA: `aws_bedrockagentcore_gateway_target` and `aws_bedrockagentcore_policy`
# argument/block names below are verified against the hashicorp/aws 6.64.0
# provider schema via `terraform providers schema -json`:
#   - target: gateway_identifier (required) + target_configuration { mcp { lambda { lambda_arn } } }
#   - policy: policy_engine_id (required) + definition { cedar { statement } }
# The Cedar statement content is read from the reviewed files in policies/
# (see the aws_bedrockagentcore_policy block below and variables.tf). Those
# files still contain <GATEWAY_ARN>/action-ID placeholders that must be
# substituted and re-validated by the analyzer before this module is enabled.

# --- Reviewed Cedar policy content --------------------------------------------
# Resolve the deployed Cedar content. When `cedar_policy_content` is left empty
# (the default) the module reads the reviewed files directly from the repo
# `policies/` directory and concatenates them in a fixed, documented order:
# guardrails.cedar (forbids) first, then remediation-permits.cedar (permits).
# Ordering is for readability only; Cedar is unordered and forbid-wins.
#
# An explicit `cedar_policy_content` override wins — used to inject the
# analyzer-validated, ARN-substituted content after gate-0.2 schema capture.
locals {
  # The AgentCore policy name allows only [A-Za-z0-9_] and must start with a
  # letter (same rule as the policy engine). name_prefix is hyphenated, so
  # normalize to underscores for the policy name. Target names follow the
  # gateway rule (hyphens allowed) and keep name_prefix as-is.
  agentcore_name_prefix = replace(var.name_prefix, "-", "_")

  cedar_policy_dir = var.cedar_policy_dir != "" ? var.cedar_policy_dir : "${path.module}/../../policies"

  cedar_reviewed_content = join("\n\n", [
    file("${local.cedar_policy_dir}/guardrails.cedar"),
    file("${local.cedar_policy_dir}/remediation-permits.cedar"),
  ])

  cedar_policy_statement = var.cedar_policy_content != "" ? var.cedar_policy_content : local.cedar_reviewed_content
}

# --- Tool targets (one per approved remediation Lambda) -----------------------
#
# Each MCP lambda target requires a `tool_schema`. The inline payload below is a
# minimal PLACEHOLDER (single string `finding_id` input): just enough to satisfy
# the provider's required-block contract so the layout validates. The real tool
# input/output schema is captured at gate-0.2 and replaces these payloads before
# any target is deployed. The handler contracts live in src/ccg/tools.py.

resource "aws_bedrockagentcore_gateway_target" "sg_correction" {
  count = var.enable_gateway_policy ? 1 : 0

  name               = "${var.name_prefix}-tool-sg-correction"
  gateway_identifier = var.gateway_id
  description        = "Security-group ingress correction tool (sandbox-gated only)."

  target_configuration {
    mcp {
      lambda {
        lambda_arn = var.sg_correction_lambda_arn

        tool_schema {
          inline_payload {
            name        = "sg_correction"
            description = "PLACEHOLDER schema — replaced by gate-0.2 capture. Restrict one approved sandbox SG ingress rule."

            input_schema {
              type = "object"
            }
          }
        }
      }
    }
  }
}

resource "aws_bedrockagentcore_gateway_target" "s3_encryption" {
  count = var.enable_gateway_policy ? 1 : 0

  name               = "${var.name_prefix}-tool-s3-encryption"
  gateway_identifier = var.gateway_id
  description        = "S3 encryption enablement tool (sandbox-gated only)."

  target_configuration {
    mcp {
      lambda {
        lambda_arn = var.s3_encryption_lambda_arn

        tool_schema {
          inline_payload {
            name        = "s3_encryption"
            description = "PLACEHOLDER schema — replaced by gate-0.2 capture. Enable approved SSE on an eligible sandbox bucket."

            input_schema {
              type = "object"
            }
          }
        }
      }
    }
  }
}

resource "aws_bedrockagentcore_gateway_target" "tagging" {
  count = var.enable_gateway_policy ? 1 : 0

  name               = "${var.name_prefix}-tool-tagging"
  gateway_identifier = var.gateway_id
  description        = "Compliant tagging tool (sandbox-gated only)."

  target_configuration {
    mcp {
      lambda {
        lambda_arn = var.tagging_lambda_arn

        tool_schema {
          inline_payload {
            name        = "tagging"
            description = "PLACEHOLDER schema — replaced by gate-0.2 capture. Add/correct approved compliance tags."

            input_schema {
              type = "object"
            }
          }
        }
      }
    }
  }
}

resource "aws_bedrockagentcore_gateway_target" "key_rotation" {
  count = var.enable_gateway_policy ? 1 : 0

  name               = "${var.name_prefix}-tool-key-rotation"
  gateway_identifier = var.gateway_id
  description        = "Access-key rotation workflow tool (sandbox-gated only; dry-run unless confirm=true)."

  target_configuration {
    mcp {
      lambda {
        lambda_arn = var.key_rotation_lambda_arn

        tool_schema {
          inline_payload {
            name        = "key_rotation"
            description = "PLACEHOLDER schema — replaced by gate-0.2 capture. Rotate a specifically approved sandbox access key."

            input_schema {
              type = "object"
            }
          }
        }
      }
    }
  }
}

# --- Cedar policy set ---------------------------------------------------------
# The deployed Cedar content is the REVIEWED content from policies/, not an
# inline placeholder. By default `cedar_policy_content` concatenates the two
# reviewed files in a fixed, documented order (see variables.tf):
#   1. policies/guardrails.cedar          (always-on forbids)
#   2. policies/remediation-permits.cedar (per-tool permits)
# Forbids are placed first purely for human readability; Cedar is unordered and
# forbid-wins regardless of textual position.
#
# GATE-0.2 PRECONDITION: both files still carry `<GATEWAY_ARN>` and placeholder
# action IDs. They WILL fail the policy analyzer until those are substituted
# with the live Gateway ARN and generated action IDs after first schema capture.
# This resource therefore stays gated (enable_gateway_policy = false) until the
# substituted content passes the analyzer. Do not enable before then.
#
# LOG_ONLY correctness (C1 / P0.1): enforcement mode lives on the Policy Engine
# binding (agentcore-gateway, mode = LOG_ONLY). This resource defines policy
# CONTENT only. In LOG_ONLY nothing here enforces — forbids and permits are
# evaluated for logging but do not block or authorize. Capture safety rests on
# there being NO ACTIVE PERMIT, not on forbids blocking. Activation to ENFORCE
# is a control-plane-only UpdatePolicy (src/ccg/policy.py); there is no
# enforcement_mode = "ACTIVE" argument or permit-activation variable here.
resource "aws_bedrockagentcore_policy" "ccg" {
  count = var.enable_gateway_policy ? 1 : 0

  name             = "${local.agentcore_name_prefix}_ccg_policy"
  policy_engine_id = var.policy_engine_id
  description      = "CCG POC Cedar policy set: reviewed forbids + per-tool permits (content only; mode is LOG_ONLY on the engine)."

  definition {
    cedar {
      statement = local.cedar_policy_statement
    }
  }
}
