provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(var.tags, {
      Project     = "comp_guardian"
      Environment = var.environment
      ManagedBy   = "terraform"
    })
  }
}

module "audit_storage" {
  source = "./modules/audit-storage"

  name_prefix           = var.name_prefix
  audit_expiration_days = var.audit_expiration_days
  enable_access_logging = var.enable_audit_access_logging
}

module "findings_store" {
  source = "./modules/findings-store"

  name_prefix                = var.name_prefix
  enable_deletion_protection = var.enable_findings_deletion_protection
}

module "observability" {
  source = "./modules/observability"

  name_prefix        = var.name_prefix
  log_retention_days = var.log_retention_days
}

data "aws_caller_identity" "current" {}

# Least-privilege policy documents (source of truth for gate-0.2 role creation).
module "iam_policies" {
  source = "./modules/iam-policies"

  name_prefix        = var.name_prefix
  account_id         = data.aws_caller_identity.current.account_id
  region             = var.aws_region
  audit_bucket_arn   = module.audit_storage.bucket_arn
  findings_table_arn = module.findings_store.table_arn
  log_group_arn      = module.observability.log_group_arn
}

# AgentCore Gateway execution role (always created) + feature-flagged Gateway
# skeleton (default off; no Gateway deployed until a reviewed HCP plan enables it).
module "agentcore_gateway" {
  source = "./modules/agentcore-gateway"

  name_prefix             = var.name_prefix
  assume_role_policy_json = module.iam_policies.gateway_assume_role_policy_json
  execution_policy_json   = module.iam_policies.gateway_execution_policy_json
  enable_gateway          = var.enable_agentcore_gateway
}

# --- Stub modules (all gated off by default) ---------------------------------
# These modules are present for layout review and incremental enablement.
# None deploy any live AWS resource until their respective feature flags are
# set to true in a reviewed HCP plan.

# IAM execution roles (discovery, tool, control-plane, audit-reader).
# Safe to enable before the Gateway; carries no live-runtime permissions
# until a Lambda is associated. Gate: gate-0.2 trust-policy capture.
module "identity" {
  source = "./modules/identity"

  name_prefix                = var.name_prefix
  account_id                 = data.aws_caller_identity.current.account_id
  region                     = var.aws_region
  discovery_policy_json      = module.iam_policies.discovery_policy_json
  tool_execution_policy_json = module.iam_policies.tool_execution_policy_json
  control_plane_policy_json  = module.iam_policies.control_plane_policy_json
  audit_reader_policy_json   = module.iam_policies.audit_reader_policy_json
  api_policy_json            = module.iam_policies.api_policy_json
  enable_roles               = var.enable_identity_roles
}

# EventBridge schedule + Python 3.14 discovery Lambda.
# Gate: gate-0.2 discovery role + read-only source permissions confirmed.
module "discovery" {
  source = "./modules/discovery"

  name_prefix         = var.name_prefix
  region              = var.aws_region
  account_id          = data.aws_caller_identity.current.account_id
  log_group_arn       = module.observability.log_group_arn
  log_group_name      = module.observability.log_group_name
  discovery_role_arn  = coalesce(module.identity.discovery_role_arn, "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.name_prefix}-discovery")
  findings_table_name = module.findings_store.table_name
  audit_bucket_name   = module.audit_storage.bucket_name
  discovery_schedule  = var.discovery_schedule
  enable_discovery    = var.enable_discovery
}

# Four remediation tool Lambdas (sg-correction, s3-encryption, tagging, key-rotation).
# Gate: gate-0.2 tool-execution role, Gateway schema, and tool input contracts confirmed.
module "remediation_tools" {
  source = "./modules/remediation-tools"

  name_prefix              = var.name_prefix
  region                   = var.aws_region
  account_id               = data.aws_caller_identity.current.account_id
  log_group_arn            = module.observability.log_group_arn
  log_group_name           = module.observability.log_group_name
  tool_execution_role_arn  = coalesce(module.identity.tool_execution_role_arn, "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.name_prefix}-tool-exec")
  findings_table_name      = module.findings_store.table_name
  audit_bucket_name        = module.audit_storage.bucket_name
  enable_remediation_tools = var.enable_remediation_tools
}

# AgentCore Gateway tool targets and Cedar policy set.
# Gate: agentcore-gateway enabled + gate-0.2 schema/Cedar-analyzer validation complete.
module "gateway_policy" {
  source = "./modules/gateway-policy"

  name_prefix              = var.name_prefix
  gateway_id               = coalesce(module.agentcore_gateway.gateway_id, "")
  policy_engine_id         = coalesce(module.agentcore_gateway.policy_engine_id, "")
  sg_correction_lambda_arn = coalesce(module.remediation_tools.sg_correction_lambda_arn, "")
  s3_encryption_lambda_arn = coalesce(module.remediation_tools.s3_encryption_lambda_arn, "")
  tagging_lambda_arn       = coalesce(module.remediation_tools.tagging_lambda_arn, "")
  key_rotation_lambda_arn  = coalesce(module.remediation_tools.key_rotation_lambda_arn, "")
  enable_gateway_policy    = var.enable_agentcore_gateway && var.enable_remediation_tools
}

# Cognito user pool (always created; safe to provision before the API).
# API Gateway + Lambda are gated behind enable_console.
# Gate: gate-0.2 Cognito/API Gateway contract + Next.js hosting URL confirmed.
module "console_api" {
  source = "./modules/console-api"

  name_prefix         = var.name_prefix
  region              = var.aws_region
  account_id          = data.aws_caller_identity.current.account_id
  log_group_arn       = module.observability.log_group_arn
  log_group_name      = module.observability.log_group_name
  findings_table_name = module.findings_store.table_name
  audit_bucket_name   = module.audit_storage.bucket_name
  enable_console      = var.enable_console
}

# Nova Sonic read-only voice adapter (off by default, CCG-REQ-032).
# Gate: gate-0.3 Nova Sonic contract + microphone consent flow implemented.
module "voice_adapter" {
  source = "./modules/voice-adapter"

  name_prefix         = var.name_prefix
  region              = var.aws_region
  account_id          = data.aws_caller_identity.current.account_id
  log_group_arn       = module.observability.log_group_arn
  log_group_name      = module.observability.log_group_name
  findings_table_name = module.findings_store.table_name
  enable_voice        = var.enable_voice
}
