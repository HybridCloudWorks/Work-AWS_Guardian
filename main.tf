provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "comp_guardian"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

module "audit_storage" {
  source = "./modules/audit-storage"

  name_prefix           = var.name_prefix
  audit_expiration_days = var.audit_expiration_days
}

module "findings_store" {
  source = "./modules/findings-store"

  name_prefix = var.name_prefix
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
