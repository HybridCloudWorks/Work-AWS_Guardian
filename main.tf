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
