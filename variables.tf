# ---------------------------------------------------------------------------
# Distribution inputs (Option 1: customer-deployed module).
# Defaults are safe PLACEHOLDERS for evaluation; override in a tfvars file.
# Validations are bounded (not hard-locked) so operators can tune within sane
# limits. See DISTRIBUTION.md.
# ---------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS Region to deploy CCG into."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.aws_region))
    error_message = "aws_region must be a valid region code, e.g. us-east-1."
  }
}

variable "name_prefix" {
  description = "Lowercase, hyphenated prefix for all CCG resource names. Choose something unique per deployment."
  type        = string
  default     = "ccg" # PLACEHOLDER - override per deployment

  validation {
    condition     = can(regex("^[a-z0-9-]{3,24}$", var.name_prefix))
    error_message = "name_prefix must be 3-24 lowercase letters, numbers, or hyphens."
  }
}

variable "environment" {
  description = "Environment label applied as a tag. CCG refuses to remediate resources tagged Environment=prod regardless of this value (enforced at the Cedar/tool boundary, not here)."
  type        = string
  default     = "sandbox" # PLACEHOLDER - e.g. sandbox | dev | staging

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{2,20}$", var.environment))
    error_message = "environment must be 2-20 alphanumeric/underscore/hyphen characters."
  }
}

variable "audit_expiration_days" {
  description = "S3 audit record lifecycle expiration in days."
  type        = number
  default     = 30

  validation {
    condition     = var.audit_expiration_days >= 1 && var.audit_expiration_days <= 3650
    error_message = "audit_expiration_days must be between 1 and 3650."
  }
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days (must be a value CloudWatch Logs accepts)."
  type        = number
  default     = 7

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a valid CloudWatch Logs retention value."
  }
}

variable "tags" {
  description = "Additional tags merged onto all CCG resources. CCGDemo and Environment are managed by the module; do not override them here."
  type        = map(string)
  default     = {} # PLACEHOLDER - e.g. { CostCenter = "sec-eng", Owner = "platform" }
}


variable "enable_findings_deletion_protection" {
  description = "Enable DynamoDB deletion protection on the findings/idempotency table (P1.9). Default true; teardown must set false explicitly before destroy. See modules/findings-store/README.md."
  type        = bool
  default     = true
}

variable "enable_audit_access_logging" {
  description = "Enable S3 server access logging on the audit bucket (self-logging under log/ prefix). Default true; set false for teardown or when a dedicated log bucket is used instead."
  type        = bool
  default     = true
}

variable "enable_agentcore_gateway" {
  description = "Feature flag for the AgentCore Gateway. Default false: only the Gateway execution role is created, no live Gateway. Set true ONLY with a reviewed HCP plan approved for the minimal schema-capture deploy (docs/THREAT_MODEL.md gate)."
  type        = bool
  default     = false
}

variable "enable_identity_roles" {
  description = "Create the four separate POC IAM execution roles (discovery, tool-execution, control-plane, audit-reader). Safe to review before the Gateway is deployed. Set true after gate-0.2 trust-policy capture."
  type        = bool
  default     = false
}

variable "enable_discovery" {
  description = "Deploy the EventBridge schedule and Python 3.14 discovery Lambda. Set true only after gate-0.2 discovery role and read-only source permissions are confirmed."
  type        = bool
  default     = false
}

variable "discovery_schedule" {
  description = "EventBridge cron/rate expression for the scheduled discovery run."
  type        = string
  default     = "rate(15 minutes)"
}

variable "enable_remediation_tools" {
  description = "Deploy the four remediation tool Lambdas. Set true only after gate-0.2 execution role, Gateway schema, and tool input contracts are confirmed."
  type        = bool
  default     = false
}

variable "enable_console" {
  description = "Deploy API Gateway, Cognito, and API Lambda for the authenticated admin console. Set true only after gate-0.2 Cognito/API Gateway contract is confirmed and console acceptance tests are ready. Cognito user pool is always created."
  type        = bool
  default     = false
}

variable "enable_voice" {
  description = "Deploy the Nova Sonic read-only voice adapter Lambda (off by default, CCG-REQ-032). Set true only after gate-0.3 Nova Sonic contract is verified and microphone consent flow is implemented."
  type        = bool
  default     = false
}
