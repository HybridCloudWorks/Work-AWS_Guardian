variable "aws_region" {
  description = "AWS Region for the dedicated POC sandbox."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Lowercase, hyphenated prefix for POC resource names."
  type        = string
  default     = "ccg-poc"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,24}$", var.name_prefix))
    error_message = "name_prefix must be 3-24 lowercase letters, numbers, or hyphens."
  }
}

variable "environment" {
  description = "Environment label; production is intentionally invalid for this POC."
  type        = string
  default     = "sandbox"

  validation {
    condition     = lower(var.environment) == "sandbox"
    error_message = "The POC environment must be exactly sandbox."
  }
}

variable "audit_expiration_days" {
  description = "S3 audit record expiration in days."
  type        = number
  default     = 30

  validation {
    condition     = var.audit_expiration_days == 30
    error_message = "The POC audit retention requirement is exactly 30 days."
  }
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days."
  type        = number
  default     = 7

  validation {
    condition     = var.log_retention_days == 7
    error_message = "The POC log retention requirement is exactly 7 days."
  }
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
