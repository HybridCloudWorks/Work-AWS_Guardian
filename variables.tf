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

variable "enable_agentcore_gateway" {
  description = "Feature flag for the AgentCore Gateway. Default false: only the Gateway execution role is created, no live Gateway. Set true ONLY with a reviewed HCP plan approved for the minimal schema-capture deploy (docs/THREAT_MODEL.md gate)."
  type        = bool
  default     = false
}
