variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "region" {
  description = "AWS region for ARN construction."
  type        = string
}

variable "account_id" {
  description = "AWS account ID for ARN construction."
  type        = string
}

variable "log_group_arn" {
  description = "CloudWatch log group ARN."
  type        = string
}

variable "log_group_name" {
  description = "CloudWatch log group name (passed to Lambda environment)."
  type        = string
}

variable "tool_execution_role_arn" {
  description = "ARN of the tool-execution IAM role (from identity module)."
  type        = string
  default     = ""
}

variable "findings_table_name" {
  description = "DynamoDB findings table name (for idempotency and finding-version checks)."
  type        = string
}

variable "audit_bucket_name" {
  description = "Private audit S3 bucket name (for writing tool decision evidence)."
  type        = string
}

variable "lambda_timeout_seconds" {
  description = "Tool Lambda maximum execution time (seconds)."
  type        = number
  default     = 60

  validation {
    condition     = var.lambda_timeout_seconds > 0 && var.lambda_timeout_seconds <= 900
    error_message = "lambda_timeout_seconds must be between 1 and 900."
  }
}

variable "lambda_memory_mb" {
  description = "Tool Lambda memory allocation (MB)."
  type        = number
  default     = 256

  validation {
    condition     = var.lambda_memory_mb >= 128 && var.lambda_memory_mb <= 3008
    error_message = "lambda_memory_mb must be between 128 and 3008."
  }
}

# Feature flag: deploying tool Lambdas creates the Gateway invocation surface.
# They must only be enabled after gate-0.2 role/schema capture and with the
# Gateway feature flag already enabled.
variable "enable_remediation_tools" {
  description = "Deploy the four remediation tool Lambdas. Set true only after gate-0.2 execution role, Gateway schema, and tool input contract are confirmed."
  type        = bool
  default     = false
}
