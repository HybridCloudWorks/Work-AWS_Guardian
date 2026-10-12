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

variable "findings_table_name" {
  description = "DynamoDB findings table name."
  type        = string
}

variable "audit_bucket_name" {
  description = "Private audit S3 bucket name."
  type        = string
}

variable "lambda_timeout_seconds" {
  description = "API Lambda maximum execution time (seconds)."
  type        = number
  default     = 30

  validation {
    condition     = var.lambda_timeout_seconds > 0 && var.lambda_timeout_seconds <= 900
    error_message = "lambda_timeout_seconds must be between 1 and 900."
  }
}

variable "lambda_memory_mb" {
  description = "API Lambda memory allocation (MB)."
  type        = number
  default     = 256

  validation {
    condition     = var.lambda_memory_mb >= 128 && var.lambda_memory_mb <= 3008
    error_message = "lambda_memory_mb must be between 128 and 3008."
  }
}

# Feature flag: provisioning Cognito, API Gateway, and Lambda creates a live
# authenticated endpoint. Gate behind gate-0.2 and console acceptance tests.
variable "enable_console" {
  description = "Deploy Cognito, API Gateway, and API Lambda. Set true only after gate-0.2 Cognito/API Gateway contract is confirmed and console acceptance tests are ready."
  type        = bool
  default     = false
}
