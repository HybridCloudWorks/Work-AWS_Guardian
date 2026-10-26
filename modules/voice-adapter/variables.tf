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
  description = "DynamoDB findings table name (read-only access for summary generation)."
  type        = string
}

variable "lambda_timeout_seconds" {
  description = "Voice adapter Lambda maximum execution time (seconds)."
  type        = number
  default     = 30

  validation {
    condition     = var.lambda_timeout_seconds > 0 && var.lambda_timeout_seconds <= 900
    error_message = "lambda_timeout_seconds must be between 1 and 900."
  }
}

variable "lambda_memory_mb" {
  description = "Voice adapter Lambda memory allocation (MB)."
  type        = number
  default     = 256

  validation {
    condition     = var.lambda_memory_mb >= 128 && var.lambda_memory_mb <= 3008
    error_message = "lambda_memory_mb must be between 128 and 3008."
  }
}

# Voice is explicitly OFF by default (CCG-REQ-032 / design §3.5).
# Prerequisites before enabling:
#   - Gate-0.3: Nova Sonic model ID, region, transport, quota, and browser
#     audio path must be verified.
#   - Voice adapter must be confirmed read-only with no mutation tool schema.
#   - Browser microphone consent flow must be implemented and tested.
variable "enable_voice" {
  description = "Deploy the Nova Sonic voice adapter Lambda. Voice is OFF by default (CCG-REQ-032). Set true only after gate-0.3 Nova Sonic contract is verified."
  type        = bool
  default     = false
}

variable "lambda_package_path" {
  description = "Path to the built CCG Lambda deployment zip (from scripts/build_lambda_package.py or the root archive_file). Defaults to the committed placeholder so the module validates standalone before a real build exists."
  type        = string
  default     = ""
}

variable "lambda_package_hash" {
  description = "base64-encoded sha256 of the Lambda package, for source_code_hash change detection. Empty with the placeholder."
  type        = string
  default     = ""
}
