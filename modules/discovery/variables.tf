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
  description = "CloudWatch log group ARN for the Lambda execution environment."
  type        = string
}

variable "log_group_name" {
  description = "CloudWatch log group name for the Lambda execution environment."
  type        = string
}

variable "discovery_role_arn" {
  description = "ARN of the discovery IAM execution role (from the identity module)."
  type        = string
}

variable "findings_table_name" {
  description = "DynamoDB findings table name the Lambda writes current state to."
  type        = string
}

variable "audit_bucket_name" {
  description = "Private audit S3 bucket name the Lambda writes JSON evidence records to."
  type        = string
}

variable "discovery_schedule" {
  description = "EventBridge cron/rate expression for the discovery schedule."
  type        = string
  default     = "rate(15 minutes)"
}

variable "lambda_timeout_seconds" {
  description = "Discovery Lambda maximum execution time (seconds). Bounded to sub-five-minute runtimes so the Lambda finishes well inside the 15-minute schedule interval."
  type        = number
  default     = 300

  validation {
    # Keep the ceiling at 300s (5 min): discovery is a read-and-write pass over
    # Config/SecurityHub/CloudTrail; anything longer indicates a stuck run that
    # should fail fast and surface via the failure alarm rather than overlap.
    condition     = var.lambda_timeout_seconds > 0 && var.lambda_timeout_seconds <= 300
    error_message = "lambda_timeout_seconds must be between 1 and 300 (sub-five-minute runtimes)."
  }
}

variable "lambda_memory_mb" {
  description = "Discovery Lambda memory allocation (MB)."
  type        = number
  default     = 256

  validation {
    condition     = var.lambda_memory_mb >= 128 && var.lambda_memory_mb <= 3008
    error_message = "lambda_memory_mb must be between 128 and 3008."
  }
}

# Feature flag: deploying the schedule fires real AWS API calls against
# Config/SecurityHub/CloudTrail. Gate behind gate-0.2 role capture.
variable "enable_discovery" {
  description = "Deploy the EventBridge schedule and discovery Lambda. Set true only after gate-0.2 discovery role and read-only source permissions are confirmed."
  type        = bool
  default     = false
}

# --- Failure handling (DLQ + alarm) ------------------------------------------

variable "dlq_retention_days" {
  description = "Message retention for the discovery dead-letter queue (days). Defaults to 7 to match CloudWatch log retention so DLQ messages and logs expire together for correlation."
  type        = number
  default     = 7

  validation {
    # SQS allows 60s..14 days; cap at 14 days and keep POC-small.
    condition     = var.dlq_retention_days >= 1 && var.dlq_retention_days <= 14
    error_message = "dlq_retention_days must be between 1 and 14."
  }
}

variable "enable_failure_alarm" {
  description = "Create the CloudWatch failure alarms (Lambda Errors and DLQ depth) for CCG-REQ-037. Alarms carry no action by default; the ALARM state itself is the POC signal."
  type        = bool
  default     = true
}

variable "alarm_error_threshold" {
  description = "Discovery Lambda Errors count that trips the failure alarm within one evaluation period."
  type        = number
  default     = 0

  validation {
    condition     = var.alarm_error_threshold >= 0
    error_message = "alarm_error_threshold must be zero or greater (fires on > threshold)."
  }
}

variable "alarm_period_seconds" {
  description = "Evaluation period (seconds) for the discovery failure alarms. Default 900 aligns with the 15-minute schedule."
  type        = number
  default     = 900

  validation {
    # CloudWatch standard-resolution periods must be a multiple of 60.
    condition     = var.alarm_period_seconds >= 60 && var.alarm_period_seconds % 60 == 0
    error_message = "alarm_period_seconds must be at least 60 and a multiple of 60."
  }
}

variable "alarm_sns_topic_arns" {
  description = "Optional SNS topic ARNs for alarm/ok actions. Empty by default (POC relies on the ALARM state; voice/notification wiring stays off per cost-and-poc defaults)."
  type        = list(string)
  default     = []
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
