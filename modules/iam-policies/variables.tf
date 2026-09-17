variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "account_id" {
  description = "The sandbox account ID these policies are scoped to."
  type        = string
}

variable "region" {
  description = "The region these policies are scoped to."
  type        = string
}

variable "audit_bucket_arn" {
  description = "ARN of the S3 audit bucket the discovery role may write and the audit-reader may read."
  type        = string
}

variable "findings_table_arn" {
  description = "ARN of the DynamoDB findings table the discovery role may upsert into."
  type        = string
}

variable "log_group_arn" {
  description = "ARN of the CloudWatch log group components may write structured logs to."
  type        = string
}

variable "sandbox_tag_key" {
  description = "Tag key that gates mutation eligibility."
  type        = string
  default     = "CCGDemo"
}

variable "sandbox_tag_value" {
  description = "Tag value that gates mutation eligibility."
  type        = string
  default     = "true"
}
