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
  description = "ARN of the DynamoDB findings table the discovery role may upsert into and the console/API role may read."
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

variable "remediation_bucket_arns" {
  description = <<-EOT
    Explicit list of sandbox bucket ARNs the S3-encryption tool may operate on.
    S3 bucket-level actions (e.g. s3:PutEncryptionConfiguration) do NOT honor an
    aws:ResourceTag condition key, so the sandbox restriction for S3 is enforced
    by explicit-ARN scoping here (plus the Lambda-layer live CCGDemo/Environment
    recheck), never by an unenforceable tag condition. Empty by default so the
    statement resolves to the name_prefix sandbox-bucket prefix pattern below;
    pass concrete ARNs once the sandbox buckets are known (gate-0.2).
  EOT
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.remediation_bucket_arns : startswith(a, "arn:aws:s3:::")])
    error_message = "Every remediation_bucket_arns entry must be an S3 bucket ARN (arn:aws:s3:::...)."
  }

  validation {
    condition     = !contains(var.remediation_bucket_arns, "arn:aws:s3:::*")
    error_message = "remediation_bucket_arns must not contain the all-buckets wildcard arn:aws:s3:::*."
  }
}

variable "control_plane_role_arn" {
  description = <<-EOT
    ARN (or ARN pattern) of the control-plane role the console/API role may
    assume or invoke to reach the audited policy-activation path. The API role
    reaches activation ONLY through this indirection; it is never granted
    remediation actions or lambda:InvokeFunction on the tool Lambdas (that would
    bypass the Gateway). Defaults to the conventional ctrl-plane role ARN.
  EOT
  type        = string
  default     = ""
}
