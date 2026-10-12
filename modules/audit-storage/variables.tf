variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "audit_expiration_days" {
  description = "Audit object expiration period."
  type        = number
}
variable "enable_access_logging" {
  description = "Enable S3 server access logging. POC default on: logs are written to the audit bucket itself under a log/ prefix (self-logging) to avoid a second always-on log bucket. Set false for teardown or when a dedicated log bucket is provisioned instead."
  type        = bool
  default     = true
}
