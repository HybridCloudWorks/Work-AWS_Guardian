variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "enable_deletion_protection" {
  description = "Enable DynamoDB deletion protection. Left off by default so the POC teardown/destroy flow is not blocked; enable for longer-lived deployments."
  type        = bool
  default     = false
}
