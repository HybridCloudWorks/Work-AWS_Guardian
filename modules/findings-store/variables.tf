variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "enable_deletion_protection" {
  description = "Enable DynamoDB deletion protection (P1.9/M4). Default true so the current-finding and idempotency state cannot be destroyed accidentally. Teardown MUST flip this to false explicitly before `terraform destroy`; see modules/findings-store/README.md."
  type        = bool
  default     = true
}
