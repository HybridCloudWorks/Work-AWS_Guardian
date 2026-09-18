variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "assume_role_policy_json" {
  description = "Trust policy JSON for the Gateway execution role."
  type        = string
}

variable "execution_policy_json" {
  description = "Permission policy JSON for the Gateway execution role."
  type        = string
}

variable "enable_gateway" {
  description = "Feature flag. When false (default) NO AgentCore Gateway is created — only the execution role exists. Set true only after the Phase 1.2 threat model is reviewed and a reviewed HCP plan is approved for schema capture."
  type        = bool
  default     = false
}
