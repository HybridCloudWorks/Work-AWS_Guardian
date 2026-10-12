variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "gateway_id" {
  description = "ID of the AgentCore Gateway (from agentcore-gateway module)."
  type        = string
  default     = ""
}

variable "policy_engine_id" {
  description = "ID of the AgentCore Policy Engine (from agentcore-gateway module)."
  type        = string
  default     = ""
}

# Lambda ARNs for the four registered tool targets. Populated from
# remediation-tools module outputs once that module is enabled.
variable "sg_correction_lambda_arn" {
  description = "ARN of the security-group correction tool Lambda."
  type        = string
  default     = ""
}

variable "s3_encryption_lambda_arn" {
  description = "ARN of the S3 encryption enablement tool Lambda."
  type        = string
  default     = ""
}

variable "tagging_lambda_arn" {
  description = "ARN of the compliant tagging tool Lambda."
  type        = string
  default     = ""
}

variable "key_rotation_lambda_arn" {
  description = "ARN of the access-key rotation workflow tool Lambda."
  type        = string
  default     = ""
}

variable "cedar_policy_content" {
  description = <<-DESC
    Cedar policy set content deployed into the AgentCore policy resource.

    Default (empty string): the module reads and concatenates the REVIEWED Cedar
    files from the repository `policies/` directory, in this documented order:
      1. policies/guardrails.cedar          (always-on forbids)
      2. policies/remediation-permits.cedar (per-tool permits)
    Ordering is for human readability only — Cedar is unordered and forbid-wins.

    Override with an explicit string only to inject analyzer-validated content
    that has had `<GATEWAY_ARN>` and placeholder action IDs substituted after
    gate-0.2 schema capture. The reviewed files still carry those placeholders,
    so the default content will fail the policy analyzer until substituted; the
    module stays gated (enable_gateway_policy = false) until then.
  DESC
  type        = string
  default     = ""
}

variable "cedar_policy_dir" {
  description = "Directory holding the reviewed Cedar files (guardrails.cedar, remediation-permits.cedar). Defaults to the repository policies/ directory relative to this module."
  type        = string
  default     = ""
}

# Feature flag: gateway-policy resources depend on agentcore-gateway being
# enabled AND gate-0.2 schema/Cedar-analyzer work being complete.
variable "enable_gateway_policy" {
  description = "Deploy Gateway tool targets and Cedar policy resources. Set true only after gate-0.2 schema capture and Cedar analyzer validation are complete, AND agentcore-gateway is enabled."
  type        = bool
  default     = false
}
