variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "account_id" {
  description = "AWS account ID used to scope trust policies."
  type        = string
}

variable "region" {
  description = "AWS region used to scope trust policies."
  type        = string
}

variable "discovery_policy_json" {
  description = "Least-privilege permission policy JSON for the discovery role."
  type        = string
}

variable "tool_execution_policy_json" {
  description = "Least-privilege permission policy JSON for the tool execution role."
  type        = string
}

variable "control_plane_policy_json" {
  description = "Least-privilege permission policy JSON for the control-plane role."
  type        = string
}

variable "audit_reader_policy_json" {
  description = "Read-only permission policy JSON for the audit-reader role."
  type        = string
}

variable "api_policy_json" {
  description = "Least-privilege permission policy JSON for the console/API role (read findings/audit + assume control-plane; no remediation, no Gateway bypass)."
  type        = string
}

# Feature flag: IAM roles are always safe to create (no runtime cost); this
# flag exists so main.tf composition can be reviewed as a unit.
variable "enable_roles" {
  description = "Create the four POC IAM roles. Safe to enable before the Gateway is deployed because the roles carry no permissions without a live runtime attaching to them."
  type        = bool
  default     = false
}
