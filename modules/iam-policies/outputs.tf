output "discovery_policy_json" {
  description = "Least-privilege policy for the read-only discovery role (with deny boundary)."
  value       = data.aws_iam_policy_document.discovery_boundary.json
}

output "tool_execution_policy_json" {
  description = "Least-privilege policy for the sandbox-gated tool-execution role (with deny boundary)."
  value       = data.aws_iam_policy_document.tool_execution_boundary.json
}

output "control_plane_policy_json" {
  description = "Least-privilege policy for the policy-activation control-plane role (with deny boundary)."
  value       = data.aws_iam_policy_document.control_plane_boundary.json
}

output "audit_reader_policy_json" {
  description = "Read-only policy for the audit-reader role."
  value       = data.aws_iam_policy_document.audit_reader.json
}

output "gateway_assume_role_policy_json" {
  description = "Trust policy allowing AgentCore to assume the Gateway execution role (SourceAccount-scoped)."
  value       = data.aws_iam_policy_document.gateway_assume_role.json
}

output "gateway_execution_policy_json" {
  description = "Least-privilege permission policy for the Gateway execution role (invoke tool Lambdas + logs)."
  value       = data.aws_iam_policy_document.gateway_execution.json
}
