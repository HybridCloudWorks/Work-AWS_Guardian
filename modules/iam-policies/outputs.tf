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
