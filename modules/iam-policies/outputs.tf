output "discovery_policy_json" {
  description = "Least-privilege policy for the read-only discovery role (allow statements + inlined deny boundary)."
  value       = data.aws_iam_policy_document.discovery.json
}

output "tool_execution_policy_json" {
  description = "Least-privilege policy for the sandbox-gated tool-execution role (allow statements + inlined deny boundary)."
  value       = data.aws_iam_policy_document.tool_execution.json
}

output "control_plane_policy_json" {
  description = "Least-privilege policy for the policy-activation control-plane role (allow statements + inlined deny boundary)."
  value       = data.aws_iam_policy_document.control_plane.json
}

output "audit_reader_policy_json" {
  description = "Read-only policy for the audit-reader role."
  value       = data.aws_iam_policy_document.audit_reader.json
}

output "api_policy_json" {
  description = "Least-privilege policy for the console/API role: read findings/audit + assume the control-plane role for activation, with an inlined deny boundary that blocks remediation, direct policy activation, and tool-Lambda invocation (Gateway bypass)."
  value       = data.aws_iam_policy_document.api.json
}

output "gateway_assume_role_policy_json" {
  description = "Trust policy allowing AgentCore to assume the Gateway execution role (SourceAccount-scoped)."
  value       = data.aws_iam_policy_document.gateway_assume_role.json
}

output "gateway_execution_policy_json" {
  description = "Least-privilege permission policy for the Gateway execution role (invoke tool Lambdas + logs). This is the ONLY policy that grants lambda:InvokeFunction on the tool targets, so every mutation must traverse the Gateway."
  value       = data.aws_iam_policy_document.gateway_execution.json
}
