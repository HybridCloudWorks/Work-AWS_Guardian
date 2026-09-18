output "audit_bucket_name" {
  description = "Private S3 bucket holding redacted POC audit records."
  value       = module.audit_storage.bucket_name
}

output "audit_bucket_arn" {
  description = "ARN of the private POC audit bucket."
  value       = module.audit_storage.bucket_arn
}

output "findings_table_name" {
  description = "On-demand DynamoDB table holding current findings."
  value       = module.findings_store.table_name
}

output "application_log_group_name" {
  description = "Seven-day CloudWatch application log group."
  value       = module.observability.log_group_name
}

output "discovery_role_policy_json" {
  description = "Least-privilege policy document for the read-only discovery role."
  value       = module.iam_policies.discovery_policy_json
}

output "tool_execution_role_policy_json" {
  description = "Least-privilege policy document for the sandbox-gated tool-execution role."
  value       = module.iam_policies.tool_execution_policy_json
}

output "control_plane_role_policy_json" {
  description = "Least-privilege policy document for the policy-activation control-plane role."
  value       = module.iam_policies.control_plane_policy_json
}

output "audit_reader_role_policy_json" {
  description = "Read-only policy document for the audit-reader role."
  value       = module.iam_policies.audit_reader_policy_json
}

output "agentcore_gateway_execution_role_arn" {
  description = "ARN of the AgentCore Gateway execution role (used as the Gateway roleArn when the Gateway is enabled)."
  value       = module.agentcore_gateway.gateway_execution_role_arn
}
