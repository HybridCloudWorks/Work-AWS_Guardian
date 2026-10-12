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

output "agentcore_gateway_arn" {
  description = "ARN of the AgentCore Gateway (null until enable_agentcore_gateway = true)."
  value       = module.agentcore_gateway.gateway_arn
}

# --- Identity outputs ---------------------------------------------------------

output "discovery_role_arn" {
  description = "ARN of the discovery execution role (null until enable_identity_roles = true)."
  value       = module.identity.discovery_role_arn
}

output "tool_execution_role_arn" {
  description = "ARN of the tool-execution role (null until enable_identity_roles = true)."
  value       = module.identity.tool_execution_role_arn
}

output "control_plane_role_arn" {
  description = "ARN of the policy-activation control-plane role (null until enable_identity_roles = true)."
  value       = module.identity.control_plane_role_arn
}

# --- Discovery outputs --------------------------------------------------------

output "discovery_lambda_arn" {
  description = "ARN of the discovery Lambda (null until enable_discovery = true)."
  value       = module.discovery.lambda_arn
}

output "discovery_schedule_arn" {
  description = "ARN of the EventBridge discovery schedule (null until enable_discovery = true)."
  value       = module.discovery.schedule_arn
}

# --- Remediation tools outputs ------------------------------------------------

output "sg_correction_lambda_arn" {
  description = "ARN of the security-group correction tool Lambda (null until enable_remediation_tools = true)."
  value       = module.remediation_tools.sg_correction_lambda_arn
}

output "s3_encryption_lambda_arn" {
  description = "ARN of the S3 encryption tool Lambda (null until enable_remediation_tools = true)."
  value       = module.remediation_tools.s3_encryption_lambda_arn
}

output "tagging_lambda_arn" {
  description = "ARN of the compliant tagging tool Lambda (null until enable_remediation_tools = true)."
  value       = module.remediation_tools.tagging_lambda_arn
}

output "key_rotation_lambda_arn" {
  description = "ARN of the access-key rotation tool Lambda (null until enable_remediation_tools = true)."
  value       = module.remediation_tools.key_rotation_lambda_arn
}

# --- Console API outputs ------------------------------------------------------

output "cognito_user_pool_id" {
  description = "Cognito POC admin user pool ID."
  value       = module.console_api.user_pool_id
}

output "api_gateway_endpoint" {
  description = "HTTP API Gateway invoke URL (null until enable_console = true)."
  value       = module.console_api.api_gateway_endpoint
}
