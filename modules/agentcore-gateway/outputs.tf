output "gateway_execution_role_arn" {
  description = "ARN of the AgentCore Gateway execution role."
  value       = aws_iam_role.gateway_execution.arn
}

output "gateway_execution_role_name" {
  description = "Name of the AgentCore Gateway execution role."
  value       = aws_iam_role.gateway_execution.name
}

output "gateway_arn" {
  description = "ARN of the AgentCore Gateway (null while the feature flag is off)."
  value       = try(aws_bedrockagentcore_gateway.this[0].gateway_arn, null)
}

output "gateway_id" {
  description = "ID of the AgentCore Gateway (null while the feature flag is off)."
  value       = try(aws_bedrockagentcore_gateway.this[0].gateway_id, null)
}

output "gateway_url" {
  description = "MCP URL of the AgentCore Gateway (null while the feature flag is off)."
  value       = try(aws_bedrockagentcore_gateway.this[0].gateway_url, null)
}

output "policy_engine_arn" {
  description = "ARN of the AgentCore Policy Engine (null while the feature flag is off)."
  value       = try(aws_bedrockagentcore_policy_engine.this[0].policy_engine_arn, null)
}

output "policy_engine_id" {
  description = "ID of the AgentCore Policy Engine (null while the feature flag is off)."
  value       = try(aws_bedrockagentcore_policy_engine.this[0].policy_engine_id, null)
}
