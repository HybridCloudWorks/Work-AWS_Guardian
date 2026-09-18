output "gateway_execution_role_arn" {
  description = "ARN of the AgentCore Gateway execution role."
  value       = aws_iam_role.gateway_execution.arn
}

output "gateway_execution_role_name" {
  description = "Name of the AgentCore Gateway execution role."
  value       = aws_iam_role.gateway_execution.name
}
