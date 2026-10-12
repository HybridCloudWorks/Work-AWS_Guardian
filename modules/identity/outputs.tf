output "discovery_role_arn" {
  description = "ARN of the discovery execution role (null while enable_roles = false)."
  value       = try(aws_iam_role.discovery[0].arn, null)
}

output "discovery_role_name" {
  description = "Name of the discovery execution role (null while enable_roles = false)."
  value       = try(aws_iam_role.discovery[0].name, null)
}

output "tool_execution_role_arn" {
  description = "ARN of the tool-execution role (null while enable_roles = false)."
  value       = try(aws_iam_role.tool_execution[0].arn, null)
}

output "tool_execution_role_name" {
  description = "Name of the tool-execution role (null while enable_roles = false)."
  value       = try(aws_iam_role.tool_execution[0].name, null)
}

output "control_plane_role_arn" {
  description = "ARN of the control-plane role (null while enable_roles = false)."
  value       = try(aws_iam_role.control_plane[0].arn, null)
}

output "control_plane_role_name" {
  description = "Name of the control-plane role (null while enable_roles = false)."
  value       = try(aws_iam_role.control_plane[0].name, null)
}

output "audit_reader_role_arn" {
  description = "ARN of the audit-reader role (null while enable_roles = false)."
  value       = try(aws_iam_role.audit_reader[0].arn, null)
}

output "api_role_arn" {
  description = "ARN of the console/API role (null while enable_roles = false)."
  value       = try(aws_iam_role.api[0].arn, null)
}

output "api_role_name" {
  description = "Name of the console/API role (null while enable_roles = false)."
  value       = try(aws_iam_role.api[0].name, null)
}
