output "sg_correction_target_id" {
  description = "ID of the security-group correction Gateway target (null while enable_gateway_policy = false)."
  value       = try(aws_bedrockagentcore_gateway_target.sg_correction[0].target_id, null)
}

output "s3_encryption_target_id" {
  description = "ID of the S3 encryption Gateway target (null while enable_gateway_policy = false)."
  value       = try(aws_bedrockagentcore_gateway_target.s3_encryption[0].target_id, null)
}

output "tagging_target_id" {
  description = "ID of the compliant tagging Gateway target (null while enable_gateway_policy = false)."
  value       = try(aws_bedrockagentcore_gateway_target.tagging[0].target_id, null)
}

output "key_rotation_target_id" {
  description = "ID of the access-key rotation Gateway target (null while enable_gateway_policy = false)."
  value       = try(aws_bedrockagentcore_gateway_target.key_rotation[0].target_id, null)
}

output "policy_id" {
  description = "ID of the AgentCore Cedar policy resource (null while enable_gateway_policy = false)."
  value       = try(aws_bedrockagentcore_policy.ccg[0].policy_id, null)
}

output "policy_arn" {
  description = "ARN of the AgentCore Cedar policy resource (null while enable_gateway_policy = false)."
  value       = try(aws_bedrockagentcore_policy.ccg[0].policy_arn, null)
}

output "policy_statement_source" {
  description = "Where the deployed Cedar content came from, for plan review: 'reviewed-files' (concatenated policies/*.cedar) or 'explicit-override'."
  value       = var.cedar_policy_content != "" ? "explicit-override" : "reviewed-files"
}

output "gateway_target_ids" {
  description = "All four Gateway tool target IDs (null entries while enable_gateway_policy = false). Confirms the four-and-only-four mutation targets from plan/state."
  value = [
    try(aws_bedrockagentcore_gateway_target.sg_correction[0].target_id, null),
    try(aws_bedrockagentcore_gateway_target.s3_encryption[0].target_id, null),
    try(aws_bedrockagentcore_gateway_target.tagging[0].target_id, null),
    try(aws_bedrockagentcore_gateway_target.key_rotation[0].target_id, null),
  ]
}
