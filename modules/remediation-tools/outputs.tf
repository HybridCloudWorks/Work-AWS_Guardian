output "sg_correction_lambda_arn" {
  description = "ARN of the security-group correction tool Lambda (null while enable_remediation_tools = false)."
  value       = try(aws_lambda_function.sg_correction[0].arn, null)
}

output "sg_correction_lambda_name" {
  description = "Name of the security-group correction tool Lambda (null while enable_remediation_tools = false)."
  value       = try(aws_lambda_function.sg_correction[0].function_name, null)
}

output "s3_encryption_lambda_arn" {
  description = "ARN of the S3 encryption tool Lambda (null while enable_remediation_tools = false)."
  value       = try(aws_lambda_function.s3_encryption[0].arn, null)
}

output "s3_encryption_lambda_name" {
  description = "Name of the S3 encryption tool Lambda (null while enable_remediation_tools = false)."
  value       = try(aws_lambda_function.s3_encryption[0].function_name, null)
}

output "tagging_lambda_arn" {
  description = "ARN of the compliant tagging tool Lambda (null while enable_remediation_tools = false)."
  value       = try(aws_lambda_function.tagging[0].arn, null)
}

output "tagging_lambda_name" {
  description = "Name of the compliant tagging tool Lambda (null while enable_remediation_tools = false)."
  value       = try(aws_lambda_function.tagging[0].function_name, null)
}

output "key_rotation_lambda_arn" {
  description = "ARN of the access-key rotation workflow tool Lambda (null while enable_remediation_tools = false)."
  value       = try(aws_lambda_function.key_rotation[0].arn, null)
}

output "key_rotation_lambda_name" {
  description = "Name of the access-key rotation workflow tool Lambda (null while enable_remediation_tools = false)."
  value       = try(aws_lambda_function.key_rotation[0].function_name, null)
}
