output "lambda_arn" {
  description = "ARN of the voice adapter Lambda function (null while enable_voice = false)."
  value       = try(aws_lambda_function.voice_adapter[0].arn, null)
}

output "lambda_name" {
  description = "Name of the voice adapter Lambda function (null while enable_voice = false)."
  value       = try(aws_lambda_function.voice_adapter[0].function_name, null)
}

output "role_arn" {
  description = "ARN of the voice adapter IAM role (null while enable_voice = false)."
  value       = try(aws_iam_role.voice_adapter[0].arn, null)
}
