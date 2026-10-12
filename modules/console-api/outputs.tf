output "user_pool_id" {
  description = "Cognito user pool ID (null while enable_console = false)."
  value       = try(aws_cognito_user_pool.poc.id, null)
}

output "user_pool_arn" {
  description = "Cognito user pool ARN (null while enable_console = false)."
  value       = try(aws_cognito_user_pool.poc.arn, null)
}

output "api_lambda_arn" {
  description = "ARN of the API Lambda function (null while enable_console = false)."
  value       = try(aws_lambda_function.api[0].arn, null)
}

output "api_lambda_name" {
  description = "Name of the API Lambda function (null while enable_console = false)."
  value       = try(aws_lambda_function.api[0].function_name, null)
}

output "api_gateway_id" {
  description = "HTTP API Gateway ID (null while enable_console = false)."
  value       = try(aws_apigatewayv2_api.console[0].id, null)
}

output "api_gateway_endpoint" {
  description = "HTTP API Gateway invoke URL (null while enable_console = false)."
  value       = try(aws_apigatewayv2_api.console[0].api_endpoint, null)
}
