output "lambda_arn" {
  description = "ARN of the discovery Lambda function (null while enable_discovery = false)."
  value       = try(aws_lambda_function.discovery[0].arn, null)
}

output "lambda_name" {
  description = "Name of the discovery Lambda function (null while enable_discovery = false)."
  value       = try(aws_lambda_function.discovery[0].function_name, null)
}

output "schedule_arn" {
  description = "ARN of the EventBridge Scheduler schedule (null while enable_discovery = false)."
  value       = try(aws_scheduler_schedule.discovery[0].arn, null)
}

output "scheduler_role_arn" {
  description = "ARN of the EventBridge Scheduler IAM role (null while enable_discovery = false)."
  value       = try(aws_iam_role.scheduler[0].arn, null)
}

output "dlq_arn" {
  description = "ARN of the discovery dead-letter queue (null while enable_discovery = false)."
  value       = try(aws_sqs_queue.discovery_dlq[0].arn, null)
}

output "dlq_url" {
  description = "URL of the discovery dead-letter queue (null while enable_discovery = false)."
  value       = try(aws_sqs_queue.discovery_dlq[0].url, null)
}

output "error_alarm_name" {
  description = "Name of the discovery Lambda Errors alarm (null when the alarm is disabled)."
  value       = try(aws_cloudwatch_metric_alarm.discovery_errors[0].alarm_name, null)
}

output "dlq_alarm_name" {
  description = "Name of the discovery DLQ-depth alarm (null when the alarm is disabled)."
  value       = try(aws_cloudwatch_metric_alarm.discovery_dlq_depth[0].alarm_name, null)
}
