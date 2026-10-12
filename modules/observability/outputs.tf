output "log_group_name" {
  description = "Application log group name."
  value       = aws_cloudwatch_log_group.app.name
}

output "log_group_arn" {
  description = "Application log group ARN."
  value       = aws_cloudwatch_log_group.app.arn
}

output "metric_namespace" {
  description = "CloudWatch namespace the CCG metric catalog emits under (label only; see docs/OBSERVABILITY_RUNBOOK.md)."
  value       = var.metric_namespace
}

output "dashboard_name" {
  description = "Operational dashboard name when enable_dashboard is set, else null."
  value       = var.enable_dashboard ? aws_cloudwatch_dashboard.ccg[0].dashboard_name : null
}
