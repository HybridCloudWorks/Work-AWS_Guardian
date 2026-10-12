variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch log retention period."
  type        = number
}

variable "metric_namespace" {
  description = <<-EOT
    CloudWatch namespace the application emits CCG metrics under (see the
    `ccg.observability.Metric` catalog and docs/OBSERVABILITY_RUNBOOK.md). This
    is a label only; no resource is created from it unless `enable_dashboard`
    is set. Kept out of the metric *values* so no secret/ARN can leak.
  EOT
  type        = string
  default     = "CCG"
}

variable "enable_dashboard" {
  description = <<-EOT
    Create the operational CloudWatch dashboard stub. OFF by default: the POC
    baseline emits no custom metrics yet (CloudWatch EMF/PutMetricData is gated
    on 0.2), so the dashboard would render empty widgets. Enabling it is
    credential-free at plan time and creates only a dashboard document; it does
    not require the application to be emitting.
  EOT
  type        = bool
  default     = false
}

variable "region" {
  description = "AWS region used only to scope the dashboard widgets (no resource is created from it unless enable_dashboard is set)."
  type        = string
  default     = "us-east-1"
}
