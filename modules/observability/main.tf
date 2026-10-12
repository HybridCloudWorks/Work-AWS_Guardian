resource "aws_cloudwatch_log_group" "app" {
  name              = "/ccg/${var.name_prefix}"
  retention_in_days = var.log_retention_days
}

# --- Operational dashboard stub (CCG-REQ-037) --------------------------------
# GATING: `enable_dashboard` (default false). The POC baseline emits no custom
# CloudWatch metrics yet — application EMF/PutMetricData emission is gated on
# gate-0.2 (see docs/OBSERVABILITY_RUNBOOK.md). Until then this would render
# empty widgets, so it is off by default. It is credential-free at plan time
# and creates only a dashboard document (no cost, no always-on compute). The
# widgets reference the metric namespace (var.metric_namespace) and the stable
# metric names from the `ccg.observability.Metric` catalog, so the dashboard
# lights up automatically once emission is wired, with no name drift.
resource "aws_cloudwatch_dashboard" "ccg" {
  count = var.enable_dashboard ? 1 : 0

  dashboard_name = "${var.name_prefix}-ccg"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "Gateway decisions (allow vs deny)"
          region  = var.region
          view    = "timeSeries"
          stacked = false
          metrics = [
            [var.metric_namespace, "ccg.gateway.allow"],
            [var.metric_namespace, "ccg.gateway.deny"],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Discovery runs (partial / failure)"
          region = var.region
          view   = "timeSeries"
          metrics = [
            [var.metric_namespace, "ccg.discovery.run"],
            [var.metric_namespace, "ccg.discovery.partial"],
            [var.metric_namespace, "ccg.discovery.failure"],
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Tool outcomes"
          region = var.region
          view   = "timeSeries"
          metrics = [
            [var.metric_namespace, "ccg.tool.applied"],
            [var.metric_namespace, "ccg.tool.noop"],
            [var.metric_namespace, "ccg.tool.failed"],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Activation / audit / voice"
          region = var.region
          view   = "timeSeries"
          metrics = [
            [var.metric_namespace, "ccg.policy.activation_success"],
            [var.metric_namespace, "ccg.policy.activation_failure"],
            [var.metric_namespace, "ccg.audit.write_failure"],
            [var.metric_namespace, "ccg.voice.error"],
          ]
        }
      },
    ]
  })
}
