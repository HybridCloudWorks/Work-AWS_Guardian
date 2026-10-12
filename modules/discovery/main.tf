# EventBridge schedule and discovery Lambda stub.
#
# Design §3.1: EventBridge invokes a Python 3.14 discovery Lambda at a
# configurable schedule (default 15 min). The discovery role can read only
# the approved source APIs (Config, Security Hub, CloudTrail) and write the
# evidence destinations; it cannot assume the remediation role or call any
# Gateway mutation tool.
#
# GATING: All resources are gated behind `enable_discovery` (default false).
# This includes the dedicated Scheduler IAM role and its invoke policy, so the
# module creates nothing in the "all inactive by default" POC baseline. The
# IAM policy-document data sources are gated too (count-indexed) for strict
# symmetry; data sources make no AWS calls and carry no runtime cost, but
# gating them keeps every resource/reference consistent.
#
# PREREQUISITES (gate-0.2 before enabling):
#   - discovery_role_arn must reference a confirmed least-privilege role.
#   - Lambda package ARN/S3 key must be populated (placeholder below).
#   - Source adapter throttle/permission handling must be confirmed live.
#
# COST / POC TOPOLOGY (CCG-REQ-038):
#   - Lambda is billed per invocation/duration; EventBridge Scheduler is billed
#     per schedule invocation; SQS DLQ is per-request. All well within the
#     $150/month POC budget at 15-minute intervals and sub-five-minute runtimes.
#   - The Lambda has NO vpc_config, so no NAT gateway / NAT instance is
#     required (serverless egress over the AWS network). There is no always-on
#     compute, no provisioned capacity, and no multi-AZ topology.

# --- EventBridge Scheduler schedule ------------------------------------------
resource "aws_scheduler_schedule" "discovery" {
  count = var.enable_discovery ? 1 : 0

  name        = "${var.name_prefix}-discovery"
  description = "CCG POC discovery run (read-only source collection)."

  schedule_expression          = var.discovery_schedule
  schedule_expression_timezone = "UTC"

  # Allow one active run at a time; drop if the previous run is still in
  # flight (prevents overlapping runs against the findings table).
  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.discovery[0].arn
    role_arn = aws_iam_role.scheduler[0].arn

    retry_policy {
      maximum_retry_attempts       = 2
      maximum_event_age_in_seconds = 900
    }

    # Scheduler invokes the Lambda SYNCHRONOUSLY. If every retry above is
    # exhausted (or the target is throttled/unreachable), Scheduler routes the
    # undeliverable event here. This is the schedule-delivery failure path.
    dead_letter_config {
      arn = aws_sqs_queue.discovery_dlq[0].arn
    }
  }
}

# Dedicated EventBridge Scheduler IAM role — invoke the discovery Lambda only.
resource "aws_iam_role" "scheduler" {
  count = var.enable_discovery ? 1 : 0

  name        = "${var.name_prefix}-scheduler"
  description = "EventBridge Scheduler role — invoke the discovery Lambda only."

  assume_role_policy = data.aws_iam_policy_document.scheduler_assume_role[0].json

  tags = {
    Component = "discovery"
    CCGDemo   = "true"
  }
}

data "aws_iam_policy_document" "scheduler_assume_role" {
  count = var.enable_discovery ? 1 : 0

  statement {
    sid     = "SchedulerAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_iam_role_policy" "scheduler_invoke" {
  count = var.enable_discovery ? 1 : 0

  name = "${var.name_prefix}-scheduler-invoke"
  role = aws_iam_role.scheduler[0].id

  policy = data.aws_iam_policy_document.scheduler_invoke[0].json
}

data "aws_iam_policy_document" "scheduler_invoke" {
  count = var.enable_discovery ? 1 : 0

  statement {
    sid       = "InvokeDiscoveryLambda"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = ["arn:aws:lambda:${var.region}:${var.account_id}:function:${var.name_prefix}-discovery"]
  }

  # Allow Scheduler to deliver undeliverable events to the DLQ.
  statement {
    sid       = "SendToDiscoveryDLQ"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.discovery_dlq[0].arn]
  }
}

# --- Failure destination (dead-letter queue) ---------------------------------
# Covers TWO failure paths:
#   1. EventBridge Scheduler schedule-delivery failures (wired above via the
#      target's dead_letter_config) — e.g. the Lambda is throttled/unreachable
#      and all retries are exhausted.
#   2. Lambda ASYNCHRONOUS invocation failures (wired below via
#      aws_lambda_function_event_invoke_config on_failure). Scheduler itself is
#      synchronous, but any async path (e.g. a future EventBridge rule) lands
#      here too, and it bounds Lambda-side retries.
# SSE is enabled (SQS-managed keys, consistent with ADR 0003 "AWS-managed keys,
# no CMK"). Retention matches the 7-day CloudWatch log retention so the DLQ and
# logs expire together for correlation.
resource "aws_sqs_queue" "discovery_dlq" {
  count = var.enable_discovery ? 1 : 0

  name = "${var.name_prefix}-discovery-dlq"

  message_retention_seconds = var.dlq_retention_days * 24 * 60 * 60

  # SSE with the SQS-managed key (no CMK per ADR 0003).
  sqs_managed_sse_enabled = true

  tags = {
    Component = "discovery"
    CCGDemo   = "true"
  }
}

# Bound Lambda-side async retries and route failures to the DLQ.
resource "aws_lambda_function_event_invoke_config" "discovery" {
  count = var.enable_discovery ? 1 : 0

  function_name          = aws_lambda_function.discovery[0].function_name
  maximum_retry_attempts = 0

  destination_config {
    on_failure {
      destination = aws_sqs_queue.discovery_dlq[0].arn
    }
  }
}

# --- Discovery Lambda ---------------------------------------------------------
# The Lambda package is intentionally a placeholder. The actual zip/S3 key is
# populated in a later task (3.x live-transport work) after gate-0.2 confirms
# the execution role and source adapter behavior.
resource "aws_lambda_function" "discovery" {
  count = var.enable_discovery ? 1 : 0

  function_name = "${var.name_prefix}-discovery"
  description   = "CCG POC read-only discovery run (Config / SecurityHub / CloudTrail)."

  # Python 3.14 baseline (ADR 0006).
  runtime = "python3.14"
  handler = "ccg.discovery_handler.lambda_handler"
  role    = var.discovery_role_arn

  # Placeholder: replace with an aws_s3_object data source or
  # aws_lambda_function_url once the deployment package exists.
  filename = "${path.module}/placeholder.zip"

  timeout     = var.lambda_timeout_seconds
  memory_size = var.lambda_memory_mb

  # Cap concurrent runs to 1 to prevent overlapping discovery jobs from
  # producing duplicate findings. Increase only after idempotency is confirmed.
  reserved_concurrent_executions = 1

  environment {
    variables = {
      FINDINGS_TABLE_NAME = var.findings_table_name
      AUDIT_BUCKET_NAME   = var.audit_bucket_name
      LOG_GROUP_NAME      = var.log_group_name
      # Tracing correlation IDs are generated inside the handler; no secrets here.
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Component = "discovery"
    CCGDemo   = "true"
  }
}

# Allow EventBridge Scheduler to invoke the Lambda (in addition to the
# Scheduler role's IAM policy, Lambda requires a resource-based policy).
resource "aws_lambda_permission" "scheduler_invoke" {
  count = var.enable_discovery ? 1 : 0

  statement_id  = "AllowEventBridgeScheduler"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.discovery[0].function_name
  principal     = "scheduler.amazonaws.com"

  source_account = var.account_id
}

# --- Failure alarm (CCG-REQ-037: discovery failure) --------------------------
# POC-appropriate: fires on either discovery Lambda Errors > 0 or DLQ depth > 0
# over a single period. No SNS action is attached by default (an alarm in the
# ALARM state is the required operational signal for the POC); set
# alarm_sns_topic_arns to wire notifications without changing this module.
resource "aws_cloudwatch_metric_alarm" "discovery_errors" {
  count = var.enable_discovery && var.enable_failure_alarm ? 1 : 0

  alarm_name        = "${var.name_prefix}-discovery-errors"
  alarm_description = "CCG-REQ-037: discovery Lambda invocation errors over the evaluation window."

  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = var.alarm_period_seconds
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.alarm_error_threshold
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.discovery[0].function_name
  }

  alarm_actions = var.alarm_sns_topic_arns
  ok_actions    = var.alarm_sns_topic_arns

  tags = {
    Component = "discovery"
    CCGDemo   = "true"
  }
}

# Secondary alarm on DLQ depth — catches schedule-delivery failures that never
# produce a Lambda Errors datapoint (the Lambda was never reached).
resource "aws_cloudwatch_metric_alarm" "discovery_dlq_depth" {
  count = var.enable_discovery && var.enable_failure_alarm ? 1 : 0

  alarm_name        = "${var.name_prefix}-discovery-dlq-depth"
  alarm_description = "CCG-REQ-037: undeliverable discovery events landed in the dead-letter queue."

  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = var.alarm_period_seconds
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.discovery_dlq[0].name
  }

  alarm_actions = var.alarm_sns_topic_arns
  ok_actions    = var.alarm_sns_topic_arns

  tags = {
    Component = "discovery"
    CCGDemo   = "true"
  }
}
