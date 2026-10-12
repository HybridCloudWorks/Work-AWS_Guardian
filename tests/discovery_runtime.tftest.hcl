# Native Terraform tests (Terraform 1.6+; repo runtime 1.16.5) for the task-2.4
# discovery runtime: EventBridge schedule, Lambda bounds, failure DLQ, and
# failure alarms.
#
# Credential-free by design:
#   - A mock AWS provider supplies computed values, so no AWS calls are made.
#   - Each `run` targets the discovery module directly via
#     `module { source = "./modules/discovery" }`, so unrelated Gateway/IAM/
#     storage wiring need not resolve.
#
# Run from the repository root:
#   terraform init -backend=false -input=false
#   terraform test

# The mock provider returns arbitrary strings for computed attributes, but
# aws_iam_role.assume_role_policy validates that its input is a JSON object.
# Supply a valid JSON object for the policy-document data source's `json`
# attribute so the mocked plan passes that client-side validation. The IAM
# policy *content* is asserted separately in iam_negative_permissions.tftest.hcl
# against a real (credential-free) provider; here we only exercise the
# discovery runtime wiring.
mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  name_prefix         = "ccg-poc"
  region              = "us-east-1"
  account_id          = "111122223333"
  log_group_arn       = "arn:aws:logs:us-east-1:111122223333:log-group:/ccg-poc"
  log_group_name      = "/ccg-poc"
  discovery_role_arn  = "arn:aws:iam::111122223333:role/ccg-poc-discovery"
  findings_table_name = "ccg-poc-findings"
  audit_bucket_name   = "ccg-poc-audit"
}

# --- Enabled: schedule, runtime bounds, DLQ, alarms (DR1-DR10) ---------------

run "discovery_runtime_enabled" {
  command = plan

  module {
    source = "./modules/discovery"
  }

  variables {
    enable_discovery = true
  }

  # DR1 — schedule expression defaults to 15 minutes.
  assert {
    condition     = aws_scheduler_schedule.discovery[0].schedule_expression == "rate(15 minutes)"
    error_message = "DR1: discovery schedule must default to rate(15 minutes)."
  }

  # DR2 — bounded Scheduler retry policy.
  assert {
    condition = (
      aws_scheduler_schedule.discovery[0].target[0].retry_policy[0].maximum_retry_attempts == 2 &&
      aws_scheduler_schedule.discovery[0].target[0].retry_policy[0].maximum_event_age_in_seconds == 900
    )
    error_message = "DR2: Scheduler retry policy must be 2 attempts / 900s."
  }

  # DR3 — reserved concurrency is pinned to 1 (no overlapping runs).
  assert {
    condition     = aws_lambda_function.discovery[0].reserved_concurrent_executions == 1
    error_message = "DR3: reserved_concurrent_executions must be 1."
  }

  # DR4 — bounded, sub-five-minute timeout default.
  assert {
    condition     = aws_lambda_function.discovery[0].timeout == 300
    error_message = "DR4: Lambda timeout must default to 300s (bounded)."
  }

  # DR5 — Python 3.14 baseline.
  assert {
    condition     = aws_lambda_function.discovery[0].runtime == "python3.14"
    error_message = "DR5: Lambda runtime must be python3.14."
  }

  # DR6 — NO vpc_config, so no NAT is required.
  assert {
    condition     = length(aws_lambda_function.discovery[0].vpc_config) == 0
    error_message = "DR6: Lambda must have no vpc_config (no NAT in the POC topology)."
  }

  # DR7 — DLQ SSE enabled.
  assert {
    condition     = aws_sqs_queue.discovery_dlq[0].sqs_managed_sse_enabled == true
    error_message = "DR7: discovery DLQ must have SQS-managed SSE enabled."
  }

  # DR8 — DLQ retention defaults to 7 days (matches log retention).
  assert {
    condition     = aws_sqs_queue.discovery_dlq[0].message_retention_seconds == 7 * 24 * 60 * 60
    error_message = "DR8: discovery DLQ retention must be 7 days."
  }

  # DR9 — Scheduler target routes failures to the DLQ.
  assert {
    condition     = length(aws_scheduler_schedule.discovery[0].target[0].dead_letter_config) == 1
    error_message = "DR9: Scheduler target must have a dead_letter_config (DLQ)."
  }

  # DR10 — Lambda async failures route to the DLQ with retries bounded to 0.
  assert {
    condition = (
      aws_lambda_function_event_invoke_config.discovery[0].maximum_retry_attempts == 0 &&
      length(aws_lambda_function_event_invoke_config.discovery[0].destination_config) == 1
    )
    error_message = "DR10: async invoke config must bound retries to 0 and route on_failure to the DLQ."
  }

  # DR11 — failure alarms exist by default (CCG-REQ-037).
  assert {
    condition = (
      length(aws_cloudwatch_metric_alarm.discovery_errors) == 1 &&
      length(aws_cloudwatch_metric_alarm.discovery_dlq_depth) == 1
    )
    error_message = "DR11: both failure alarms must be created when enabled."
  }

  # DR12 — error alarm targets the discovery Lambda Errors metric.
  assert {
    condition = (
      aws_cloudwatch_metric_alarm.discovery_errors[0].namespace == "AWS/Lambda" &&
      aws_cloudwatch_metric_alarm.discovery_errors[0].metric_name == "Errors" &&
      aws_cloudwatch_metric_alarm.discovery_errors[0].comparison_operator == "GreaterThanThreshold"
    )
    error_message = "DR12: error alarm must watch AWS/Lambda Errors > threshold."
  }
}

# --- Disabled by default: zero resources (DR13) ------------------------------

run "discovery_runtime_disabled_by_default" {
  command = plan

  module {
    source = "./modules/discovery"
  }

  # enable_discovery defaults to false; create nothing.
  assert {
    condition = (
      length(aws_scheduler_schedule.discovery) == 0 &&
      length(aws_lambda_function.discovery) == 0 &&
      length(aws_iam_role.scheduler) == 0 &&
      length(aws_iam_role_policy.scheduler_invoke) == 0 &&
      length(aws_sqs_queue.discovery_dlq) == 0 &&
      length(aws_lambda_function_event_invoke_config.discovery) == 0 &&
      length(aws_cloudwatch_metric_alarm.discovery_errors) == 0 &&
      length(aws_cloudwatch_metric_alarm.discovery_dlq_depth) == 0
    )
    error_message = "DR13: no discovery resources may exist when enable_discovery = false."
  }
}

# --- Alarm toggle off keeps the DLQ but drops the alarms (DR14) --------------

run "discovery_runtime_alarm_toggle_off" {
  command = plan

  module {
    source = "./modules/discovery"
  }

  variables {
    enable_discovery     = true
    enable_failure_alarm = false
  }

  assert {
    condition = (
      length(aws_cloudwatch_metric_alarm.discovery_errors) == 0 &&
      length(aws_cloudwatch_metric_alarm.discovery_dlq_depth) == 0 &&
      length(aws_sqs_queue.discovery_dlq) == 1
    )
    error_message = "DR14: disabling the alarm must drop both alarms but keep the DLQ."
  }
}

# --- Variable-validation guard: timeout ceiling is 300s (DR15) ---------------

run "lambda_timeout_rejects_over_300" {
  command = plan

  module {
    source = "./modules/discovery"
  }

  variables {
    lambda_timeout_seconds = 600
  }

  expect_failures = [
    var.lambda_timeout_seconds,
  ]
}
