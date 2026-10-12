# `discovery` module

Provisions the EventBridge Scheduler schedule, the Python 3.14 discovery
Lambda, and the failure-handling signals (dead-letter queue + CloudWatch
alarms) for the Continuous Compliance Guardian POC.

Design reference: §3.1 (discovery runtime); requirements CCG-REQ-037
(operational alarms) and CCG-REQ-038 (cost/POC topology).

## Gating — "all inactive by default"

Every resource in this module is gated behind `enable_discovery`
(**default `false`**), including the dedicated Scheduler IAM role, its invoke
policy, and the IAM policy-document data sources. With the flag off the module
plans and applies to **zero resources**, which is the required POC baseline.
Enable only after gate-0.2 confirms the least-privilege discovery role and the
read-only source permissions (Config / Security Hub / CloudTrail).

All outputs are `try(...[0]..., null)`, so the module is safe to consume while
disabled.

## Runtime bounds

| Control | Value | Why |
| --- | --- | --- |
| Schedule | `var.discovery_schedule` (default `rate(15 minutes)`) | Configurable cadence; UTC; `flexible_time_window = OFF`. |
| Scheduler retries | 2 attempts / 900s max event age | Bounded redelivery before the event is dead-lettered. |
| Lambda timeout | `var.lambda_timeout_seconds` (default 300, validated **≤ 300**) | Sub-five-minute runtimes finish well inside the schedule interval; a stuck run fails fast and alarms. |
| Reserved concurrency | `1` | Prevents overlapping discovery runs from writing duplicate findings. |
| Memory | `var.lambda_memory_mb` (default 256, validated 128–3008) | POC-sized. |
| Tracing | `Active` | Correlation across the run. |

## Failure handling

Two distinct failure paths are covered, both draining into one SQS
dead-letter queue (`aws_sqs_queue.discovery_dlq`):

1. **Schedule-delivery failure** — EventBridge Scheduler invokes the Lambda
   *synchronously*. If the target is throttled/unreachable and all retries are
   exhausted, Scheduler routes the undeliverable event to the DLQ via the
   target's `dead_letter_config`. The Scheduler role is granted
   `sqs:SendMessage` on the queue.
2. **Lambda async-invocation failure** — `aws_lambda_function_event_invoke_config`
   sets `maximum_retry_attempts = 0` and an `on_failure` destination to the
   same DLQ, bounding Lambda-side retries for any asynchronous caller.

DLQ properties:
- **SSE enabled** via the SQS-managed key (`sqs_managed_sse_enabled = true`); no
  CMK, consistent with ADR 0003.
- **Retention** `var.dlq_retention_days` (default **7 days**) to match the
  CloudWatch log retention so DLQ messages and logs expire together.

### Alarms (CCG-REQ-037)

Gated behind `enable_failure_alarm` (default `true`):

- `aws_cloudwatch_metric_alarm.discovery_errors` — `AWS/Lambda` `Errors`
  `> var.alarm_error_threshold` (default 0) over `var.alarm_period_seconds`
  (default 900s). Catches invocations that ran but failed.
- `aws_cloudwatch_metric_alarm.discovery_dlq_depth` — `AWS/SQS`
  `ApproximateNumberOfMessagesVisible` `> 0`. Catches schedule-delivery
  failures where the Lambda was never reached (no Lambda `Errors` datapoint).

Alarms carry **no action by default** — the ALARM state is the POC signal.
Supply `var.alarm_sns_topic_arns` to wire notifications without editing the
module (voice/notification wiring stays off per the cost-and-poc defaults).

## Cost / POC topology (CCG-REQ-038)

- **No NAT.** The Lambda has **no `vpc_config`**, so it reaches AWS APIs over
  the AWS-managed network — no NAT gateway or NAT instance is required.
- **No always-on compute** and **no provisioned capacity** — Lambda, Scheduler,
  and SQS are all per-invocation / per-request.
- **No multi-AZ topology** — all services here are regional/serverless.
- At 15-minute intervals with sub-five-minute runtimes this stays well within
  the sub-$150/month POC budget.

## Tests

`tests/discovery_runtime.tftest.hcl` (credential-free, mock provider,
module-scoped) asserts the schedule expression default, retry policy, reserved
concurrency, bounded timeout, DLQ encryption + retention, and that **no**
resources are created when `enable_discovery = false`.
