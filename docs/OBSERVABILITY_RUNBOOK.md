# Observability & Budget Runbook (CCG-REQ-037, CCG-REQ-038)

This runbook is the operational evidence for spec task **6.3** and remediation
item **P1.4**. It documents the metric catalog, which component emits each
metric and when, the CCG-REQ-037 alarm mapping, the operator dashboard, and the
budget/retention posture.

**Live-emitting status.** Every metric below is emitted *today* by the Python
components (`src/ccg/`) through the `MetricSink` seam. In the offline/CI build
the sink is `InMemoryMetricSink` (asserted by `tests/test_metric_emission.py`)
and in production the default is `NullMetricSink` until the CloudWatch backend
is wired. The CloudWatch EMF/`PutMetricData` sink implementation, the custom
alarms, and the dashboard population are **gated on gate-0.2** (no boto3 offline;
see ADR 0005/0006). What is live now vs gated is called out per section.

---

## 1. Metric catalog

Source of truth: `src/ccg/observability.py` (`Metric` StrEnum). Names are a
**stable catalog** — renaming one is a breaking dashboard change. All names are
namespaced `ccg.*`. Dimensions are low-cardinality strings only; **no secrets,
ARNs, or free-form user input** ever appear in a dimension (enforced by
`InMemoryMetricSink._validate_dimensions` and asserted in
`tests/test_metric_emission.py::_assert_no_secrets_or_arns`).

| Metric | Name | Kind | Dimensions |
| --- | --- | --- | --- |
| `DISCOVERY_RUN` | `ccg.discovery.run` | counter | `outcome` = `succeeded` \| `partial` |
| `DISCOVERY_PARTIAL` | `ccg.discovery.partial` | counter | — |
| `DISCOVERY_FAILURE` | `ccg.discovery.failure` | counter | `source` (adapter name) |
| `FINDINGS_UPSERTED` | `ccg.discovery.findings_upserted` | gauge | — |
| `GATEWAY_ALLOW` | `ccg.gateway.allow` | counter | `tool` |
| `GATEWAY_DENY` | `ccg.gateway.deny` | counter | `tool` |
| `TOOL_APPLIED` | `ccg.tool.applied` | counter | `tool` |
| `TOOL_NOOP` | `ccg.tool.noop` | counter | `tool`, (`reason` on replay) |
| `TOOL_FAILED` | `ccg.tool.failed` | counter | `tool` |
| `ACTIVATION_SUCCESS` | `ccg.policy.activation_success` | counter | `activate` = `true` \| `false` |
| `ACTIVATION_FAILURE` | `ccg.policy.activation_failure` | counter | `failure` = `update` \| `propagation` |
| `ACTIVATION_REJECTED` | `ccg.policy.activation_rejected` | counter | `activate` = `true` \| `false` |
| `AUDIT_WRITE_FAILURE` | `ccg.audit.write_failure` | counter | `event_type` |
| `VOICE_SESSION` | `ccg.voice.session` | counter | `interrupted` = `true` \| `false` |
| `VOICE_ERROR` | `ccg.voice.error` | counter | — |
| `CLEANUP_RUN` | `ccg.cleanup.run` | counter | — |
| `CLEANUP_FAILURE` | `ccg.cleanup.failure` | counter | — |

The `tool` dimension is a known, low-cardinality tool name (one of the four
narrow remediation tools). The raw Cedar decision-reason string is deliberately
**not** a dimension — it can carry detail, so only the stable `tool` label is
emitted on a decision.

---

## 2. Who emits what, and when

| Component | File | Emits | When |
| --- | --- | --- | --- |
| Discovery | `src/ccg/discovery.py` (`DiscoveryCoordinator.run`) | `DISCOVERY_RUN`, `DISCOVERY_PARTIAL`, `DISCOVERY_FAILURE`, `FINDINGS_UPSERTED` | once per run (`run` with `outcome`), `partial` when any source failed, `failure` per failed source, `findings_upserted` gauge set to the run's upsert count |
| Gateway | `src/ccg/gateway_core.py` (`GatewayInvocationSkeleton`) | `GATEWAY_ALLOW` / `GATEWAY_DENY`; `TOOL_APPLIED` / `TOOL_NOOP` / `TOOL_FAILED` | allow/deny per decision; a tool metric per executed outcome; an idempotent replay emits `TOOL_NOOP` with `reason=idempotent_replay` (no re-execution) |
| Policy | `src/ccg/policy.py` (`PolicyActivationService.apply`) | `ACTIVATION_SUCCESS` / `ACTIVATION_FAILURE` / `ACTIVATION_REJECTED` | success on a confirmed update; failure on a failed/uncertain update (deny-safe reconcile); rejected on an unapproved version / stale generation / version mismatch |
| Reconcile | `src/ccg/reconcile.py` | **none (by design)** | tool outcomes are counted once at the Gateway; the reconciler only mirrors them into the finding lifecycle — emitting again would double-count. Documented in the module header. |
| Audit | `src/ccg/audit.py` (`FailClosedAuditSink`) | `AUDIT_WRITE_FAILURE` | when the wrapped store write fails and the event is dead-lettered |
| Voice | `src/ccg/voice.py` (`ReadOnlyVoiceAdapter.brief`) | `VOICE_SESSION`, `VOICE_ERROR` | session on a served brief (`interrupted` dimension); error on the transport-unavailable path. Flag-off / no-consent return DISABLED and emit nothing (expected state, not a failure). |
| Seed/cleanup | `src/ccg/seed.py` (`run_cleanup`) via `scripts/seed_drift.py` | `CLEANUP_RUN`, `CLEANUP_FAILURE` | `run` incremented by the number of cleaned scenarios on success; `failure` if a target guard refuses or the effector raises |

Avoiding double-counting is a deliberate choice (P1.4): the **Gateway boundary**
is the single origin for tool-outcome counts.

**Live now:** all emission above runs against `InMemoryMetricSink` in tests and
`NullMetricSink` by default in app code — no backend required.
**Gated on 0.2:** a `CloudWatchMetricSink` (EMF or `PutMetricData` under the
observability role) injected in place of the default.

---

## 3. CCG-REQ-037 alarm mapping

Two classes of operational signal:

### 3a. Real CloudWatch alarms (live Terraform, task 2.4)

These are AWS-native alarms over AWS/Lambda and AWS/SQS metrics — they do not
depend on custom-metric emission, so they work the moment discovery is enabled.
Defined in `modules/discovery/main.tf`, gated behind
`enable_discovery && enable_failure_alarm`:

| Alarm | Metric | Fires when | Covers |
| --- | --- | --- | --- |
| `${name_prefix}-discovery-errors` | `AWS/Lambda Errors` (Sum) | discovery Lambda errors over the window | discovery crash / unhandled failure |
| `${name_prefix}-discovery-dlq-depth` | `AWS/SQS ApproximateNumberOfMessagesVisible` (Max) | an undeliverable event lands in the DLQ | schedule-delivery failure where the Lambda was never reached |

No SNS action is attached by default (ALARM state is the POC signal); wire
`alarm_sns_topic_arns` to notify without editing the module.

### 3b. Custom-metric alarms (gated on 0.2)

Once the CloudWatch sink is wired, these catalog metrics become the alarm
sources. Suggested thresholds for the POC:

| Signal | Metric | Suggested alarm |
| --- | --- | --- |
| Discovery degraded | `ccg.discovery.partial` / `ccg.discovery.failure` | any datapoint > 0 over 1 period |
| Repeated denials | `ccg.gateway.deny` | sustained rate above baseline (investigate confused-deputy / misconfig) |
| Tool failures | `ccg.tool.failed` | any datapoint > 0 |
| Activation failure | `ccg.policy.activation_failure` | any datapoint > 0 (deny-safe reconcile occurred) |
| Audit integrity | `ccg.audit.write_failure` | any datapoint > 0 (fail-closed — evidence path degraded) |
| Voice unavailable | `ccg.voice.error` | optional; voice is off by default |
| Cleanup failure | `ccg.cleanup.failure` | any datapoint > 0 during a demo teardown |

Threat-model cross-reference (`docs/THREAT_MODEL.md`): T1/T2 → `ccg.gateway.deny`;
T3 → `ccg.tool.noop` + `ccg.policy.activation_rejected`; T5/T7 →
`ccg.audit.write_failure`; T6 → `ccg.policy.activation_success` /
`ccg.policy.activation_failure`; T8 → `ccg.discovery.partial` /
`ccg.discovery.failure`.

---

## 4. Operator dashboard

A gated dashboard stub is defined in `modules/observability/main.tf`
(`aws_cloudwatch_dashboard.ccg`, `count = var.enable_dashboard ? 1 : 0`,
default **off**). It is credential-free at plan time and creates only a
dashboard document (no cost, no always-on compute). Widgets reference
`var.metric_namespace` (default `CCG`) and the stable catalog names, so the
panels light up automatically once the CloudWatch sink is emitting — no name
drift.

Panels an operator reviews:

1. **Gateway decisions** — `ccg.gateway.allow` vs `ccg.gateway.deny` (time series).
2. **Discovery health** — `ccg.discovery.run`, `ccg.discovery.partial`, `ccg.discovery.failure`.
3. **Tool outcomes** — `ccg.tool.applied` / `ccg.tool.noop` / `ccg.tool.failed`.
4. **Activation / audit / voice** — `ccg.policy.activation_success`,
   `ccg.policy.activation_failure`, `ccg.audit.write_failure`, `ccg.voice.error`.

Supplement with the task-2.4 Lambda/SQS alarm widgets (section 3a) for a
discovery-health view that works before custom emission is wired.

**Live now:** the dashboard document renders (empty) when enabled.
**Gated on 0.2:** populated panels require the CloudWatch metric sink.

---

## 5. Budget & retention posture (CCG-REQ-038)

The POC stays event-driven/serverless and under the $150/month target. Each
guard is enforced in Terraform and verified by a credential-free native test —
this runbook only cross-references, it does not re-implement.

| Guard | Where enforced | Verified by |
| --- | --- | --- |
| CloudWatch log retention = 7 days | `modules/observability/main.tf` (`retention_in_days`) | `tests/storage_retention.tftest.hcl` run `observability_log_retention` (C1) |
| S3 audit object expiration = 30 days | `modules/audit-storage` lifecycle | `tests/storage_retention.tftest.hcl` run `audit_storage_controls` (S1), noncurrent (S2) |
| DLQ retention = 7 days (matches logs) | `modules/discovery/main.tf` (`message_retention_seconds`) | `tests/discovery_runtime.tftest.hcl` (DR8) |
| No NAT (no VPC egress) | discovery Lambda has no `vpc_config` | `tests/discovery_runtime.tftest.hcl` (DR6) |
| No provisioned DynamoDB | `modules/findings-store` `PAY_PER_REQUEST` | `tests/storage_retention.tftest.hcl` run `findings_store_controls` (D1) |
| No always-on compute / no overlap | Lambda `reserved_concurrent_executions = 1`; EventBridge Scheduler (per-invocation) | `tests/discovery_runtime.tftest.hcl` (DR3) |
| No multi-AZ POC topology | single-region serverless; no multi-AZ resources declared | design review + `terraform validate` |
| Voice off by default | `ReadOnlyVoiceAdapter(enabled=False)`; `modules/voice-adapter` gated | `tests/test_voice.py` |

Run the retention/runtime checks locally:

```
terraform init -backend=false -input=false
terraform test
PYTHONPATH=src python -m pytest tests/ -v
```

---

## 6. Structured logging & correlation

Components log structured JSON with a `correlation_id` carried end-to-end
(e.g. `scripts/seed_drift.py` `_JsonLogFormatter`; `voice.py` logs
`voice.summary.*` with `correlation_id`). Every audit event
(`src/ccg/contracts.py::AuditEvent`) carries `request_id` and `correlation_id`
and is redacted before write (`src/ccg/audit.py::redact_details` /
`redact_text`). The metric layer is intentionally correlation-free: metrics are
aggregate counters/gauges, and correlation lives in logs and audit records where
cardinality is safe.
