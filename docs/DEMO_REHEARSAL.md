# Demo Rehearsal — Evidence Checklist (spec task 6.4)

This is the rehearsed demo script for the Continuous Compliance Guardian POC and
the evidence checklist that proves each step. The **offline rehearsal** runs
today, in CI, with no AWS calls:

```
PYTHONPATH=src python scripts/demo_rehearsal.py            # full run, with voice
PYTHONPATH=src python scripts/demo_rehearsal.py --no-voice # chain only
PYTHONPATH=src python -m pytest tests/test_demo_rehearsal.py -v
```

It chains **all** demo-script steps across the four seeded drift scenarios
through the faithful AgentCore emulator and returns a non-zero exit if any
invariant fails. The code is `src/ccg/rehearsal.py`; it reuses the production
`AgentCoreGatewayClient` + emulator, `ComplianceApi`, `PolicyActivationService`,
and `ReconciliationService` rather than re-implementing the chain.

The **live-sandbox rehearsal** (real AWS) is a separate step gated on task 0.2;
its delta is described at the end of this document. It is documented here, not
executed.

---

## 1. The ordered demo script

The four seeded scenarios (`src/ccg/seed.py`) are:

| Scenario | Drift | Remediation tool | Demo outcome |
| --- | --- | --- | --- |
| `unencrypted-s3` | S3 default encryption disabled | `s3_encryption_enablement` | APPLIED (one mutation) |
| `permissive-security-group` | Ingress open to `0.0.0.0/0` | `security_group_correction` | APPLIED (one mutation) |
| `untagged-resource` | Missing required `Owner` tag | `compliant_tagging` | NOOP (already-compliant target) |
| `old-test-access-key` | Access key past rotation age | `access_key_rotation` | NOOP (dry-run; `confirm` omitted) |

The APPLIED and NOOP scenarios are both included on purpose: the demo proves the
allow path *and* the safe no-op path.

| # | Presenter does / says | System behavior |
| --- | --- | --- |
| 0 | "First, we seed four sandbox-only drift scenarios — dry-run, nothing is actually mutated." | `DryRunSeedEffector` records a create plan for all four; `applied` stays empty. |
| 1 | "Discovery runs and normalizes the drift into findings, each with a correlation ID." | `DiscoveryCoordinator` upserts four `OPEN` findings with deterministic IDs. |
| 2 | "I ask to remediate the S3 finding — but the permit set is inactive, so it's denied." | Gateway returns **DENY**; no tool runs. One deny per scenario. |
| 3 | "An admin activates the versioned permit set through the audited control plane." | `change_policy_state` → **ACTIVATED**, effective version `v1`; intent + result audit events. |
| 4 | "Now I repeat the same request — it's allowed, and the tool applies exactly once." | Gateway returns **ALLOW**; the APPLIED tools mutate once, the NOOP tools change nothing. |
| 5 | "If I replay the request, nothing happens again — it's idempotent." | Same idempotency key → `idempotency_replayed=True`, no second mutation. |
| 6 | "Discovery runs again, the drift is gone, so the findings reconcile to RESOLVED." | Clean discovery read → `confirm_from_discovery` → **RESOLVED** per finding. |
| 7 | "Here's the collected decision and audit evidence, plus the operational metrics." | Structured report: per-scenario evidence, ordered audit trail, metric counts. |
| 8 | "Optionally, a read-only voice briefing — and I can barge in over it at any time." | `ReadOnlyVoiceAdapter` (flag on + consent) summarizes; a barge-in sets `interrupted=True`. Voice has no Gateway/tool access. |

---

## 2. Evidence checklist

For each step, the exact artifact that proves it. All artifacts are fields on
the `RehearsalResult` returned by `run_rehearsal` (and printed by the script).

| Step | Proven by (artifact) | Expected value |
| --- | --- | --- |
| Seed (dry-run) | `result.seed_plan` entries; each `op == "CREATE"`; `DryRunSeedEffector.applied` empty | 4 planned, 0 applied |
| Discovery | `audit_event_types` contains `discovery.run`; metric `ccg.discovery.run` | 2 runs (detect + confirm) |
| Denied-before | `ScenarioEvidence.denied_before_activation`; metric `ccg.gateway.deny` | `True`; count = 4 |
| Activation | `activation_outcome`; `effective_policy_version`; audit `policy.activation.intent` + `policy.activation.result` | `ACTIVATED`; `v1` |
| Allowed-after | `ScenarioEvidence.allowed_after_activation`; metric `ccg.gateway.allow` | `True`; count = 8 (2 per scenario) |
| Single execution | `ScenarioEvidence.tool_outcome` / `tool_executions`; metric `ccg.tool.applied` | APPLIED→1 exec; NOOP→0 exec; applied count = 2 |
| Idempotent replay | `ScenarioEvidence.idempotent_replay`; audit shows one `remediation.execution` per scenario | `True`; no second mutation |
| Reconciled | `ScenarioEvidence.final_status`; audit `reconcile.resolved` per scenario | `RESOLVED`; 4 resolutions |
| Decision/audit evidence | `audit_event_types` ordering (deny < activation < execution) | ordering holds |
| Metrics | `result.metrics` catalog counts (`InMemoryMetricSink`) | deny=4, allow=8, applied=2, discovery.run=2 |
| Voice barge-in | `result.voice.status` / `result.voice.interrupted`; metric `ccg.voice.session` | `AVAILABLE`; `interrupted=True`; count = 1 |

Audit trail ordering invariant (the Cedar-first guarantee): the first
`gateway.decision` (a DENY) precedes `policy.activation.result`, which precedes
the first `remediation.execution`. A mutation can never be audited before the
permit set was activated.

---

## 3. Resource attribution

Every seeded resource is attributable to the POC and bounded for cleanup. The
seed model (`src/ccg/seed.py`) guarantees, for each target:

- `CCGDemo=true` — the demo tag the caller cannot self-assert in the Cedar
  context; absence of it is a hard deny at both the seed guard and the Gateway.
- `CCGSeed=true` — this workflow's own creation marker.
- the `ccg-seed-` **name prefix** on the ARN.
- **never** `Environment=prod` (hard-refused by `guard_target`).

Cleanup (`run_cleanup` / `seed_drift.py --cleanup`) only ever deletes targets
that carry **both** `CCGSeed=true` **and** the `ccg-seed-` prefix
(`is_self_created`), so the workflow can never remove a resource it did not
create. `test_demo_rehearsal.py::test_all_seeded_resources_are_attributable_and_bounded`
asserts this for every scenario.

Example seeded ARNs:

```
arn:aws:s3:::ccg-seed-unencrypted-bucket
arn:aws:s3:::ccg-seed-untagged-bucket
arn:aws:iam::000000000000:user/ccg-seed-test-user
arn:aws:ec2:us-east-1:000000000000:security-group/ccg-seed-open-sg
```

---

## 4. Live-sandbox delta (gated on task 0.2)

The offline rehearsal is a faithful stand-in; the live sandbox rehearsal adds
the following and **must not run until task 0.2 lifts the gate**:

| Offline rehearsal (today, in CI) | Live-sandbox rehearsal (gated on 0.2) |
| --- | --- |
| `DryRunSeedEffector` records a plan | Real sandbox effector creates the four tagged resources (`CCG_SANDBOX=true` + explicit confirmation) |
| Discovery over `StaticDiscoverySource` | Real read-only Config / Security Hub / CloudTrail adapters under the discovery role |
| Faithful AgentCore emulator decides | Real AgentCore Gateway + Cedar policy engine returns the decision and real action IDs |
| `InMemoryPolicyControlPlane` activation | Real `UpdatePolicy` control-plane call, propagation, and effective-state reconciliation |
| `DryRunEffector` tool mutations | Real least-privilege tool Lambdas mutate the sandbox targets |
| `InMemoryMetricSink` counts | Real CloudWatch EMF / `PutMetricData` metrics and alarms |
| `MockNovaSonicTransport` barge-in | Real Nova Sonic bidirectional session (voice remains default-off) |

The safety invariants are identical across both: Cedar-first authorization,
default-deny while permits are inactive, forbid-overrides-permit, `CCGDemo`
required, `Environment=prod` always denied, idempotent single execution, and
confirmation-driven resolution. The live run adds real targets and a real
decision boundary; it does not relax any invariant. See
`docs/DESIGN_REVIEW_RECONCILIATION.md` and the gate-0.2 capability record for
the exact live-capture prerequisites.

---

## Exit criteria (task 6.4)

- [x] Demo evidence checklist is complete (this document).
- [x] The offline rehearsal chains all demo-script steps and passes every
  invariant (`scripts/demo_rehearsal.py`, `tests/test_demo_rehearsal.py`).
- [x] All seeded resources are attributable to the POC (`CCGDemo=true` +
  `CCGSeed=true` + `ccg-seed-` prefix) and bounded for cleanup.
- [ ] Live-sandbox rehearsal executed — **gated on task 0.2** (documented, not run).
