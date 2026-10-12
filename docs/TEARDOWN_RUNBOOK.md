# Teardown & Rollback Runbook — Continuous Compliance Guardian POC

**Purpose:** the complete, reviewed procedure to tear down the whole POC — not just the minimal schema-capture deploy in `docs/DEPLOY_RUNBOOK.md` Step 6. It covers deactivating enforcement first, reconciling in-flight work, bounded seed cleanup, flipping every feature flag off, destroying storage/evidence in the right order, and running a human-approved Terraform destroy that can never select a production or out-of-scope resource.

**Fail-closed principle:** teardown **deactivates enforcement before it deletes anything**. Once permits are `LOG_ONLY`, no mutation can be authorized regardless of what happens next, so a partial or ambiguous teardown degrades to the safe state by construction.

## Who does what

Terraform **state and applies/destroys run in HCP Terraform Cloud** (workspace `compliance_guardian`), authenticated to AWS via OIDC. A workstation CLI session is **read-only** — it cannot apply or destroy. Every destructive plan is approved by a human in HCP. There is **no local `terraform destroy`** in this runbook.

## Preconditions

- The demo rehearsal (task 6.4) is complete and its evidence is captured.
- You know which feature flags are currently `true` (check the HCP workspace variables; defaults are all `false`).
- You have the admin principal (`CCGAdmin`) used for the audited control plane.
- `CCG_SANDBOX=true` is set only in the sandbox session where seed cleanup runs.

---

## Phase A — Deactivate enforcement first (fail-closed)

Enforcement is a **separately versioned policy state**, not an application boolean. Deactivation goes through the same audited control plane as activation (`src/ccg/policy.py` `PolicyActivationService`), which calls the AgentCore `UpdatePolicy` operation and reconciles the effective mode to `LOG_ONLY`.

1. **Deactivate the permit set** through the audited control plane. Submit a `PolicyActivationRequest` with `activate=False` and the current effective version/generation. The service records intent, calls `UpdatePolicy` → `LOG_ONLY`, confirms propagation, and records the result.
   - Outcome must be `DEACTIVATED` and effective mode `LOG_ONLY`.
   - If the update fails or propagation is uncertain, the service fails closed to deny-safe (`force_deny_safe()` → `LOG_ONLY`) and records `FAILED`. Either way **no permit is active**, which is the goal of this phase.
2. **Confirm no mutation can be authorized.** With permits inactive, a remediation request through the Gateway returns `DENY` (proven in `tests/test_activation_control_plane.py::MutationsRemainDeniedAfterFailureTests`). Do not proceed until this is confirmed.
3. **Reconciliation gate — no in-flight tool operation.** Teardown may only proceed when every finding is in a terminal/clean state (`OPEN`, `RESOLVED`, or `ACCEPTED_RISK`). A finding mid-remediation (`REMEDIATION_REQUESTED` / `_SUCCEEDED` / `_NOOP` / `_FAILED`) means a tool outcome was recorded but not yet confirmed by a discovery read — deleting under that uncertainty is forbidden.
   - Offline check: `ccg.reconcile.teardown_blocking_findings(findings)` returns the blocking findings; an empty list satisfies the gate (`ccg.reconcile.is_teardown_clean` for a single status).
   - If the list is non-empty, let discovery reconcile (drift-gone read resolves it) or record an explicit `ACCEPTED_RISK` decision through the audited path, then re-check. Enforcement is already off, so waiting is safe.

**Why first:** everything after this is deletion. With enforcement off and no in-flight remediation, nothing can mutate a live resource during the rest of the teardown.

---

## Phase B — Seed cleanup (bounded, self-created only)

Remove the demo drift fixtures with the same reviewable core the demo used (`src/ccg/seed.py` `run_cleanup`, driven by `scripts/seed_drift.py --cleanup`).

```bash
export CCG_SANDBOX=true
# Dry run first — records the delete plan, changes nothing:
PYTHONPATH=src python scripts/seed_drift.py --cleanup
# Apply only with the explicit gate + confirmation:
PYTHONPATH=src python scripts/seed_drift.py --cleanup --apply --sandbox-confirmation I_UNDERSTAND
```

**Bounded by construction — can never select a prod or out-of-scope resource:**

- Cleanup refuses any target that is not **provably self-created**: it must carry `CCGSeed=true` **and** the `ccg-seed-` name prefix (`guard_cleanup_target` / `is_self_created` in `seed.py`).
- Any `Environment=prod` or non-`CCGDemo` target is refused by `guard_target` before that check even runs.
- The committed default effector is a dry-run recorder; a real mutation requires `CCG_SANDBOX=true` **and** `--sandbox-confirmation I_UNDERSTAND`.

This is asserted offline, not just documented — see `tests/test_seed.py` (`CleanupBoundTests`, `CliSandboxGateTests`) and the focused references in `tests/test_teardown.py`.

---

## Phase C — Flip feature flags off (gated resources destroy)

Set every `enable_*` flag to `false` in a **reviewed HCP plan**. Each gated resource is destroyed as its flag goes false. Do this in dependency order so a resource is never destroyed while another still references it.

| Order | Flag(s) set `false` | Resources destroyed | Depends on |
|---|---|---|---|
| 1 | `enable_agentcore_gateway` (gates `gateway_policy` via `&& enable_remediation_tools`) | Cedar policy set + Gateway tool targets (`gateway-policy`) | nothing references it |
| 2 | `enable_agentcore_gateway` | Gateway + Policy Engine (`agentcore-gateway`); execution role remains until identity flag | after policy set is gone |
| 3 | `enable_identity_roles` | discovery / tool-exec / control-plane / audit-reader roles (`identity`) | after Gateway no longer assumes them |
| — | `enable_discovery` | EventBridge schedule + discovery Lambda | independent |
| — | `enable_console` | API Gateway + API Lambda (Cognito user pool stays) | independent |
| — | `enable_voice` | Nova Sonic adapter Lambda | independent |
| — | `enable_remediation_tools` | four tool Lambdas | independent of each other; keep until the gateway-policy set that targets them is gone (step 1) |

`gateway-policy` is gated on `enable_agentcore_gateway && enable_remediation_tools`, so it is removed the moment either goes false — do step 1 before destroying the tool Lambdas it references. `discovery`, `console`, and `voice` have no cross-dependencies and may be flipped in any order.

Flags default to `false`, so a fresh workspace is already torn down for these resources.

---

## Phase D — Storage and evidence

Storage is destroyed last and deliberately, because it holds the audit evidence.

- **DynamoDB findings/idempotency table** (`modules/findings-store`) has `enable_deletion_protection` defaulting to **true**. The table **cannot be destroyed** until you set `enable_findings_deletion_protection = false` **explicitly** in the plan. This is a hard, intentional stop against accidental state loss — never a default.
- **Audit S3 bucket** (`modules/audit-storage`) has a **30-day** lifecycle expiration.
  - **Default: preserve the evidence window.** Leave the bucket in place and let the 30-day lifecycle expire the objects. The demo evidence remains auditable for its retention window.
  - **Force-delete is an explicit, logged decision.** Only empty and destroy the bucket early when a reviewer has recorded the reason. There is no "force destroy by default"; emptying a non-empty bucket is a separate, deliberate step.
- **CloudWatch logs** (`modules/observability`) retain for **7 days** and expire on their own; destroying the log group early is optional.

| Item | Default teardown action | Retention |
|---|---|---|
| Findings/idempotency table | destroy **after** `enable_findings_deletion_protection = false` | n/a (current-state only) |
| Audit S3 bucket | **preserve** (lifecycle expires objects) | 30 days |
| CloudWatch log group | optional destroy; otherwise self-expires | 7 days |

---

## Phase E — Reviewed Terraform destroy plan (HCP, human-approved)

The destroy runs **only** via HCP with a human-approved plan — never a local apply/destroy.

1. Trigger a destroy run (or an apply of the all-flags-false, deletion-protection-false configuration) in HCP.
2. **Review the plan before approval.** It MUST target only POC-prefixed resources:
   - every destroyed resource name begins with `ccg-poc-` (Terraform-managed) or `ccg-seed-` (demo fixtures);
   - **no** resource carries `Environment=prod`. The `environment` variable is validated to `sandbox` only (`variables.tf`), so a prod-tagged default is impossible — but the review is still a hard gate.
3. **Reject the plan** if it shows any non-`ccg-poc-`/`ccg-seed-` resource, any `Environment=prod` tag, or the audit bucket being emptied without a recorded force-delete decision (Phase D).
4. Approve. The resources are destroyed in Terraform's dependency order; the phases above pre-sequence the risky edges (enforcement off, state unprotected explicitly, evidence decision made).

The destroy-plan review is a **hard gate**: the "no prod / out-of-scope by default" guarantee is enforced by (a) the bounded seed cleanup, (b) the `sandbox`-only `environment` validation plus the `ccg-poc-`/`ccg-seed-` naming, and (c) this human review step.

---

## Resource deletion order (summary)

| Step | Action | Mechanism | Reversible? |
|---|---|---|---|
| 1 | Deactivate permits → `LOG_ONLY` | audited `UpdatePolicy` (Phase A) | yes (re-activate via control plane) |
| 2 | Confirm no in-flight remediation | reconciliation gate (Phase A) | n/a (read-only) |
| 3 | Bounded seed cleanup | `seed_drift.py --cleanup` (Phase B) | re-seed via `--apply` |
| 4 | Destroy Gateway Cedar policy set + targets | `enable_agentcore_gateway=false` | re-apply flag |
| 5 | Destroy Gateway + Policy Engine | `enable_agentcore_gateway=false` | re-apply flag |
| 6 | Destroy IAM execution roles | `enable_identity_roles=false` | re-apply flag |
| 7 | Destroy discovery / console / voice / tool Lambdas | respective `enable_*=false` | re-apply flags |
| 8 | Unprotect + destroy findings table | `enable_findings_deletion_protection=false` | state is lost (current-state only) |
| 9 | Audit bucket | preserve (default) or logged force-delete | force-delete loses evidence |
| 10 | HCP-approved destroy of remaining `ccg-poc-*` | reviewed destroy plan (Phase E) | re-apply from config |

---

## Evidence retention

| Evidence | Where | Preserved | For how long |
|---|---|---|---|
| Audit JSON (decisions, activations, tool outcomes, cleanup) | `ccg-poc-audit-*` S3 bucket | yes (default teardown preserves) | 30-day lifecycle |
| Operational logs (structured JSON, correlation IDs) | `/ccg/...` CloudWatch log group | until self-expiry | 7 days |
| Current finding/idempotency state | `ccg-poc-*` DynamoDB table | **not** preserved past teardown | n/a (destroyed in step 8) |
| Demo rehearsal checklist | `docs/` (task 6.4) | yes | repo lifetime |

Preserve the audit bucket by default so the decision/activation trail outlives the compute. Force-deleting it early requires a recorded reviewer decision.

---

## Incident handling / rollback

**Partial teardown.** If teardown stops midway, enforcement is already `LOG_ONLY` (Phase A ran first), so no mutation can be authorized. Re-run the remaining phases; each flag flip and the destroy plan are idempotent.

**Failed destroy.** If the HCP destroy fails on a resource, re-review and re-run the plan. Do not switch to a local destroy. If the findings table refuses to delete, confirm `enable_findings_deletion_protection = false` is in the plan (Phase D).

**Orphaned resources.** If a resource is left behind, confirm it is `ccg-poc-`/`ccg-seed-` prefixed and `Environment=sandbox` before removing it, then target it in a reviewed HCP destroy. Never bulk-delete by wildcard.

**aws-nuke interaction.** The sandbox runs a periodic `aws-nuke` auto-clean (see `docs/CLOUD_INVENTORY.md`). It may remove POC resources independently; this is a backstop, **not** the primary teardown. Always run Phase A (deactivate enforcement) through the audited control plane rather than relying on auto-clean, so the deactivation is versioned and audited.

**Ambiguous state → fail closed.** If at any point the effective policy state is uncertain, the control plane has already reconciled to deny-safe (`force_deny_safe()` → `LOG_ONLY`) and recorded `FAILED`. Treat the system as non-authorizing: nothing can mutate, and manual reconciliation only needs to confirm the deny-safe posture before continuing deletion.

---

## "No prod / out-of-scope by default" guarantee

Three independent controls make a production or out-of-scope deletion impossible by default:

1. **Bounded seed cleanup.** Cleanup only ever touches `CCGSeed=true` + `ccg-seed-` resources and refuses anything else (`tests/test_seed.py`).
2. **Sandbox-only naming/validation.** Every destroyable resource is `ccg-poc-`/`ccg-seed-` prefixed, and the `environment` variable is validated to exactly `sandbox` (`variables.tf`), so a prod-tagged default cannot exist in this configuration.
3. **Hard destroy-plan review.** The HCP destroy plan is human-reviewed to confirm it targets only POC-prefixed resources and nothing with `Environment=prod` (Phase E).

Teardown-relevant behavior that is testable offline is asserted in `tests/test_teardown.py` (permit deactivation leaves mutations denied; reconciliation gate blocks on in-flight findings) with references to the existing `tests/test_seed.py` and `tests/test_activation_control_plane.py` coverage.
