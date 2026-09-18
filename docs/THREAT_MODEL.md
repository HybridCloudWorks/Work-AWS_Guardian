# Continuous Compliance Guardian — Threat Model (Phase 1.2)

**Status:** Review artifact satisfying spec task **1.2** and requirements §6 gate 6. This is the mandatory gate before any AgentCore Gateway / tool Lambda / policy resource is deployed (spec task 2.5 and the gate-0.2 capture note).

**Date:** 2026-09-18
**Scope:** POC only, single dedicated sandbox account `…8441` / `us-east-1` (SSO role `cloud-sandbox`). See `docs/CLOUD_INVENTORY.md` for the confirmed empty starting state and `docs/AGENTCORE_CAPABILITY_RECORD.md` for verified API facts.

## Method

STRIDE-informed, organized by trust boundary. Each threat maps to: a mitigation, the EARS requirement it satisfies, the enforcing IAM/Cedar boundary, the test that proves it, and the operational metric/alarm that detects it at runtime (`Metric` catalog in `src/ccg/observability.py`). Mitigations already implemented offline are marked ✅; those that land at deploy time are marked ⏳ (gated on gate 0.2 + this review).

## Trust boundaries (from requirements §2)

| # | Boundary | Trusts | Must not be trusted to |
|---|---|---|---|
| B1 | POC admin (human, via Cognito) | authenticate, view, request | authorize a mutation by UI state |
| B2 | Discovery agent (Lambda) | read sources, write evidence | mutate audited resources, call tools, activate policy |
| B3 | API / control plane (Lambda) | authenticate, validate, request | replace Cedar decisions |
| B4 | AgentCore Gateway + Cedar | authorize every mutation | be bypassed by any direct path |
| B5 | Tool target Lambdas | execute one bounded op after allow | accept arbitrary ARN/op or override a deny |
| B6 | AWS evidence services (Config/SecurityHub/CloudTrail/DynamoDB/S3/CloudWatch) | store/serve evidence | be a policy input (audit is evidence, not authz) |
| B7 | Nova Sonic voice adapter | read-only summaries | see or invoke a mutation tool |

## Threats, mitigations, and traceability

### T1 — Confused deputy (caller induces a privileged component to act on its behalf)
- **Vector:** console/API or voice tricks the Gateway or a tool Lambda into mutating a target the caller shouldn't reach.
- **Mitigation:** every mutation traverses the AgentCore Gateway/Cedar boundary (B4); the API resolves the target ARN **server-side** from the stored finding, never from the caller's command; tool Lambdas re-check safety tags independently. ✅ (offline) / ⏳ (live Gateway)
- **Requirement:** CCG-REQ-008, CCG-REQ-009. **IAM/Cedar:** tool role scoped to `CCGDemo`-tagged ARNs; default-deny. **Test:** `test_api_authorization::test_api_never_authorizes_locally...`, `test_gateway`. **Metric:** `ccg.gateway.deny`.

### T2 — Forged tag / forged request context (caller self-asserts `CCGDemo=true` or hides `Environment=prod`)
- **Vector:** caller supplies attributes in the request so Cedar believes a prod target is a sandbox target.
- **Mitigation:** safety attributes must reach Cedar via Gateway-injected/server-resolved context, not caller input; tool Lambda re-reads live tags before mutating; `Environment=prod` is a forbid that overrides any permit. ✅ (design + offline authz) / ⏳ **OPEN until gate-0.2 §2 confirms the live context source** — this is the single most important unresolved item; if the only path is caller-supplied, target identity/tags MUST be resolved server-side.
- **Requirement:** CCG-REQ-012, CCG-REQ-020. **IAM/Cedar:** `aws:ResourceTag/Environment != prod`, `aws:ResourceTag/CCGDemo = true` conditions in `modules/iam-policies`; Cedar forbid-overrides-permit. **Test:** `test_authz::test_forbid_overrides_active_permit_for_prod`, `test_tools::SafetyRecheckTests`. **Metric:** `ccg.gateway.deny`.

### T3 — Replay (a captured allow is re-submitted to cause a second mutation)
- **Vector:** replay a remediation request or a policy-activation request.
- **Mitigation:** idempotency key on remediation (second call is a no-op replay); activation carries an expected version/generation and is rejected if stale. ✅ (offline)
- **Requirement:** CCG-REQ-025, CCG-REQ-017. **Test:** `test_gateway::test_repeated_idempotency_key...`, `test_policy_api_voice::test_stale_generation_is_rejected`, `test_reconcile`. **Metric:** `ccg.tool.noop` (replay path), `ccg.policy.activation_rejected`.

### T4 — Privilege escalation (a low-trust component gains mutation or activation rights)
- **Vector:** discovery role mutates a resource; tool role activates policy; control-plane role performs remediation.
- **Mitigation:** four separate least-privilege roles with explicit **deny boundaries** — discovery cannot mutate or `sts:AssumeRole`; tool cannot touch `Environment=prod` or control policy/trail; control-plane can only `UpdatePolicy`/`GetPolicy`/`GetPolicyEngine` and is denied every remediation action. ✅ (policy documents) / ⏳ (roles attached at deploy)
- **Requirement:** CCG-REQ-002, CCG-REQ-013. **IAM:** `modules/iam-policies` discovery_boundary / tool_execution_boundary / control_plane_boundary. **Test:** deny-boundary statements + `test_authz`. **Verification:** the live `cloud-sandbox` role is already observed to be non-admin (`iam:ListAccountAliases`/`ListOpenIDConnectProviders` denied — see CLOUD_INVENTORY).

### T5 — Secret leakage (credentials/keys/audio land in logs, audit, state, or responses)
- **Vector:** access-key rotation output, tokens, or raw voice audio written to a durable store.
- **Mitigation:** audit sink redacts sensitive keys; access-key rotation never returns secret material and is dry-run unless `confirm=true`; voice raw audio not retained; no secrets in Git (secret-scan + GitGuardian in CI). ✅ (offline)
- **Requirement:** CCG-REQ-035, CCG-REQ-024. **Test:** `test_audit::RedactionTests`, `test_tools::test_no_secret_material_in_result`. **Metric:** `ccg.audit.write_failure` (fail-closed signal).

### T6 — Policy-activation abuse (unauthorized or unsafe enforcement-mode change)
- **Vector:** non-admin activates permits; activation fails ambiguously and leaves mutations allowed.
- **Mitigation:** activation is `UpdatePolicy(enforcementMode=ACTIVE|LOG_ONLY)` behind admin authz + audited intent/result; on failure/uncertainty the service reconciles to deny-safe (`LOG_ONLY`); enum verified against the live API. ✅ (offline) / ⏳ (live control plane)
- **Requirement:** CCG-REQ-015, CCG-REQ-016, CCG-REQ-029. **IAM:** control-plane role `UpdatePolicy` only, corrected to real action names (PR #7). **Test:** `test_policy_api_voice::test_non_admin_cannot_activate`, `test_activation_failure_is_deny_safe`. **Metric:** `ccg.policy.activation_success` / `ccg.policy.activation_failure`.

### T7 — Audit integrity (decision/audit evidence lost, tampered, or treated as authz input)
- **Vector:** a storage failure silently drops decision evidence; audit records are used to make an allow decision.
- **Mitigation:** `FailClosedAuditSink` raises + dead-letters on write failure (never silent drop); `MultiplexAuditSink` fan-out doesn't mask a failing store; audit is written to a private, encrypted, TLS-enforced, versioned S3 bucket with 30-day lifecycle; audit is explicitly **evidence, not a policy input**. ✅ (offline + storage hardened in PR #2)
- **Requirement:** CCG-REQ-005, CCG-REQ-034, CCG-REQ-036. **Test:** `test_audit::FailClosedTests`, `test_persistence`. **Metric:** `ccg.audit.write_failure`.

### T8 — Discovery integrity (a partial/failed read is treated as "compliant")
- **Vector:** a throttled or unauthorized source read is interpreted as "no findings."
- **Mitigation:** typed source errors surface as partial-run evidence; an unknown result never becomes a compliant result; only a confirming read resolves a finding. ✅ (offline)
- **Requirement:** CCG-REQ-006, CCG-REQ-026. **Test:** `test_sources::SourceFailureIsolationTests`, `test_reconcile::test_failed_outcome_never_resolves...`. **Metric:** `ccg.discovery.partial` / `ccg.discovery.failure`.

## Residual risks / open items (must resolve before or during deploy)

1. **T2 live context source (HIGH):** confirm at gate-0.2 §2 exactly how `target_arn`/`CCGDemo`/`Environment` reach Cedar and prove the caller cannot self-assert them. Blocks the permit design.
2. **HCP OIDC provider unverified:** the `cloud-sandbox` role cannot read IAM OIDC providers; confirm the `app.terraform.io` provider + run-role trust via admin/console (capability record §0).
3. **Sandbox auto-nuke:** `aws-nuke` is present; the teardown runbook (task 6.5) must assume resources can be wiped and design idempotent re-deploy.
4. **Runtime activation semantics (T3/T6):** optimistic-concurrency field and request-ID mapping still need a deployed policy to confirm (capability record §3).

## Deploy gate decision

With mitigations traced to requirements, IAM boundaries, tests, and metrics, the **only HIGH residual is T2**, which is itself a gate-0.2 capture item. A minimal, reviewed deploy of one Gateway + one Lambda target **to capture the live schema** is acceptable **provided** it targets only `CCGDemo`-tagged sandbox resources, keeps the permit set inactive (`LOG_ONLY`), and is applied via a reviewed Terraform plan through HCP. No remediation permits are activated during capture.
