# AgentCore Capability Record — Gate 0.2 / 0.3

**Purpose:** This is the evidence template that clears spec tasks **0.2 (Capture live AgentCore contract)** and **0.3 (Capture Nova Sonic contract)**. It is filled in only from a **dedicated non-production sandbox account**, against the smallest representative Gateway/target deployment. Until every REQUIRED field below is populated and reviewed, Phase 1.3 (Cedar reconciliation), Phase 2.5 (Gateway/policy Terraform), and Phase 4 (tools + control plane) remain blocked.

**Rules for filling this in**
- Capture from the **live deployed schema**, not documentation or assumption. Documentation informs the plan; only the generated schema authorizes policy work.
- **Redact** all account-identifying material that is not required: no secrets, no access-key material, no raw tokens, no full ARNs of unrelated resources.
- Every captured value gets a **source** (SDK/CLI call, console screen, or Terraform state attribute) and a **capture date**.
- If a field cannot be captured, mark it **BLOCKED** with the reason. A blocked REQUIRED field blocks the dependent phase.

---

## Section 0 — Sandbox identity (clears the "AWS account identity" baseline block)

| Field | Value | Source | Status |
|---|---|---|---|
| Account ID (last 4 only) | `____` | `aws sts get-caller-identity` | ☐ |
| Configured profile / role | `____` | caller identity | ☐ |
| Region | `____` | caller identity / config | ☐ |
| Explicit non-production designation | `sandbox` confirmed; account is NOT shared with prod | operator attestation | ☐ |
| HCP OIDC run role ARN (redacted) | `arn:aws:iam::…:role/____` | `TFC_AWS_RUN_ROLE_ARN` workspace var | ☐ |
| IAM OIDC provider for `app.terraform.io` exists | yes / no | IAM console / CLI | ☐ |

> Note: the OIDC identity provider and run role are bootstrapped **outside** this repo's Terraform. Record their existence and trust policy here so the connector is auditable.

---

## Section 1 — Gateway + target contract (REQUIRED for 1.3, 2.5, 4.x)

Deploy the smallest representative Gateway with **one** Lambda-backed MCP target, then capture:

| Field | What to capture | Status |
|---|---|---|
| Gateway ID / type | Gateway identifier and confirmed MCP protocol | ☐ |
| Target type | Confirmed `Lambda` MCP target (not OpenAPI/Smithy/MCP-server) | ☐ |
| Lambda tool schema limits | Max tool count, input schema size, parameter typing constraints | ☐ |
| **Generated action identifier(s)** | The exact `Action::"…"` string(s) AgentCore generates per registered tool | ☐ |
| Principal / entity type | How the authenticated caller appears to Cedar (entity type + attributes) | ☐ |
| Resource representation | Whether the Cedar `resource` is the Gateway, the tool, or the target — and its attributes | ☐ |
| **Request input context shape** | Exact context keys available to Cedar (this determines how `target_arn`, `CCGDemo`, `Environment` reach the policy) | ☐ |
| Policy engine association | How a Policy Engine binds to this Gateway | ☐ |
| Policy analyzer behavior | What the analyzer validates/rejects; sample analyzer output on a known-bad policy | ☐ |

**Decision it unblocks:** replaces the placeholder `Action::"ModifySecurityGroup"` / `resource.hasTag(...)` expressions in `policies/guardrails.cedar` with validated names, and lets Phase 1.3 add one narrow permit per real action to `policies/remediation-permits.cedar`.

---

## Section 2 — Tamper-resistant safety attributes (REQUIRED — answers design Q2)

The demo's core claim is that the caller **cannot self-assert** `CCGDemo=true` or a non-prod `Environment`. Capture how the safety attributes actually reach Cedar:

| Field | What to capture | Status |
|---|---|---|
| Attribute source | Gateway-injected context vs. principal tag vs. resolved entity attribute | ☐ |
| Can the caller supply it? | Prove the caller **cannot** set `CCGDemo`/`Environment` in the request | ☐ |
| Target ARN resolution | How the real target ARN is bound server-side (not from the untrusted `RemediationCommand`) | ☐ |
| Tag lookup path | Whether tags are read live at eval time or passed in trusted context | ☐ |

> If the only path is caller-supplied context, that is a **BLOCKER**: the tool Lambda or Gateway must resolve target identity/tags server-side before the Cedar decision. Record the chosen mechanism.

---

## Section 3 — Policy activation control plane (REQUIRED for 4.3 — answers design Q1)

`src/ccg/policy.py` is already written against this contract; confirm the real operation matches.

| Field | What to capture | Status |
|---|---|---|
| Update operation | Exact SDK/CLI operation that changes enforcement mode | ☐ |
| Enforcement modes | Confirm `LOG_ONLY` and `ACTIVE` (or the real mode names) | ☐ |
| Optimistic concurrency | Whether the API supports a version/generation/ETag guard (maps to `expected_generation`) | ☐ |
| Propagation behavior | Sync vs. eventual; how long until effective; how to confirm effective state | ☐ |
| Request ID | Where the control-plane request ID appears (maps to `control_plane_request_id`) | ☐ |
| IAM permissions | Minimum actions the control-plane role needs | ☐ |
| Failure / rollback | Behavior on timeout, conflict, partial apply; how to force deny-safe | ☐ |

**Decision it unblocks:** confirms `PolicyActivationService` fail-closed and stale-generation rejection map to real API semantics, or flags where the contract must change.

---

## Section 4 — Nova Sonic contract (REQUIRED for 5.3 / task 0.3 — answers design Q4 indirectly)

Voice stays **off by default** regardless. Capture only enough to decide real-adapter vs. mock.

| Field | What to capture | Status |
|---|---|---|
| Model ID | Selected Nova Sonic model identifier | ☐ |
| Region availability | Confirm model is available in the sandbox region | ☐ |
| Quotas | Session/stream/concurrency limits | ☐ |
| Bidirectional API | Event types for speech/text/audio | ☐ |
| Browser transport | The supported browser streaming path + auth | ☐ |
| Interruption events | The stop/supersede (barge-in) event contract | ☐ |
| **Decision** | Real adapter **or** mock for first implementation | ☐ |

---

## Section 5 — Terraform provider/runtime (mostly RESOLVED — answers design Q7)

| Field | Value | Status |
|---|---|---|
| AWS provider version | `= 6.64.0` (pinned in `versions.tf`) | ☑ pinned |
| Terraform runtime floor | `>= 1.8.0, < 2.0.0`; confirm AgentCore resource schemas validate on the chosen runtime | ☐ confirm |
| Lock file committed | `.terraform.lock.hcl` matches 6.64.0 with no secrets | ☐ verify |
| AgentCore resources present | `aws_bedrockagentcore_gateway`, `_gateway_target`, `_policy_engine`, `_policy` schemas confirmed in provider | ☐ |

---

## Section 6 — Pre-apply evidence checklist (from CAPABILITY_BASELINE.md)

Before any sandbox apply is approved, all of the following are captured and reviewed:

1. ☐ Caller identity, account, profile, region, non-prod designation (Section 0)
2. ☐ Terraform runtime/provider versions + committed lock file, no secrets/state (Section 5)
3. ☐ Live Gateway target schema + generated Cedar action/resource/entity identifiers (Sections 1–2)
4. ☐ Verified activation API, IAM, propagation, reconciliation (Section 3)
5. ☐ Nova Sonic model/region/quota/transport decision, or explicit mock/off (Section 4)
6. ☐ Reviewed plan artifact: no NAT, no always-on compute, no provisioned DynamoDB, no multi-AZ, no prod targets, no unregistered mutation path

**This record authorizes nothing on its own.** It is the evidence input to the human review gates in `requirements.md` §6.
