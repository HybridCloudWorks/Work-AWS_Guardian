# Design Review Reconciliation — Task 0.1

**Purpose:** Resolve the design-review questions in `design.md` §10 and the review gates in `requirements.md` §6 so requirements and design can be marked approved. This records **decisions**, not implementation. Items that genuinely depend on the live schema are routed to `AGENTCORE_CAPABILITY_RECORD.md` (gate 0.2/0.3) rather than guessed.

**Date:** 2026-09-15
**Status:** Proposed decisions for owner sign-off (security, platform, POC).

---

## Decision status legend
- **RESOLVED** — decided now; no live capture needed.
- **RESOLVED-PENDING-CAPTURE** — approach decided; exact values captured in gate 0.2/0.3.
- **OPEN** — needs an owner decision before approval.

---

## Design §10 questions

### Q1. Does the AgentCore API expose a safe, auditable per-policy activation flow with optimistic concurrency?
**RESOLVED-PENDING-CAPTURE.** The design commits to activation as an audited control-plane operation, and `src/ccg/policy.py` already implements it fail-closed with `expected_generation` optimistic-concurrency and idempotent replay. The decision stands; the **exact** update operation, mode names, and concurrency guard are captured in Capability Record **Section 3**. If the real API lacks a version/generation guard, the fallback is a control-plane-side conditional check plus the existing deny-safe reconciliation — recorded before Phase 4.3.

### Q2. How do target ARN and `CCGDemo`/`Environment` attributes reach Cedar without being supplied solely by the untrusted caller?
**RESOLVED (principle) / PENDING-CAPTURE (mechanism).** Principle is fixed: the caller **must not** be able to self-assert safety attributes. The untrusted `RemediationCommand` carries only `finding_id`; the server resolves the real `TargetRef` (see `contracts.py`). The concrete injection mechanism — Gateway context vs. server-side tag lookup at eval time — is captured in Capability Record **Section 2**. If the only available path is caller-supplied context, the tool Lambda resolves target identity and tags server-side and re-checks before mutating. This is a **hard approval condition**.

### Q3. Which Gateway principal/action/resource schema is generated for the four Lambda targets in the selected region?
**RESOLVED-PENDING-CAPTURE.** Cannot be answered without deployment. Captured in Capability Record **Section 1** (generated action IDs, principal entity type, resource representation, context shape). Until captured, `policies/guardrails.cedar` action names and `resource.hasTag(...)` expressions remain **intent, not deployable**.

### Q4. Can the chosen console hosting mode satisfy Next.js App Router without always-on compute or exceeding budget?
**OPEN — decision needed for approval.** Recommendation: target **static export** of the App Router console served from S3 + CloudFront, with all dynamic behavior behind the API Gateway/Lambda control plane. This keeps the cost boundary (no always-on compute). If a required App Router feature forces server rendering, the fallback is Lambda@Edge/SSR-on-Lambda, which must be cost-reviewed **before** implementation (Phase 5.2). Owners: confirm static-export-first is acceptable.

### Q5. Are the four remediation scopes narrow enough for a one-account sandbox, especially access-key rotation?
**RESOLVED with conditions.** SG correction, S3 encryption, and tagging are bounded to a single allowlisted sandbox resource with no-op-on-compliant semantics (design §3.3). **Access-key rotation** is the highest-risk tool; approval condition: it operates on a single explicitly-approved sandbox IAM identity, validates the replacement before disabling the old key, never returns secret material, and pauses for reconciliation on uncertainty. If owners prefer, rotation can be **demonstrated as a dry-run-only workflow** for the POC to further reduce blast radius. Owners: choose full-rotation vs. dry-run-only.

### Q6. What exact S3 immutability guarantee is required beyond private encrypted storage + lifecycle expiry?
**OPEN — decision needed.** Current modules provide private, encrypted, public-access-blocked storage with 30-day expiry ("immutable-shaped", not WORM). Options: (a) keep append-only-shaped + lifecycle only (lowest cost, no WORM claim); (b) add S3 Object Lock in governance mode (real immutability, added cost/complexity). Recommendation for a POC: **(a)**, and explicitly stop describing records as immutable — call them "append-only-shaped with 30-day expiry." Owners: confirm (a) vs. (b).

### Q7. Which provider/runtime versions will CI pin, and can the Terraform 1.8 floor support the AgentCore schemas?
**RESOLVED (provider) / PENDING-CONFIRM (runtime).** AWS provider is pinned to `= 6.64.0` in `versions.tf` (the validated AgentCore baseline) — the old `~> 5.0` concern no longer applies to the committed config. CI pins Terraform `1.15.8`. Remaining confirmation: that the AgentCore resource schemas validate on the chosen runtime and that `.terraform.lock.hcl` matches 6.64.0 (Capability Record Section 5).

---

## Requirements §6 review gates — status

| Gate | Status | Where resolved |
|---|---|---|
| 1. Human approval of requirements + design | OPEN — this doc enables sign-off | this document |
| 2. Live Gateway schema + Cedar mapping | PENDING-CAPTURE | Capability Record §1–2 |
| 3. Activation API / IAM / propagation / rollback | PENDING-CAPTURE | Capability Record §3 |
| 4. Nova Sonic model/region/transport or mock | PENDING-CAPTURE | Capability Record §4 |
| 5. Provider 6.64.0 upgrade decision | RESOLVED | `versions.tf` pinned; §5 confirm lock |
| 6. Threat-model review (task 1.2) | OPEN | scheduled as Phase 1.2 |

---

## Cross-cutting decisions already settled since the spec was written
- **Python runtime baseline is 3.14** (was 3.12): `pyproject.toml` `>=3.14,<3.15`, `ruff.toml` `py314`, CI `python-version: 3.14`, `ruff==0.16.6`. 22-test suite passes. All spec, steering, and handoff references were updated from 3.12 to 3.14 in the same change.
- **AWS provider pinned to 6.64.0**; OIDC dynamic credentials via HCP (`TFC_AWS_PROVIDER_AUTH` / `TFC_AWS_RUN_ROLE_ARN`), no static credentials in repo.
- **Encryption keys: AWS-managed keys only, no customer-managed KMS (CMK)** (owner-approved 2026-09-17). S3 audit bucket keeps SSE-S3 (AES256); DynamoDB keeps its AWS-owned-key SSE; CloudWatch keeps default encryption. This holds POC cost/complexity down; CMK is deferred to the production-later list. Any future control that would require a CMK must be flagged as a budget/scope change.

## Open items — RESOLVED (owner-approved 2026-09-15)

1. **Q4 — Console hosting: APPROVED static-export-first.** Next.js App Router is statically exported to S3 + CloudFront; all dynamic behavior goes through the API Gateway/Lambda control plane. No always-on compute. If a required feature forces SSR, it must be cost-reviewed before Phase 5.2 — it is not adopted by default.
2. **Q5 — Access-key rotation: APPROVED dry-run-only for the POC.** The rotation tool defaults to a validated dry-run that plans create→validate→disable without performing the disable. A real rotation requires an explicit non-default `confirm=true` parameter AND an active permit AND sandbox tags. Secret material never enters logs, responses, or state. This shrinks blast radius while still demonstrating the workflow and Cedar boundary.
3. **Q6 — S3 evidence: APPROVED append-only-shaped + 30-day lifecycle.** No Object Lock/WORM for the POC. Records are described as "append-only-shaped with 30-day expiry," never as WORM-immutable. Object Lock is deferred to the production-later list.
4. **Gate 6 — Threat model: SCHEDULED as Phase 1.2, blocking Phase 2 Terraform expansion.** No AgentCore Gateway/policy/IAM Terraform resources are expanded until the threat model is reviewed.

**Task 0.1 is satisfied.** These decisions authorize planning and offline (no-live-AWS) implementation behind adapters/test doubles. They do NOT authorize Terraform resource expansion, policy activation, seed mutation, or live AWS changes — those remain gated on 0.2 capture and the Phase 1.2 threat model.
