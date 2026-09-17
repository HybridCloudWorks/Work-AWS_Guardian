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
| Account ID (last 4 only) | `…8441` | `aws sts get-caller-identity` (2026-09-17) | ☑ |
| Configured profile / role | profile `ccg-sandbox` → SSO role `cloud-sandbox` | caller identity | ☑ |
| Region | `us-east-1` | caller identity / config | ☑ |
| Explicit non-production designation | `cloud-sandbox` SSO role; 1 of 2 accounts; role cannot `iam:ListAccountAliases` (scoped, non-admin) — operator to attest it is NOT shared with prod | operator attestation | ☑ |
| HCP OIDC run role ARN (redacted) | `arn:aws:iam::…:role/____` | `TFC_AWS_RUN_ROLE_ARN` workspace var | ☐ |
| IAM OIDC provider for `app.terraform.io` exists | yes / no | IAM console / CLI | ☐ |

> Note: the OIDC identity provider and run role are bootstrapped **outside** this repo's Terraform. Record their existence and trust policy here so the connector is auditable.

---

## Section 1 — Gateway + target contract (REQUIRED for 1.3, 2.5, 4.x)

**Confirmed from the CLI service model (2026-09-17, read-only, nothing deployed):** the `bedrock-agentcore-control` API (v`2023-06-05`) exposes the full resource surface — `CreateGateway`/`GetGateway`/`ListGateways`, `CreateGatewayTarget`/`GetGatewayTarget`/`ListGatewayTargets`/`SynchronizeGatewayTargets`, `CreatePolicyEngine`/`GetPolicyEngine`, `CreatePolicy`/`GetPolicy`/`UpdatePolicy`, and a **PolicyGeneration** family (`StartPolicyGeneration`, `GetPolicyGeneration`, `ListPolicyGenerationAssets`) that is almost certainly how Cedar is generated from the target schema. `CreatePolicyEngine.encryptionKeyArn` is **optional** → the "AWS-managed keys, no CMK" decision holds by omitting it. The fields below still require an actual deploy to capture:

| Field | What to capture | Status |
|---|---|---|
| API reachability | **CONFIRMED**: `aws bedrock-agentcore-control list-gateways --region us-east-1` → `{"items": []}` (exit 0) on 2026-09-17. Service is enabled, the `cloud-sandbox` role can read it, and there are **no pre-existing gateways** (clean slate). | ☑ |
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

Partially captured from the pinned AWS CLI service model (`bedrock-agentcore-control`, API version `2023-06-05`, aws-cli 2.36.47) on 2026-09-17. **Static model facts** are ☑; **runtime behavior** (propagation, request IDs, live IAM) still needs a deployed engine/policy and is ☐.

| Field | What to capture | Status |
|---|---|---|
| Update operation | **`UpdatePolicy`** (`PATCH /policies/{id}`) carries `enforcementMode`. `UpdatePolicyEngine` only edits the engine description — it is **not** the activation lever. | ☑ (model) |
| Enforcement modes | Confirmed enum **`EnforcementMode = ['ACTIVE','LOG_ONLY']`** on `enforcementMode`. Exactly matches `contracts.PolicyEnforcementMode`. A separate `GatewayPolicyEngineMode = ['LOG_ONLY','ENFORCE']` exists at engine level. | ☑ (model) |
| Optimistic concurrency | Not visible in the input model; need to check for a conditional/ETag header or `clientToken` at runtime. `contracts.expected_generation` may need to map to a returned version field. | ☐ (runtime) |
| Propagation behavior | `PolicyStatus = ['CREATING','ACTIVE','UPDATING','DELETING','CREATE_FAILED','UPDATE_FAILED','DELETE_FAILED']` — implies async status; confirm via `GetPolicy` polling. | ☐ (runtime) |
| Request ID | Standard AWS `x-amzn-RequestId`; confirm it maps to `control_plane_request_id` at runtime. | ☐ (runtime) |
| IAM permissions | Minimum: `bedrock-agentcore:UpdatePolicy`, `bedrock-agentcore:GetPolicy` (+ `GetPolicyEngine`). **Corrects** the `UpdateGatewayPolicy` guess in `modules/iam-policies` (PR #3) — that operation does not exist. | ☐ (confirm namespace) |
| Failure / rollback | `*_FAILED` statuses exist; deny-safe = re-`UpdatePolicy` to `LOG_ONLY`. Confirm at runtime. | ☐ (runtime) |

**Decision it unblocks:** confirms `PolicyActivationService` maps to `UpdatePolicy(enforcementMode=ACTIVE|LOG_ONLY)`; fail-closed reconciliation = force `LOG_ONLY`. **Follow-up required:** fix the action name in `modules/iam-policies` from `UpdateGatewayPolicy` to `UpdatePolicy`.

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
