# CCG Policy Catalog

**Status:** Intent stubs — pending first sandbox deploy to confirm gateway ARN and action IDs.
**Last updated:** 2026-10-12 (task 1.3 — Cedar reconciliation)
**Schema:** `policies/ccg-schema.cedarschema`
**Sources:** `policies/guardrails.cedar`, `policies/remediation-permits.cedar`

---

## 1. Authorization model summary

### Forbid-wins / default-deny

Cedar evaluates both forbid and permit policies on every request. If any forbid matches, the result is **DENY** — regardless of any active permit. If no forbid matches but no permit matches (or all permits are `LOG_ONLY`/inactive), the result is **DENY**. An `ALLOW` requires:

1. No forbid fires.
2. At least one `ACTIVE` permit matches.

This is the standard Cedar semantics enforced by the AgentCore Gateway Policy Engine.

### Policy-level enforcement modes

| Mode | Behavior |
|---|---|
| `ACTIVE` | Policy is evaluated and enforced; contributes to the allow/deny decision. |
| `LOG_ONLY` | Policy is evaluated but never enforced; decision appears only in traces and CloudWatch metrics. Permits in `LOG_ONLY` cannot grant access. |

All four CCG permit policies are created in `LOG_ONLY` mode. No mutation is possible until at least the relevant permit is activated via the control-plane process described in §4 below.

### Engine-level enforcement mode (separate control)

The Policy Engine itself also has a mode (`ENFORCE` / `LOG_ONLY`) set on the `aws_bedrockagentcore_gateway` `policyEngineConfiguration.mode` field. Engine-level `LOG_ONLY` disables enforcement for *all* policies regardless of individual policy modes. CCG deploys with `LOG_ONLY` initially for schema capture, then switches to `ENFORCE` before any permit activation.

---

## 2. Always-on forbid policies (`guardrails.cedar`)

Forbid policies are **always evaluated** regardless of enforcement mode. When the Policy Engine is in `ENFORCE` mode, matching forbids block the call. There is no activation step for forbids — they are always present.

### Policy F-1 — Block global-open IPv4 ingress

| Field | Value |
|---|---|
| **Effect** | `forbid` |
| **Action** | `AgentCore::Action::"RemediationTarget___security_group_correction"` |
| **Resource** | `AgentCore::Gateway::"<GATEWAY_ARN>"` *(placeholder)* |
| **Condition** | `context.input.proposed_cidr == "0.0.0.0/0"` |
| **Rationale** | Prevents the security-group tool from widening a rule to global IPv4 internet access regardless of the calling principal or permit state. |
| **Override** | Cannot be overridden by any permit. Forbid-wins. |

### Policy F-2 — Block global-open IPv6 ingress

| Field | Value |
|---|---|
| **Effect** | `forbid` |
| **Action** | `AgentCore::Action::"RemediationTarget___security_group_correction"` |
| **Resource** | `AgentCore::Gateway::"<GATEWAY_ARN>"` *(placeholder)* |
| **Condition** | `context.input.proposed_cidr == "::/0"` |
| **Rationale** | Same as F-1 for IPv6 global-open ingress. |
| **Override** | Cannot be overridden by any permit. Forbid-wins. |

### Policy F-3 — Block S3 public-access flag

| Field | Value |
|---|---|
| **Effect** | `forbid` |
| **Action** | `AgentCore::Action::"RemediationTarget___s3_encryption_enablement"` |
| **Resource** | `AgentCore::Gateway::"<GATEWAY_ARN>"` *(placeholder)* |
| **Condition** | `context.input.make_public == true` |
| **Rationale** | Prevents any call that sets the `make_public` flag, which would widen bucket access rather than strengthen it. |
| **Override** | Cannot be overridden by any permit. Forbid-wins. |

### Policy F-4 — Block non-tool-call actions (catch-all)

| Field | Value |
|---|---|
| **Effect** | `forbid` |
| **Action** | Any (`action` unconstrained) |
| **Resource** | `resource is AgentCore::Gateway` |
| **Condition** | `unless { action in AgentCore::Action::"CallTool" }` |
| **Rationale** | Explicitly forbids any Gateway action that is not an MCP tool call. Cedar default-deny already handles unknown actions, but this forbid makes the intent explicit and ensures non-tool invocations are denied even if the schema evolves. |
| **Note** | This policy uses the type-form resource (`resource is AgentCore::Gateway`) because the action is unconstrained. The Cedar analyzer requires a specific gateway ARN only when a policy targets a specific action. |

---

## 3. Per-tool permit policies (`remediation-permits.cedar`)

All four permits are **`LOG_ONLY` by default**. They must be activated individually through the control-plane process (§4) after schema validation passes against the deployed gateway.

### Policy P-1 — Security-group correction permit

| Field | Value |
|---|---|
| **Effect** | `permit` |
| **Action** | `AgentCore::Action::"RemediationTarget___security_group_correction"` |
| **Resource** | `AgentCore::Gateway::"<GATEWAY_ARN>"` *(placeholder)* |
| **Principal** | `principal is AgentCore::IamEntity` with `principal.id like "arn:aws:sts::<ACCOUNT_ID>:assumed-role/<REMEDIATOR_ROLE_NAME>*"` |
| **Default mode** | `LOG_ONLY` |
| **Overrides** | F-1 and F-2 forbids override this permit when `proposed_cidr` is globally open. |
| **Additional enforcement** | IAM deny condition (`aws:ResourceTag/Environment=prod`) on the tool execution role; Lambda safety recheck of `CCGDemo=true` and `Environment≠prod` before any mutation. |

### Policy P-2 — S3 encryption enablement permit

| Field | Value |
|---|---|
| **Effect** | `permit` |
| **Action** | `AgentCore::Action::"RemediationTarget___s3_encryption_enablement"` |
| **Resource** | `AgentCore::Gateway::"<GATEWAY_ARN>"` *(placeholder)* |
| **Principal** | `principal is AgentCore::IamEntity` with role pattern |
| **Default mode** | `LOG_ONLY` |
| **Overrides** | F-3 forbid overrides this permit when `make_public=true`. |

### Policy P-3 — Compliant tagging permit

| Field | Value |
|---|---|
| **Effect** | `permit` |
| **Action** | `AgentCore::Action::"RemediationTarget___compliant_tagging"` |
| **Resource** | `AgentCore::Gateway::"<GATEWAY_ARN>"` *(placeholder)* |
| **Principal** | `principal is AgentCore::IamEntity` with role pattern |
| **Default mode** | `LOG_ONLY` |

### Policy P-4 — Access-key rotation permit

| Field | Value |
|---|---|
| **Effect** | `permit` |
| **Action** | `AgentCore::Action::"RemediationTarget___access_key_rotation"` |
| **Resource** | `AgentCore::Gateway::"<GATEWAY_ARN>"` *(placeholder)* |
| **Principal** | `principal is AgentCore::IamEntity` with role pattern |
| **Default mode** | `LOG_ONLY` |
| **Note** | The tool Lambda enforces dry-run semantics until `confirm=true` is supplied. That is enforced at the Lambda layer, not in Cedar. |

---

## 4. Activation process (LOG_ONLY → ACTIVE)

Activation is a **control-plane operation** — never a Terraform change, a direct AWS CLI call, or a UI boolean.

### Pre-activation gates (must all pass before any permit is activated)

1. **Deploy and confirm ARNs.** Run `aws bedrock-agentcore-control list-gateway-targets` and `agentcore status` after the first sandbox deploy. Confirm the exact generated action IDs match those in the policy files and update `docs/AGENTCORE_CAPABILITY_RECORD.md`.
2. **Replace `<GATEWAY_ARN>` placeholder.** Update both `guardrails.cedar` and `remediation-permits.cedar` with the actual gateway ARN.
3. **Replace `<ACCOUNT_ID>` and `<REMEDIATOR_ROLE_NAME>`.** Update the principal pattern in all four permits.
4. **Run the Cedar validator.** Execute `scripts/validate_cedar.sh` — all policies must pass.
5. **Run the AgentCore policy analyzer.** Call `UpdatePolicy` (or use `StartPolicyGeneration` validation) with `validationMode=FAIL_ON_ANY_FINDINGS`. All four permit policies must pass with zero findings before activation is attempted.

### Activation flow

```
1.  Authenticate admin (Cognito + narrowly scoped control-plane role)
2.  GET  GetPolicy → confirm current enforcementMode=LOG_ONLY, record generation
3.  Write intent audit record (PolicyActivationRecord.requested_mode=ACTIVE)
4.  PATCH UpdatePolicy(enforcementMode=ACTIVE)
          → HTTP 202; poll GetPolicy.status until ACTIVE
5.  Write result audit record (effective_mode, control_plane_request_id)
6.  Verify: send a test request through the Gateway and confirm ALLOW
```

All activation steps are implemented in `src/ccg/policy.py` (`PolicyActivationService`).

### Rollback / deactivation

- Call `UpdatePolicy(enforcementMode=LOG_ONLY)` to return a permit to inactive state.
- The offline model's `force_deny_safe()` path handles uncertain activation status by reverting to `LOG_ONLY`.
- On `UPDATE_FAILED`: check `GetPolicy.statusReasons`, call `UpdatePolicy(enforcementMode=LOG_ONLY)`, and reconcile before retrying activation.

### Policy version and generation tracking

- The `policy_set_version` string in `contracts.PolicyDecision` and `DecisionEvidence` records the version active at evaluation time.
- The offline model's `expected_generation` field is an application-level guard; there is no direct `ETag` or generation field in the live `UpdatePolicy` API. Use `GetPolicy` to read current state before retrying.

---

## 5. CCGDemo / Environment two-layer enforcement

Cedar cannot enforce `CCGDemo=true` or `Environment≠prod` because `AgentCore::Gateway` entities carry no resource tags in the Cedar context. The enforcement is split across two server-side layers:

| Layer | Mechanism | Location |
|---|---|---|
| **IAM deny** | `aws:ResourceTag/Environment = prod` deny condition on the tool execution role. Applied by IAM before the Lambda is invoked — caller cannot bypass this. | `modules/iam-policies/main.tf` (`tool_execution_boundary`) |
| **Lambda recheck** | Each tool Lambda re-reads live resource tags from AWS APIs before any mutation. Independently verifies `CCGDemo=true` and `Environment≠prod`. A deny here is fail-closed regardless of Cedar's decision. | `src/ccg/tools.py` (`_recheck_target_safety`) |

The offline `src/ccg/authz.py` model also enforces these rules as `FORBID_RULES` to keep test coverage honest. The forbids `always-deny-production-target` and `always-deny-missing-demo-tag` mirror the two-layer server-side enforcement.

---

## 6. What the policy analyzer validates vs. does NOT cover

### What the analyzer validates

- Action IDs and resource types exist in the generated Cedar schema.
- Context attribute accesses (`context.input.<param>`) match the declared type.
- Resource constraint matches the action's resource type (specific ARN required for specific actions).
- No unsupported Cedar functions (e.g., `.hasTag()` on `AgentCore::Gateway`).
- Correct Cedar syntax and type safety.

### What the analyzer does NOT cover

- Whether the gateway ARN placeholder has been replaced with a real ARN.
- Whether the principal IAM role pattern (`like "arn:aws:sts::..."`) matches the actual deployed role.
- Whether the CCGDemo / Environment gates are correctly enforced at the IAM and Lambda layers.
- Whether the `LOG_ONLY` policy engine mode has been switched to `ENFORCE` before permit activation.
- Whether tool parameters supplied by the caller at runtime are valid and safe (beyond what Cedar context types enforce).
- Runtime behavior: whether the Lambda actually re-reads tags, whether the IAM deny condition is correctly applied, etc.

---

## 7. Policy ID reference

| Policy ID | File | Effect | Tool / Scope |
|---|---|---|---|
| `guardrail-block-ipv4-open-ingress` | guardrails.cedar | forbid | security_group_correction — proposed_cidr=0.0.0.0/0 |
| `guardrail-block-ipv6-open-ingress` | guardrails.cedar | forbid | security_group_correction — proposed_cidr=::/0 |
| `guardrail-block-s3-make-public` | guardrails.cedar | forbid | s3_encryption_enablement — make_public=true |
| `guardrail-block-non-calltool` | guardrails.cedar | forbid | catch-all non-MCP-tool actions |
| `permit-security-group-correction` | remediation-permits.cedar | permit (LOG_ONLY) | security_group_correction |
| `permit-s3-encryption-enablement` | remediation-permits.cedar | permit (LOG_ONLY) | s3_encryption_enablement |
| `permit-compliant-tagging` | remediation-permits.cedar | permit (LOG_ONLY) | compliant_tagging |
| `permit-access-key-rotation` | remediation-permits.cedar | permit (LOG_ONLY) | access_key_rotation |

> The policy IDs above are the logical names used in audit records and the offline model. Live AgentCore policy IDs are generated UUIDs assigned at `CreatePolicy` time; record the mapping from logical name to live UUID in `docs/AGENTCORE_CAPABILITY_RECORD.md` after the first deploy.
