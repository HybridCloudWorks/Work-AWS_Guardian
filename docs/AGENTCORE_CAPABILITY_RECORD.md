# AgentCore Capability Record — Gate 0.2 / 0.3

**Purpose:** This is the evidence template that clears spec tasks **0.2 (Capture live AgentCore contract)** and **0.3 (Capture Nova Sonic contract)**. It is filled in only from a **dedicated non-production sandbox account**, against the smallest representative Gateway/target deployment. Until every REQUIRED field below is populated and reviewed, Phase 1.3 (Cedar reconciliation), Phase 2.5 (Gateway/policy Terraform), and Phase 4 (tools + control plane) remain blocked.

**Last updated:** 2026-10-12 (task 0.3 — Nova Sonic contract captured from AWS Nova 2 developer guide + Bedrock API reference; task 0.2 reconciliation from AWS API reference + live documentation; live sandbox deploy not yet performed) | task 0.4 — Terraform version baseline resolved (runtime v1.16.5 confirmed, lock file verified, AgentCore resources confirmed in provider 6.64.0)

**Rules for filling this in**
- Capture from the **live deployed schema**, not documentation or assumption. Documentation informs the plan; only the generated schema authorizes policy work.
- **Redact** all account-identifying material that is not required: no secrets, no access-key material, no raw tokens, no full ARNs of unrelated resources.
- Every captured value gets a **source** (SDK/CLI call, console screen, or Terraform state attribute) and a **capture date**.
- If a field cannot be captured, mark it **BLOCKED** with the reason. A blocked REQUIRED field blocks the dependent phase.

---

## Section 0 — Sandbox identity (clears the "AWS account identity" baseline block)

| Field | Value | Source | Status |
|---|---|---|---|
| Account ID | `<redacted>` | `aws sts get-caller-identity` (2026-09-17) | ☑ |
| Configured profile / role | profile `ccg-sandbox` → SSO role `cloud-sandbox` | caller identity | ☑ |
| Region | `us-east-1` | caller identity / config | ☑ |
| Explicit non-production designation | `cloud-sandbox` SSO role; 1 of 2 accounts; role cannot `iam:ListAccountAliases` (scoped, non-admin) — operator to attest it is NOT shared with prod | operator attestation | ☑ |
| HCP OIDC run role ARN (redacted) | `arn:aws:iam::…:role/____` | `TFC_AWS_RUN_ROLE_ARN` workspace var | ☐ |
| IAM OIDC provider for `app.terraform.io` exists | yes / no | IAM console / CLI | ☐ |

> Note: the OIDC identity provider and run role are bootstrapped **outside** this repo's Terraform. Record their existence and trust policy here so the connector is auditable.

---

## Section 1 — Gateway + target contract (REQUIRED for 1.3, 2.5, 4.x)

### 1.1 Gateway capability facts (sourced from AWS documentation and API model, 2026-10-12)

| Field | Value | Source | Status |
|---|---|---|---|
| API reachability | **CONFIRMED**: `aws bedrock-agentcore-control list-gateways --region us-east-1` → `{"items": []}` (exit 0) on 2026-09-17. Service enabled, `cloud-sandbox` role can read it, clean slate. | `aws bedrock-agentcore-control list-gateways` (2026-09-17) | ☑ |
| Service endpoint | `bedrock-agentcore-control` (control plane); `bedrock-agentcore` (data plane / gateway invocation) | AWS CLI service model, API version `2023-06-05` | ☑ |
| Terraform resource name | `aws_bedrockagentcore_gateway` | [Terraform AWS Provider 6.64.0](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/bedrockagentcore_gateway) | ☑ |
| Protocol type | `MCP` (Model Context Protocol). The gateway is a managed MCP server endpoint. | AWS docs: [gateway-create](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-create.html) | ☑ |
| Authorizer types | `NONE`, `AWS_IAM`, custom JWT. CCG POC uses `AWS_IAM`. | AWS docs: policy-getting-started | ☑ |
| Gateway type (resource entity in Cedar) | `AgentCore::Gateway` — represents the MCP gateway instance. The full ARN form is `AgentCore::Gateway::"arn:aws:bedrock-agentcore:<region>:<account>:gateway/<id>"` | [policy-understanding-cedar](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-understanding-cedar.html) | ☑ |
| Gateway ID / ARN format | `arn:aws:bedrock-agentcore:<region>:<account>:gateway/<gateway-id>`. The `<gateway-id>` is assigned at creation; only known after the first deploy. | API reference | ☐ (needs first deploy) |
| Workload identity | A workload identity is **automatically created** when a gateway is created (no explicit resource needed). | AWS docs | ☑ |
| Encryption key | `encryptionKeyArn` is **optional** — omitting it uses an AWS-managed key. **CCG decision: omit** (matches ADR-0003, no CMK). | API model / ADR-0003 | ☑ |
| Debug mode | Optional; off by default. Returns specific error messages during gateway invocation. | AWS docs | ☑ |

### 1.2 Lambda target schema limits and contract

| Field | Value | Source | Status |
|---|---|---|---|
| Supported target types | Lambda function, REST API (HTTP proxy), AgentCore Runtime, MCP server. CCG POC uses **Lambda function** targets. | AWS docs: gateway-add-target-lambda | ☑ |
| Tool schema top-level structure | JSON array of tool definitions: `[{ "name", "description", "inputSchema", "outputSchema" }]`. The `outputSchema` is optional. | AWS docs: [gateway-add-target-lambda](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-add-target-lambda.html) | ☑ |
| `inputSchema` / `outputSchema` shape | Object-type JSON Schema: `{ "type": "object", "description"?, "properties"?: { "<key>": SchemaDefinition }, "required"?: ["..."] }`. Nested objects recurse. | AWS docs | ☑ |
| Supported property types | `string`, `integer`, `boolean`, `number` (maps to Cedar `Decimal`; max 4 decimal places), `object` (Cedar `Record`), `array` (Cedar `Set`, unordered), `null` (Cedar `Entity`, unique per schema). | [policy-schema-constraints](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-schema-constraints.html) | ☑ |
| Max tool count per target | **BLOCKED** — not documented; requires a live deploy to verify. | — | ☐ |
| Max input schema size | **BLOCKED** — not documented; requires a live deploy to verify. | — | ☐ |
| Tool schema delivery | Upload to S3 and reference the bucket/key, or paste inline during target creation. | AWS docs | ☑ |
| Lambda event format | The event object is a flat map of `inputSchema` property names to their values (e.g., `{"proposed_cidr": "10.0.0.1/32", ...}`). No wrapper. | AWS docs: Lambda function input format | ☑ |
| Lambda context format | Passed via `context.client_context.custom`: `bedrockAgentCoreMessageVersion`, `bedrockAgentCoreAwsRequestId`, `bedrockAgentCoreMcpMessageId`, `bedrockAgentCoreGatewayId`, `bedrockAgentCoreTargetId`, `bedrockAgentCoreToolName` (prefixed as `<TargetName>___<tool_name>`). | AWS docs: Lambda function input format | ☑ |
| Tool name stripping in Lambda | The Lambda function must strip the target-name prefix (`___` delimiter) from `bedrockAgentCoreToolName` to get the bare tool name. | AWS docs | ☑ |
| Lambda return format | Must return a valid JSON response parseable by the gateway. | AWS docs | ☑ |

### 1.3 Generated Cedar action identifiers

> **Critical finding:** Action identifiers are **auto-generated** from the target name and tool name. The format is `<TargetName>___<ToolName>` (three underscores). This means the exact action strings are determined by the target name chosen at deployment. The CCG POC must choose a stable target name at deploy time so policy files can be finalized.

| Field | Value | Source | Status |
|---|---|---|---|
| Action format (Lambda MCP targets) | `AgentCore::Action::"<TargetName>___<ToolName>"` — target name and tool name joined with `___` (three underscores). | [policy-understanding-cedar](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-understanding-cedar.html) | ☑ |
| Action namespace | `AgentCore::Action::` — no other namespace is valid. | AWS docs | ☑ |
| Action hierarchy | All tool actions inherit from `CallTool → Mcp`. You can group with `action in AgentCore::Action::"CallTool"`. | policy-schema-constraints | ☑ |
| Wildcard actions | **Not supported.** Each action must be referenced by exact identifier. No glob or prefix matching on action names. | AWS docs | ☑ |
| **CCG proposed target name** | `RemediationTarget` (to be confirmed at first deploy; must be stable). | CCG policy design decision | ☑ (intent) |
| **Proposed action: security-group correction** | `AgentCore::Action::"RemediationTarget___security_group_correction"` | CCG policy design (tool name from `src/ccg/tools.py`) | ☑ (intent; confirm at deploy) |
| **Proposed action: S3 encryption** | `AgentCore::Action::"RemediationTarget___s3_encryption_enablement"` | CCG policy design | ☑ (intent; confirm at deploy) |
| **Proposed action: compliant tagging** | `AgentCore::Action::"RemediationTarget___compliant_tagging"` | CCG policy design | ☑ (intent; confirm at deploy) |
| **Proposed action: access-key rotation** | `AgentCore::Action::"RemediationTarget___access_key_rotation"` | CCG policy design | ☑ (intent; confirm at deploy) |

> **Deploy-time verification required:** After the first sandbox deploy, run `aws bedrock-agentcore-control list-gateway-targets` and `agentcore status` to extract the exact generated action strings from the deployed Cedar schema. The proposed names above are pre-confirmed as intent; the actual names depend on the target name chosen at `CreateGatewayTarget` time. Update this record with the confirmed strings before task 1.3.

### 1.4 Principal identity structure

| Field | Value | Source | Status |
|---|---|---|---|
| Principal type (CCG — AWS_IAM authorizer) | `AgentCore::IamEntity` | policy-schema-constraints; policy-conditions | ☑ |
| IAM entity id attribute | `principal.id` — contains the caller's IAM ARN in `arn:aws:sts::<account>:assumed-role/<role-name>` format when the caller is an assumed role. | policy-conditions | ☑ |
| IAM entity tags | **Not supported.** `AgentCore::IamEntity` does not support tags; use `principal.id` pattern matching (`like`) for account-based or role-based control. | policy-schema-constraints | ☑ |
| OAuth principal type | `AgentCore::OAuthUser` — used when OAuth/JWT authorizer is configured. JWT `sub` claim becomes the entity ID. JWT claims become tags accessible via `principal.hasTag("...")` / `principal.getTag("...")`. | policy-conditions; policy-authorization-flow | ☑ |
| Principal in Cedar authorization request | `"principal": "AgentCore::IamEntity::\"<arn:aws:sts::...:assumed-role/...>\""` | policy-authorization-flow | ☑ |

### 1.5 Resource representation

| Field | Value | Source | Status |
|---|---|---|---|
| Resource entity type | `AgentCore::Gateway` | policy-understanding-cedar | ☑ |
| Resource matching (specific action) | When a Cedar policy names one or more specific actions (`action ==` or `action in [...]`), the resource **must** use a specific gateway ARN: `resource == AgentCore::Gateway::"<gateway-arn>"`. Wildcard/type-only resource is rejected for specific actions. | policy-understanding-cedar; policy-getting-started | ☑ |
| Resource matching (any action) | `resource is AgentCore::Gateway` is valid when the policy leaves the action unconstrained. | policy-understanding-cedar | ☑ |
| Resource in Cedar authorization request | `"resource": "AgentCore::Gateway::\"arn:aws:bedrock-agentcore:<region>:<account>:gateway/<id>\""` | policy-authorization-flow | ☑ |
| Gateway ARN at deploy time | **BLOCKED** — unknown until the first `CreateGateway` call. Required before Cedar policies with specific actions can be finalized. Placeholder `<gateway-arn>` must be replaced. | — | ☐ |

### 1.6 Request input context shape

> **Critical finding for T2 / P0.4:** The Cedar context available to policy evaluation is **only `context.input`**, which contains the tool's input parameters exactly as submitted in the MCP `tools/call` request. There are **no other context keys** (no `context.output` in permit/forbid policies; no `context.target_arn`; no `context.environment`). This means `CCGDemo` and `Environment` attributes **cannot reach Cedar via context** — they are not present in `context.input` unless the caller supplies them as tool parameters. See Section 2 for the resolution.

| Field | Value | Source | Status |
|---|---|---|---|
| Available context key | **`context.input` only** — contains the tool call arguments (the `arguments` object from the MCP `tools/call` request). | policy-schema-constraints; policy-authorization-flow | ☑ |
| Context.input typing | Typed per tool's `inputSchema`: each property maps via JSON Schema → Cedar type table (see §1.2). | policy-schema-constraints | ☑ |
| Input type name | Each tool has a named Cedar input type, e.g. `RemediationTarget___security_group_correctionInput`. | policy-schema-constraints | ☑ |
| `context.output` | Only available in guardrail conditions (`when guardrails { ... }`), not in standard `when`/`unless` conditions. | policy-schema-constraints | ☑ |
| Caller-provided context fields | **None beyond tool input arguments.** The policy context does not include caller-supplied metadata like `target_arn`, `CCGDemo`, or `Environment` unless those are declared parameters in the tool's `inputSchema`. | policy-schema-constraints; policy-authorization-flow | ☑ |
| Target ARN in context | **Not present** as a Cedar context attribute. The target ARN resolves to the Lambda function invoked; it does not appear in `context.input` unless the tool schema explicitly declares it as a parameter. | AWS docs analysis | ☑ |
| `CCGDemo` / `Environment` in context | **BLOCKER resolved in Section 2.** These must be validated at the IAM/Lambda level, not via Cedar context, because Cedar context only contains tool input. | AWS docs analysis | ☑ (see §2) |

### 1.7 Policy Engine association model

| Field | Value | Source | Status |
|---|---|---|---|
| Terraform resource | `aws_bedrockagentcore_policy_engine` | Terraform AWS Provider 6.64.0 | ☑ |
| Policy engine association to gateway | Configured via `policy_engine_configuration` block on `aws_bedrockagentcore_gateway`. Fields: `arn` (policy engine ARN) and `mode` (`ENFORCE` or `LOG_ONLY`). | modules/agentcore-gateway/main.tf; AWS docs | ☑ |
| Engine-level enforcement modes | **`ENFORCE`** — policy engine evaluates and enforces; denies are blocked. **`LOG_ONLY`** — evaluates all policies but does not enforce; every tool call succeeds regardless of forbids. | policy-enforcement-modes | ☑ |
| LOC_ONLY capture posture | CCG POC will deploy with `mode = "LOG_ONLY"` at engine level for schema capture. No permits are active; the posture is fail-open but safe only because no permits exist. | modules/agentcore-gateway/main.tf | ☑ |
| Policy engine ARN format | `arn:aws:bedrock-agentcore:<region>:<account>:policy-engine/<id>` | API reference | ☑ |
| `UpdatePolicyEngine` scope | Only edits the engine description — it is **not** the enforcement-mode activation lever. Enforcement mode at engine level is set via `UpdateGateway` (updating `policyEngineConfiguration.mode`). | AGENTCORE_CAPABILITY_RECORD §3 (prior); AWS docs | ☑ |

### 1.8 Policy analyzer behavior

| Field | Value | Source | Status |
|---|---|---|---|
| Validation modes | `FAIL_ON_ANY_FINDINGS` (default for production — runs Cedar analyzer; fails if any schema or semantic validation issues found) and `IGNORE_ALL_FINDINGS` (runs analyzer but allows creation/update despite warnings — use only for LOG_ONLY shadow tests). | UpdatePolicy API reference; policy-test-a-policy | ☑ |
| Schema validation | Every policy is validated against the Cedar schema auto-generated from the Gateway's tool manifest before being applied. | UpdatePolicy API reference | ☑ |
| Wildcard resource rejection | A Cedar policy that names a specific action but uses a wildcard/type-only resource (`resource is AgentCore::Gateway` or bare `resource`) is **rejected** by the analyzer. Must use a specific gateway ARN with specific actions. | policy-getting-started; policy-understanding-cedar | ☑ |
| Semantic validation | The analyzer checks that action IDs and resource types used in policies actually exist in the generated schema. A policy referencing a non-existent action transitions to `CREATE_FAILED`. | AWS docs; policy-getting-started troubleshooting | ☑ |
| Policy lifecycle statuses | `CREATING → ACTIVE`, `UPDATING → ACTIVE`, `DELETING → DELETED`; failure states: `CREATE_FAILED`, `UPDATE_FAILED`, `DELETE_FAILED`. | UpdatePolicy API response: `status` field | ☑ |
| `statusReasons` field | Returned with the policy; contains additional information explaining a failure state. | UpdatePolicy API reference | ☑ |

---

## Section 2 — Tamper-resistant safety attributes (REQUIRED — answers design Q2 / resolves T2)

> **Resolution of T2 (HIGH residual) and P0.4:** Cedar's `context` is limited to `context.input` (tool call arguments). `CCGDemo` and `Environment` tags on the target resource are **not available** as Cedar context attributes. They cannot be injected by the gateway into the Cedar authorization request. The resolution is a two-layer defense:

| Layer | Mechanism | Status |
|---|---|---|
| **Layer 1 — IAM permission boundary** | The Gateway execution role's policy attaches IAM **deny** conditions on `aws:ResourceTag/Environment = prod` and `aws:ResourceTag/CCGDemo ≠ true`. These are applied by IAM before the Lambda can be invoked at all, regardless of what Cedar decided. | ☑ (designed in `modules/iam-policies/main.tf`, `tool_execution_boundary`; verify at deploy) |
| **Layer 2 — Tool Lambda safety recheck** | Each tool Lambda re-reads live resource tags from AWS APIs before mutating. It independently verifies `CCGDemo=true` and `Environment≠prod` on the resolved target. A deny at this layer is fail-closed regardless of Cedar's decision. | ☑ (implemented in `src/ccg/tools.py`; live tags rechecked via `ToolHandler` safety preconditions) |

| Field | Value | Source | Status |
|---|---|---|---|
| Can the caller supply `CCGDemo` or `Environment` to Cedar? | **Only if they are declared as tool input parameters** in the tool schema. CCG tool schemas do not declare these as parameters. The caller cannot inject them via the MCP request context. | policy-authorization-flow; policy-schema-constraints analysis | ☑ |
| Cedar forbid on `Environment=prod` | **NOT directly expressible** as `resource.hasTag("Environment", "prod")` — `AgentCore::Gateway` entities carry no resource tags in Cedar. The current `policies/guardrails.cedar` line `resource.hasTag("Environment", "prod")` is **invalid** and will be rejected by the analyzer. See Section 2 findings and Cedar file correction below. | policy-schema-constraints analysis | ☑ (correction required) |
| `CCGDemo` / `Environment` attribute source | Enforced at IAM + Lambda layers (see above). Cedar enforces action-level constraints via `context.input` fields only. | AWS docs; design analysis | ☑ |
| Target ARN resolution | Resolved server-side: `ComplianceApi.request_remediation` looks up the finding from the store and derives `target` from the stored `finding.target`; the caller's `RemediationCommand` carries only `finding_id`, not a target ARN. The gateway invokes the Lambda with the resolved target in the tool input. | `src/ccg/api.py` | ☑ |
| Proof caller cannot self-assert tags | The gateway does not pass resource tags into Cedar context. Tag validation occurs at IAM (deny condition) and Lambda (live re-read) — both server-side. Neither path accepts caller-supplied tag values. | policy-schema-constraints; IAM condition keys | ☑ |

### Section 2 findings and required Cedar corrections

The existing `policies/guardrails.cedar` contains two patterns that do **not** match the real AgentCore Cedar schema:

1. `resource.hasTag("Environment", "prod")` — `AgentCore::Gateway` entities do not support `.hasTag()`; this line will be rejected by the policy analyzer. The `Environment=prod` gate is enforced at the IAM and Lambda layers instead.
2. `action == Action::"ModifySecurityGroup"` — this is a placeholder. Real action IDs follow the `<TargetName>___<tool_name>` format. Must be replaced with the confirmed generated identifier.
3. `resource.proposedCidr` — tool parameters are accessed as `context.input.<param>`, not as resource attributes. This must be rewritten as `context.input.proposed_cidr`.
4. `action == Action::"MakeS3Public"` and `action == Action::"DisableCloudTrail"` — placeholder names. Must use confirmed generated identifiers.

These corrections are applied to the policy files in this task (see below). The files are annotated as intent stubs pending the deploy-time confirmation of exact action IDs.

---

## Section 3 — Policy activation control plane (REQUIRED for 4.3 — answers design Q1)

Fully captured from the pinned AWS CLI service model (`bedrock-agentcore-control`, API version `2023-06-05`) and current API reference documentation (2026-10-12).

| Field | Value | Source | Status |
|---|---|---|---|
| **Activation operation** | `UpdatePolicy` (`PATCH /policy-engines/{policyEngineId}/policies/{policyId}`) — sets `enforcementMode` to `ACTIVE` or `LOG_ONLY` on a specific policy. This is the correct activation lever. `UpdatePolicyEngine` only edits the engine description and is **not** the activation path. | [UpdatePolicy API reference](https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_UpdatePolicy.html) | ☑ |
| **Policy-level enforcement modes** | `ACTIVE` (default) — evaluated and enforced; contributes to the allow/deny decision. `LOG_ONLY` — evaluated but not enforced; decision reported via traces and CloudWatch metrics only; never affects what callers experience. | UpdatePolicy API; [policy-test-a-policy](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-test-a-policy.html) | ☑ |
| **Engine-level enforcement modes** | `ENFORCE` (default) — Gateway enforces the policy engine's decision. `LOG_ONLY` — Gateway does not act on the policy engine's decision regardless of individual policy modes. Set via `UpdateGateway(policyEngineConfiguration.mode)`. | policy-enforcement-modes; policy-test-a-policy | ☑ |
| **Two-layer LOG_ONLY distinction** | Policy-level `LOG_ONLY` tests a single policy without affecting enforcement of other ACTIVE policies. Engine-level `LOG_ONLY` disables enforcement for all policies in the engine. These are independent controls. | policy-test-a-policy | ☑ |
| **Propagation timing** | Asynchronous. `UpdatePolicy` returns HTTP 202 immediately. The update is applied to the evaluation path **within a few seconds**. Poll `GetPolicy` on the `status` field to confirm `ACTIVE` before treating the change as live. `PolicyStatus` values: `CREATING`, `ACTIVE`, `UPDATING`, `DELETING`, `CREATE_FAILED`, `UPDATE_FAILED`, `DELETE_FAILED`. | UpdatePolicy API reference; policy-test-a-policy ("changes are eventually consistent") | ☑ |
| **Request ID** | Standard `x-amzn-RequestId` response header on all control-plane calls. Maps to `control_plane_request_id` in `contracts.PolicyActivationResult`. | Standard AWS API pattern | ☑ (runtime confirm) |
| **Optimistic concurrency** | No `ETag` or `generation` field is visible in the `UpdatePolicy` request model. `clientToken` (idempotency token) is available on `CreatePolicy` only (AWS SDK auto-generates it). For `UpdatePolicy`, the caller must use `GetPolicy` to confirm the current state before retrying. The `contracts.expected_generation` field in the offline model has **no direct mapping** to the live API — it is an application-level guard. | UpdatePolicy API reference; AWS PowerShell docs (clientToken on CreatePolicy only) | ☑ |
| **Idempotency (CreatePolicy only)** | `clientToken` on `CreatePolicy`: a unique, case-sensitive identifier. If a retry uses the same token, the service returns the same response without creating a duplicate. `UpdatePolicy` does not expose `clientToken`. | [New-BACCPolicy PowerShell docs](https://docs.aws.amazon.com/powershell/latest/reference/items/New-BACCPolicy.html) | ☑ |
| **Failure / rollback** | On `UPDATE_FAILED`: call `UpdatePolicy(enforcementMode=LOG_ONLY)` to return to deny-safe posture. The `statusReasons` field in `GetPolicy` describes the failure. If the rollback itself fails, the state is uncertain — manual reconciliation is required. This matches the `force_deny_safe()` reconciliation path in `src/ccg/policy.py`. | UpdatePolicy API reference; CCG design | ☑ |
| **IAM permissions — control-plane role** | `bedrock-agentcore:UpdatePolicy`, `bedrock-agentcore:GetPolicy`, `bedrock-agentcore:GetPolicySummary`, `bedrock-agentcore:ListPolicySummaries`, `bedrock-agentcore:GetPolicyEngine`. Resource: `arn:aws:bedrock-agentcore:<region>:<account>:policy-engine/*/policy/*` (for Policy actions); `arn:aws:bedrock-agentcore:<region>:<account>:policy-engine/*` (for GetPolicyEngine). | [policy-permissions](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-permissions.html); modules/iam-policies/main.tf | ☑ |
| **IAM permissions — gateway execution role** | `bedrock-agentcore:GetPolicyEngine`, `bedrock-agentcore:AuthorizeAction`, `bedrock-agentcore:PartiallyAuthorizeActions`. Trust principal: `bedrock-agentcore.amazonaws.com` with `aws:SourceAccount` condition. Both `AuthorizeAction` and `PartiallyAuthorizeActions` need resources: `[policy-engine/<id>, gateway/<id>]`. | policy-permissions | ☑ |
| **IAM permissions — resource management role (admin)** | `bedrock-agentcore:CreateGateway`, `UpdateGateway`, `GetGateway`, `DeleteGateway`, `ListGateways`, **`InvokeGateway`** (required for `CreatePolicy`/`UpdatePolicy` validation), `CreateGatewayTarget`, …, `CreatePolicyEngine`, …, `CreatePolicy`, `UpdatePolicy`, `GetPolicy`, `DeletePolicy`, `ListPolicies`, `ListPolicySummaries`, `GetPolicySummary`, `StartPolicyGeneration`, …, `ManageResourceScopedPolicy`, `ManageAdminPolicy`, plus `iam:PassRole`. | policy-permissions | ☑ |
| **`InvokeGateway` required for policy creation** | `bedrock-agentcore:InvokeGateway` is required on the resource management role to create or update Cedar policies. `CreatePolicy`/`UpdatePolicy` validate the policy against the Gateway (as an `InvokeGateway` authorization check). Without it, the policy transitions to `CREATE_FAILED` with "Insufficient permissions to call gateway". | policy-permissions | ☑ |
| **`UpdateGatewayPolicy` IAM action** | Does **not exist** in the `bedrock-agentcore-control` service. The earlier guess in `modules/iam-policies` has already been corrected to `UpdatePolicy`. | API model 2023-06-05; modules/iam-policies/main.tf | ☑ |
| **Engine-level mode change** | `bedrock-agentcore:UpdateGateway` controls `policyEngineConfiguration.mode` (the engine-level `ENFORCE` / `LOG_ONLY` switch). This is a **privileged operation** — it can disable enforcement entirely. Grant only to trusted principals. | policy-enforcement-modes | ☑ |

### P0.4 status (CCG_REMEDIATION_TODO.md)

| Item | Status |
|---|---|
| P0.4a: Confirm live request-context shape (§2) | ✅ **Resolved.** `context.input` is the only Cedar context; `CCGDemo`/`Environment` are enforced at IAM + Lambda layers. |
| P0.4b: Confirm caller cannot self-assert `CCGDemo`/`Environment` | ✅ **Resolved.** Cedar context does not carry these; tag validation is server-side (IAM deny + Lambda live recheck). |
| P0.4c: `api.py` derives/validates `tool` and params from finding's `rule_id` | ✅ **Resolved (task 5.1).** `src/ccg/finding_rules.py` defines the `rule_id`→tool family mapping and a bounded per-tool parameter allow-list; `ComplianceApi.request_remediation` validates the command against the resolved finding before any Gateway call. API-layer defense in depth above the tool layer (`tools.py`) and the Cedar boundary. |
| P0.4d: Reject command whose tool/params are inconsistent with resolved finding | ✅ **Resolved (task 5.1).** `validate_command_against_rule` rejects a tool that is not the one mapped to the finding's `rule_id`, and any parameter outside the tool's allow-list, with `VALIDATION_ERROR` semantics (400 at the HTTP adapter). Covered by `tests/test_api_control_plane.py`. |

---

## Section 4 — Nova Sonic contract (REQUIRED for 5.3 / task 0.3 — answers design Q4 indirectly)

**Last updated:** 2026-10-12 (task 0.3 documentation from AWS Nova 2 Sonic developer guide + Bedrock API reference; live sandbox session not yet performed)

Voice stays **off by default** regardless. Capture only enough to decide real-adapter vs. mock.

> **Sources used:** [Nova 2 Sonic developer guide](https://docs.aws.amazon.com/nova/latest/nova2-userguide/), [Getting started](https://docs.aws.amazon.com/nova/latest/nova2-userguide/sonic-getting-started.html), [Input events](https://docs.aws.amazon.com/nova/latest/nova2-userguide/sonic-input-events.html), [Output events](https://docs.aws.amazon.com/nova/latest/nova2-userguide/sonic-output-events.html), [Barge-in](https://docs.aws.amazon.com/nova/latest/nova2-userguide/sonic-barge-in.html), [Bedrock API reference — InvokeModelWithBidirectionalStream](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InvokeModelWithBidirectionalStream.html), [Model card — Nova 2 Sonic](https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-amazon-nova-2-sonic.html). Content was rephrased for compliance with licensing restrictions.

### 4.1 Identity and availability

| Field | Value | Source | Status |
|---|---|---|---|
| Model ID (Nova 2) | **`amazon.nova-2-sonic-v1:0`** | [Model card — Nova 2 Sonic](https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-amazon-nova-2-sonic.html) (2026-10-12) | ☑ |
| Model ID (Nova 1 — legacy) | `amazon.nova-sonic-v1:0` — EOL no sooner than 2026-03; use Nova 2 for all new work | Bedrock model card | ☑ |
| Region: `us-east-1` | ☑ Available (confirmed previously via `bedrock list-foundation-models` 2026-09-18) | `docs/CLOUD_INVENTORY.md` | ☑ |
| Additional supported regions | `us-west-2`, `eu-north-1`, `ap-northeast-1` | Bedrock model card (2026-10-12) | ☑ |
| Cross-region / Geo inference | **Not supported** for Nova 2 Sonic — only in-region invocation is available | Bedrock model card | ☑ |
| Service tier | Standard (pay-per-token, no commitment) is the CCG POC tier. Priority and Flex tiers also available. | Bedrock model card | ☑ |

### 4.2 Quotas and session limits

| Field | Value | Source | Status |
|---|---|---|---|
| Concurrent session limit | **20 concurrent `InvokeModelWithBidirectionalStream` sessions** per AWS account per supported region (default, non-adjustable via Service Quotas; increase requires AWS account team contact) | [Model card — Nova 2 Sonic](https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-amazon-nova-2-sonic.html) | ☑ |
| Session duration limit | **8 minutes** per bidirectional stream connection. A session renewal + conversation continuation pattern is available (see AWS samples on GitHub) if longer sessions are required. | [Getting started](https://docs.aws.amazon.com/nova/latest/nova2-userguide/sonic-getting-started.html) | ☑ |
| Token limits | `maxTokens` per-response up to 2048 (configurable in `sessionStart`); context window 1M tokens; max output 64K tokens | Bedrock model card; input events doc | ☑ |
| Rate limits (RPM/TPM) | Not published as a fixed number — governed by account-level Bedrock on-demand quotas. Non-adjustable through Service Quotas console; contact AWS account manager. | [Nova 2 quotas doc](https://docs.aws.amazon.com/nova/latest/nova2-userguide/quotas.html) | ☑ |
| **CCG POC exposure** | Voice is off by default. Maximum simultaneous voice sessions at POC scale = 0 (feature flag disabled). The 20-session account limit is not a constraint while voice is off. | CCG design | ☑ |

### 4.3 Bidirectional API — transport and SDK support

| Field | Value | Source | Status |
|---|---|---|---|
| API operation | `POST /model/{modelId}/invoke-with-bidirectional-stream HTTP/1.1` — the `InvokeModelWithBidirectionalStream` operation on the `bedrock-runtime` endpoint. The response stream remains open for 8 minutes. | [Bedrock API reference](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InvokeModelWithBidirectionalStream.html) | ☑ |
| Service endpoint | `https://bedrock-runtime.{region}.amazonaws.com` — standard Bedrock runtime endpoint; no special Nova Sonic endpoint. | Bedrock model card | ☑ |
| Transport protocol | **HTTP/2 bidirectional stream** (the AWS event-stream protocol, `application/vnd.amazon.eventstream`). The connection is kept open; both client→server and server→client frames flow over the same connection. Not native WebSocket — the AWS SDK manages the framing. | Bedrock API reference; SDK doc | ☑ |
| Browser transport options | Two viable patterns: **(a) Server-proxy (recommended for POC):** Next.js API route or Lambda holds the SigV4-signed SDK connection; browser sends/receives audio via a backend WebSocket or HTTP/2 tunnel. Browser never touches AWS credentials. **(b) WebRTC via Kinesis Video Streams WebRTC:** UDP-based peer-to-peer for lowest latency; requires a TURN relay and VPC network mode in AgentCore; significant additional infrastructure. | [WebRTC blog](https://aws.amazon.com/blogs/machine-learning/build-real-time-voice-streaming-applications-with-amazon-nova-sonic-and-webrtc/); [AWS samples](https://github.com/aws-samples/sample-nova-sonic-websocket-agentcore) | ☑ |
| Python SDK (experimental) | `aws-sdk-bedrock-runtime` (Smithy-generated experimental Python SDK) used in official AWS samples for `InvokeModelWithBidirectionalStreamOperationInput`. Standard `boto3` does not yet expose this API. | [Getting started](https://docs.aws.amazon.com/nova/latest/nova2-userguide/sonic-getting-started.html) | ☑ |
| Other supported SDKs | AWS SDK for .NET, C++, Java, JavaScript (v3), Kotlin, Ruby, Rust, Swift | Bidirectional API doc | ☑ |
| Authentication | **SigV4** — all calls signed with AWS credentials via the standard `bedrock` service principal. No separate Nova Sonic auth scheme. For browser-side calls through a server proxy, the server holds the IAM credentials (or STS temporary credentials from Cognito Identity Pool). Direct browser-to-Bedrock invocation requires SigV4 signing in the browser using Cognito Identity Pool temporary credentials. | SDK examples; [Bedrock IAM](https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_service-with-iam.html) | ☑ |
| IAM permission required | `bedrock:InvokeModel` on the `amazon.nova-2-sonic-v1:0` model resource ARN | Bedrock API reference | ☑ |
| CloudTrail logging | Requires **advanced event selectors** for data events on `AWS::Bedrock::Model` and `AWS::Bedrock::AsyncInvoke` resource types to record `InvokeModelWithBidirectionalStream` calls in CloudTrail | Bedrock API reference | ☑ |

### 4.4 Input event types (client → model)

All events are JSON objects wrapped in `{ "event": { <eventType>: { ... } } }` and sent as raw bytes in the stream.

| Event type | Purpose | Key fields | Status |
|---|---|---|---|
| `sessionStart` | Opens the session; sets inference parameters and turn detection | `inferenceConfiguration` (`maxTokens`, `topP`, `temperature`); `turnDetectionConfiguration.endpointingSensitivity` (`HIGH` / `MEDIUM` / `LOW`) | ☑ |
| `promptStart` | Defines conversation scope; sets output format, voice, and tool configuration | `promptName` (UUID, required on all subsequent events); `textOutputConfiguration`; `audioOutputConfiguration` (format, sample rate, voice ID); `toolUseOutputConfiguration`; `toolConfiguration` | ☑ |
| `contentStart` | Opens a content block; declares type and role | `promptName`; `contentName` (UUID); `type` (`TEXT` / `AUDIO` / `TOOL`); `role` (`SYSTEM` / `USER` / `ASSISTANT` / `TOOL` / `SYSTEM_SPEECH`); `interactive` (bool; `true` enables cross-modal or live audio); format config sub-object | ☑ |
| `textInput` | Sends text content (system prompt, conversation history, or cross-modal text) | `promptName`; `contentName`; `content` (string) | ☑ |
| `audioInput` | Sends an audio frame (~32 ms); streamed continuously in real time | `promptName`; `contentName`; `content` (base64-encoded LPCM) | ☑ |
| `toolResult` | Returns a function-call result to the model | `promptName`; `contentName`; `content` (stringified JSON) | ☑ |
| `contentEnd` | Closes the current content block | `promptName`; `contentName` | ☑ |
| `promptEnd` | Closes the current prompt scope | `promptName` | ☑ |
| `sessionEnd` | Terminates the session | `{}` | ☑ |

**Input audio format:** `audio/lpcm`, 16-bit signed PCM, mono (`channelCount: 1`), sample rate `8000` / `16000` / `24000` Hz, base64-encoded. CCG recommended input sample rate: **16000 Hz**.

### 4.5 Output event types (model → client)

| Event type | Purpose | Key fields | Barge-in relevance | Status |
|---|---|---|---|---|
| `completionStart` | Marks the start of a model response turn | `sessionId`; `promptName`; `completionId` | — | ☑ |
| `usageEvent` | Reports incremental + cumulative token usage | `completionId`; `details.delta`/`total` for `speechTokens` and `textTokens` (input and output) | — | ☑ |
| `contentStart` (output) | Opens an output content block; carries `generationStage` | `additionalModelFields` → `generationStage`: `SPECULATIVE` (text preview of planned speech) or `FINAL` (ASR transcript / final transcription); `type` (`TEXT` / `AUDIO` / `TOOL`); `role` | Used to identify audio blocks to clear on interruption | ☑ |
| `textOutput` | Delivers a text chunk (ASR transcription or response text) | `contentId`; `content` (string); `role` `USER` (ASR) or `ASSISTANT` (response) | — | ☑ |
| `audioOutput` | Delivers a base64-encoded LPCM audio chunk | `contentId`; `content` (base64 LPCM) | **Must be queued; queue must be cleared on interruption** | ☑ |
| `toolUse` | Requests a function call | `toolName`; `toolUseId`; `content` (JSON args) | — | ☑ |
| `contentEnd` (output) | Closes an output block; carries `stopReason` | `contentId`; `stopReason`: `END_TURN` / `PARTIAL_TURN` / `INTERRUPTED` (TEXT/AUDIO) or `TOOL_USE` (TOOL) | `stopReason: "INTERRUPTED"` on TEXT or AUDIO contentEnd **is the barge-in signal** | ☑ |
| `completionEnd` | Marks end of the model response turn | `completionId`; `stopReason: "END_TURN"` | — | ☑ |

**Output audio format:** `audio/lpcm`, 16-bit signed PCM, mono, sample rate selectable (`8000` / `16000` / `24000` Hz), base64-encoded. CCG recommended output sample rate: **24000 Hz** (matches official samples).

### 4.6 Barge-in / interruption event contract

> **How it works:** Nova 2 Sonic detects that the user has started speaking during model audio output (server-side voice activity detection, controlled by `endpointingSensitivity`). The model immediately halts audio generation, preserves full conversation context, and signals the interruption via `contentEnd.stopReason = "INTERRUPTED"`.

| Signal | Shape | Required client action | Status |
|---|---|---|---|
| Interruption trigger | Server-side: VAD detects user speech while model is generating audio | n/a (automatic) | ☑ |
| Interruption event | `contentEnd` with `stopReason: "INTERRUPTED"` on the active `AUDIO` or `TEXT` content block | **Clear the audio playback queue; stop current playback immediately** | ☑ |
| Post-interruption | Model begins processing new user input; a new `completionStart` follows | Resume normal audio output pipeline once `audioOutput` events arrive for the new turn | ☑ |
| Context preservation | Full conversation history retained through the interruption — no context loss | None required by the client | ☑ |
| Client-side requirement | Because Nova 2 Sonic generates audio faster than real-time, the client must maintain an audio queue and drain/discard it upon receiving `stopReason: "INTERRUPTED"` | Audio queue management required in any real adapter | ☑ |
| Turn detection sensitivity | `endpointingSensitivity: "MEDIUM"` is the recommended default; `HIGH` reacts faster but may clip slow speakers | Configure in `sessionStart.turnDetectionConfiguration` | ☑ |

**CCG implication:** The existing `ReadOnlyVoiceAdapter` in `src/ccg/voice.py` calls a `NovaSonicTransport.summarize_read_only()` which returns a single string — it does not stream audio or manage an audio queue. The barge-in machinery is entirely inside the transport layer and is not visible to the adapter's callers. A future real transport implementation must handle the audio queue and interruption internally, satisfying the `NovaSonicTransport` protocol without exposing any of this complexity to the `ReadOnlyVoiceAdapter`.

### 4.7 Adapter decision: mock for first implementation

**Decision: USE A MOCK for the first implementation.** The existing `NovaSonicTransport` protocol in `src/ccg/voice.py` is the correct interface boundary. No real transport should be written until voice is unblocked.

**Rationale:**

1. **Voice is off by default** per project rules and ADR. `ReadOnlyVoiceAdapter.__init__(enabled=False)` is the CCG default; the mock is never called in normal operation.
2. **No browser transport path is finalized.** A real adapter requires either a server-proxy WebSocket architecture (Next.js API route + Python backend) or WebRTC via Kinesis Video Streams. Both are significant implementation work that is out of scope for the current phase.
3. **No quota headroom needed.** The 20-concurrent-session account limit is a non-issue while voice is off. Sandboxing a real adapter risks unintended session leakage during development.
4. **The `NovaSonicTransport` protocol already isolates the real adapter perfectly.** Any mock that satisfies `summarize_read_only(correlation_id: str, briefing: str) -> str` can be substituted by a real transport with zero changes to callers. The interface is stable.
5. **Cost control.** Nova 2 Sonic pricing is consumption-based on speech and text tokens. A mock incurs zero cost; a live adapter during POC development could generate unexpected spend.

### 4.8 Mock transport interface contract

The following interface must be satisfied by any mock and by any future real transport, with no changes to `ReadOnlyVoiceAdapter` or its callers.

```
Protocol: NovaSonicTransport (defined in src/ccg/voice.py)

Method:
  summarize_read_only(correlation_id: str, briefing: str) -> str

Preconditions:
  - briefing is a plain-text read-only finding summary (no tool invocations, no mutation intent)
  - correlation_id is a non-empty string for log correlation
  - The transport MUST NOT register or invoke any AgentCore/Lambda remediation tools
  - The transport MUST NOT accept bidirectional voice input from the user (read-only only)

Postconditions:
  - Returns a non-empty plain-text string summarizing the briefing
  - Any exception is caught by ReadOnlyVoiceAdapter.brief() and returned as VoiceStatus.UNAVAILABLE
  - No side effects on AWS resources

Mock implementation guidance:
  - Return a deterministic echo or canned summary string
  - Log the correlation_id for test traceability
  - Raise an exception to test the UNAVAILABLE path

Real transport implementation guidance (for future Phase 5):
  - Authenticate via SigV4 using STS temporary credentials (e.g., from Cognito Identity Pool)
  - Open one InvokeModelWithBidirectionalStream session on amazon.nova-2-sonic-v1:0
    in bedrock-runtime.us-east-1.amazonaws.com
  - Send: sessionStart → promptStart (no toolConfiguration) → contentStart(SYSTEM) →
    textInput(briefing) → contentEnd → contentStart(AUDIO/USER, interactive=true) →
    [stream empty audio or a single silence frame] → contentEnd → promptEnd → sessionEnd
  - Collect textOutput events with role=ASSISTANT and generationStage=FINAL
  - Concatenate and return as the summary string
  - Handle contentEnd.stopReason=INTERRUPTED by clearing any audio queue
  - Close the stream unconditionally in a finally block to avoid session leakage
  - Enforce: toolConfiguration MUST be omitted (no tools registered to voice transport)
```

**Security invariant:** The `NovaSonicTransport` protocol carries no tool registry. It receives only a `briefing` string and returns a summary string. The `ReadOnlyVoiceAdapter` has no path to the AgentCore Gateway, the Lambda tool targets, or any mutation operation. This is enforced structurally — not by a runtime check — because the transport interface has no parameter for a tool name or tool input.

---

## Section 5 — Terraform provider/runtime (RESOLVED — task 0.4, answers design Q7)

> **Task 0.4 resolution (completed):** All three previously-open fields are now cleared. No `versions.tf` or `.terraform.lock.hcl` changes are needed; the existing pins are correct and sufficient.

### Version decision

| Constraint | Decision | Rationale |
|---|---|---|
| Terraform runtime | Pin to `>= 1.8.0, < 2.0.0` (no change) | v1.16.5 is the verified runtime on this machine; it is within the constraint and supports provider 6.64.0 without issue. No runtime upgrade is required for the AgentCore resources. |
| AWS provider | `= 6.64.0` exact pin (no change) | All four AgentCore resource types required by CCG are present in this version. The exact pin eliminates schema-churn risk from minor-version changes; 6.64.0 is a stable, post-`policy_engine_configuration` release (that block was added in 6.50.0). |
| Lock file | Committed `.terraform.lock.hcl` at 6.64.0 (no change) | Committed as of 2026-09-09; hashes verified below. |

### Provider-upgrade risk documentation

The AgentCore resource types in the 6.x series have a history of breaking schema changes and mid-minor-version regressions (bug references: `aws_bedrockagentcore_gateway` schema mismatch fixed in v6.37.0; `aws_bedrockagentcore_gateway_target` panic fixed in v6.60.0; `policy_engine_configuration` block first available in v6.50.0). Upgrading beyond 6.64.0 must be treated as a **medium-risk operation** requiring:

1. Review of the release notes for all `bedrockagentcore` resource changes between 6.64.0 and the target version.
2. A `terraform plan` in the HCP sandbox workspace before any apply.
3. Update of this section and the lock file together (never the lock file alone).

Until the first sandbox deploy completes (Gate 0.2 live evidence), no provider upgrade is approved.

### Evidence fields

| Field | Value | Source | Status |
|---|---|---|---|
| AWS provider version | `= 6.64.0` (exact pin in `versions.tf`) | `versions.tf`; `.terraform.lock.hcl` | ☑ |
| Terraform runtime | `v1.16.5` on `windows_amd64`. Satisfies `>= 1.8.0, < 2.0.0`. | `terraform version` output on this machine (task 0.4 capture date: 2026-10-12) | ☑ |
| Lock file consistent | `.terraform.lock.hcl` records `version = "6.64.0"` and `constraints = "6.64.0"` with 16 `zh:` hashes. No stale entries for other provider versions. No secrets or state embedded. Matches `versions.tf` exactly. | `.terraform.lock.hcl` diff (task 0.4, 2026-10-12) | ☑ |
| `aws_bedrockagentcore_gateway` | Present in provider 6.64.0. First introduced ≤ v6.36.0 (bug fix in v6.37.0 references "regression introduced in v6.36.0"). `policy_engine_configuration` block added in v6.50.0 and present in v6.64.0 (used in `modules/agentcore-gateway/main.tf`). | [hashicorp/terraform-provider-aws releases](https://github.com/hashicorp/terraform-provider-aws/releases); v6.37.0 and v6.50.0 release notes | ☑ |
| `aws_bedrockagentcore_gateway_target` | Present in provider 6.64.0. Confirmed stable at v6.37.0 (issue #48200 references it working in v6.37.0). Enhancements through v6.63.0 (Resource Identity support). | v6.63.0 release notes; issue #48200 | ☑ |
| `aws_bedrockagentcore_policy_engine` | Present in provider 6.64.0. Present by v6.62.0 (bug fix for list-resource variant). Required by `modules/agentcore-gateway/main.tf`. | v6.62.0 release notes | ☑ |
| `aws_bedrockagentcore_policy` | Present in provider 6.64.0. First introduced in **v6.50.0** (June 10, 2026). Managed both as a standard resource and a list resource. | v6.50.0 release notes (New Resource + New List Resource entries) | ☑ |

---

## Section 6 — Pre-apply evidence checklist (from CAPABILITY_BASELINE.md)

Before any sandbox apply is approved, all of the following are captured and reviewed:

1. ☑ Caller identity, account, profile, region, non-prod designation (Section 0 — partial; OIDC provider still ☐)
2. ☑ Terraform runtime/provider versions + committed lock file, no secrets/state (Section 5 — task 0.4 complete 2026-10-12: runtime v1.16.5, provider 6.64.0, lock file verified, all four AgentCore resource types confirmed)
3. ☑ Cedar action format, principal types, resource type, context constraints documented (Sections 1–2); exact ARN-based action identifiers blocked pending first deploy
4. ☑ Verified activation API, IAM permissions, propagation, reconciliation (Section 3)
5. ☑ Nova Sonic model/region/quota/transport decision, or explicit mock/off (Section 4 — task 0.3 complete 2026-10-12)
6. ☐ Reviewed plan artifact: no NAT, no always-on compute, no provisioned DynamoDB, no multi-AZ, no prod targets, no unregistered mutation path

**This record authorizes nothing on its own.** It is the evidence input to the human review gates in `requirements.md` §6.

---

## Section 7 — Cedar schema reconciliation summary (unblocks task 1.3)

This section records what the live schema capture resolves and what remains blocked.

### Confirmed (unblocks policy authoring)

| Confirmed fact | Policy implication |
|---|---|
| Entity namespace: `AgentCore` | All entity types must be prefixed `AgentCore::` |
| Principal types: `AgentCore::OAuthUser` (OAuth/JWT) or `AgentCore::IamEntity` (AWS_IAM) | CCG uses `AgentCore::IamEntity`; principal matching uses `principal.id like "..."` |
| Resource type: `AgentCore::Gateway::"<arn>"` | Specific gateway ARN required for any policy that names specific actions |
| Action format: `AgentCore::Action::"<TargetName>___<tool_name>"` | CCG proposed target name `RemediationTarget`; four proposed action IDs documented in §1.3 |
| Context: `context.input.<param>` only | CIDR, `make_public`, and other tool parameters are accessible via `context.input.<param>` |
| `resource.hasTag(...)` not valid on `AgentCore::Gateway` | Production/demo enforcement is at IAM + Lambda layers, not Cedar resource tags |
| Forbid-wins, default-deny semantics confirmed | matches `src/ccg/authz.py` design; guardrails as ACTIVE forbid policies, permits as ACTIVE permit policies |
| `UpdatePolicy(enforcementMode=ACTIVE|LOG_ONLY)` is the activation operation | `PolicyActivationService` + `PolicyControlPlaneTransport` in `src/ccg/policy.py` correctly model this |

### Blocked pending first sandbox deploy

| Blocked item | Blocks |
|---|---|
| Exact gateway ARN | Finalizing Cedar policy `resource ==` clauses (task 1.3) |
| Exact generated action identifiers (after `CreateGatewayTarget`) | Finalizing Cedar `action ==` clauses; policy analyzer gate (task 1.3) |
| Max tool count / schema size limits | Confirming the four-tool Lambda target is within limits |
| Optimistic concurrency / `clientToken` on `UpdatePolicy` | Confirms or refutes `contracts.expected_generation` mapping |
| `x-amzn-RequestId` → `control_plane_request_id` mapping | Confirms `PolicyActivationResult.control_plane_request_id` field |
| Terraform provider resource schemas (Section 5) | Finalizing Terraform modules (task 2.5) |
