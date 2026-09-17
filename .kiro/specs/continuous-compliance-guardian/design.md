# Continuous Compliance Guardian — Infrastructure Design

**Status:** Design proposal for review; no implementation is included in this document.

**Date:** 2026-09-14

**Design objective:** Build the smallest event-driven AWS sandbox topology that demonstrates discovery, external Cedar authorization, safe remediation, auditability, and an optional read-only voice briefing while preserving a monthly POC budget below $150.

## 1. Design principles

- **Cedar first:** A mutation is authorized only by the AgentCore Gateway Policy Engine. Application code can validate and reject, but cannot grant authorization.
- **Forbid wins:** Always-on forbids remain effective even when a permit is active. No matching permit is deny.
- **Sandbox only:** Every mutation requires `CCGDemo=true`; every `Environment=prod` target is denied.
- **Separate read and write trust:** Discovery, console reads, policy administration, Gateway, and each tool target use separate IAM roles and contracts.
- **Event-driven and reversible:** Prefer schedules, Lambda, DynamoDB on-demand, S3 lifecycle, and short-lived sessions. Keep applies manual and cleanup documented.
- **Evidence by default:** Every meaningful event has a correlation ID, structured JSON record, and an auditable outcome.
- **Capability honesty:** AgentCore-generated schemas, SDK operations, model IDs, quotas, and region support are verified before code or Terraform is emitted.

## 2. Proposed topology

```text
                         +------------------------------+
                         | Cognito POC user pool        |
                         +---------------+--------------+
                                         |
                                  authenticated admin
                                         |
+------------------+          +----------v-----------+          +-------------------+
| Next.js App      | HTTPS    | API Gateway + Lambda |          | Nova Sonic adapter|
| Router console   +----------> read/control plane   |<---------+ read-only voice  |
| static/serverless|          +----+-------------+---+          | off by default    |
+------------------+               |             |
                                   |             +-----------------------------+
                                   |                                           |
                         findings/policy status                    audited policy activation
                                   |                                           |
                   +---------------v---------------+                 +---------v----------+
                   | DynamoDB current findings     |                 | AgentCore control  |
                   | S3 private audit JSON         |                 | plane adapter      |
                   | CloudWatch structured logs    |                 +---------+----------+
                   +-------------------------------+                           |
                                                                               |
EventBridge schedule --> Discovery Lambda (Python 3.14, read-only)             |
       |                       |                                                |
       |                       +--> Config / Security Hub / CloudTrail          |
       |                       +--> normalize + deduplicate                      |
       |                                                                      policy state
       |                                                                         |
       |                  Remediation request                                    |
       +--------------------------------------------------------------------------v
                              AgentCore Gateway (MCP)
                              Policy Engine / Cedar
                              LOG_ONLY for inactive permits; ENFORCE boundary
                                         |
                       +-----------------+------------------+
                       | registered Lambda MCP targets    |
                       | SG | S3 encryption | tags | keys  |
                       +-----------------+------------------+
                                         |
                              eligible CCGDemo sandbox only
```

The diagram is logical. The exact AgentCore runtime/client placement, console hosting mode, and Nova Sonic browser transport are implementation gates, not assumed resources.

## 3. Component responsibilities and boundaries

### 3.1 Discovery path

- EventBridge invokes a Python 3.14 discovery Lambda at a configurable schedule, defaulting to 15 minutes.
- The discovery role can read only the approved AWS Config, Security Hub, and CloudTrail APIs plus write the finding/audit destinations. It cannot assume the remediation role, call Gateway mutation tools, change resource tags, or alter policy state.
- Source adapters normalize findings into a stable contract. A deterministic identity is derived from rule ID plus target identity and relevant scope. Source errors remain visible as partial-run evidence.
- DynamoDB stores current finding state and operational idempotency metadata. S3 stores append-only-shaped JSON audit records with private access, encryption, lifecycle expiration at 30 days, and no credentials or secrets.
- Discovery does not mark a finding compliant solely because a remediation call returned success; a later read confirms the desired state.

### 3.2 Gateway and Cedar boundary

- AgentCore Gateway is the only mutation ingress. It is configured for MCP and exposes four explicit Lambda-backed targets after the target schema has been captured.
- The Gateway is configured with a Policy Engine. The policy engine is the external decision boundary and receives the authenticated principal, exact generated action identifier, Gateway resource, and validated input context needed to make the sandbox decision.
- Always-on forbids cover production targets, unapproved/global-open ingress, public S3 changes, and CloudTrail disablement. Their exact Cedar expressions and entity references must be adapted to the deployed AgentCore schema; the current files are policy intent, not a deployable schema contract.
- Permit policies are split by registered tool/action rather than using the current broad wildcard permit. Each permit requires the sandbox tag and excludes production. No permit is considered active until its effective enforcement mode is confirmed by the AgentCore control plane.
- The default state is fail-closed: forbids are active, the permit set is inactive or log-only, and the Gateway enforces deny for calls with no active permit.
- The activation flow is a control-plane operation, not a UI boolean: authenticate the admin, check version and optimistic concurrency, write an activation-intent audit record, call the supported AgentCore policy update operation, write the result, and expose the server-confirmed effective state. Any timeout or ambiguous result leaves mutation authorization denied until reconciled.
- A Gateway decision record includes request ID, actor/principal, exact action, target, decision, matched/determining policy IDs, effective policy version, correlation ID, timestamp, and validation/error details.

### 3.3 Remediation targets

Each tool target is a small Lambda with an explicit input/output schema and a separate least-privilege execution role. The target rechecks safety preconditions but cannot override a Gateway denial.

| Tool | Allowed operation | Safety and idempotency contract |
|---|---|---|
| Security-group correction | Correct one approved sandbox ingress rule to the declared compliant value. | Reject unsupported CIDR/protocol/port changes; never create global IPv4/IPv6 ingress; compliant state is a no-op. |
| S3 encryption enablement | Enable the approved encryption configuration on one eligible sandbox bucket. | Never make a bucket public; reject prod/unowned bucket; already encrypted is a no-op. |
| Compliant tagging | Add/correct approved compliance tags on an eligible target. | Preserve `CCGDemo=true`; never write `Environment=prod`; stable desired state is a no-op. |
| Access-key rotation workflow | Rotate a specifically approved sandbox identity/key under a controlled sequence. | Replacement must validate before old key disablement; secret material never returns to logs, responses, or state; uncertain result pauses for reconciliation. |

The target contract includes an idempotency key, expected finding version, target ARN, requested change, actor, and correlation ID. A target never accepts an arbitrary AWS API operation or resource ARN outside its allowlisted type and scope.

### 3.4 Console and control plane

- Cognito authenticates the POC admin. API Gateway and Lambda provide read-only findings/policy views and administrative activation/deactivation requests.
- The console renders effective server state, decision evidence, and proposed actions. It may send a request, but it cannot decide that a request is authorized.
- A static-exportable Next.js App Router deployment is preferred to avoid always-on compute; if App Router requirements require server execution, the hosting alternative must be approved against the cost constraint before implementation.
- The control plane may read current findings and policy metadata. Only the narrowly authorized admin operation can request policy activation. It cannot invoke a tool target directly.
- Cognito/API authorization and Cedar/Gateway authorization are separate: Cognito authenticates the operator; Cedar authorizes the mutation at the tool boundary.

### 3.5 Nova Sonic adapter

- Nova Sonic is an optional adapter behind a typed interface. It is disabled by default and requires explicit feature enablement plus microphone consent.
- The adapter provides read-only finding summaries and policy status. It does not expose any remediation tool schema and cannot call the Gateway mutation surface.
- Browser audio capture and streaming use the transport selected after live model/region/API validation. Session correlation IDs are attached to logs; raw audio is not retained by default.
- Interruption sends the adapter’s supported stop/supersede behavior and stops playback. If the API, model, region, quota, or browser path is unavailable, the adapter returns a safe unavailable result and the console remains functional.

## 4. Data and evidence model

The following are logical contracts, not implementation schemas.

### 4.1 Normalized finding

Required fields: `finding_id`, `rule_id`, `source`, `source_event_id`, `target_arn`, `target_type`, `target_tags`, `severity`, `title`, `description`, `evidence_refs`, `status`, `first_seen_at`, `last_seen_at`, `accepted_risk`, `correlation_id`, and `schema_version`.

Allowed status transitions are explicit and monotonic enough for replay safety: `OPEN`, `REMEDIATION_REQUESTED`, `REMEDIATION_SUCCEEDED`, `REMEDIATION_NOOP`, `REMEDIATION_FAILED`, `RESOLVED`, and `ACCEPTED_RISK`. Only a confirming discovery read may transition a finding to `RESOLVED`.

### 4.2 Decision evidence

Required fields: `decision_id`, `request_id`, `correlation_id`, `actor`, `principal_attributes`, `gateway_id`, `action_id`, `target`, `decision`, `determining_policy_ids`, `policy_set_version`, `enforcement_mode`, `validation_errors`, `created_at`, and `schema_version`.

### 4.3 Audit event

Required fields: `event_id`, `event_type`, `actor`, `component`, `request_id`, `correlation_id`, `target`, `outcome`, `policy_set_version`, `timestamp`, a redacted `details` object, and `schema_version`. Audit events are written privately and are never used as an authorization input.

### 4.4 Policy activation record

Required fields: `activation_id`, `requested_version`, `previous_version`, `requested_mode`, `actor`, `reason`, `expected_version`, `intent_recorded_at`, `control_plane_request_id`, `result`, `effective_version`, `effective_mode`, `completed_at`, and `correlation_id`. A failed or uncertain operation records a deny-safe state.

## 5. Terraform composition

The implementation should move from the current single-file scaffold to:

```text
environments/
  poc/
    main.tf
    variables.tf
    outputs.tf
    backend.tf
modules/
  audit-storage/
  findings-store/
  observability/
  identity/
  discovery/
  gateway-policy/
  remediation-tools/
  console-api/
  voice-adapter/
```

The exact module split can be reduced if a smaller composition is demonstrably clearer. The environment root owns composition and POC variables; modules own one bounded concern. No application implementation is authorized by this design alone.

Planned managed resources include only the required event-driven/serverless pieces: IAM roles and policies, EventBridge schedule, discovery Lambda, AgentCore Gateway/targets/policy engine/policies, remediation Lambdas, API Gateway/Lambda, Cognito POC user pool, on-demand DynamoDB, private encrypted S3, CloudWatch logs/metrics/alarms, and the selected console hosting resources. Avoid NAT Gateway, EC2/ECS service, provisioned DynamoDB, and multi-AZ topology.

### 5.1 Provider and runtime baseline

- Existing Terraform floor is `>= 1.8.0, < 2.0.0`; retain only if every selected resource schema and test path validates against it.
- Terraform MCP returned AWS provider `6.64.0`, while the repository currently constrains `~> 5.0`. The first implementation must handle this as a reviewed provider upgrade, pin the chosen version, and commit the lock file.
- Terraform Cloud remains the sole state backend. No local state, credentials, or secret values enter Git or CI artifacts.
- The implementation must use a reviewed plan artifact and manual apply. Destructive cleanup requires a destroy plan, explicit scope review, and confirmation.
- Default tags include the POC safety identity and environment. The design must ensure tag defaults cannot accidentally imply production eligibility.

### 5.2 Storage and retention controls

- S3 audit storage is private, encrypted, blocked from public access, scoped by bucket policy, and expires records after 30 days. Versioning/object-lock semantics require a separate cost and service-availability decision; “immutable-shaped” records must not be represented as a guarantee of WORM compliance without validation.
- DynamoDB uses on-demand billing and a stable partition key for current findings. Secondary indexes and TTL are added only when justified by read paths and retention behavior.
- CloudWatch logs retain seven days. Structured logs avoid secrets and include correlation/request IDs. Alarms cover source failure, policy activation failure, denied-call spikes, tool errors, and budget/resource anomalies.

## 6. Security model

- Discovery role: read-only source APIs plus narrowly scoped writes to evidence stores.
- Control-plane role: authenticated admin read access and narrowly scoped AgentCore policy activation operations; no remediation AWS permissions.
- Gateway role: only permissions needed to invoke the registered tool targets and operate the Gateway.
- Tool roles: one role per tool or bounded tool group, scoped to sandbox resources and required APIs; no wildcard administrative policy.
- Console hosting/API roles: no direct audited-resource mutation permissions.
- Audit readers: separate read-only role; audit records are not trusted as policy inputs.
- Network design avoids a VPC/NAT dependency for the POC unless a validated service requirement forces one; such a change requires cost and blast-radius review.

The Cedar schema must model the actual AgentCore request shape. The current policies’ `resource.hasTag(...)` expressions cannot be assumed to apply unchanged because AgentCore examples use Gateway resources plus principal tags and input context. The final schema must represent target identity and safety tags in a validated, tamper-resistant request context or entity relationship and must ensure the caller cannot self-assert those attributes.

## 7. Failure and rollback behavior

- Unknown policy activation status: deny mutations, reconcile from the control plane, and surface the incident.
- Policy schema/analyzer failure: keep the affected policy inactive and fail the deployment/activation validation.
- Gateway unavailable: no direct fallback; mutation request fails closed.
- Tool timeout/uncertain AWS result: record uncertainty, do not claim resolution, and require discovery reconciliation.
- DynamoDB/S3 audit write failure: do not silently discard decision evidence; define the Gateway/tool behavior so a mutation cannot proceed without the required decision/audit path.
- Terraform drift: plan and review; never repair production or out-of-scope resources from the POC workspace.
- Cleanup: remove seed resources first, disable active permits, verify no pending tool operation, then destroy POC infrastructure using a reviewed destroy plan. Preserve only the explicitly required evidence window.

## 8. Observability and CI design

The existing seven-day CloudWatch log baseline is retained. Each component emits JSON events with event type, component, actor, target class, correlation ID, request ID, outcome, latency, and redaction status. Metrics include discovery runs/success/partial/failure, finding counts by severity/status, Gateway allow/deny, policy activation success/failure, tool no-op/success/failure, voice sessions/errors, and cleanup results.

CI remains validation-only: Terraform format/validate/tflint, provider lock/schema checks, Python Ruff/pytest, TypeScript ESLint/typecheck, Cedar validation/analyzer checks against the captured schema, and secret scanning. The pipeline must not apply Terraform or invoke real remediation by default. Integration tests use doubles or explicitly tagged sandbox runs with teardown.

## 9. Capability decision log

1. **Use AgentCore Policy Engine rather than introducing Verified Permissions for the Gateway decision.** Terraform supports both, but the requirement is an AgentCore Gateway boundary and AgentCore’s native policy engine owns the Gateway tool schema. Verified Permissions remains a possible separate application authorization service only if a later requirement needs it; adding it now would create a second policy boundary.
2. **Use Lambda-backed Gateway targets for the four POC tools.** This matches the documented target capability and serverless cost constraint. OpenAPI/Smithy/MCP-server targets are not needed for the first implementation.
3. **Use Lambda for scheduled discovery unless an AgentCore Runtime requirement is proven.** The handoff requires a Python 3.14 Strands-compatible agent, not an always-on runtime. AgentCore Runtime is a validated provider resource but is not required by the discovery flow and would add an integration gate.
4. **Keep Nova Sonic optional and read-only.** The streaming and interruption capabilities are validated, but browser transport, model/region, quotas, and tool exposure remain unverified.
5. **Treat AWS provider 6.64.0 as the initial design baseline, not an automatic upgrade.** The repository’s current provider constraint must be changed only through a reviewed compatibility/lock-file task.

## 10. Design review questions

- Does the selected AgentCore API expose a safe, auditable per-policy activation/update flow with the required optimistic concurrency semantics?
- How will target ARN and `CCGDemo`/`Environment` attributes reach Cedar without being supplied solely by the untrusted caller?
- Which AgentCore Gateway principal/action/resource schema is generated for the four Lambda targets in the selected region?
- Can the chosen console hosting mode satisfy Next.js App Router requirements without always-on compute or exceeding the budget?
- Are the four remediation scopes sufficiently narrow for a one-account sandbox demo, especially access-key rotation?
- What exact S3 immutability guarantee is required beyond private encrypted storage and lifecycle expiry?
- Which provider/runtime versions will CI pin, and can the current Terraform 1.8 floor support the selected AgentCore resource schemas?

Approval of this design authorizes planning only. It does not authorize code, Terraform, policy, IAM, seed, or live AWS changes.
