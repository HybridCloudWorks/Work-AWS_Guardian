# Continuous Compliance Guardian — EARS Requirements

**Status:** Draft for human review; implementation is intentionally blocked until this document and `design.md` are approved.

**Date:** 2026-09-14

**Intent:** Define a cost-bounded AWS sandbox proof of concept that detects Security-pillar drift, presents explainable findings, and proves that every mutation is authorized at an external Amazon Bedrock AgentCore Gateway policy boundary using Cedar.

## 1. Scope and success criteria

The POC shall detect a small, representative set of AWS Well-Architected Security-pillar findings in one dedicated sandbox account and region. It shall normalize and retain finding evidence, expose findings through an authenticated Next.js admin console, and offer four narrowly registered, idempotent remediation tools:

1. restricted security-group correction;
2. S3 encryption enablement;
3. compliant resource tagging; and
4. a sandbox-safe access-key rotation workflow.

The demo is successful only when it can show all of the following in one traceable flow: a finding is discovered; a mutation is denied while the permit set is inactive; an authorized admin activates a versioned permit set through an audited control-plane operation; the same request is allowed for an eligible sandbox resource; one remediation makes a safe change or no-op; the subsequent discovery reflects the result; and the decision/audit evidence is visible.

### 1.1 In scope

- Python 3.14 discovery and remediation services with typed contracts and test doubles.
- EventBridge scheduling, configurable with a 15-minute POC default.
- Read-only discovery from AWS Config, Security Hub, and CloudTrail.
- AgentCore Gateway with MCP tools backed by Lambda targets, subject to live schema validation.
- AgentCore Policy Engine and Cedar policy evaluation at the Gateway boundary.
- Cognito-backed POC authentication, API Gateway/Lambda control plane, and a Next.js App Router console.
- On-demand DynamoDB current finding state and private S3 JSON audit records with 30-day expiration.
- CloudWatch structured logs with seven-day retention and minimum operational metrics.
- Optional, feature-flagged, read-only Nova Sonic voice briefing.
- Terraform Cloud remote state and modular Terraform in an `environments/poc` layout.
- Unit, contract, policy, integration, idempotency, audit, and cleanup tests.

### 1.2 Out of scope for this POC

- Production deployment, production accounts, or resources tagged `Environment=prod`.
- Cross-account discovery, IAM Identity Center/SSO, all six Well-Architected pillars, WAF, Shield, enterprise retention/resilience, and high-impact human approval workflows.
- NAT Gateway, EC2/ECS always-on services, provisioned DynamoDB, or multi-AZ POC topology.
- Unbounded agent autonomy, unregistered tools, direct AWS mutations from the UI or agent, and policy decisions made by prompts, memory, UI state, or application booleans.
- Voice-initiated mutations, general-purpose voice assistant behavior, or storing raw microphone audio by default.

## 2. Actors and trust boundaries

| Actor/component | Trust boundary and responsibility |
|---|---|
| POC admin | Authenticated human who views findings and requests/activates operations; never directly authorizes a mutation from UI state. |
| Discovery agent | Read-only collector and normalizer; cannot write audited AWS resources or call remediation tools. |
| Remediation agent | Proposes and invokes only registered Gateway tools; has no direct mutation path around the Gateway. |
| API/control plane | Authenticates requests, validates contracts, records correlation data, and requests policy activation; it cannot replace Cedar decisions. |
| AgentCore Gateway | Mandatory mutation boundary; exposes MCP tools, evaluates the AgentCore Cedar Policy Engine, and blocks denied calls before the target. |
| Cedar policy engine | Deterministic authorization decision point. Forbids override permits and no match denies. |
| Lambda tool targets | Execute only validated, idempotent operations after a Gateway allow; enforce safe preconditions again before changing AWS. |
| AWS evidence services | Config, Security Hub, CloudTrail, DynamoDB, S3, and CloudWatch; accessed under separate least-privilege roles. |
| Nova Sonic adapter | Optional read-only voice interface; may request finding summaries only and cannot invoke mutation tools. |

## 3. Capability baseline and explicit implementation gates

The following facts were validated against AWS documentation and the Terraform Registry on 2026-09-14. They are design inputs, not permission to implement yet.

| Area | Validated capability | Requirement/design consequence | Gate before implementation |
|---|---|---|---|
| AgentCore Gateway | Gateway supports MCP and documented Lambda, OpenAPI, Smithy, and MCP-server target types. | The four tools may be exposed as narrowly defined Lambda-backed MCP targets. | Confirm the selected target type, Lambda tool schema, caller identity, region, and generated action identifiers in the target account. |
| AgentCore Policy/Cedar | AgentCore Policy uses Cedar `permit`/`forbid`; no matching permit is default deny; a matching forbid overrides permits. Conditions can use principal tags and tool input context. | All mutation requests must traverse the Gateway Policy Engine in enforce mode. The committed Cedar files are intent sources until their schema is adapted to the generated AgentCore schema. | Retrieve the deployed Gateway schema and validate entity types, action IDs, context attributes, tag representation, and policy analyzer findings. |
| Policy activation | AgentCore control-plane documentation exposes policy enforcement modes including `LOG_ONLY` and active/enforced behavior, and an update operation accepts an enforcement-mode change. | Keep forbids active; keep the versioned permit set inactive/log-only until an audited admin operation activates it. | Verify the supported SDK/CLI operation, IAM permissions, propagation behavior, concurrency controls, and rollback semantics. Never substitute a local flag. |
| Nova Sonic | Nova Sonic supports bidirectional event streaming, speech/text/audio responses, function calling, multi-turn behavior, and interruption handling. | A voice adapter can provide a read-only briefing with barge-in; it must be off by default and isolated behind an interface/mock. | Verify model ID, region availability, quotas, browser transport, authentication, audio formats, session limits, and tool-use restrictions. |
| Terraform AWS provider | Terraform MCP returned AWS provider 6.64.0 and resources for AgentCore Gateway, Gateway Target, Policy Engine, Policy, plus Verified Permissions resources. | The current `~> 5.0` provider constraint is incompatible with the validated AgentCore resource baseline and must be resolved in a reviewed provider-upgrade task. | Confirm the provider version, lock file, resource schemas, import behavior, and Terraform runtime floor in CI before changing IaC. |
| Observability/DevOps Powers | No separately named Observability or DevOps Power is installed in this workspace. | Use the existing CloudWatch/GitHub Actions design requirements; do not claim unavailable MCP-backed integrations. | Revisit if those Powers are installed later; their absence does not relax logging, audit, CI, or manual-apply requirements. |

**Authoritative references:** [AgentCore Cedar semantics](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-understanding-cedar.html), [AgentCore policy getting started](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-getting-started.html), [Nova Sonic speech-to-speech](https://docs.aws.amazon.com/nova/latest/userguide/speech.html), [Terraform AgentCore Gateway resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/bedrockagentcore_gateway), [Terraform AgentCore Policy resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/bedrockagentcore_policy), and [Terraform AWS provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs).

## 4. Functional EARS requirements

### Discovery and finding lifecycle

**CCG-REQ-001 — Scheduled discovery (event-driven):** WHEN the configured EventBridge schedule fires, THE SYSTEM SHALL start one read-only discovery run with a new correlation ID and SHALL collect only the approved Config, Security Hub, and CloudTrail signals.

**CCG-REQ-002 — Read-only discovery (ubiquitous):** THE SYSTEM SHALL prevent the discovery execution role from changing audited resources, invoking remediation tools, or activating policies.

**CCG-REQ-003 — Normalized finding (event-driven):** WHEN a source signal indicates drift, THE SYSTEM SHALL produce a typed normalized finding containing a deterministic finding ID, rule ID, evidence references, severity, target ARN, target tags, status, first-seen and last-seen timestamps, source, correlation ID, and accepted-risk fields.

**CCG-REQ-004 — Finding identity (ubiquitous):** THE SYSTEM SHALL derive finding identity from stable rule and target attributes rather than a random value so repeated discovery updates the same finding.

**CCG-REQ-005 — Current state and audit history (event-driven):** WHEN a discovery run completes, THE SYSTEM SHALL upsert current finding state in on-demand DynamoDB and SHALL write an immutable-shaped JSON audit record to private S3 with the required 30-day expiration policy.

**CCG-REQ-006 — Partial source failure (unwanted behavior):** IF one discovery source is unavailable, throttled, unauthorized, or returns malformed data, THEN THE SYSTEM SHALL retain source-level error evidence, continue independent sources where safe, mark the run partial, and SHALL NOT convert an unknown result into a compliant result.

**CCG-REQ-007 — Duplicate and stale events (unwanted behavior):** IF the same source event or discovery run is processed more than once, THEN THE SYSTEM SHALL deduplicate it and SHALL NOT create duplicate current findings or duplicate remediation effects.

### Gateway authorization and policy lifecycle

**CCG-REQ-008 — Mandatory Gateway boundary (ubiquitous):** THE SYSTEM SHALL route every remediation mutation through the AgentCore Gateway Policy Engine before a tool target executes.

**CCG-REQ-009 — No direct authorization (unwanted behavior):** IF a request is initiated by a prompt, agent memory, client/UI state, application boolean, or an unregistered direct AWS path, THEN THE SYSTEM SHALL NOT treat that request as authorized.

**CCG-REQ-010 — Default deny (unwanted behavior):** IF no active permit policy matches the principal, exact registered action, target, and validated request context, THEN THE Gateway SHALL deny the call and record an authorization decision.

**CCG-REQ-011 — Forbid precedence (unwanted behavior):** IF any always-on forbid policy matches, THEN THE Gateway SHALL deny the call even when an active permit matches.

**CCG-REQ-012 — Mutation sandbox gate (ubiquitous):** THE SYSTEM SHALL deny every mutation unless the target has `CCGDemo=true` and SHALL deny every target with `Environment=prod`, regardless of caller, UI state, permit state, or requested action.

**CCG-REQ-013 — Registered action catalog (ubiquitous):** THE SYSTEM SHALL expose only the four approved remediation tools, each with an explicit action identifier, typed input schema, target-resource contract, least-privilege execution role, and documented preconditions.

**CCG-REQ-014 — Policy inactive default (state-driven):** WHILE the versioned permit set is inactive, THE SYSTEM SHALL keep the permit path non-authorizing and SHALL still enforce always-on forbids at the Gateway.

**CCG-REQ-015 — Audited activation (event-driven):** WHEN an authenticated, authorized admin requests permit activation, THE SYSTEM SHALL record the requested policy-set version, actor, reason, correlation ID, and timestamp before requesting the supported AgentCore control-plane activation operation.

**CCG-REQ-016 — Activation result (event-driven):** WHEN policy activation succeeds or fails, THE SYSTEM SHALL record the control-plane result, effective version, prior version, actor, request ID, and timestamp; on uncertainty or failure, THE effective state SHALL remain deny-by-default.

**CCG-REQ-017 — Version and concurrency (unwanted behavior):** IF an activation request references a stale version, is replayed, or conflicts with another activation, THEN THE SYSTEM SHALL reject it without changing the effective policy and SHALL record the conflict.

**CCG-REQ-018 — Policy visibility (ubiquitous):** THE SYSTEM SHALL expose the effective policy-set version, activation state, enforcement mode, last activation actor, and last change time to the authenticated console without allowing the display value to authorize a call.

**CCG-REQ-019 — Decision evidence (event-driven):** WHEN the Gateway evaluates a tool call, THE SYSTEM SHALL retain decision evidence containing request ID, actor/principal, exact tool/action, target, decision, matched/determining policy IDs, policy version, correlation ID, timestamp, and error/status details where applicable.

**CCG-REQ-020 — Schema safety (unwanted behavior):** IF the principal, action, resource, target tags, or request context cannot be mapped to the validated AgentCore Cedar schema, THEN THE Gateway SHALL deny the request and record a schema/error outcome.

### Remediation behavior

**CCG-REQ-021 — Security-group correction:** WHEN the registered security-group tool is allowed, THE SYSTEM SHALL change only the approved sandbox rule, SHALL reject unsupported CIDR/protocol/port changes, and SHALL treat an already compliant rule as a successful no-op.

**CCG-REQ-022 — S3 encryption:** WHEN the registered S3 encryption tool is allowed, THE SYSTEM SHALL enable the approved encryption configuration only on the eligible sandbox bucket and SHALL treat the desired configuration already being present as a successful no-op.

**CCG-REQ-023 — Compliant tagging:** WHEN the registered tagging tool is allowed, THE SYSTEM SHALL add or correct only the approved non-production compliance tags and SHALL never remove the safety tag or set `Environment=prod`.

**CCG-REQ-024 — Access-key rotation:** WHEN the registered access-key workflow is allowed, THE SYSTEM SHALL operate only on the explicitly approved sandbox identity, SHALL create/validate the replacement before disabling the old key, SHALL avoid returning secret material in logs or responses, and SHALL define a safe failure/rollback state.

**CCG-REQ-025 — Idempotency:** WHEN an identical remediation request with the same idempotency key is repeated, THE SYSTEM SHALL return the original outcome or a safe no-op and SHALL NOT perform a second mutation.

**CCG-REQ-026 — Tool failure:** IF an allowed tool fails, times out, or returns an uncertain result, THEN THE SYSTEM SHALL record the failure, SHALL not claim compliance, and SHALL require a subsequent read/discovery confirmation before marking the finding corrected.

### Console, identity, and voice

**CCG-REQ-027 — Authenticated console:** WHEN the POC admin opens the console, THE SYSTEM SHALL require Cognito-backed authentication and SHALL display current findings, evidence, effective policies, remediation mode, proposed action, and decision evidence.

**CCG-REQ-028 — Server-side authorization:** WHEN the console requests a read or mutation operation, THE API SHALL authenticate and authorize the request server-side and SHALL never rely on a hidden control, route, or client boolean.

**CCG-REQ-029 — Admin control:** WHEN the admin changes remediation mode, THE SYSTEM SHALL submit a versioned activation/deactivation request to the control plane; the UI control SHALL reflect server-confirmed state only.

**CCG-REQ-030 — Read-only voice:** WHEN voice is enabled and started, THE SYSTEM SHALL provide only read-only finding and policy-status summaries, SHALL propagate the session correlation ID, and SHALL not expose mutation tools to the voice session.

**CCG-REQ-031 — Voice interruption:** WHEN the user interrupts a voice response, THE SYSTEM SHALL stop or supersede playback and continue the session without authorizing any mutation.

**CCG-REQ-032 — Voice disabled default:** UNLESS the explicit POC voice feature flag is enabled and the user grants microphone consent, THE SYSTEM SHALL not open a Nova Sonic stream or capture microphone audio.

**CCG-REQ-033 — Voice fallback:** IF the selected Nova Sonic model, region, transport, quota, or API is unavailable, THEN THE SYSTEM SHALL use the adapter/mock failure path and SHALL retain the console’s read-only behavior without weakening authorization.

### Audit, observability, cost, and operations

**CCG-REQ-034 — Structured logging:** THE SYSTEM SHALL emit structured JSON logs for discovery, API, Gateway decision, policy activation, tool execution, voice session, and cleanup events with correlation ID, request ID, actor, component, outcome, and timestamp.

**CCG-REQ-035 — Sensitive data:** THE SYSTEM SHALL exclude credentials, access-key secret material, raw microphone audio by default, tokens, and confidential payloads from logs, S3 audit records, DynamoDB findings, Git, and CI artifacts.

**CCG-REQ-036 — Audit retention:** THE SYSTEM SHALL retain CloudWatch logs for seven days and S3 audit records for 30 days, with private access, encryption, and lifecycle controls defined by infrastructure design.

**CCG-REQ-037 — Operational alarms:** THE SYSTEM SHALL expose minimum metrics/alarms for discovery failure, partial discovery, denied mutations, policy activation failure, tool failure, and unexpected cost/resource conditions.

**CCG-REQ-038 — Cost boundary:** THE SYSTEM SHALL use event-driven/serverless resources and SHALL remain designed for a monthly POC budget below $150, excluding user-managed account commitments; it SHALL not require NAT, provisioned DynamoDB, always-on compute, or multi-AZ topology.

**CCG-REQ-039 — Manual infrastructure apply:** THE SYSTEM SHALL keep Terraform applies manual and SHALL require a reviewed plan artifact; CI SHALL validate but SHALL not apply infrastructure automatically.

**CCG-REQ-040 — Teardown:** THE SYSTEM SHALL document and test sandbox cleanup, including seed resources, policy state, audit data, logs, and Terraform-managed resources, without deleting outside the POC scope.

## 5. Acceptance scenarios

| ID | Given | When | Then |
|---|---|---|---|
| ACC-01 | A tagged sandbox finding exists | Discovery runs | A deterministic normalized finding and evidence are visible with one correlation ID. |
| ACC-02 | Permit set is inactive | Admin requests a registered mutation | Gateway denies before target execution; decision evidence records default deny. |
| ACC-03 | Permit is active and target has `CCGDemo=true` | Admin requests an eligible registered mutation | Gateway allows, target executes once, and audit evidence shows determining permit. |
| ACC-04 | Target has `Environment=prod` | Any mutation is requested | Gateway denies even if a permit matches. |
| ACC-05 | Target lacks `CCGDemo=true` | Any mutation is requested | Gateway denies; no target call occurs. |
| ACC-06 | A forbid condition matches | An active permit also matches | Gateway denies and records both relevant policy evidence and forbid precedence. |
| ACC-07 | Same allowed request is repeated with same idempotency key | Tool is invoked again | No second mutation occurs and the original/no-op outcome is returned. |
| ACC-08 | Admin activates a known policy version | Control-plane update succeeds | Pre/post activation audit events and effective version are visible. |
| ACC-09 | Activation uses a stale/replayed version | Control plane receives request | Request is rejected and effective state is unchanged. |
| ACC-10 | A discovery source fails | Scheduled run completes | Run is partial, failure evidence is retained, and no false compliance is asserted. |
| ACC-11 | An unregistered tool or malformed Cedar context is requested | Gateway receives the call | Request is denied and target is not invoked. |
| ACC-12 | Voice flag is off | User opens the console | No microphone or Nova Sonic stream starts. |
| ACC-13 | Voice flag is on and consent is granted | User requests a finding briefing and interrupts playback | Read-only summary streams, transcript/audio behavior is interruptible, and no mutation capability is available. |
| ACC-14 | Tool execution fails or is uncertain | Remediation returns | Finding remains unresolved until discovery confirms the desired state. |
| ACC-15 | CI runs on a pull request | Validation pipeline executes | Terraform, Python, TypeScript, Cedar, and secret checks run; no apply occurs. |

## 6. Review gates before implementation

1. Human approval of this requirements baseline and the infrastructure design.
2. Live AgentCore Gateway tool schema and Cedar entity/action mapping captured as an implementation artifact.
3. Confirmation of AgentCore control-plane activation API, IAM permissions, propagation, and rollback behavior.
4. Confirmation of Nova Sonic model/region/transport and browser audio approach; otherwise keep voice adapter mocked and disabled.
5. Decision on AWS provider 6.64.0 upgrade from the current `~> 5.0` constraint, including lock-file and CI impact.
6. Threat-model review of trust boundaries, IAM roles, audit storage, and the admin activation path.

No code, Terraform resource expansion, policy activation, seed mutation, or live remediation is authorized merely by approval of this document.
