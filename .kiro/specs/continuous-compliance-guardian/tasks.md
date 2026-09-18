# Continuous Compliance Guardian — Implementation Task List

**Status:** Planning only; tasks are not approved for execution until requirements and design receive human review.

**Ordering:** Complete in dependency order. Every task must preserve the Cedar-first boundary and the POC cost/safety constraints.

**Offline progress (2026-09-15):** Task 0.1 is resolved (see `docs/DESIGN_REVIEW_RECONCILIATION.md`). The parts of Phases 3–4 that require no live AWS have been implemented behind test doubles: deterministic discovery normalization/dedup (3.2), the four remediation tools as dry-run handlers (4.1), and the Cedar-first decision engine (4.2, local model). A runnable offline end-to-end harness (`src/ccg/demo.py`, wired into CI) proves discover → deny-while-inactive → audited activation → allow → idempotent execution → reconcile-to-RESOLVED. All work marked `[x]`/`[~]` below is **offline only** and does not lift the gate-0.2 requirements: live Gateway/target schema capture, real action IDs, live AWS effectors, and least-privilege roles are still required before any sandbox apply. Legend: `[x]` done, `[~]` partially done (offline model complete, live integration gated), `[ ]` not started.

## Phase 0 — Review and capability gates

- [ ] **0.1 Approve requirements and design**
  - Review `requirements.md` and `design.md` with security, platform, and POC owners.
  - Resolve the design review questions and record decisions before implementation.
  - **Exit:** Requirements and design are marked approved; no code changes are part of this task.

- [ ] **0.2 Capture live AgentCore contract**
  - In a non-production sandbox, create or inspect the smallest representative Gateway/target definition needed to obtain the generated Cedar schema and exact action identifiers.
  - Verify Lambda target tool-schema limits, principal identity, target/resource representation, request input context, policy engine association, and policy analyzer behavior.
  - Verify the control-plane operation for policy updates, enforcement modes, propagation, IAM permissions, request IDs, and failure/rollback behavior.
  - **Exit:** A versioned, redacted capability record exists; all Cedar requirements map to real entity/action/context names; unresolved items block later policy work.

- [ ] **0.3 Capture Nova Sonic contract**
  - Verify model ID, region availability, quotas, bidirectional API, audio formats, browser transport, interruption events, and authentication path.
  - Decide whether the first implementation uses a real adapter or a mock while keeping voice disabled.
  - **Exit:** A capability record and explicit adapter boundary exist; no voice mutation path is permitted.

- [ ] **0.4 Resolve Terraform version baseline**
  - Compare the repository’s Terraform `>=1.8.0,<2.0.0` and AWS provider `~>5.0` constraints with the validated AgentCore resource schemas in AWS provider 6.64.0.
  - Select and pin a compatible runtime/provider pair, document the provider-upgrade risk, and plan lock-file changes.
  - **Exit:** Version decision is approved before Terraform resources are expanded.

## Phase 1 — Contracts, threat model, and policy model

- [ ] **1.1 Define typed contracts**
  - Define finding, discovery-run, remediation-request, tool input/output, decision-evidence, audit-event, policy-activation, and error contracts.
  - Include schema versions, correlation/request IDs, deterministic identities, redaction rules, idempotency keys, expected finding versions, and allowed status transitions.
  - **Exit:** Contracts are reviewable independently of implementation and cover every acceptance scenario.

- [x] **1.2 Threat-model the trust boundaries**
  - Model admin, Cognito, API, discovery, AgentCore Gateway, Cedar, tool Lambdas, AWS sources, S3/DynamoDB, and Nova Sonic.
  - Identify confused-deputy, forged-tag/context, replay, privilege escalation, secret leakage, policy activation, and audit-integrity threats.
  - **Exit:** Mitigations map to requirements, IAM boundaries, tests, and operational alarms.
  - **Done:** `docs/THREAT_MODEL.md` models boundaries B1–B7 and threats T1–T8, each traced to a mitigation, EARS requirement, IAM/Cedar boundary, test, and `Metric` alarm. Grounded in verified gate-0.2 facts (real `UpdatePolicy` activation, `cloud-sandbox` non-admin scope, empty account, `aws-nuke` auto-clean). One HIGH residual (T2: live Cedar context source) is itself a gate-0.2 §2 capture item. Sets the reviewed deploy gate: a minimal schema-capture deploy is acceptable only against `CCGDemo`-tagged targets with permits inactive (`LOG_ONLY`) via a reviewed HCP plan.

- [ ] **1.3 Reconcile Cedar policies with the live schema**
  - Convert current guardrail/permit intent into explicit per-tool policies using actual AgentCore action/resource/entity names.
  - Keep always-on forbids active; replace the broad wildcard permit with narrow action-specific permits.
  - Represent `CCGDemo=true` and `Environment=prod` using attributes that the caller cannot self-assert.
  - Define inactive/log-only permit behavior, activation version, rollback, concurrency, and policy analyzer gates.
  - **Exit:** Policies pass schema/analyzer validation and have no unreviewed wildcard authorization.

- [ ] **1.4 Define policy tests before policy deployment**
  - Specify allow, default-deny, forbid-overrides-permit, missing-tag, prod-tag, malformed-context, unknown-tool, inactive-permit, active-permit, stale-version, replay, and activation-failure tests.
  - **Exit:** Tests are executable against a double or validated sandbox boundary and cover CCG-REQ-008 through CCG-REQ-020.

## Phase 2 — Terraform foundation and security controls

- [ ] **2.1 Establish modular Terraform layout**
  - Create the reviewed `environments/poc` root and bounded modules without introducing application behavior.
  - Preserve Terraform Cloud as the only backend; add typed variables, outputs, default tags, and safe POC validation.
  - **Exit:** Format, initialization, backendless validation, and module contract checks pass without credentials or local state committed.

- [ ] **2.2 Harden evidence storage**
  - Refine private encrypted S3 audit storage, public-access blocking, ownership/policy controls, 30-day lifecycle, and the chosen versioning/immutability posture.
  - Refine on-demand DynamoDB current-finding/idempotency layout and seven-day CloudWatch log retention.
  - **Exit:** Storage controls are plan-visible, least privilege is reviewed, and retention tests exist.

- [ ] **2.3 Provision least-privilege identities**
  - Define separate discovery, control-plane, Gateway, tool, API, and audit-reader roles.
  - Scope permissions to the POC account, region, resource types, tags, and specific APIs; avoid wildcard administrative access.
  - **Exit:** IAM policy review and negative permission tests show discovery cannot mutate, console cannot bypass Gateway, and tools cannot activate policy.

- [ ] **2.4 Provision EventBridge and discovery runtime**
  - Add the configurable schedule with 15-minute default, Lambda runtime configuration, bounded timeout/concurrency, retries, and failure destination/metric where justified.
  - **Exit:** Schedule and runtime are deployable in the POC topology without NAT, always-on compute, or multi-AZ requirements.

- [ ] **2.5 Provision AgentCore Gateway and policy resources**
  - Add only the validated Gateway, target, Policy Engine, and policy resources using the approved provider version and actual schema.
  - Ensure inactive permit state and active forbids are represented without relying on application booleans.
  - **Exit:** Terraform plan shows the intended external policy boundary and no unreviewed mutation path.

## Phase 3 — Discovery and evidence path

- [x] **3.1 Implement source adapters** *(offline; live boto3 transports gated on 0.2)*
  - Add read-only adapters for Config, Security Hub, and CloudTrail behind interfaces/test doubles.
  - Define throttling, permission, malformed-response, and partial-run handling.
  - **Exit:** Unit tests cover source success/failure and no write permission is required.
  - **Done:** `src/ccg/sources.py` provides `NormalizingSource` plus `config_source`/`security_hub_source`/`cloudtrail_source`, reading through an injected `SourceTransport` seam (no AWS SDK). Typed `SourceThrottledError`/`SourceUnauthorizedError`/`SourceUnavailableError` propagate as whole-source failures the coordinator records as partial runs; a single `MalformedRecordError` is skipped (counted) without fabricating a signal, or escalates under `strict=True`. Covered by `tests/test_sources.py`. Live boto3-backed transports under the read-only discovery role remain gated on 0.2.

- [x] **3.2 Implement normalization and deduplication** *(offline; live source adapters still gated on 0.2/3.1)*
  - Produce deterministic finding IDs, evidence references, severity/status, target tags, timestamps, accepted-risk fields, and correlation propagation.
  - **Exit:** Replayed events update the same finding and cannot claim compliance from incomplete data.
  - **Done:** `src/ccg/discovery.py` (`normalize_signal`, `merge_finding`, `derive_finding_id`) preserves `first_seen_at`, advances `last_seen_at` monotonically, bumps `revision` only on content change, preserves in-flight lifecycle status, and dedups within a run. Covered by `tests/test_discovery_merge.py`.

- [x] **3.3 Implement persistence and audit writes** *(offline; live DynamoDB/S3 transports gated on 0.2)*
  - Upsert current state in DynamoDB and write redacted audit JSON to private S3.
  - Handle storage failure without silently losing decision/audit evidence.
  - **Exit:** Contract tests verify retention fields, redaction, idempotency, and partial failure behavior.
  - **Done:** `src/ccg/audit.py` adds `FailClosedAuditSink` (a store failure raises `AuditWriteError` and dead-letters the event rather than dropping it) and `MultiplexAuditSink` (fan-out to current-state + audit stores; one failure never masks the others). `redact_details` is reused for the JSON-line writer. Contract tests: `tests/test_audit.py` (redaction of secret/token/audio keys, required correlation/request/timestamp fields, deterministic JSON, fail-closed) and `tests/test_persistence.py` (idempotent re-upsert, retention-relevant serialized fields, UTC ISO timestamps). Live DynamoDB/S3 transports remain gated on 0.2.

- [ ] **3.4 Replace the seed plan stub only after safety review**
  - Implement a reversible, explicitly sandbox-gated seed/cleanup workflow for 3–5 findings only after IAM and threat-model approval.
  - Ensure dry-run is real, `CCG_SANDBOX=true` and explicit confirmation are required, and cleanup is bounded.
  - **Exit:** Seed cannot target prod/out-of-scope resources and cleanup is tested before demo use.

## Phase 4 — Gateway tools and control plane

- [x] **4.1 Implement four narrow remediation tools** *(offline handlers; live AWS effector + least-privilege roles gated on 0.2)*
  - Build one bounded tool per approved operation with typed input validation, target allowlisting, safety-tag rechecks, least-privilege role, idempotency, and redacted outcomes.
  - **Exit:** Unit and integration tests cover allow, deny, no-op, failure, audit, and cleanup for each tool.
  - **Done:** `src/ccg/tools.py` implements all four as pure `ToolHandler`s with server-side safety rechecks, no-op-on-compliant, and a `DryRunEffector` seam (no AWS calls). Access-key rotation is dry-run unless `confirm=true` (approved Q5). Covered by `tests/test_tools.py`. Live mutation via a real `Effector` and least-privilege roles remain gated on 0.2.

- [ ] **4.2 Implement Gateway invocation adapter** *(local Cedar-first model + double done; live AgentCore transport gated on 0.2)*
  - Route remediation requests through the AgentCore Gateway MCP boundary only.
  - Capture exact action IDs, decision evidence, policy version, request IDs, and correlation IDs.
  - **Exit:** Direct tool/Lambda invocation is absent from agents, API, console, and voice paths.
  - **Done:** `src/ccg/authz.py` models forbid-overrides-permit / default-deny ordering as explicit named rules producing full `PolicyDecision` evidence; `InMemoryCedarGateway` delegates to it. `src/ccg/gateway.py` keeps the real AgentCore transport as a seam with no local authorization. Covered by `tests/test_authz.py` and `tests/test_gateway.py`. **Still gated:** exact generated action IDs and the live MCP transport come from 0.2.

- [ ] **4.3 Implement audited policy activation control plane**
  - Authenticate the admin, validate requested version/reason/concurrency, write intent, call the verified AgentCore control-plane update, reconcile effective state, and write result.
  - Fail closed on timeout, stale version, replay, schema error, or uncertain propagation.
  - **Exit:** Activation tests prove the UI cannot grant access and a failed/ambiguous update leaves mutations denied.

- [x] **4.4 Implement remediation reconciliation** *(offline; driven by test doubles until 0.2)*
  - Record requested/running/succeeded/no-op/failed/uncertain outcomes and require discovery confirmation before `RESOLVED`.
  - **Exit:** Findings, audit records, and tool outcomes remain consistent under retries and timeouts.
  - **Done:** `src/ccg/reconcile.py` (`ReconciliationService`) is the single finding-status authority with an explicit allowed-transition map. Tool outcomes record SUCCEEDED/NOOP/FAILED but never resolve; only a confirming discovery read (drift gone, from a success/no-op state) transitions to `RESOLVED`. Failed/uncertain outcomes stay unresolved. Idempotent, audited, illegal transitions rejected. Wired into `demo.py` (replaces the previous inline RESOLVED hack). Covered by `tests/test_reconcile.py`.

## Phase 5 — Console, identity, and optional voice

- [ ] **5.1 Implement Cognito/API control plane** *(service + authz contracts done offline; Cognito/API Gateway/Lambda wiring gated on 0.2)*
  - Add authenticated findings, policy-status, decision-evidence, activation, and remediation-request endpoints.
  - Enforce server-side input validation and correlation propagation; do not expose direct AWS mutation endpoints.
  - **Exit:** API authorization tests cover unauthenticated, unauthorized, stale, malformed, and valid requests.
  - **Done:** `src/ccg/api.py` (`ComplianceApi`) is framework-neutral with no direct AWS mutation path — every mutation is delegated to the Gateway port, and the target is resolved server-side from the stored finding (a command cannot smuggle its own target). `tests/test_api_authorization.py` covers unauthenticated reads/writes, actor mismatch, missing/stale finding version, unresolvable finding, and the valid allow-and-apply path; `tests/test_policy_api_voice.py` covers activation auth, stale generation, and deny-safe failure. **Still gated:** Cognito authentication, the API Gateway/Lambda HTTP adapter, and the decision-evidence read endpoint wiring depend on 0.2.

- [ ] **5.2 Implement Next.js App Router console**
  - Display findings, evidence, effective policy version/mode, proposed actions, and server-confirmed outcomes.
  - Make remediation mode a server-state view, not a local authorizer.
  - **Exit:** Console acceptance scenarios ACC-01 through ACC-11 are demonstrable without a hidden bypass.

- [ ] **5.3 Implement Nova Sonic adapter or safe mock**
  - Add feature flag off by default, consent flow, read-only finding summary, correlation IDs, interruption handling, redaction, and unavailable fallback.
  - **Exit:** ACC-12 and ACC-13 pass; voice has no mutation tool visibility or Gateway bypass.

## Phase 6 — Validation, CI, demo, and operations

- [ ] **6.1 Build complete test matrix** *(offline matrix + traceability done; sandbox e2e gated on 0.2)*
  - Run contract, policy, unit, integration, idempotency, audit, cleanup, and negative authorization tests.
  - Add a sandbox-only end-to-end path for discovery → deny → activation → allow/no-op → rediscovery.
  - **Exit:** Every requirement and acceptance scenario has traceable evidence.
  - **Done:** 108 offline tests spanning contract/policy/unit/idempotency/audit/negative-authorization plus the `test_demo` end-to-end chain. `docs/TEST_TRACEABILITY.md` maps every CCG-REQ and ACC scenario to its covering test(s) and flags which remain gated on 0.2. **Still gated:** the sandbox-only (real AWS) end-to-end path requires 0.2.

- [ ] **6.2 Extend CI validation**
  - Add pinned Terraform fmt/validate/tflint and provider lock/schema checks; Ruff/pytest; TypeScript ESLint/typecheck; Cedar validation/analyzer checks; and secret scanning.
  - Keep real-cloud integration and remediation opt-in; never apply from CI.
  - **Exit:** Pull-request CI is validation-only and reports artifacts without secrets.

- [ ] **6.3 Add observability and budget checks** *(metric contracts done offline; CloudWatch emission + dashboard gated on 0.2)*
  - Add structured JSON logs, correlation fields, metrics/alarms for discovery, denials, activation, tool failures, voice failures, and cleanup.
  - Add cost/resource guardrails and verify seven-day CloudWatch/30-day S3 retention.
  - **Exit:** Operational dashboard/runbook demonstrates the required evidence and budget posture.
  - **Done:** `src/ccg/observability.py` defines the stable `Metric` catalog covering every CCG-REQ-037 family (discovery run/partial/failure, gateway allow/deny, activation success/failure/rejected, tool applied/noop/failed, voice session/error, cleanup, audit-write failure) behind a `MetricSink` seam with `NullMetricSink` default and `InMemoryMetricSink` recorder. Dimensions are validated string-only (no secrets/ARNs). Covered by `tests/test_observability.py`. Cost guardrails already live as validated Terraform variable constraints (7-day CW / 30-day S3). **Still gated:** CloudWatch EMF/PutMetricData emission, alarms, and dashboard require 0.2.

- [ ] **6.4 Run the demo rehearsal**
  - Seed 3–5 sandbox-only findings; detect; show denied remediation with inactive permits; activate through the audited control plane; repeat the request; show allow/no-op; rediscover; show evidence; optionally run an interruptible voice briefing.
  - **Exit:** Demo evidence checklist is complete and all resources are attributable to the POC.

- [ ] **6.5 Document teardown and rollback**
  - Document permit deactivation, reconciliation, seed cleanup, reviewed Terraform destroy plan, resource deletion order, evidence retention, and incident handling.
  - **Exit:** Teardown is tested and no production or out-of-scope resource can be selected by default.

## Definition of done

The implementation may be considered complete only when:

- every approved EARS requirement has implementation and test evidence;
- every mutation traverses AgentCore Gateway/Cedar and no UI/application boolean authorizes it;
- forbids override permits, no-match denies, missing `CCGDemo` denies, and `Environment=prod` always denies;
- policy activation is versioned, audited, server-confirmed, concurrency-safe, and fail-closed;
- all four tools are narrow, idempotent, least-privilege, and cleanup-tested;
- discovery is read-only and later confirmation drives resolution;
- logs/audit records contain required correlation and decision evidence without secrets;
- the POC topology remains event-driven/serverless, under the budget target, with required retention;
- CI validates but does not apply; and
- the demo and teardown runbooks have been rehearsed in the dedicated sandbox.

## Explicitly not authorized by this task list

Approval of this list does not authorize live remediation, policy activation, production access, Terraform apply, destructive cleanup, credential creation, or adding dependencies/resources before the capability gates and human review are complete.
