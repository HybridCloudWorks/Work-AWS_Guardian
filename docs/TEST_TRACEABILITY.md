# Test Traceability Matrix

Maps EARS requirements (`requirements.md` §4) and acceptance scenarios (§5) to
the tests that cover them. Everything is proven **offline** (behind test doubles
and a faithful AgentCore transport emulator, Python 3.14) plus credential-free
Terraform and console checks. No test makes a live AWS call.

"Gated on 0.2" means the offline behavior is proven but the live-AWS path (real
Gateway schema, boto3 transports, Cognito, Terraform-applied sandbox) still
requires the sandbox account; "gated on 0.3" is the equivalent for live Nova
Sonic voice.

**Last updated:** 2026-10-01 · Suite: **346 Python tests** (+143 subtests)
passing (`PYTHONPATH=src python -m pytest tests/`), **15 Terraform tests**
passing across 4 `*.tftest.hcl` files (`terraform test`), **14 console tests**
passing (`cd console && npm test`).

## Faithful-transport (FT) legend

A ✅ in the **FT** column means the row is additionally proven against the
**faithful AgentCore transport path** — `AgentCoreGatewayClient` wired to
`FaithfulAgentCoreEmulator` in `test_gateway_live_path.py` (and, for the
control-plane, the `AgentCoreControlPlaneTransport` + fake-client seam in
`test_activation_control_plane.py`) — not only the in-memory double. The
offline end-to-end `test_demo.py` also runs through this faithful transport. A
blank FT cell means the row is proven against in-memory doubles / module logic
only (its live binding is gated on 0.2 or 0.3).

## Requirements coverage

| Requirement | Covered by | FT | Notes |
|---|---|---|---|
| CCG-REQ-001 Scheduled discovery | `test_discovery`, `test_discovery_audit`; `tests/discovery_runtime.tftest.hcl` (schedule/retry/concurrency) | | EventBridge Scheduler wiring asserted in Terraform; live trigger gated on 0.2 |
| CCG-REQ-002 Read-only discovery | `test_sources`; `tests/iam_negative_permissions.tftest.hcl` (N1) | | adapters have no write path; IAM doc denies mutation/assume-role |
| CCG-REQ-003 Normalized finding | `test_discovery_merge`, `test_sources`, `test_contracts` | | deterministic fields + mapping |
| CCG-REQ-004 Finding identity | `test_discovery_merge::test_finding_id_is_deterministic...` | | sha256(rule:arn) |
| CCG-REQ-005 Current state + audit history | `test_persistence`, `test_audit` | | live DynamoDB/S3 gated on 0.2 |
| CCG-REQ-006 Partial source failure | `test_sources::SourceFailureIsolationTests` | | throttle/unauthorized -> partial run |
| CCG-REQ-007 Duplicate/stale events | `test_discovery_merge::CoordinatorDedupTests` | | dedup, no revision churn |
| CCG-REQ-008 Mandatory Gateway boundary | `test_gateway`, `test_policy_scenarios`, `test_api_authorization`, `test_gateway_live_path` | ✅ | mutations only via Gateway port; proven on faithful transport too |
| CCG-REQ-009 No direct authorization | `test_api_authorization::test_api_never_authorizes_locally...`, `test_policy_scenarios`, `test_gateway_live_path` | ✅ | target resolved server-side; state visibility never authorizes |
| CCG-REQ-010 Default deny | `test_authz::test_inactive_permit_denies`, `test_policy_scenarios::DefaultDenyTests`, `test_gateway_live_path::test_default_deny_when_inactive` | ✅ | |
| CCG-REQ-011 Forbid precedence | `test_authz::test_forbid_overrides_active_permit_for_prod`, `test_policy_scenarios::ForbidOverridesPermitTests`, `test_gateway_live_path` | ✅ | forbid overrides permit on both drivers |
| CCG-REQ-012 Mutation sandbox gate | `test_authz`, `test_policy_scenarios::ForbidOverridesPermitTests`, `test_tools::SafetyRecheckTests`, `test_gateway_live_path` | ✅ | CCGDemo required, prod denied (defense in depth) |
| CCG-REQ-013 Registered action catalog | `test_authz`, `test_policy_scenarios::AllowScenariosTests`/`UnregisteredToolTests`, `test_api_control_plane::RuleToolValidationTests` (P0.4c), `test_gateway_live_path::test_unknown_tool_denied` | ✅ | four tools only; tool/rule consistency enforced above Cedar |
| CCG-REQ-014 Policy inactive default | `test_gateway::test_inactive_permit_defaults_to_deny...`, `test_policy_scenarios::DefaultDenyTests`, `test_gateway_live_path` (LOG_ONLY still forbids) | ✅ | forbids still enforced while inactive |
| CCG-REQ-015 Audited activation | `test_policy_api_voice::test_activation_is_audited...`, `test_activation_control_plane::SuccessfulActivationTests`, `test_policy_scenarios` | ✅ | intent recorded before result; live-transport seam exercised |
| CCG-REQ-016 Activation result / deny-safe | `test_policy_api_voice::test_activation_failure_is_deny_safe`, `test_activation_control_plane` (TransportError / UncertainPropagation / Deactivation / LiveTransportSeam) | ✅ | uncertain propagation fails closed to LOG_ONLY |
| CCG-REQ-017 Version & concurrency | `test_policy_api_voice::test_stale_generation_is_rejected`, `test_activation_control_plane::StaleGenerationTests`/`ReplayTests`, `test_policy_scenarios::StaleVersionReplayTests` | ✅ | optimistic concurrency + replay cache |
| CCG-REQ-018 Policy visibility | `test_api_authorization::test_get_policy_state_requires_authentication`, `test_policy_scenarios::PolicyVisibilityTests` | | display value never authorizes |
| CCG-REQ-019 Decision evidence | `test_authz::test_decision_evidence_is_populated`, `test_policy_scenarios::DecisionEvidenceCompletenessTests`, `test_api_control_plane::DecisionEvidenceReadTests`, `test_gateway_live_path::test_decision_evidence_completeness` | ✅ | matched policy IDs, full Cedar action_id, version; authenticated read |
| CCG-REQ-020 Schema safety | `test_policy_scenarios::MalformedContextTests`/`UnregisteredToolTests`, `test_authz`, `test_gateway_live_path` (unknown tool/ambiguous-allow fail closed) | ✅ | malformed context -> deny; ambiguous allow fails closed |
| CCG-REQ-021 Security-group correction | `test_tools::SecurityGroupTests` | | no-op on compliant, rejects global-open |
| CCG-REQ-022 S3 encryption | `test_tools::S3EncryptionTests` | | no-op if already encrypted |
| CCG-REQ-023 Compliant tagging | `test_tools::TaggingTests`; `tests/iam_negative_permissions.tftest.hcl` (N3) | | never sets prod; IAM denies prod-tagged targets |
| CCG-REQ-024 Access-key rotation | `test_tools::AccessKeyRotationTests` | | dry-run default, no secret material |
| CCG-REQ-025 Idempotency | `test_gateway::test_repeated_idempotency_key...`, `test_reconcile`, `test_gateway_live_path::test_idempotent_replay_no_double_execution` | ✅ | no second mutation on replay |
| CCG-REQ-026 Tool failure | `test_reconcile::test_failed_outcome_never_resolves...` | | no false compliance |
| CCG-REQ-027 Authenticated console | `test_api_authorization` (read endpoints), `test_api_control_plane::JwtPrincipalResolverTests`/`HttpAdapterCognitoTests` | | Cognito JWT resolver proven offline; live user pool gated on 0.2 |
| CCG-REQ-028 Server-side authorization | `test_api_authorization`, `test_api_control_plane::HttpAdapterCognitoTests` (401/403 on missing/invalid token) | | not client-state driven |
| CCG-REQ-029 Admin control | `test_policy_api_voice::test_non_admin_cannot_activate`, `test_activation_control_plane::NonAdminCannotActivateTests` | ✅ | versioned activation; UI reflects server-confirmed state only |
| CCG-REQ-030 Read-only voice | `test_voice::VoiceAvailableTests::test_acc13_no_mutation_capability_exposed`, `VoiceCorrelationTests` | | no mutation/gateway path; correlation propagated |
| CCG-REQ-031 Voice interruption | `test_voice::test_acc13_interruption_sets_flag_and_session_continues` | | barge-in -> INTERRUPTED, session continues |
| CCG-REQ-032 Voice disabled default | `test_voice::VoiceDisabledTests`, `VoiceConsentTests` | | off by default; consent required; no stream/mic |
| CCG-REQ-033 Voice fallback | `test_voice::VoiceUnavailableTests` | | adapter/mock failure path, no raise; live Nova Sonic gated on 0.3 |
| CCG-REQ-034 Structured logging | `test_audit`, `test_discovery_audit`, `test_seed::test_correlation_id_present_in_structured_log` | | correlation/request/timestamp fields |
| CCG-REQ-035 Sensitive data | `test_audit::RedactionTests`, `test_voice::VoiceRedactionTests`/`VoiceNoRawAudioTests`, `test_tools::test_no_secret_material...` | | secrets/tokens/raw audio excluded |
| CCG-REQ-036 Audit retention | `test_persistence::RetentionAndSerializationTests`; `tests/storage_retention.tftest.hcl` (S1-S3 30d S3, C1 7d CW), `tests/terraform/storage_retention.md` (V1-V3) | | 30d S3 / 7d CW enforced in Terraform |
| CCG-REQ-037 Operational alarms | `test_observability`; `tests/discovery_runtime.tftest.hcl` (DR11-DR12, DR14 real CloudWatch alarms) | | metric catalog + real failure alarms |
| CCG-REQ-038 Cost boundary | `tests/discovery_runtime.tftest.hcl` (DR3-DR6, DR15 serverless/no-NAT/bounded), `tests/storage_retention.tftest.hcl` (D1 on-demand DynamoDB), `tests/iam_negative_permissions.tftest.hcl` | | serverless-only, validated var constraints |
| CCG-REQ-039 Manual apply | `.github/workflows/ci.yml` | | CI validates, never applies |
| CCG-REQ-040 Teardown | `test_seed::CleanupBoundTests` (bounded cleanup), `scripts/seed_drift.py` gate; runbook `docs/DEPLOY_RUNBOOK.md` | | cleanup only self-created seed resources; live teardown rehearsal in task 6.5 |

## Acceptance scenarios

| Scenario | Covered by | FT |
|---|---|---|
| ACC-01 discover deterministic finding | `test_discovery`, `test_demo` | ✅ |
| ACC-02 deny while inactive | `test_demo::test_denied_before_activation`, `test_gateway`, `test_gateway_live_path::test_default_deny_when_inactive` | ✅ |
| ACC-03 allow + single execution | `test_demo::test_tool_executes_exactly_once`, `test_gateway_live_path::test_allow_after_activation` | ✅ |
| ACC-04 prod denied even with permit | `test_authz::test_forbid_overrides_active_permit_for_prod`, `test_policy_scenarios`, `test_gateway_live_path::test_forbid_overrides_permit_prod_tag` | ✅ |
| ACC-05 missing CCGDemo denied | `test_authz::test_missing_demo_tag_denies...`, `test_gateway_live_path::test_forbid_overrides_permit_missing_demo_tag` | ✅ |
| ACC-06 forbid precedence with evidence | `test_authz`, `test_gateway::test_forbid_overrides_active_permit`, `test_gateway_live_path` | ✅ |
| ACC-07 idempotent repeat | `test_gateway::test_repeated_idempotency_key...`, `test_demo::test_repeat_is_idempotent`, `test_gateway_live_path::test_idempotent_replay_no_double_execution` | ✅ |
| ACC-08 activation audit + version | `test_policy_api_voice::test_activation_is_audited...`, `test_activation_control_plane::SuccessfulActivationTests`/`MutationsRemainDeniedAfterFailureTests` | ✅ |
| ACC-09 stale/replay rejected | `test_policy_api_voice::test_stale_generation_is_rejected`, `test_activation_control_plane::StaleGenerationTests`/`ReplayTests` | ✅ |
| ACC-10 partial discovery, no false compliance | `test_sources::test_coordinator_marks_run_partial...`, `test_reconcile` | |
| ACC-11 unregistered/malformed denied | `test_gateway::test_unknown_tool_is_denied`, `test_policy_scenarios::UnregisteredToolTests`, `test_api_control_plane::RuleToolValidationTests`, `test_gateway_live_path::test_unknown_tool_denied` | ✅ |
| ACC-12 voice off | `test_policy_api_voice::test_voice_is_disabled_by_default...`, `test_voice::VoiceDisabledTests` | |
| ACC-13 voice read-only + interrupt | `test_voice::test_acc13_enabled_with_consent_streams_summary`, `test_acc13_interruption_sets_flag_and_session_continues`, `test_acc13_no_mutation_capability_exposed` | |
| ACC-14 uncertain tool stays unresolved | `test_reconcile::test_failed_outcome_never_resolves...` | |
| ACC-15 CI validates, no apply | `.github/workflows/ci.yml` | |

ACC-13 is now **fully covered** offline (read-only streaming summary, barge-in
interrupt handling, and the structural no-mutation-path guarantee all have
tests); only the live Nova Sonic transport binding is gated on 0.3.

## End-to-end

### Offline (CI, no AWS) — faithful stand-in

`src/ccg/demo.py` + `tests/test_demo.py` chain discover → deny → audited
activation → allow → single execution → idempotent replay →
reconcile-to-RESOLVED, running through the **faithful AgentCore transport
emulator** (`AgentCoreGatewayClient` + `FaithfulAgentCoreEmulator`) with no AWS.
This is the faithful stand-in for the live sandbox e2e below.

### Sandbox-only (gated on 0.2) — `tests/test_sandbox_e2e.py`

The live-AWS chain (discovery → deny → activation → allow/no-op → rediscovery
against a real sandbox) is **skipped by default** and makes **no AWS calls**
unless opted in. Enabling it requires **both** `CCG_SANDBOX_E2E=1` (operator
intent flag, mirroring the `CCG_SANDBOX` gate in `scripts/seed_drift.py`) **and**
the live wiring from implementation gate 0.2. Until 0.2 is complete the scaffold
fails loudly with a "gated on 0.2" message rather than passing silently; the
ordered steps it must perform are recorded in `E2E_STEPS`, and always-on plan
tests keep that chain complete and ordered. See `tests/README.md` for details.

## Coverage completeness

Every requirement **CCG-REQ-001..040** and every acceptance scenario
**ACC-01..15** has at least one covering test above. No item is unmapped. The
only coverage that remains behind an implementation gate (and is explicitly
noted inline) is the *live-AWS binding* of otherwise-proven behavior:

- the live transport/schema binding of the Gateway and control plane (**0.2**);
- the live Cognito user pool and Terraform-applied sandbox (**0.2**);
- the live Nova Sonic voice transport (**0.3**); and
- the live sandbox end-to-end run (**0.2**, faithful offline stand-in: `test_demo`).
