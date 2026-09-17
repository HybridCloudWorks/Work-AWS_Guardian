# Test Traceability Matrix

Maps EARS requirements (`requirements.md` §4) and acceptance scenarios (§5) to the tests that cover them **offline** (behind test doubles, Python 3.14). "Gated on 0.2" means the offline behavior is proven but the live-AWS path (real Gateway schema, boto3 transports, Cognito, Terraform) still requires the sandbox account.

**Last updated:** 2026-09-15 · Suite: 108 tests passing.

## Requirements coverage

| Requirement | Covered by | Notes |
|---|---|---|
| CCG-REQ-001 Scheduled discovery | `test_discovery`, `test_discovery_audit` | EventBridge trigger itself gated on 0.2 |
| CCG-REQ-002 Read-only discovery | `test_sources` | adapters have no write path by construction |
| CCG-REQ-003 Normalized finding | `test_discovery_merge`, `test_sources` | deterministic fields + mapping |
| CCG-REQ-004 Finding identity | `test_discovery_merge::test_finding_id_is_deterministic...` | sha256(rule:arn) |
| CCG-REQ-005 Current state + audit history | `test_persistence`, `test_audit` | live DynamoDB/S3 gated on 0.2 |
| CCG-REQ-006 Partial source failure | `test_sources::SourceFailureIsolationTests` | throttle/unauthorized -> partial run |
| CCG-REQ-007 Duplicate/stale events | `test_discovery_merge::CoordinatorDedupTests` | dedup, no revision churn |
| CCG-REQ-008 Mandatory Gateway boundary | `test_gateway`, `test_api_authorization` | mutations only via Gateway port |
| CCG-REQ-009 No direct authorization | `test_api_authorization::test_api_never_authorizes_locally...` | target resolved server-side |
| CCG-REQ-010 Default deny | `test_authz::test_inactive_permit_denies` | |
| CCG-REQ-011 Forbid precedence | `test_authz::test_forbid_overrides_active_permit_for_prod` | forbid overrides permit |
| CCG-REQ-012 Mutation sandbox gate | `test_authz`, `test_tools::SafetyRecheckTests` | CCGDemo required, prod denied (defense in depth) |
| CCG-REQ-013 Registered action catalog | `test_authz::test_unregistered_tool_denies_first`, `test_tools` | four tools only |
| CCG-REQ-014 Policy inactive default | `test_gateway::test_inactive_permit_defaults_to_deny...` | forbids still enforced |
| CCG-REQ-015 Audited activation | `test_policy_api_voice::test_activation_is_audited...` | intent + result events |
| CCG-REQ-016 Activation result / deny-safe | `test_policy_api_voice::test_activation_failure_is_deny_safe` | |
| CCG-REQ-017 Version & concurrency | `test_policy_api_voice::test_stale_generation_is_rejected` | optimistic concurrency |
| CCG-REQ-018 Policy visibility | `test_api_authorization::test_get_policy_state_requires_authentication` | display value never authorizes |
| CCG-REQ-019 Decision evidence | `test_authz::test_decision_evidence_is_populated` | matched policy IDs, version |
| CCG-REQ-020 Schema safety | partial (`test_authz`) | full schema-mismatch deny gated on 0.2 |
| CCG-REQ-021 Security-group correction | `test_tools::SecurityGroupTests` | no-op on compliant, rejects global-open |
| CCG-REQ-022 S3 encryption | `test_tools::S3EncryptionTests` | no-op if already encrypted |
| CCG-REQ-023 Compliant tagging | `test_tools::TaggingTests` | never sets prod, never weakens demo tag |
| CCG-REQ-024 Access-key rotation | `test_tools::AccessKeyRotationTests` | dry-run default, no secret material |
| CCG-REQ-025 Idempotency | `test_gateway::test_repeated_idempotency_key...`, `test_reconcile` | |
| CCG-REQ-026 Tool failure | `test_reconcile::test_failed_outcome_never_resolves...` | no false compliance |
| CCG-REQ-027 Authenticated console | `test_api_authorization` (read endpoints) | Cognito wiring gated on 0.2 |
| CCG-REQ-028 Server-side authorization | `test_api_authorization` | not client-state driven |
| CCG-REQ-029 Admin control | `test_policy_api_voice::test_non_admin_cannot_activate` | |
| CCG-REQ-030..033 Voice | `test_policy_api_voice::test_voice_is_disabled_by_default...` | off by default, no Gateway |
| CCG-REQ-034 Structured logging | `test_audit`, `test_discovery_audit` | correlation/request/timestamp fields |
| CCG-REQ-035 Sensitive data | `test_audit::RedactionTests`, `test_tools::test_no_secret_material...` | |
| CCG-REQ-036 Audit retention | `test_persistence::RetentionAndSerializationTests` | 30d S3 / 7d CW enforced in Terraform |
| CCG-REQ-037 Operational alarms | `test_observability` | metric catalog; CloudWatch wiring gated on 0.2 |
| CCG-REQ-038 Cost boundary | Terraform variables (`variables.tf`) | serverless-only, validated var constraints |
| CCG-REQ-039 Manual apply | `.github/workflows/ci.yml` | CI validates, never applies |
| CCG-REQ-040 Teardown | pending (task 6.5) | runbook + cleanup tests |

## Acceptance scenarios

| Scenario | Covered by |
|---|---|
| ACC-01 discover deterministic finding | `test_discovery`, `test_demo` |
| ACC-02 deny while inactive | `test_demo::test_denied_before_activation`, `test_gateway` |
| ACC-03 allow + single execution | `test_demo::test_tool_executes_exactly_once` |
| ACC-04 prod denied even with permit | `test_authz::test_forbid_overrides_active_permit_for_prod` |
| ACC-05 missing CCGDemo denied | `test_authz::test_missing_demo_tag_denies...` |
| ACC-06 forbid precedence with evidence | `test_authz`, `test_gateway::test_forbid_overrides_active_permit` |
| ACC-07 idempotent repeat | `test_gateway::test_repeated_idempotency_key...` |
| ACC-08 activation audit + version | `test_policy_api_voice::test_activation_is_audited...` |
| ACC-09 stale/replay rejected | `test_policy_api_voice::test_stale_generation_is_rejected` |
| ACC-10 partial discovery, no false compliance | `test_sources::test_coordinator_marks_run_partial...` |
| ACC-11 unregistered/malformed denied | `test_gateway::test_unknown_tool_is_denied`, `test_api_authorization` |
| ACC-12 voice off | `test_policy_api_voice::test_voice_is_disabled_by_default...` |
| ACC-13 voice read-only + interrupt | partial; live Nova Sonic gated on 0.3 |
| ACC-14 uncertain tool stays unresolved | `test_reconcile::test_failed_outcome_never_resolves...` |
| ACC-15 CI validates, no apply | `.github/workflows/ci.yml` |

## End-to-end

`src/ccg/demo.py` + `tests/test_demo.py` chain discover → deny → audited activation → allow → single execution → idempotent replay → reconcile-to-RESOLVED, and run in CI with no AWS.
