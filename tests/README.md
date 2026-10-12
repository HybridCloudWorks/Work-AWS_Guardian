# Tests

The suite proves the Continuous Compliance Guardian behavior **offline** (behind
test doubles and a faithful AgentCore transport emulator, Python 3.14) plus
credential-free Terraform and console checks. No test makes a live AWS call.

Full requirement/scenario coverage is tracked in
[`docs/TEST_TRACEABILITY.md`](../docs/TEST_TRACEABILITY.md).

## Running

Python (from the repository root):

```
PYTHONPATH=src python -m pytest tests/ -v
```

Terraform (credential-free native tests; from the repository root):

```
terraform init -backend=false -input=false
terraform test
```

Console (from `console/`):

```
npm test
```

## Layers

| Layer | Files | What it proves |
|---|---|---|
| Contract | `test_contracts.py` | Typed finding/command/decision contracts, validation, determinism. |
| Policy / authz | `test_authz.py`, `test_policy_scenarios.py` | Cedar-model decisions: default deny, forbid precedence, sandbox gate, evidence. |
| Gateway (double) | `test_gateway.py` | Boundary + audit emission through the in-memory Cedar gateway. |
| Gateway (faithful transport) | `test_gateway_live_path.py` | The **same** scenario matrix re-run against `AgentCoreGatewayClient` + `FaithfulAgentCoreEmulator` so no "green" rests solely on the double. |
| Activation control plane | `test_activation_control_plane.py` | Audited activation, stale/replay, uncertain-propagation fail-closed, live-transport seam (fake client, no boto3). |
| API control plane | `test_api_authorization.py`, `test_api_control_plane.py` | Server-side authz, tool/rule validation (P0.4c/d), decision-evidence read, Cognito JWT resolver. |
| Tools | `test_tools.py` | Four registered tools: scoped change, no-op, no secret material, dry-run key rotation. |
| Discovery | `test_discovery*.py`, `test_sources.py`, `test_reconcile.py` | Deterministic findings, dedup, partial-source isolation, reconcile-to-resolved. |
| Persistence / audit | `test_persistence.py`, `test_audit.py` | DynamoDB/S3 shaping, retention, structured logging, redaction, fail-closed sinks. |
| Observability | `test_observability.py` | Metric catalog covering the CCG-REQ-037 signal families. |
| Voice | `test_voice.py` | Off by default, consent gate, read-only, barge-in, redaction, no mutation path. |
| Seed | `test_seed.py` | Sandbox-only seed/cleanup with a `CCG_SANDBOX` + confirmation gate; dry-run default. |
| HTTP | `test_http.py` | API HTTP adapter wiring. |
| Preflight | `test_gate02_preflight.py` | Captures what gate 0.2 must confirm before live wiring. |
| End-to-end (offline) | `test_demo.py` | discover -> deny -> audited activation -> allow -> single execution -> idempotent replay -> reconcile, through the faithful transport, in CI with no AWS. |
| End-to-end (sandbox) | `test_sandbox_e2e.py` | **Skipped by default.** Gated on `CCG_SANDBOX_E2E=1` **and** implementation gate 0.2. See below. |
| Terraform | `*.tftest.hcl` | Retention, IAM negative permissions, discovery runtime + alarms, Gateway/policy wiring — all credential-free. |

## Sandbox-only end-to-end (`test_sandbox_e2e.py`)

The real-AWS chain — discovery → deny → activation → allow/no-op → rediscovery
against a live sandbox — is the one flow the offline matrix cannot prove by
itself. It is **skipped by default** and makes **no AWS calls** unless opted in.

Enabling it requires **both**:

1. `CCG_SANDBOX_E2E=1` — operator intent flag (mirrors the `CCG_SANDBOX` gate
   used by `scripts/seed_drift.py` and `test_seed.py`); and
2. the live-AWS wiring from implementation **gate 0.2**: the captured AgentCore
   Gateway schema + Cedar entity/action mapping, the confirmed control-plane
   activation API, Cognito, and a Terraform-applied sandbox.

Until 0.2 is complete the live class is a scaffold: with the flag set it fails
loudly with a "gated on 0.2" message (never a silent pass), and the ordered
steps it must perform are recorded in `E2E_STEPS` so the live implementation is
a mechanical fill-in rather than a redesign. Always-on `*PlanTests` assert the
plan stays complete and ordered even while the live body is pending.

**Today's faithful stand-in:** `test_demo.py` runs the identical chain through
the faithful AgentCore transport emulator with no AWS, so the behavior is proven
offline; only the live transport/schema binding waits on 0.2.
