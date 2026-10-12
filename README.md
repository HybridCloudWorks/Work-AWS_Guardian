# Continuous Compliance Guardian (CCG)

> **Status: POC — nothing is deployed to any cloud account.** The offline domain model and the full test/validation suite are complete; all live-AWS paths are feature-flagged off and gated on a capability-capture step (0.2/0.3). The sandbox is a verified clean slate; all Terraform is validated but unapplied.

AWS sandbox proof-of-concept that detects Well-Architected **Security-pillar** drift and proves that every remediation is authorized at an **external Amazon Bedrock AgentCore Cedar policy boundary** — never by a prompt, UI state, or application boolean.

## What actually works today

- **Offline domain model** (`src/ccg/`, Python 3.14): discovery normalization, Cedar-first authorization model with a faithful AgentCore transport emulator, four idempotent remediation tools, audited policy-activation control plane, finding-reconciliation lifecycle, Cognito/API control plane, read-only Nova Sonic voice mock, and a redacting audit sink.
- **Validation:** 388 Python tests + 15 Terraform native tests + 14 console tests, all green in CI (plus CodeQL and secret scanning).
- **Runnable end-to-end demo, no AWS required:**
  ```bash
  PYTHONPATH=src python -m ccg.demo
  ```
  Chains discover → deny (permits inactive) → audited activation → allow → single idempotent execution → reconcile-to-RESOLVED.
- **Terraform** (repo root is the Terraform root — there is no `terraform/` subdir; see [`README-terraform.md`](README-terraform.md) for the layout): storage, least-privilege IAM, discovery, gateway/policy, console-api, and voice-adapter modules, all validated via HCP speculative plans and **off by default** (every `enable_*` flag defaults `false`).

## Honest status of the safety guarantee

The Cedar-first guarantee is **designed, implemented, and tested as an offline model** — the production gateway client defers the decision to the transport (no local allow/deny substitute) and is exercised against a faithful AgentCore emulator so no "green" result rests on an in-memory double alone. It is **not yet enforced against real AWS**: live enforcement requires the capability-capture step (0.2) to confirm the generated Cedar schema, real action IDs, and the live transport. Treat the boundary as unproven against real AWS until that live capture and a reviewed enforcement activation are done. The deployed engine mode is `LOG_ONLY` by default; flipping to enforce is an audited, control-plane-only activation.

## Key documents

| Doc | Purpose |
|---|---|
| [`docs/review/CCG_REVIEW_REPORT.md`](docs/review/CCG_REVIEW_REPORT.md) | Full code/security/architecture review (findings register) |
| [`docs/review/CCG_REMEDIATION_TODO.md`](docs/review/CCG_REMEDIATION_TODO.md) | Prioritized remediation backlog |
| [`docs/adr/`](docs/adr/) | Architecture Decision Records |
| [`docs/diagrams/`](docs/diagrams/) | Editable `.drawio` architecture diagrams (+ PNG exports) |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Trust boundaries & threats (being corrected per review C1) |
| [`docs/DEPLOY_RUNBOOK.md`](docs/DEPLOY_RUNBOOK.md) | HCP schema-capture deploy procedure |
| [`.kiro/specs/continuous-compliance-guardian/`](.kiro/specs/continuous-compliance-guardian/) | EARS requirements, design, tasks |

## Safety

Use a dedicated sandbox account only. Remediation is off by default. No credentials, Terraform state, or production data belong in this repository.

## Quick start (validation only — no apply)

```bash
# Python model + tests
PYTHONPATH=src python -m pytest -q
PYTHONPATH=src python -m ccg.demo

# Terraform (validate only; state + apply live in HCP Terraform Cloud)
terraform init -backend=false
terraform validate
```

Applies are triggered by the reviewed VCS/HCP workflow after a human-approved plan — never from CI, never locally.
