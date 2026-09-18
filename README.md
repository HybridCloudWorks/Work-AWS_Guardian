# Continuous Compliance Guardian (CCG)

> **Status: planning-stage POC. Nothing is deployed to any cloud account.** The sandbox is a verified clean slate. All Python is an offline domain model behind test doubles; all Terraform is validated but unapplied (feature-flagged off).

AWS sandbox proof-of-concept that detects Well-Architected **Security-pillar** drift and proves that every remediation is authorized at an **external Amazon Bedrock AgentCore Cedar policy boundary** — never by a prompt, UI state, or application boolean.

## What actually works today

- **Offline domain model** (`src/ccg/`, Python 3.14, 117 passing tests): discovery normalization, Cedar-first authorization *model*, four idempotent remediation tools, audited policy-activation service, finding-reconciliation lifecycle, redacting audit sink.
- **Runnable end-to-end demo, no AWS required:**
  ```bash
  PYTHONPATH=src python -m ccg.demo
  ```
  Chains discover → deny (permits inactive) → audited activation → allow → single idempotent execution → reconcile-to-RESOLVED.
- **Terraform** (repo root is the Terraform root — there is no `terraform/` subdir): storage, least-privilege IAM policy documents, and a feature-flagged AgentCore Gateway + Policy Engine, all validated via HCP speculative plans and **off by default** (`enable_agentcore_gateway = false`).

## Honest status of the safety guarantee

The Cedar-first guarantee is **designed and tested as an offline model**, but is **not yet enforced in any deployable configuration**. See the review below — in particular, the deployed engine mode (`LOG_ONLY`) does **not** enforce decisions, and the production gateway client is currently a pass-through. Treat the boundary as unproven against real AWS until the enforcement work in the remediation plan is done.

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
