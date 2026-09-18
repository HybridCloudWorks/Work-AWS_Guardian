# ADR 0005 — Pin AWS provider 6.64.0; state and apply in HCP via OIDC

**Status:** Accepted
**Date:** 2026-09-18

## Context
AgentCore resources require a recent AWS provider. State must not live in Git; applies must be reviewable and use short-lived credentials.

## Decision
Pin `hashicorp/aws = 6.64.0` (the version whose AgentCore Gateway/Target/PolicyEngine/Policy schemas were verified via `terraform providers schema -json`). Use HCP Terraform Cloud (org `hcw`, workspace `compliance_guardian`) as the sole backend; authenticate to AWS via HCP OIDC dynamic credentials (`TFC_AWS_PROVIDER_AUTH` / `TFC_AWS_RUN_ROLE_ARN`). No static credentials in the repo. Applies are human-approved in HCP.

## Consequences
- **Positive:** no long-lived keys; reviewable plans; verified provider schema.
- **Open items:** the HCP OIDC run role could not be verified from the scoped `cloud-sandbox` CLI role (`iam:ListOpenIDConnectProviders` denied) — confirm via admin/console before the first apply (review + capability record §0).
- Submodules currently lack their own `required_providers` (review M-tf); the pin is root-only. Add per-module constraints for reusability.
- CI pins a Terraform *runtime* version that does not exist (`1.15.8`, review M8) — fix to a real 1.x.
