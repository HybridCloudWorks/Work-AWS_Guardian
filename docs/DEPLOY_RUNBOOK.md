# Deploy Runbook — Minimal AgentCore Schema-Capture

**Purpose:** the exact, reviewed steps to deploy the smallest AgentCore footprint (Gateway + Policy Engine, permits inactive) so the remaining gate-0.2 capture items can be recorded, then tear it down. This is the first real AWS mutation in the project.

**Preconditions (all satisfied unless noted):**
- Phase 1.2 threat model reviewed → `docs/THREAT_MODEL.md`
- Terraform for the resources merged and validated (PRs #9–#11); `enable_agentcore_gateway` defaults `false`
- Sandbox `<SANDBOX_ACCOUNT_ID>` / `us-east-1` confirmed empty (`docs/CLOUD_INVENTORY.md`)
- ⚠️ **Unverified:** the HCP workspace's `TFC_AWS_RUN_ROLE_ARN` OIDC run role. The `cloud-sandbox` CLI role cannot read IAM providers, so confirm via console before applying (see step 1).

## Who does what

Terraform **state and applies run in HCP Terraform Cloud** (workspace `compliance_guardian`), authenticated to AWS via OIDC. The CLI session on a workstation is for **read-only capture only** — it does not and cannot apply. The apply is approved by a human in HCP.

## Step 1 — Confirm the HCP → AWS OIDC run role (one-time)

In the AWS console (or with an admin role), confirm:
- an IAM OIDC provider for `app.terraform.io` exists, and
- the run role referenced by the workspace variable `TFC_AWS_RUN_ROLE_ARN` exists and trusts that provider, scoped to this workspace.

Record the run-role ARN (redacted) in `docs/AGENTCORE_CAPABILITY_RECORD.md` §0. If this is missing, the apply fails on AWS auth even though the plan is valid.

## Step 2 — Enable the flag

Set the workspace variable (or tfvars) `enable_agentcore_gateway = true`. Keep every other variable at its default. Leave it `true` only for the duration of capture.

## Step 3 — Review the plan in HCP

Trigger a run. The plan MUST create exactly these and nothing else:

| Resource | Expectation |
|---|---|
| `aws_iam_role.gateway_execution` (`ccg-poc-gateway-exec`) | trust = `bedrock-agentcore.amazonaws.com`, `aws:SourceAccount` guard |
| `aws_iam_role_policy.gateway_execution` | invoke `ccg-poc-tool-*` + logs only |
| `aws_bedrockagentcore_policy_engine.this` (`ccg-poc-policy-engine`) | no `encryption_key_arn` (AWS-managed keys) |
| `aws_bedrockagentcore_gateway.this` (`ccg-poc-gateway`) | `protocol_type=MCP`, `authorizer_type=AWS_IAM`, `policy_engine_configuration.mode = "LOG_ONLY"` |

**Reject the plan if** it shows `mode = "ENFORCE"`, any `Environment=prod` target, a KMS key, or any resource beyond the four above. These are the threat-model deploy-gate conditions.

## Step 4 — Approve the apply

Approve in HCP. This creates the four resources. No permit is enforced (`LOG_ONLY`), so no mutation can be authorized yet — this is deliberate.

## Step 5 — Post-deploy capture (read-only CLI)

With the Gateway live, capture the items in `AGENTCORE_CAPABILITY_RECORD.md` that require a running Gateway. All read-only:

```bash
export AWS_PROFILE=ccg-sandbox AWS_PAGER="" AWS_DEFAULT_REGION=us-east-1
aws sso login --profile ccg-sandbox          # if the SSO token expired

GW=$(aws bedrock-agentcore-control list-gateways --query 'items[0].gatewayId' --output text)
aws bedrock-agentcore-control get-gateway --gateway-identifier "$GW"      # §1 gateway shape
aws bedrock-agentcore-control list-gateway-targets --gateway-identifier "$GW"

PE=$(aws bedrock-agentcore-control list-policy-engines --query 'policyEngines[0].policyEngineId' --output text)
aws bedrock-agentcore-control get-policy-engine --policy-engine-id "$PE"
```

Record into the capability record:
- **§1** generated action identifier(s), principal/entity type, resource representation, request-input **context shape**
- **§2** whether `CCGDemo`/`Environment`/target-ARN reach Cedar via injected context vs. caller-supplied (resolves threat **T2**, the one HIGH residual) — if caller-supplied, the tool Lambda must resolve target identity/tags server-side
- **§3** confirm `UpdatePolicy` request-ID + any optimistic-concurrency field at runtime

Do **not** register a real tool target or activate a permit during capture.

## Step 6 — Teardown

The sandbox runs `aws-nuke` (see `docs/CLOUD_INVENTORY.md`), so resources may be auto-removed. To tear down deliberately: set `enable_agentcore_gateway = false` and apply — the four resources are destroyed. The design uses no data that must survive (audit bucket is separate and not created by this flag). Re-deploy is idempotent from this flag.

## Rollback / fail-closed

If the apply is partial or ambiguous, the Gateway is bound `LOG_ONLY` and no permit is active, so no mutation can be authorized regardless. Never flip to `ENFORCE` as part of deploy; enforcement is a separate audited `UpdatePolicy` activation covered by `src/ccg/policy.py`.
