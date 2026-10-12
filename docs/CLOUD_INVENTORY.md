# Cloud Inventory — Sandbox Account

**Captured:** 2026-09-18 (read-only probes; nothing was created or modified)
**Account:** `<SANDBOX_ACCOUNT_ID>` (redacted; a dedicated non-production sandbox account)
**Region:** `us-east-1`
**Identity:** SSO role `cloud-sandbox` (`AWSReservedSSO_cloud-sandbox_...`), operated by the sandbox SSO operator
**Profile:** `ccg-sandbox`

All values below come from read-only AWS API calls (`list-*`, `describe-*`, `get-caller-identity`). No mutation was performed. The `cloud-sandbox` role is intentionally scoped — some account-level IAM reads are denied, which is expected and noted.

## CCG-relevant resources

| Area | Command | Result | Meaning for CCG |
|---|---|---|---|
| **AgentCore gateways** | `bedrock-agentcore-control list-gateways` | `{ items: [] }` | Clean slate — no Gateway exists yet. A gate-0.2 deploy would be the first. |
| **AgentCore policy engines** | `bedrock-agentcore-control list-policy-engines` | `{ policyEngines: [] }` | No policy engine yet. |
| **DynamoDB tables** | `dynamodb list-tables` | `[]` | The `ccg-poc-drift` findings table is **not deployed**. |
| **CloudWatch log groups** (`/ccg`) | `logs describe-log-groups --log-group-name-prefix /ccg` | `[]` | The `/ccg/...` log group is **not deployed**. |
| **S3 buckets** | `s3api list-buckets` | `elasticbeanstalk-us-east-2-<SANDBOX_ACCOUNT_ID>` (unrelated) | The `ccg-poc-audit-*` bucket is **not deployed**. The one existing bucket is a stray Elastic Beanstalk bucket in us-east-2, unrelated to CCG. |
| **Lambda functions** | `lambda list-functions` | `aws-nuke` (unrelated) | No CCG functions. `aws-nuke` suggests this sandbox is periodically wiped by a cleanup tool — relevant to teardown planning. |
| **Bedrock foundation models** | `bedrock list-foundation-models` | 115 models available | Bedrock is enabled and readable. |
| **Nova Sonic** | filter `nova` model IDs | **`amazon.nova-2-sonic-v1:0` present** (also nova-pro/lite/micro/canvas/reel) | Fills capability-record §4: the voice model **is available** in us-east-1. Voice stays off-by-default regardless. |

## Access boundaries observed (least-privilege confirmation)

The `cloud-sandbox` role could **not** perform these — which is the desired scoped posture, not a problem:

- `iam:ListAccountAliases` → `AccessDenied`
- `iam:ListOpenIDConnectProviders` → `AccessDenied`

**Consequence:** the HCP Terraform OIDC provider (`app.terraform.io`) and the `TFC_AWS_RUN_ROLE_ARN` cannot be verified from this role. Those must be confirmed via an admin/console check and recorded in `AGENTCORE_CAPABILITY_RECORD.md` §0. (Terraform applies run in HCP via OIDC, independent of this CLI session.)

## Summary

**Nothing CCG-related is currently deployed.** The account is effectively a clean slate for the POC: no gateway, policy engine, findings table, audit bucket, log group, or CCG Lambda. Bedrock (incl. Nova 2 Sonic) is available. A periodic `aws-nuke` presence indicates the sandbox is auto-cleaned, which the teardown runbook (task 6.5) should account for.

## What this inventory does NOT authorize

Confirming the account is empty does not authorize creating anything. A gate-0.2 Gateway/target/Lambda deploy remains blocked on the Phase 1.2 threat-model review and an explicit, reviewed Terraform plan.
