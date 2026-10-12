# IAM negative-permission verification (task 2.3)

Task 2.3 exit criterion: *IAM policy review and negative permission tests show
discovery cannot mutate, console cannot bypass Gateway, and tools cannot
activate policy.*

Live IAM policy simulation (`iam:SimulatePrincipalPolicy`) requires credentials
that CI does not carry. This document is the credential-free verification
artifact: it enumerates every negative-permission assertion, names the exact
statement that enforces it, and states the expected outcome.

Most of these are additionally machine-checked by
`tests/iam_negative_permissions.tftest.hcl` (Terraform native tests, no
credentials): it renders each policy document (via a real AWS provider whose
`aws_iam_policy_document` is computed locally with no API calls), decodes the
JSON, and asserts both that the expected **Deny** statements are present
(N1/N3/N4/N6/N7) and that the forbidden **Allow** actions are absent
(N2/N5/N7). What that native test cannot do is prove runtime *evaluation* order
against the live IAM engine — that is what `iam:SimulatePrincipalPolicy` on a
reviewed credentialed run covers, and the per-row expectations below are the
checklist for it.

All statement names below refer to `modules/iam-policies/main.tf`.

## Separation-of-duties summary

| Role | May | May NOT |
|---|---|---|
| discovery | read Config/SecurityHub/CloudTrail, write findings table + audit objects + logs | mutate any resource, assume a role, stop/delete CloudTrail, touch IAM |
| tool_execution | narrow remediation on sandbox SGs / explicit sandbox buckets / tagging | activate policy, touch prod-tagged targets, disable CloudTrail, make a bucket public |
| control_plane | activate AgentCore policy + reconciliation reads | perform any remediation mutation |
| api (console) | read findings + audit, assume control-plane for activation | remediate, activate policy directly, invoke tool Lambdas (Gateway bypass) |
| audit_reader | read audit bucket | everything else |

> **Document structure:** each role's allow statements and its deny statements
> live in the *same* `aws_iam_policy_document` (the deny statements are inlined
> rather than chained via a separate `_boundary` document). A Deny is always
> evaluated before an Allow, so the guarantee is identical; inlining is what
> lets `tests/iam_negative_permissions.tftest.hcl` render and assert the policy
> without AWS credentials.

## N1 — Discovery cannot mutate

Enforced by `data.aws_iam_policy_document.discovery` → statement
`DenyResourceMutation` (effect **Deny**, resources `*`). A deny is evaluated
before any allow, so these are blocked regardless of any additive allow.

| # | Denied action(s) | Expected |
|---|---|---|
| N1.1 | `ec2:AuthorizeSecurityGroupIngress`, `ec2:RevokeSecurityGroupIngress` | implicit/explicit **Deny** |
| N1.2 | `s3:PutBucketPolicy`, `s3:PutBucketAcl` | explicit **Deny** |
| N1.3 | `iam:*` | explicit **Deny** |
| N1.4 | `sts:AssumeRole` | explicit **Deny** (discovery cannot escalate by assuming another role) |
| N1.5 | `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail` | explicit **Deny** (audit integrity) |

Discovery's only writes are `WriteFindings` (findings table ARN only),
`WriteAuditObjects` (audit bucket, SSE required), and `WriteLogs` (log group).
It has no remediation allow at all.

## N2 — Tools cannot activate policy

There is **no** `bedrock-agentcore:UpdatePolicy` (or any `bedrock-agentcore:*`)
allow in `data.aws_iam_policy_document.tool_execution`, and nothing elsewhere
grants it to the tool role. Policy activation lives only in `control_plane`.

| # | Assertion | Expected |
|---|---|---|
| N2.1 | tool_execution policy JSON contains no `bedrock-agentcore:` action | absent |
| N2.2 | tool role → policy activation path | **impossible** (no grant exists) |

## N3 — Tools cannot touch production

Enforced by `data.aws_iam_policy_document.tool_execution` → statement
`DenyProductionTargets` (effect **Deny**, actions `*`) conditioned on
`aws:ResourceTag/Environment = prod`.

| # | Target | Expected |
|---|---|---|
| N3.1 | any action on a resource tagged `Environment=prod` | explicit **Deny** |

Belt-and-suspenders with the Cedar `Environment=prod` forbid (always-on).

## N4 — Tools cannot disable audit or make buckets public

Enforced by `tool_execution` → statement `DenyPolicyAndTrailControl`:
denies `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`,
`s3:PutBucketPublicAccessBlock`, `s3:PutBucketAcl`.

## N5 — Tool S3 scope is explicit ARNs, not a wildcard (P1.3 / H1)

`data.aws_iam_policy_document.tool_execution` → statement
`S3EncryptionEnablement` resources resolve to either the explicit
`var.remediation_bucket_arns` list or the `${name_prefix}-sandbox-*` prefix —
never `arn:aws:s3:::*`.

| # | Assertion | Expected |
|---|---|---|
| N5.1 | `S3EncryptionEnablement` resources do not contain `arn:aws:s3:::*` | true |
| N5.2 | S3 remediation uses no `aws:ResourceTag` condition (unenforceable on bucket-level actions) | true — enforcement is explicit ARN + Lambda-layer live recheck |

> **Why the tag condition was removed here:** S3 bucket-level actions such as
> `s3:PutEncryptionConfiguration` do not honor the `aws:ResourceTag` condition
> key, so the previous `arn:aws:s3:::*` + tag condition was silently
> unenforceable and effectively allowed the action on every bucket. The sandbox
> gate for S3 is now explicit-ARN scoping plus the Lambda-layer `CCGDemo` /
> `Environment` recheck. The EC2 security-group statement keeps its tag
> condition because `aws:ResourceTag` *is* supported there.

## N6 — Control plane cannot remediate

Enforced by `data.aws_iam_policy_document.control_plane` → statement
`DenyRemediationActions` (effect **Deny**): denies
`ec2:AuthorizeSecurityGroupIngress`, `ec2:RevokeSecurityGroupIngress`,
`s3:PutEncryptionConfiguration`, `iam:CreateAccessKey`, `iam:DeleteAccessKey`,
`iam:UpdateAccessKey`.

| # | Assertion | Expected |
|---|---|---|
| N6.1 | control_plane may `bedrock-agentcore:UpdatePolicy` | **Allow** (its only job) |
| N6.2 | control_plane may perform any remediation mutation | explicit **Deny** |

## N7 — Console/API cannot bypass the Gateway

The console/API role (`data.aws_iam_policy_document.api`) has:

- **Allow**: `dynamodb:GetItem`/`Query` on the findings table, `s3:GetObject`/
  `ListBucket` on the audit bucket, `sts:AssumeRole` on the control-plane role
  ARN only, and log writes.
- **Deny** (statement `DenyGatewayBypass`): `lambda:InvokeFunction`,
  all remediation actions, `tag:TagResources`, `bedrock-agentcore:UpdatePolicy`.

| # | Assertion | Expected |
|---|---|---|
| N7.1 | api policy contains no direct remediation allow | true |
| N7.2 | api role may `lambda:InvokeFunction` on tool Lambdas | explicit **Deny** (cannot invoke a tool target directly) |
| N7.3 | api role may `bedrock-agentcore:UpdatePolicy` directly | explicit **Deny** (activation only via assuming the control-plane role) |
| N7.4 | api role reaches activation | only by `sts:AssumeRole` on the ctrl-plane role ARN |

Only `data.aws_iam_policy_document.gateway_execution` carries
`lambda:InvokeFunction`, scoped to `function:${name_prefix}-tool-*`. The Gateway
execution role is the sole invoker of tool targets, so every mutation must
traverse the AgentCore Gateway / Cedar boundary (design §6, Cedar-first rule).

## Resource-scoping ledger (no bare `*` except read-only)

| Statement | Resource | Justification |
|---|---|---|
| `discovery.ReadOnlySources` | `*` | read-only Config/SecurityHub/CloudTrail Describe/Get/List; no resource-level ARN exists |
| `tool_execution.TagDiscoveryReadOnly` | `*` | `tag:GetResources` read-only cross-service query; no resource scoping |
| `tool_execution.CompliantTagging` | `*` | `tag:TagResources` addresses heterogeneous ARNs; gated by Lambda recheck + `DenyProductionTargets` |
| `api.ReadAuditEvidence` / `audit_reader.ReadAuditObjects` | audit bucket + `/*` | scoped to the audit bucket ARN |
| all inlined Deny statements | `*` | denies are intentionally broad; a deny on `*` cannot over-permit |

Every mutating allow (`SecurityGroupCorrection`, `S3EncryptionEnablement`,
`PolicyActivation`, Gateway `InvokeToolTargets`, discovery/API writes) is scoped
to account + region + resource type + specific ARN(s).

## How to run the native test

```
terraform init -backend=false -input=false
terraform test
```

The `.tftest.hcl` uses `command = plan` on module-scoped runs. It configures a
real AWS provider with credential/metadata lookups disabled: the
`aws_iam_policy_document` data source is computed locally and makes no AWS API
calls, so the suite executes without AWS credentials. (A mock provider cannot be
used here because it does not render the real policy JSON, and chaining policy
documents under a mock fails outright — hashicorp/terraform-provider-aws#36700.)
