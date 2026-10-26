# Distributing Continuous Compliance Guardian (CCG)

**Model: Option 1 — customer-deployed Terraform module.** CCG runs entirely in the
customer's own AWS account; their data never leaves it. This is the fastest
honest path that avoids hardcoding, manual scripts, and pasted IAM policies.

> Status: packaging groundwork. Nothing deploys by default — every component is
> behind an `enable_*` flag (all default `false`), and all inputs are
> placeholders meant to be overridden per deployment.

## How a customer deploys it (the happy path)

1. **Grant privileges — one click, no pasted policy.** Launch the bootstrap
   CloudFormation stack (`deploy/bootstrap-role.yaml`). It creates a single,
   tightly-scoped `ccg-deploy` IAM role and nothing else. Parameters:
   - `NamePrefix` — must match Terraform `var.name_prefix`
   - `TrustedPrincipalArn` — the ARN that may assume the role (their CI / SSO / HCP OIDC role)
   - `ExternalId` — a random shared secret (confused-deputy guard)

   This is the AWS-blessed way to grant "exactly the privileges needed, fast":
   a scoped role, assumed, never admin, never static keys.

2. **Point Terraform at the role.** No backend is baked into the module. Copy
   `backend.tf.example` to `backend.tf` (gitignored) and choose a backend
   (local for eval, S3, or your own HCP). Configure the provider:
   ```hcl
   provider "aws" {
     region = var.aws_region
     assume_role {
       role_arn    = "<DeployRoleArn from the CloudFormation output>"
       external_id = "<ExternalId you chose>"
     }
   }
   ```

3. **Set inputs and apply in stages.** Copy `terraform.tfvars.example`, set
   `name_prefix`, `environment`, `aws_region`, `tags`, then enable components
   incrementally (storage/identity first, Gateway last):
   ```hcl
   name_prefix = "acme-ccg"
   environment = "sandbox"
   enable_identity_roles = true
   enable_discovery      = true
   # enable_agentcore_gateway = true   # only after the capability-capture gate
   ```
   ```bash
   terraform init
   terraform plan
   terraform apply
   ```

## Why not a direct AWS Marketplace "1-click product" (yet)

Marketplace's clean delivery paths are AMI, container, and SaaS. A multi-resource
IAM/Lambda/AgentCore stack fits Marketplace only via **CloudFormation delivery**,
which would require porting this Terraform to CloudFormation/CDK — and AgentCore
CloudFormation coverage is still uneven. So:

- **Now:** ship as a Terraform module (git tag or Terraform Registry) + the
  bootstrap-role CFN. The CFN template is the piece that *is* Marketplace-ready
  and can back a "Launch Stack" button.
- **Later (design toward):** a SaaS/cross-account model where the customer runs
  only the bootstrap stack and CCG operates from a central account. That is a
  larger product change (multi-tenant isolation, billing integration) and is out
  of scope for Option 1.

## The privilege set CCG needs (and nothing more)

Enforced by `deploy/bootstrap-role.yaml`, all scoped to `${NamePrefix}-*` ARNs:

| Area | Actions | Scope |
|---|---|---|
| Lambda | create/update/delete/invoke-perms | `function:${prefix}-*` |
| DynamoDB | create/delete/describe/PITR/tags | `table/${prefix}-*` |
| S3 | create/policy/encryption/lifecycle/logging/public-access-block | `${prefix}-*` buckets |
| CloudWatch Logs | create/retention/tags | `/ccg/*` |
| EventBridge | rule + targets | `rule/${prefix}-*` |
| API Gateway + Cognito | create console control plane | API GW resources; Cognito `*` (no resource-level support) |
| AgentCore | gateway/target/policy-engine/policy | `${prefix}-*` AgentCore ARNs |
| IAM | the 4 CCG execution roles only | `role/${prefix}-*` |
| Read-only helpers | `sts:GetCallerIdentity`, `bedrock:ListFoundationModels` | `*` |

Hard denies baked in: **any `Environment=prod`-tagged resource**, and privilege
escalation (`iam:CreateUser`/`CreateAccessKey`/user-policy, `organizations:*`,
`account:*`). CCG never needs org-admin or long-lived keys.

Runtime (discovery Lambda) read-only source access (Config / Security Hub /
CloudTrail) is granted by the CCG execution roles the module creates, not by the
deploy role.

## Pre-distribution checklist (not yet done)

- [ ] Lambda packaging: modules currently reference `placeholder.zip`; wire real
      artifact build (zip or container image if Python 3.14 managed runtime is
      unavailable — see ADR 0006) before a consumable release.
- [ ] Tag a module version; optionally publish to the Terraform Registry.
- [ ] Add a "Launch Stack" URL for `bootstrap-role.yaml` once hosted.
- [ ] Verify each `enable_*` path applies cleanly in a real sandbox (gated on
      the live capability-capture step).
