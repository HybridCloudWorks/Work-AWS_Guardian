# gateway-policy

Extends the `agentcore-gateway` boundary with the resources that make the Cedar
decision concrete:

- Four `aws_bedrockagentcore_gateway_target` — one Lambda-backed MCP target per
  approved remediation tool (sg-correction, s3-encryption, tagging,
  key-rotation).
- One `aws_bedrockagentcore_policy` — the reviewed Cedar policy set
  (always-on forbids + per-tool permits) attached to the Policy Engine.

All resources are gated behind `enable_gateway_policy` (default `false`).
Provider pinned to `hashicorp/aws = 6.64.0`.

## Deployed Cedar content is the reviewed content

By default (`cedar_policy_content = ""`) the module reads the reviewed Cedar
files from the repository `policies/` directory and concatenates them in a
fixed, documented order:

1. `policies/guardrails.cedar` — always-on forbids
2. `policies/remediation-permits.cedar` — per-tool permits

The order is for human readability only. **Cedar is unordered and forbid-wins**,
so a matching forbid overrides any permit regardless of textual position or of
either policy's mode.

`cedar_policy_dir` overrides where those files are read from; an explicit
`cedar_policy_content` string overrides the content entirely (used to inject the
analyzer-validated, ARN-substituted text after gate-0.2 capture). The
`policy_statement_source` output reports which source is active
(`reviewed-files` or `explicit-override`) so a reviewer can confirm it from the
plan.

### Gate-0.2 precondition

The reviewed files still carry `<GATEWAY_ARN>` and placeholder action IDs, so
the default content **will fail the policy analyzer** until those are
substituted with the live Gateway ARN and generated action IDs from the first
schema capture. The module stays gated until the substituted content passes the
analyzer.

## Inactive-permit / active-forbid posture (C1 / P0.1)

Enforcement mode lives on the Policy Engine binding in `agentcore-gateway`
(`mode = "LOG_ONLY"`). This module supplies policy **content only**.

Under `LOG_ONLY`, nothing here enforces: forbids and permits are evaluated for
logging but neither blocks nor authorizes. The capture-time safety basis is that
**no permit is active**, not that forbids block. The permits in
`remediation-permits.cedar` are "inactive" in exactly this sense — present and
logged, but not authorizing until the engine is in `ENFORCE` **and** they are
activated.

## Activation is control-plane only — never a Terraform apply

There is no `enforcement_mode = "ACTIVE"` argument and no permit-activation
variable in this module. Permits are activated only through the audited
control-plane `UpdatePolicy` flow (`src/ccg/policy.py`, task 4.3). Activation
never happens via `terraform apply`.

## Sole mutation ingress

The four tool Lambdas accept `lambda:InvokeFunction` only from the Gateway
execution role (task 2.3 / `tests/iam_negative_permissions.tftest.hcl`). These
four Gateway targets are therefore the only path to a mutation, and the Gateway
is the single ingress. The `gateway_target_ids` output lists all four targets so
a reviewer can confirm there are four and only four from plan/state.

## Plan-visible outputs

`policy_id`, `policy_arn`, `policy_statement_source`, the four
`*_target_id` outputs, and `gateway_target_ids`. All target/policy IDs are
`null` while `enable_gateway_policy = false`.
