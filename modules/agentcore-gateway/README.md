# agentcore-gateway

Provisions the AgentCore external authorization boundary for the Continuous
Compliance Guardian POC:

- `aws_iam_role` + inline policy — Gateway execution role (**always created**;
  no runtime effect on its own).
- `aws_bedrockagentcore_policy_engine` — the external Cedar decision engine
  (**feature-flagged**, `enable_gateway`, default `false`).
- `aws_bedrockagentcore_gateway` — MCP gateway bound to the policy engine
  (**feature-flagged**, `enable_gateway`, default `false`).

Provider is pinned to `hashicorp/aws = 6.64.0`; every argument/block name is
verified against that provider's schema.

## The authorization boundary (Cedar-first)

The Gateway is the external policy boundary that every dangerous action must
traverse. Authorization is decided by the bound Policy Engine evaluating Cedar
policy — never by a prompt, memory, UI state, or an application boolean.

- `protocol_type = "MCP"`, `authorizer_type = "AWS_IAM"`.
- `policy_engine_configuration.mode = "LOG_ONLY"`.

## LOG_ONLY posture — read this carefully (C1 / P0.1)

`LOG_ONLY` means every policy is **evaluated but not enforced**. In this mode:

- A **forbid does not block** a call — it only produces a log entry.
- A **permit does not authorize** a call — it only produces a log entry.

So the capture-time safety basis is **not** "forbids block". It is that **no
permit exists or is active**, so nothing can authorize a mutation regardless of
mode. Do **not** describe `LOG_ONLY` as "fail-closed because forbids enforce" —
that framing is false.

Enforcement requires **both** `mode = "ENFORCE"` **and** an active default-deny
permit set.

## Activation is control-plane only — never a Terraform apply

There is deliberately **no** `enforcement_mode = "ACTIVE"` argument and **no**
permit-activation variable in this module. Flipping the engine to `ENFORCE` and
activating permits happens exclusively through the audited control-plane
`UpdatePolicy` flow (`src/ccg/policy.py`, task 4.3). A `terraform apply` can
create the LOG_ONLY boundary but can never activate enforcement.

## Sole mutation ingress

The Gateway is the **only** mutation ingress. The sole `lambda:InvokeFunction`
grant on the tool-target Lambdas belongs to this module's Gateway execution role
(verified in task 2.3 / `tests/iam_negative_permissions.tftest.hcl`). No other
principal can invoke a remediation tool, so there is no unreviewed mutation path.

## Gating

`enable_gateway = false` by default: only the execution role is created and
nothing is deployed to AgentCore. Set `true` only via a reviewed HCP plan after
the Phase 1.2 threat model is reviewed, and only for the minimal schema-capture
step. Enabling is a real AWS mutation.

## Plan-visible outputs

`gateway_arn`, `gateway_id`, `gateway_url`, `policy_engine_arn`,
`policy_engine_id`, and `enforcement_mode` (fixed to `LOG_ONLY`) are exposed so a
reviewer can confirm the boundary and its mode directly from plan/state. All are
`null` while the feature flag is off.
