# Continuous Compliance Guardian — Capability Baseline

**Recorded:** 2026-09-14

**Purpose:** Preserve the deployment-gate results before implementation. This is evidence and planning documentation only; it does not authorize an AWS apply or policy activation.

## Gate result

| Gate | Result | Consequence |
|---|---|---|
| AgentCore Gateway | **Validated by AWS documentation and Terraform provider documentation.** MCP Gateway supports Lambda, OpenAPI, Smithy, and MCP-server targets. The Terraform AWS provider documents `aws_bedrockagentcore_gateway` and `aws_bedrockagentcore_gateway_target`. | Use a Lambda-backed MCP target design, but capture the deployed Cedar schema and exact generated action identifiers before writing policies. |
| AgentCore Cedar Policy | **Validated by AWS documentation.** AgentCore Policy uses Cedar `permit`/`forbid`, default deny, and forbid-overrides-permit semantics. | Keep mutations behind the Gateway Policy Engine; adapt the repository’s intent policies to the generated AgentCore schema. |
| Policy activation | **Capability indicated; live operation not verified.** AWS SDK control-plane documentation exposes policy enforcement mode updates between `LOG_ONLY` and `ACTIVE`. | Implement activation only through the verified control-plane API with audited versioning, concurrency, reconciliation, and fail-closed uncertainty handling. |
| Nova Sonic | **Validated conceptually.** Documentation confirms bidirectional streaming, speech/text/audio events, function calling, and interruption support. Nova 2 Sonic documentation lists US East (N. Virginia), US West (Oregon), and Asia Pacific (Tokyo); the original Nova Sonic model documentation lists its own regional availability. | Keep voice behind an off-by-default adapter. Verify the selected model ID, region, quota, browser transport, authentication, and tool restrictions before enabling it. |
| Terraform AWS provider | **Validated current registry baseline:** Terraform MCP returned `hashicorp/aws` version `6.64.0`, with AgentCore Gateway, Gateway Target, Agent Runtime, Policy Engine, and Policy resources. | The repository’s current `~> 5.0` constraint does not establish compatibility with the validated AgentCore resource baseline. Resolve and pin the provider version in the Terraform foundation phase. |
| Terraform runtime | **Available locally:** Terraform 1.15.8. The repository allows `>= 1.8.0, < 2.0.0`; CI currently installs an unpinned setup action. | Pin or otherwise document the runtime baseline before apply; keep provider/runtime upgrades separate from functional changes. |
| Python runtime | **Baseline set to 3.14.** Local interpreter is Python 3.14; `pyproject.toml` requires `>=3.14,<3.15`, `ruff.toml` targets `py314`, and CI installs Python 3.14 with `ruff==0.16.6`. The 22-test suite passes on 3.14. | Use Python 3.14 for implementation and CI validation. Keep the `ruff`/`pytest` pins on releases that support 3.14. |
| Cedar CLI | **Unavailable locally.** No `cedar` executable was found. | Use a pinned CI/container/tooling path for Cedar validation or a validated AgentCore policy analyzer path; do not claim local Cedar validation until installed. |
| AWS account identity | **Blocked:** `aws sts get-caller-identity` did not return an account identity in this workspace. | No live AgentCore schema capture, Terraform plan against AWS, policy activation, remediation, or deployment may proceed until a dedicated sandbox profile/account is configured and verified. |
| Existing Terraform syntax | **Blocked:** `terraform init -backend=false` fails before provider initialization because `terraform/main.tf` and `terraform/versions.tf` use invalid semicolon-separated HCL block syntax. | Repair and format the configuration in the Terraform foundation phase before provider schema validation or planning. |

## Evidence sources

- [AgentCore Cedar policy semantics](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-understanding-cedar.html)
- [AgentCore policy getting started](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-getting-started.html)
- [Nova Sonic speech-to-speech model](https://docs.aws.amazon.com/nova/latest/userguide/speech.html)
- [Bedrock model and Region compatibility](https://docs.aws.amazon.com/bedrock/latest/userguide/models-region-compatibility.html)
- [Nova Sonic model card and regional availability](https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-amazon-nova-sonic.html)
- [Terraform AgentCore Gateway resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/bedrockagentcore_gateway)
- [Terraform AgentCore Gateway Target resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/bedrockagentcore_gateway_target)
- [Terraform AgentCore Policy resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/bedrockagentcore_policy)
- [Terraform AWS provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)

## Required pre-deployment evidence

Before a sandbox apply is approved, capture and review:

1. AWS caller identity, account ID, configured profile, region, and explicit non-production designation.
2. Terraform runtime/provider versions and a committed lock file with no secrets or state.
3. The live AgentCore Gateway target schema and generated Cedar action/resource/entity identifiers.
4. The verified AgentCore policy activation API, IAM permissions, propagation behavior, and reconciliation procedure.
5. Selected Nova Sonic model ID, Region, quota, browser transport, and read-only adapter behavior—or an explicit decision to leave voice mocked/off.
6. A reviewed Terraform plan artifact showing no NAT, always-on compute, provisioned DynamoDB, multi-AZ topology, production targets, or unregistered mutation path.
