# Module: remediation-tools

**Status:** Stub — gated off by default (`enable_remediation_tools = false`).

## Purpose

Provisions the four narrow, idempotent remediation tool Lambdas that back the AgentCore Gateway targets. Each tool implements one approved remediation operation (CCG-REQ-021 through CCG-REQ-025) with explicit safety rechecks, typed contracts, and a dry-run seam.

All function names are prefixed `{name_prefix}-tool-*` so the Gateway execution role's Lambda invoke ARN pattern already covers them without wildcarding unrelated functions.

| Tool function | Operation | Safety contract |
|---|---|---|
| `{prefix}-tool-sg-correction` | Correct one approved sandbox SG ingress rule. | Rejects global-open ingress; compliant state is a no-op. |
| `{prefix}-tool-s3-encryption` | Enable approved encryption on an eligible sandbox bucket. | Never makes bucket public; already-encrypted is a no-op. |
| `{prefix}-tool-tagging` | Add/correct approved compliance tags. | Never writes `Environment=prod`; preserves `CCGDemo=true`. |
| `{prefix}-tool-key-rotation` | Rotate a specifically approved sandbox access key. | Dry-run unless `confirm=true`; secret material never logged. |

Lambda deployment packages are placeholders (`placeholder.zip`). The actual packages are built and referenced during the Phase 4 live-transport tasks.

## Gating conditions

Enable `enable_remediation_tools = true` only after:

1. Gate-0.2 confirms the tool-execution IAM role, Gateway schema, and tool input contracts.
2. `agentcore-gateway` module is enabled.
3. Lambda deployment packages are built and the `filename` references are updated.

## Inputs

| Name | Type | Default | Description |
|---|---|---|---|
| `name_prefix` | `string` | — | Resource name prefix. |
| `region` | `string` | — | AWS region for ARN construction. |
| `account_id` | `string` | — | AWS account ID for ARN construction. |
| `log_group_arn` | `string` | — | CloudWatch log group ARN. |
| `log_group_name` | `string` | — | CloudWatch log group name (Lambda env var). |
| `tool_execution_role_arn` | `string` | `""` | Tool execution role ARN (from `identity`). |
| `findings_table_name` | `string` | — | DynamoDB findings table name (Lambda env var). |
| `audit_bucket_name` | `string` | — | Private audit S3 bucket name (Lambda env var). |
| `lambda_timeout_seconds` | `number` | `60` | Lambda max execution time (1–900 s). |
| `lambda_memory_mb` | `number` | `256` | Lambda memory (128–3008 MB). |
| `enable_remediation_tools` | `bool` | `false` | Feature flag; all Lambdas only deployed when `true`. |

## Outputs

Outputs are the ARN and name of each tool Lambda function (null when the feature flag is off).
