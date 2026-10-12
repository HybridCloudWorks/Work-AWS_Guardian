# Module: voice-adapter

**Status:** Stub — explicitly OFF by default (`enable_voice = false`). Enabling requires gate-0.3 Nova Sonic contract verification.

## Purpose

Provisions the optional Nova Sonic read-only voice adapter (CCG-REQ-030 through CCG-REQ-033).

When enabled, the adapter provides read-only finding summaries and policy status through Nova Sonic bidirectional streaming. It does **not** expose any remediation tool schema and cannot call the AgentCore Gateway mutation surface.

Key safety constraints:
- `RETAIN_AUDIO = "false"` by default; raw audio is never logged or stored.
- The adapter IAM role has an explicit deny on `bedrock-agentcore:*`, `lambda:InvokeFunction`, and all mutation actions.
- The voice session correlation ID is attached to every log record.

## Gating conditions

Enable `enable_voice = true` only after all gate-0.3 items are verified:

1. Nova Sonic model ID and region availability.
2. Bidirectional API, audio formats, and browser transport path.
3. Interruption event semantics and session limits.
4. Microphone consent flow implemented in the Next.js console.
5. Voice adapter confirmed to have no mutation tool visibility or Gateway bypass.

## Resources

Created when `enable_voice = true`:
- `aws_lambda_function.voice_adapter` — Python 3.14 Nova Sonic adapter (read-only).
- `aws_iam_role.voice_adapter` + inline policy — read-only DynamoDB + log writes; explicit deny on all mutation surfaces.

## Inputs

| Name | Type | Default | Description |
|---|---|---|---|
| `name_prefix` | `string` | — | Resource name prefix. |
| `region` | `string` | — | AWS region. |
| `account_id` | `string` | — | AWS account ID. |
| `log_group_arn` | `string` | — | CloudWatch log group ARN. |
| `log_group_name` | `string` | — | CloudWatch log group name (Lambda env var). |
| `findings_table_name` | `string` | — | DynamoDB findings table name (read-only). |
| `lambda_timeout_seconds` | `number` | `30` | Lambda max execution time. |
| `lambda_memory_mb` | `number` | `256` | Lambda memory (128–3008 MB). |
| `enable_voice` | `bool` | `false` | Feature flag; ALL resources gated off. |

## Outputs

| Name | Description |
|---|---|
| `lambda_arn` | Voice adapter Lambda ARN (null when disabled). |
| `lambda_name` | Voice adapter Lambda name (null when disabled). |
| `role_arn` | Voice adapter IAM role ARN (null when disabled). |
