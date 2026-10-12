# Module: identity

**Status:** Stub — gated off by default (`enable_roles = false`).

## Purpose

Creates the four separate IAM execution roles that enforce CCG trust boundary separation (design §6):

| Role | Purpose |
|---|---|
| `discovery` | Read-only source APIs + evidence writes; cannot mutate or assume other roles. |
| `tool-execution` | Sandbox-gated remediation actions only; blocked from policy activation and production targets. |
| `control-plane` | AgentCore `UpdatePolicy` + reconciliation reads only; no remediation permissions. |
| `audit-reader` | Read-only on the audit bucket; for investigation only, not used at runtime. |

Permission policy documents are produced by the `iam-policies` module and passed in as variables; this module only creates the roles and attaches those documents. This keeps the policy review surface in one place.

## Gating conditions

Enable `enable_roles = true` only after:

1. Gate-0.2 trust-policy capture confirms the Lambda and AgentCore service principal behavior for this region and account.
2. Threat-model T1 (confused-deputy) review is complete, confirming `SourceAccount` conditions are sufficient.
3. Tool role Lambda ARN prefix from `gateway-policy` outputs is known and wired through `iam-policies`.

## Inputs

| Name | Type | Default | Description |
|---|---|---|---|
| `name_prefix` | `string` | — | Resource name prefix. |
| `account_id` | `string` | — | AWS account ID for trust-policy scoping. |
| `region` | `string` | — | AWS region for trust-policy scoping. |
| `discovery_policy_json` | `string` | — | Discovery permission policy JSON (from `iam-policies`). |
| `tool_execution_policy_json` | `string` | — | Tool-execution permission policy JSON (from `iam-policies`). |
| `control_plane_policy_json` | `string` | — | Control-plane permission policy JSON (from `iam-policies`). |
| `audit_reader_policy_json` | `string` | — | Audit-reader permission policy JSON (from `iam-policies`). |
| `enable_roles` | `bool` | `false` | Feature flag; roles are only created when `true`. |

## Outputs

| Name | Description |
|---|---|
| `discovery_role_arn` | Discovery role ARN (null when disabled). |
| `discovery_role_name` | Discovery role name (null when disabled). |
| `tool_execution_role_arn` | Tool-execution role ARN (null when disabled). |
| `tool_execution_role_name` | Tool-execution role name (null when disabled). |
| `control_plane_role_arn` | Control-plane role ARN (null when disabled). |
| `control_plane_role_name` | Control-plane role name (null when disabled). |
| `audit_reader_role_arn` | Audit-reader role ARN (null when disabled). |
