# findings-store

Single on-demand DynamoDB table holding **both** current finding state and
operational idempotency metadata (design §3.1). One table only — the POC cost
constraint forbids a second provisioned or always-on table.

## Controls

| Control | Resource / attribute | Value |
|---|---|---|
| On-demand billing (no provisioned capacity) | `aws_dynamodb_table` `billing_mode` | `PAY_PER_REQUEST` |
| Partition key | `aws_dynamodb_table` `hash_key` | `finding_id` (string) |
| Encryption at rest | `aws_dynamodb_table` `server_side_encryption.enabled` | `true` |
| Point-in-time recovery | `aws_dynamodb_table` `point_in_time_recovery.enabled` | `true` |
| Deletion protection | `aws_dynamodb_table` `deletion_protection_enabled` | `var.enable_deletion_protection` (true) |
| Idempotency TTL | `aws_dynamodb_table` `ttl.attribute_name` / `enabled` | `ttl_epoch` / `true` |

## Single-table idempotency layout

The table is keyed only on `finding_id`. Item types are distinguished by a
prefix convention on that key:

- **Finding items** — `finding_id = "FINDING#<deterministic-finding-id>"`.
  Carry current state (severity, status, revision, first/last seen, correlation
  id). No `ttl_epoch`, so they are retained.
- **Idempotency items** — `finding_id = "IDEMP#<key-hash>"`, where `key-hash`
  is `sha256(tool | target_arn | sorted(params) | expected_finding_version)`
  (P1.1). Attributes: `outcome` (`APPLIED` or `NOOP`), `correlation_id`,
  `request_id`, `created_at`, `ttl_epoch`.

Rules enforced in the application/tool layer (not by the table schema, which is
schemaless beyond the key):

- Only terminal success/no-op outcomes are cached; failures are **never**
  cached, so a retry re-evaluates.
- A reused idempotency key with a changed payload is rejected.
- `ttl_epoch` lets idempotency records self-expire via DynamoDB TTL with no
  sweep job; finding items omit the attribute and persist.

No sort key is used: every access is a point lookup by the prefixed key, which
keeps the table on-demand and cheap.

## Teardown

`deletion_protection_enabled` defaults to **true** (P1.9/M4). Before
`terraform destroy`:

1. Set `enable_findings_deletion_protection = false` at the root (or
   `enable_deletion_protection = false` on the module) and apply so the guard
   is removed.
2. Then run the reviewed destroy plan.

Flipping the flag off is an explicit, auditable step — the table cannot be
destroyed by an accidental or default-value apply.

## Variables

| Name | Type | Default | Purpose |
|---|---|---|---|
| `name_prefix` | string | — | Resource name prefix. |
| `enable_deletion_protection` | bool | `true` | DynamoDB deletion protection; flip false for teardown. |
