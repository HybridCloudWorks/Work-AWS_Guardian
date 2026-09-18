# ADR 0003 — AWS-managed encryption keys, no customer-managed KMS (POC)

**Status:** Accepted
**Date:** 2026-09-18

## Context
CCG stores findings (DynamoDB) and audit records (S3). Encryption at rest is required. Options: AWS-owned/managed keys vs a customer-managed KMS key (CMK). The POC has a <$150/mo budget.

## Decision
Use AWS-managed/owned keys only. DynamoDB uses `server_side_encryption { enabled = true }` (AWS-owned key); S3 uses SSE-S3 (AES256); CloudWatch uses default encryption. No CMK, no `kms_key_arn`, no `encryption_key_arn` on the Policy Engine.

## Consequences
- **Positive:** near-zero cost and complexity; fits the POC budget; `CreatePolicyEngine.encryptionKeyArn` is optional so nothing is forced.
- **Negative (explicitly accepted):** no per-key access policy, and **no CloudTrail key-usage (Encrypt/Decrypt) audit trail** — a real Security-pillar gap for a compliance product (review M5). For production, revisit with a CMK + restrictive key policy.
- This is a deliberate cost trade-off, recorded so it is not mistaken for an oversight.
