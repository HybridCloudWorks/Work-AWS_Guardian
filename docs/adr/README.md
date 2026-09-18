# Architecture Decision Records

Each ADR captures one load-bearing decision: its status, context, decision, and consequences. ADRs are immutable once accepted; a reversal is a new ADR that supersedes.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-cedar-first-authorization-boundary.md) | Cedar-first external authorization boundary | Accepted |
| [0002](0002-log-only-is-not-enforcement.md) | LOG_ONLY is non-enforcing; enforcement requires ENFORCE + default-deny | Accepted (corrects prior belief) |
| [0003](0003-aws-managed-keys-no-cmk.md) | AWS-managed encryption keys, no customer-managed KMS (POC) | Accepted |
| [0004](0004-dry-run-access-key-rotation.md) | Access-key rotation is dry-run unless explicitly confirmed | Accepted |
| [0005](0005-terraform-provider-pin-hcp-oidc.md) | Pin AWS provider 6.64.0; state + apply in HCP via OIDC | Accepted |
| [0006](0006-python-314-baseline.md) | Python 3.14 runtime baseline | Accepted |
