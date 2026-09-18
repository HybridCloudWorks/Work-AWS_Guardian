# ADR 0004 — Access-key rotation is dry-run unless explicitly confirmed

**Status:** Accepted
**Date:** 2026-09-18

## Context
Access-key rotation is the highest-blast-radius of the four remediation tools. A wrong rotation can lock out an identity.

## Decision
`access_key_rotation` defaults to a validated **dry-run** that returns a create→validate→disable plan without mutating. A real rotation requires an explicit `confirm=true` parameter AND an active permit AND sandbox tags. Secret material must never appear in `ToolResult`, `details`, logs, or audit.

## Consequences
- **Positive:** demonstrates the workflow and Cedar boundary with minimal blast radius.
- **Caveat (review M-tools):** the "no secret leaks" property currently holds only because the tool is a stub. When a live `Effector` is implemented, rotation necessarily produces a new secret; the Effector contract must deliver it out-of-band (e.g. Secrets Manager) and never return it to the handler, with an invariant/test at that seam.
- `confirm` is a plain parameter; consider a second control (e.g. a separate approval) before enabling real rotation.
