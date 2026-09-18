# ADR 0002 — LOG_ONLY is non-enforcing; enforcement requires ENFORCE + default-deny

**Status:** Accepted — corrects a prior incorrect belief (review finding C1)
**Date:** 2026-09-18

## Context
Earlier work bound the Gateway's Policy Engine in `mode = "LOG_ONLY"` and described it across the threat model, deploy runbook, and Terraform comments as the "fail-closed, permits-inactive, forbids-still-enforce" posture. A devil's-advocate review challenged this.

## Decision (correcting the record)
The AWS `bedrock-agentcore-control` service model defines `GatewayPolicyEngineConfiguration.mode`:
- **LOG_ONLY** — "evaluates each action against your policies and adds traces on whether tool calls would be allowed or denied, **but does not enforce the decision.**"
- **ENFORCE** — evaluates and enforces (allows/denies).

Therefore **LOG_ONLY does not enforce forbids or permits.** The schema-capture deploy remains acceptable in LOG_ONLY **only because no permits (and effectively no enforced forbids) are relied upon during capture — i.e., safety rests on the absence of any authorized mutation path, not on LOG_ONLY blocking anything.**

Enforcement requires `mode = "ENFORCE"` **with** a committed default-deny Cedar policy set, activated through the audited activation flow, only after the T2 request-context question is resolved.

## Consequences
- All documentation must stop calling LOG_ONLY fail-closed.
- The enforcement-mode flip is a distinct, gated, audited step — never part of a deploy.
- `enable_agentcore_gateway` stays `false` until the ENFORCE design (default-deny baseline + verified context source) is in place.
- This ADR supersedes any prior statement that LOG_ONLY keeps forbids active.
