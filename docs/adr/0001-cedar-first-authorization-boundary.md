# ADR 0001 — Cedar-first external authorization boundary

**Status:** Accepted
**Date:** 2026-09-18

## Context
CCG remediates AWS misconfigurations. The core requirement (CCG-REQ-008/009) is that no dangerous action is authorized by a prompt, UI state, memory, or an application boolean — authorization must happen at an external policy boundary. AWS Bedrock AgentCore Gateway with a Cedar Policy Engine provides this: `permit`/`forbid`, default-deny, forbid-overrides-permit.

## Decision
All mutations traverse the AgentCore Gateway/Cedar boundary. Application code (API, agents, console, voice) may validate and reject, but may never grant authorization. The API resolves the target ARN server-side from the stored finding so a caller cannot inject a target.

## Consequences
- **Positive:** a single, external, auditable decision point; the console/voice cannot escalate.
- **Negative / current gap (see ADR 0002 and review C2):** the guarantee is presently proven only against the `InMemoryCedarGateway` test double; the production `AgentCoreGatewayClient` is a pass-through and the deployed engine is not yet in enforce mode. The guarantee is DESIGNED but not yet ENFORCED in a deployable configuration.
- Tool selection and parameters are still caller-influenced (review M2/T2) and must be constrained server-side before enforcement.
