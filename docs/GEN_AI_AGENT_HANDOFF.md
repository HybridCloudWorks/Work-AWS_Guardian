# Continuous Compliance Guardian: Authoritative GenAI Build Brief

## Mission
Build a cost-bounded AWS sandbox POC that detects AWS Well-Architected Security-pillar drift, explains it through an admin console and optional Nova Sonic voice briefing, and proves that remediation is authorized at an external Cedar policy boundary—not by a prompt, client-side control, or application boolean.

## Required architecture
- Python 3.14 Strands-compatible Discovery Agent; EventBridge schedule configurable, POC default 15 minutes; read Config, Security Hub, CloudTrail; no write permissions to audited resources.
- Normalize findings with IDs, rule/evidence, severity, target ARN, status, timestamps, correlation ID, accepted-risk details. Persist current state in on-demand DynamoDB and immutable/auditable JSON to private S3 with 30-day lifecycle expiration.
- Remediation Agent exposes only registered, idempotent Gateway tools: restricted security-group correction, S3 encryption enablement, compliant tagging, and sandbox-safe access-key rotation workflow.
- AgentCore Gateway / MCP tool boundary evaluates Cedar. Always-active forbids deny production-tagged targets, global-open ingress, public S3 changes, and CloudTrail disablement. A separately versioned permit set is off by default and is activated only through an audited admin control-plane operation.
- Next.js App Router console, API Gateway/Lambda backend, Cognito POC user. Display findings, policy-set version, mode, proposed actions, and decision evidence. The toggle changes policy-set activation—not app state.
- Optional feature-flagged Nova Sonic adapter: browser mic streaming, transcript, barge-in, read-only finding lookup. Verify live APIs before implementation and isolate any unavailable API behind an adapter/mock; never bypass Cedar.

## Hard requirements
- Cedar: forbid overrides permit; no matching permit means deny. Log request ID, actor, tool, target, decision, matched policy IDs, policy version, correlation ID and timestamp for every call.
- Mutation requires `CCGDemo=true` and denies `Environment=prod`.
- Include allow, deny, idempotency, audit, and cleanup tests for every remediation.
- Terraform Cloud remote state only. Pin Terraform and providers. Modular Terraform with `environments/poc`; least-privilege IAM; default tags.
- Cost < $150/month: no NAT Gateway, EC2/ECS service, provisioned DynamoDB, multi-AZ, or always-on compute; 7-day CloudWatch retention; voice opt-in; teardown documented.
- CI: Terraform fmt/validate/tflint, Ruff/pytest, TypeScript eslint/typecheck, Cedar validation, secret scanning. Applies remain manual.

## Kiro method
Enable AWS Documentation, Observability, DevOps, and Terraform Powers/MCP tools. Follow requirements (EARS) → human review → design → tasks → human review → implementation. Never invent current AWS/AgentCore/Nova/provider APIs.

## Demo
Seed 3–5 sandbox-only tagged findings. Detect. Show denied remediation with permits inactive. Activate permit set. Re-run same action; show Cedar allow, one idempotent change, updated finding, audit evidence, and optional interruptible voice summary.

## Production later
Add all six WAF pillars, IAM Identity Center/SSO, cross-account discovery, CI policy gates, retention, resilience, threat modeling, change management, and human approval for high-impact changes.
