"""Explicit, auditable model of the Cedar-first authorization ordering.

This module is a **local model** of the safety semantics the remote AgentCore
Gateway Policy Engine enforces. It is not the production authorizer: real
authorization happens at the Gateway. Its purpose is to make the ordering
reviewable, reusable, and testable before the live Cedar schema exists, and to
keep the test double honest against the same rules the console/API depend on.

Ordering mirrors Cedar semantics:

1. **Forbids override permits.** Any matching forbid denies, regardless of
   permit state. These map to `policies/guardrails.cedar`.
2. **No matching permit is deny.** With the permit set inactive, or with no
   permit for the requested action, the result is deny.
3. **Allow only on an explicit active permit** for a registered action against
   an eligible sandbox target.

Each rule carries the policy ID it represents so decision evidence records the
determining policy, matching `CCG-REQ-019`.

Action ID format
----------------
`PolicyDecision.action_id` uses the **full Cedar action identifier** format
`AgentCore::Action::"RemediationTarget___<tool_name>"`, matching the action IDs
in `policies/remediation-permits.cedar` and `policies/guardrails.cedar`.  This
keeps audit evidence consistent with the deployed policy files.  The short tool
name (`request.tool`) continues to be used internally for forbid-rule matching
and tool-handler dispatch.

The gateway ARN target name prefix (`"RemediationTarget"`) is exported as
`CEDAR_TARGET_NAME` so it can be updated in one place when the deployed target
name is confirmed.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

from .contracts import Decision, PolicyDecision, RemediationRequest

_FORBIDDEN_CIDRS = frozenset({"0.0.0.0/0", "::/0"})

# ---------------------------------------------------------------------------
# Cedar action ID helpers
# ---------------------------------------------------------------------------

#: Target name embedded in Cedar action IDs. Must match the name given at
#: ``CreateGatewayTarget`` time. Confirm after the first sandbox deploy and
#: update ``docs/AGENTCORE_CAPABILITY_RECORD.md`` §1.3.
CEDAR_TARGET_NAME: str = "RemediationTarget"

#: Cedar namespace prefix for all CCG actions.
CEDAR_ACTION_PREFIX: str = "AgentCore::Action::"


def to_cedar_action_id(tool_name: str) -> str:
    """Return the full Cedar action ID for a registered tool name.

    Example::

        to_cedar_action_id("s3_encryption_enablement")
        # -> 'AgentCore::Action::"RemediationTarget___s3_encryption_enablement"'
    """
    return f'{CEDAR_ACTION_PREFIX}"{CEDAR_TARGET_NAME}___{tool_name}"'


@dataclass(frozen=True, slots=True)
class Rule:
    """A single named authorization rule.

    `matches` returns True when the rule fires. `effect` is the decision the
    rule produces when it fires. Forbid rules are evaluated before permit
    evaluation so that a forbid always wins.
    """

    policy_id: str
    effect: Decision
    reason: str
    matches: Callable[["AuthzContext"], bool]


@dataclass(frozen=True, slots=True)
class AuthzContext:
    """The validated inputs a decision is made against.

    `permit_active` and `registered_tools` are supplied by the boundary, not by
    the untrusted caller. Target safety attributes come from the server-resolved
    target, never from caller-supplied request fields.
    """

    request: RemediationRequest
    permit_active: bool
    registered_tools: frozenset[str]


# --- Always-on forbids (guardrails.cedar). Order among forbids is by specificity
# but any single match denies, so relative order does not change the outcome. ---

def _is_unregistered(ctx: AuthzContext) -> bool:
    return ctx.request.tool not in ctx.registered_tools


def _is_production(ctx: AuthzContext) -> bool:
    return ctx.request.target.is_production


def _missing_demo_tag(ctx: AuthzContext) -> bool:
    return not ctx.request.target.is_demo


def _global_open_ingress(ctx: AuthzContext) -> bool:
    return (
        ctx.request.tool == "security_group_correction"
        and ctx.request.parameters.get("proposed_cidr") in _FORBIDDEN_CIDRS
    )


def _public_s3(ctx: AuthzContext) -> bool:
    return ctx.request.tool == "s3_encryption_enablement" and ctx.request.parameters.get("make_public") is True


def _cloudtrail_disable(ctx: AuthzContext) -> bool:
    return ctx.request.tool == "disable_cloudtrail"


FORBID_RULES: tuple[Rule, ...] = (
    Rule("always-deny-unregistered-tool", Decision.DENY, "unregistered tool", _is_unregistered),
    Rule("always-deny-production-target", Decision.DENY, "production target is forbidden", _is_production),
    Rule("always-deny-missing-demo-tag", Decision.DENY, "CCGDemo=true is required", _missing_demo_tag),
    Rule("always-deny-global-open-ingress", Decision.DENY, "global-open ingress is forbidden", _global_open_ingress),
    Rule("always-deny-public-s3", Decision.DENY, "public S3 changes are forbidden", _public_s3),
    Rule(
        "always-deny-cloudtrail-disablement",
        Decision.DENY,
        "CloudTrail disablement is forbidden",
        _cloudtrail_disable,
    ),
)


@dataclass(frozen=True, slots=True)
class _Outcome:
    decision: Decision
    reason: str
    matched: tuple[str, ...]


def evaluate(ctx: AuthzContext, forbid_rules: Sequence[Rule] = FORBID_RULES) -> _Outcome:
    """Apply forbid-overrides-permit ordering and return the determining outcome."""
    for rule in forbid_rules:
        if rule.matches(ctx):
            return _Outcome(rule.effect, rule.reason, (rule.policy_id,))

    if not ctx.permit_active:
        return _Outcome(Decision.DENY, "permit set is inactive", ("default-deny-permits-inactive",))

    # An active, action-specific permit for an eligible sandbox target.
    # The policy ID mirrors the logical name used in remediation-permits.cedar
    # and docs/POLICY_CATALOG.md §7.
    return _Outcome(
        Decision.ALLOW,
        "registered action permit matched",
        (f"permit-{ctx.request.tool}",),
    )


def decide(
    request: RemediationRequest,
    *,
    permit_active: bool,
    registered_tools: frozenset[str],
    policy_set_version: str,
    evaluated_at: datetime | None = None,
) -> PolicyDecision:
    """Produce a full PolicyDecision with decision evidence fields populated.

    ``action_id`` is the **full Cedar action identifier**
    (``AgentCore::Action::"RemediationTarget___<tool>"``), consistent with the
    policy files and audit catalog.  Use ``to_cedar_action_id`` to reconstruct
    the short tool name from it when needed internally.
    """
    ctx = AuthzContext(request=request, permit_active=permit_active, registered_tools=registered_tools)
    outcome = evaluate(ctx)
    return PolicyDecision(
        decision=outcome.decision,
        request_id=request.request_id,
        correlation_id=request.correlation_id,
        actor=request.actor,
        action_id=to_cedar_action_id(request.tool),
        target_arn=request.target.arn,
        matched_policy_ids=outcome.matched,
        policy_set_version=policy_set_version,
        reason=outcome.reason,
        evaluated_at=evaluated_at or datetime.now(timezone.utc),
    )
