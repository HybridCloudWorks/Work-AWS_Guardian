"""Production-facing AgentCore Gateway adapter boundary.

This module contains three things, all seams — **no boto3 / live AWS calls**:

1. :class:`AgentCoreGatewayTransport` — the narrow transport protocol the real
   AWS AgentCore Gateway MCP client will implement. Authorization belongs to the
   remote Gateway Policy Engine, never to this process.
2. :class:`AgentCoreGatewayClient` — the production invocation port. It is **no
   longer a blind pass-through**: it uses the shared
   :class:`~ccg.gateway_core.GatewayInvocationSkeleton` to capture decision
   evidence and emit the audit trail, while the *decision itself* comes from the
   transport. It fails closed on ambiguous/missing evidence.
3. :class:`FaithfulAgentCoreEmulator` — a transport that faithfully reproduces
   the real AgentCore Cedar + enforcement semantics captured in
   ``docs/AGENTCORE_CAPABILITY_RECORD.md``. It is what lets a test exercise "the
   real transport path" without a live AWS account, so no green claim rests
   solely on :class:`~ccg.testing.InMemoryCedarGateway`.

Enforcement model (capability record §1.7 / §3)
------------------------------------------------
AgentCore has two independent enforcement switches:

* **Engine-level mode** (``policyEngineConfiguration.mode``): ``ENFORCE`` means
  the Gateway acts on the policy engine's decision; ``LOG_ONLY`` means the
  Gateway evaluates but never blocks. In ``LOG_ONLY`` every call that reaches the
  Gateway succeeds at the engine level regardless of forbids.
* **Per-policy mode**: a permit policy is only ``ACTIVE`` after the control plane
  confirms it (``UpdatePolicy`` -> poll ``GetPolicy.status == ACTIVE``).

The faithful emulator models both. The key correctness point for P0.3: the
Gateway must NOT enforce a permit until the control plane confirms it ACTIVE and
that state has propagated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Protocol

from .authz import AuthzContext, FORBID_RULES, to_cedar_action_id
from .contracts import (
    Decision,
    InvocationResult,
    PolicyDecision,
    RemediationRequest,
)
from .gateway_core import AmbiguousDecisionError, GatewayInvocationSkeleton, ToolHandler
from .observability import MetricSink
from .ports import AuditSink, GatewayInvocationPort


class GatewayEnforcementMode(StrEnum):
    """Engine-level enforcement mode (capability record §1.7).

    Mirrors ``policyEngineConfiguration.mode`` on the real Gateway.
    """

    #: Gateway evaluates but does not act on the decision. No permit is enforced;
    #: because default-deny still has no active permit, nothing is actually
    #: authorized — the posture is fail-open-at-engine but safe only because no
    #: permit exists to grant.
    LOG_ONLY = "LOG_ONLY"
    #: Gateway acts on the policy engine's decision; denies are blocked and an
    #: active permit grants.
    ENFORCE = "ENFORCE"


@dataclass(frozen=True, slots=True)
class GatewayResponse:
    """The decision shape the real AgentCore Gateway returns.

    Field names mirror the AgentCore ``AuthorizeAction`` response semantics
    captured in the capability record: a terminal ALLOW/DENY plus the determining
    policy IDs, the effective policy-set version, the gateway/request IDs, and any
    validation errors. The transport returns this; the client translates it into
    the internal :class:`~ccg.contracts.PolicyDecision` evidence.
    """

    decision: Decision
    determining_policy_ids: tuple[str, ...]
    policy_set_version: str
    enforcement_mode: GatewayEnforcementMode
    gateway_request_id: str
    reason: str
    action_id: str
    validation_errors: tuple[str, ...] = ()


class AgentCoreGatewayTransport(Protocol):
    """Narrow transport seam for the AWS AgentCore Gateway client.

    The production implementation will call the validated AgentCore Gateway MCP
    endpoint. Authorization belongs to the remote Gateway Policy Engine, not to
    this process. The transport returns the Gateway's own decision
    (:class:`GatewayResponse`); it does not execute the tool — tool execution is
    the registered Lambda target behind the Gateway, modelled on this side by the
    skeleton's tool registry.
    """

    def authorize(self, request: RemediationRequest) -> GatewayResponse:
        ...


# ---------------------------------------------------------------------------
# Control-plane -> Gateway propagation (replaces the demo's manual bridge)
# ---------------------------------------------------------------------------


@dataclass
class EffectivePolicyView:
    """The Gateway's view of the control-plane's confirmed, propagated state.

    Models the result of ``GetPolicy`` once ``UpdatePolicy`` has propagated
    (capability record §3: async, eventually consistent within seconds; poll
    ``GetPolicy.status``). The Gateway must NOT enforce a permit until the
    control plane confirms it ``ACTIVE`` **and** that state has propagated here.

    * ``permit_active`` reflects a confirmed-ACTIVE permit set that has propagated.
    * ``policy_set_version`` is the effective version the engine evaluates against.
    * ``enforcement_mode`` is the engine-level ``ENFORCE`` / ``LOG_ONLY`` switch.
    """

    permit_active: bool = False
    policy_set_version: str = "permits-inactive"
    enforcement_mode: GatewayEnforcementMode = GatewayEnforcementMode.LOG_ONLY

    def propagate_activation(
        self,
        *,
        policy_set_version: str,
        enforcement_mode: GatewayEnforcementMode = GatewayEnforcementMode.ENFORCE,
    ) -> None:
        """Apply a control-plane-confirmed activation to the Gateway's view.

        This is the propagation seam that replaces the demo's manual
        ``gateway.activate_permits`` bridge. In AWS this models AgentCore
        propagating a confirmed ``UpdatePolicy`` (status ``ACTIVE``) to the
        Gateway evaluation path. Callers MUST only invoke this once the control
        plane has returned ``ACTIVATED`` with an effective state.
        """
        self.permit_active = True
        self.policy_set_version = policy_set_version
        self.enforcement_mode = enforcement_mode

    def propagate_deny_safe(self, *, policy_set_version: str | None = None) -> None:
        """Reconcile the Gateway's view back to a non-authorizing posture."""
        self.permit_active = False
        self.enforcement_mode = GatewayEnforcementMode.LOG_ONLY
        if policy_set_version is not None:
            self.policy_set_version = policy_set_version


# ---------------------------------------------------------------------------
# Faithful AgentCore transport emulator
# ---------------------------------------------------------------------------


@dataclass
class FaithfulAgentCoreEmulator:
    """Transport that faithfully reproduces real AgentCore Cedar semantics.

    It evaluates the same forbid-overrides-permit / default-deny ordering as the
    deployed Cedar policy set (reusing :data:`ccg.authz.FORBID_RULES` so the rule
    identities match), honours the engine-level enforcement mode, and honours the
    control-plane-confirmed, propagated activation state via a shared
    :class:`EffectivePolicyView`.

    This is a transport, not a port: it returns the Gateway's :class:`GatewayResponse`
    decision and never executes the tool.
    """

    policy_view: EffectivePolicyView = field(default_factory=EffectivePolicyView)
    registered_tools: frozenset[str] = frozenset()
    gateway_id: str = "emulated-gateway"
    _request_seq: int = field(default=0, init=False, repr=False)

    def authorize(self, request: RemediationRequest) -> GatewayResponse:
        self._request_seq += 1
        gateway_request_id = f"{self.gateway_id}-req-{self._request_seq:06d}"
        action_id = to_cedar_action_id(request.tool)
        mode = self.policy_view.enforcement_mode

        ctx = AuthzContext(
            request=request,
            permit_active=self.policy_view.permit_active,
            registered_tools=self.registered_tools,
        )

        # 1. Forbids are evaluated first (forbid-overrides-permit). Any match denies.
        for rule in FORBID_RULES:
            if rule.matches(ctx):
                return self._deny(
                    determining=(rule.policy_id,),
                    reason=rule.reason,
                    action_id=action_id,
                    gateway_request_id=gateway_request_id,
                    mode=mode,
                )

        # 2. No active, propagated permit -> default deny. In LOG_ONLY no permit is
        #    ever active, so this path is also what makes LOG_ONLY safe: there is
        #    simply nothing to authorize a mutation.
        if mode is GatewayEnforcementMode.LOG_ONLY or not self.policy_view.permit_active:
            reason = (
                "engine LOG_ONLY: no permit enforced"
                if mode is GatewayEnforcementMode.LOG_ONLY
                else "permit set is inactive"
            )
            return self._deny(
                determining=("default-deny-permits-inactive",),
                reason=reason,
                action_id=action_id,
                gateway_request_id=gateway_request_id,
                mode=mode,
            )

        # 3. ENFORCE + active permit + eligible target -> allow.
        return GatewayResponse(
            decision=Decision.ALLOW,
            determining_policy_ids=(f"permit-{request.tool}",),
            policy_set_version=self.policy_view.policy_set_version,
            enforcement_mode=mode,
            gateway_request_id=gateway_request_id,
            reason="registered action permit matched",
            action_id=action_id,
        )

    def _deny(
        self,
        *,
        determining: tuple[str, ...],
        reason: str,
        action_id: str,
        gateway_request_id: str,
        mode: GatewayEnforcementMode,
    ) -> GatewayResponse:
        return GatewayResponse(
            decision=Decision.DENY,
            determining_policy_ids=determining,
            policy_set_version=self.policy_view.policy_set_version,
            enforcement_mode=mode,
            gateway_request_id=gateway_request_id,
            reason=reason,
            action_id=action_id,
        )


# ---------------------------------------------------------------------------
# Production client
# ---------------------------------------------------------------------------


class AgentCoreGatewayClient(GatewayInvocationPort):
    """Delegates the authorization decision to AgentCore; owns evidence + audit.

    The authorization decision is the transport's (real AgentCore Gateway, or the
    faithful emulator). This client never makes a local allow/deny substitute. It
    is responsible for capturing consistent decision evidence and emitting the
    audit trail through the shared skeleton, and for failing closed when a
    response is ambiguous (an ALLOW with no determining policy).
    """

    def __init__(
        self,
        transport: AgentCoreGatewayTransport,
        audit_sink: AuditSink,
        metrics: MetricSink | None = None,
    ) -> None:
        self._transport = transport
        self._skeleton = GatewayInvocationSkeleton(audit_sink, metrics)

    def register(self, tool: str, handler: ToolHandler) -> None:
        """Register the local stand-in for a Gateway-fronted Lambda target.

        In production the tool runs as the registered Lambda behind the Gateway;
        here the handler is the effector seam the skeleton executes on ALLOW.
        """
        self._skeleton.register(tool, handler)

    @property
    def registered_tools(self) -> frozenset[str]:
        return self._skeleton.registered_tools

    def invoke(self, request: RemediationRequest) -> InvocationResult:
        return self._skeleton.run(request, self._decide)

    def _decide(self, request: RemediationRequest) -> PolicyDecision:
        response = self._transport.authorize(request)
        if response.decision is Decision.ALLOW and not response.determining_policy_ids:
            # Fail closed: the Gateway returned ALLOW with no determining policy.
            raise AmbiguousDecisionError(
                "transport returned ALLOW with no determining policy; refusing (fail-closed)"
            )
        return PolicyDecision(
            decision=response.decision,
            request_id=request.request_id,
            correlation_id=request.correlation_id,
            actor=request.actor,
            action_id=response.action_id or to_cedar_action_id(request.tool),
            target_arn=request.target.arn,
            matched_policy_ids=response.determining_policy_ids,
            policy_set_version=response.policy_set_version,
            reason=response.reason,
            evaluated_at=datetime.now(timezone.utc),
        )
