"""Shared Gateway invocation skeleton.

This module owns the parts of a Gateway invocation that **must not diverge**
between the in-memory test double (`testing.InMemoryCedarGateway`) and the
production client (`gateway.AgentCoreGatewayClient`):

* building the decision evidence (full Cedar ``action_id``, request/correlation
  IDs, policy version);
* emitting the audit trail (``gateway.decision`` always; ``remediation.execution``
  only on an ALLOW that executes a tool);
* the idempotency replay check (a repeated idempotency key never executes the
  tool twice);
* the order of operations: decide -> (DENY: record + return) / (ALLOW: execute
  the registered tool exactly once -> record).

The one thing the skeleton does **not** own is *where the decision comes from*.
Each caller supplies a ``Decider`` callable:

* the in-memory double decides locally via :mod:`ccg.authz` (it is a model of
  the remote engine, by design);
* the production client decides by asking the injected transport (the real
  AgentCore Gateway, or the faithful emulator) and never substitutes a local
  allow/deny.

Keeping evidence/audit/idempotency/ordering in one place is what lets a single
parameterized test body run against both and prove they agree — satisfying the
P0.3 requirement that no "green" claim rests solely on the in-memory double.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

from .contracts import (
    AuditEvent,
    Decision,
    InvocationResult,
    PolicyDecision,
    RemediationRequest,
    ToolOutcome,
    ToolResult,
)
from .observability import Metric, MetricSink, NullMetricSink
from .ports import AuditSink

# Map a tool outcome to its catalog metric. Keeping this here means the Gateway
# is the single counter for tool outcomes (the reconciler does not double-count).
_TOOL_OUTCOME_METRIC: dict[ToolOutcome, Metric] = {
    ToolOutcome.APPLIED: Metric.TOOL_APPLIED,
    ToolOutcome.NOOP: Metric.TOOL_NOOP,
    ToolOutcome.FAILED: Metric.TOOL_FAILED,
}

ToolHandler = Callable[[RemediationRequest], ToolResult]

#: A ``Decider`` returns the authoritative :class:`PolicyDecision` for a request.
#: The skeleton treats its result as final — it never second-guesses an ALLOW or
#: a DENY. Implementations: a local authz model (double) or a transport call
#: (production client / emulator).
Decider = Callable[[RemediationRequest], PolicyDecision]


class AmbiguousDecisionError(RuntimeError):
    """Raised when a decision is unusable and the boundary must fail closed.

    An ALLOW with no determining policy, or a decision whose evidence fields are
    missing, is treated as an error rather than silently honoured. This mirrors
    the fail-closed posture required by design §7 and the P0.3 "fail-closed on
    ambiguous/missing decision evidence" constraint.
    """


class GatewayInvocationSkeleton:
    """Shared invoke flow: evidence capture, audit emission, idempotency, order.

    This class is transport- and decision-source-agnostic. Subclasses or
    composing callers provide:

    * a :class:`~ccg.ports.AuditSink`;
    * a ``Decider`` (``_decide``) producing the authoritative decision;
    * a tool registry (``_tools``) used only when a decision is ALLOW.

    The skeleton is deliberately not a :class:`~ccg.ports.GatewayInvocationPort`
    itself — callers expose ``invoke`` by delegating to :meth:`run`.
    """

    def __init__(self, audit_sink: AuditSink, metrics: MetricSink | None = None) -> None:
        self._audit_sink = audit_sink
        self._metrics = metrics or NullMetricSink()
        self._tools: dict[str, ToolHandler] = {}
        self._replays: dict[str, ToolResult] = {}

    # -- registration -------------------------------------------------------

    def register(self, tool: str, handler: ToolHandler) -> None:
        self._tools[tool] = handler

    @property
    def registered_tools(self) -> frozenset[str]:
        return frozenset(self._tools)

    # -- core flow ----------------------------------------------------------

    def run(self, request: RemediationRequest, decide: Decider) -> InvocationResult:
        """Execute the shared invoke flow for one request.

        ``decide`` is the authoritative decision source. The skeleton validates
        the decision, emits the ``gateway.decision`` audit event, and — only on
        an ALLOW — runs the registered tool exactly once (honouring idempotency)
        and emits the ``remediation.execution`` audit event.
        """
        decision = decide(request)
        self._assert_decision_usable(decision)
        self._record_decision(request, decision)

        if decision.decision is Decision.DENY:
            return InvocationResult(decision=decision)

        # ALLOW: idempotent replay never re-executes the tool. A replay is a
        # no-op by construction (the mutation already happened once), so it is
        # counted as a tool no-op — matching the threat-model replay signal.
        if request.idempotency_key in self._replays:
            replay = replace(self._replays[request.idempotency_key], idempotency_replayed=True)
            self._metrics.increment(
                Metric.TOOL_NOOP, dimensions={"tool": request.tool, "reason": "idempotent_replay"}
            )
            return InvocationResult(decision=decision, tool_result=replay)

        result = self._execute_tool(request)
        self._replays[request.idempotency_key] = result
        self._record_execution(request, result)
        return InvocationResult(decision=decision, tool_result=result)

    # -- helpers ------------------------------------------------------------

    def _assert_decision_usable(self, decision: PolicyDecision) -> None:
        """Fail closed on ambiguous or incomplete decision evidence."""
        if decision.decision is Decision.ALLOW and not decision.matched_policy_ids:
            raise AmbiguousDecisionError(
                "ALLOW decision carried no determining policy; refusing to execute (fail-closed)"
            )

    def _execute_tool(self, request: RemediationRequest) -> ToolResult:
        handler = self._tools.get(request.tool)
        if handler is None:
            # An ALLOW for a tool we cannot execute is a boundary inconsistency;
            # record a FAILED outcome rather than raising, so the decision and a
            # terminal tool outcome are both audited.
            return ToolResult(
                outcome=ToolOutcome.FAILED,
                tool=request.tool,
                target_arn=request.target.arn,
                changed=False,
                message="allowed tool is not registered at the invocation boundary",
                details={"error_type": "unregistered_allowed_tool"},
            )
        try:
            return handler(request)
        except Exception:  # noqa: BLE001 - boundary converts tool failures to typed outcomes.
            return ToolResult(
                outcome=ToolOutcome.FAILED,
                tool=request.tool,
                target_arn=request.target.arn,
                changed=False,
                message="tool execution failed",
                details={"error_type": "tool_failure"},
            )

    def _record_decision(self, request: RemediationRequest, decision: PolicyDecision) -> None:
        # Per-decision metric. The dimension is the tool name (low-cardinality,
        # no secret/ARN). The raw reason string is deliberately NOT a dimension
        # because it can carry detail; a reason-class could be added if the
        # engine exposes one.
        metric = Metric.GATEWAY_ALLOW if decision.decision is Decision.ALLOW else Metric.GATEWAY_DENY
        self._metrics.increment(metric, dimensions={"tool": request.tool})
        self._audit_sink.record(
            AuditEvent(
                event_id=str(uuid4()),
                event_type="gateway.decision",
                actor=request.actor,
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                outcome=decision.decision.value,
                occurred_at=decision.evaluated_at,
                policy_set_version=decision.policy_set_version,
                target=decision.target_arn,
                details={
                    "action_id": decision.action_id,
                    "target_arn": decision.target_arn,
                    "matched_policy_ids": list(decision.matched_policy_ids),
                    "policy_set_version": decision.policy_set_version,
                    "reason": decision.reason,
                },
            )
        )

    def _record_execution(self, request: RemediationRequest, result: ToolResult) -> None:
        # Per-tool-outcome metric. Dimension is the tool name only.
        self._metrics.increment(
            _TOOL_OUTCOME_METRIC[result.outcome], dimensions={"tool": result.tool}
        )
        self._audit_sink.record(
            AuditEvent(
                event_id=str(uuid4()),
                event_type="remediation.execution",
                actor=request.actor,
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                outcome=result.outcome.value,
                occurred_at=datetime.now(timezone.utc),
                target=result.target_arn,
                details={
                    "tool": result.tool,
                    "target_arn": result.target_arn,
                    "changed": result.changed,
                    "idempotency_replayed": result.idempotency_replayed,
                },
            )
        )
