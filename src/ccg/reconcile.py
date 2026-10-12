"""Remediation reconciliation: the finding lifecycle authority.

This service owns every transition of a finding's `status`. It exists so that
the truth about a finding is driven by evidence, not by optimism:

- Requesting a remediation records intent (`REMEDIATION_REQUESTED`).
- A tool outcome records what the tool reported (`SUCCEEDED` / `NOOP` /
  `FAILED`) but **never** claims the underlying drift is fixed.
- Only a **confirming discovery read** — the drift is no longer observed while
  the finding sits in a post-remediation success/no-op state — may move a
  finding to `RESOLVED` (requirements CCG-REQ-005, CCG-REQ-026, ACC-14).
- Uncertain or failed outcomes leave the finding unresolved and require a later
  read; they never short-circuit to `RESOLVED`.

All transitions are validated against an explicit allow-list, so an illegal or
out-of-order transition is rejected rather than silently applied. Every change
emits a redactable audit event with the correlation ID. No AWS calls happen
here; persistence is via the injected `FindingRepository`.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from uuid import uuid4

from .contracts import AuditEvent, Finding, FindingStatus, ToolOutcome
from .ports import AuditSink, FindingRepository

# Observability note (P1.4): the reconciler deliberately emits NO tool-outcome
# metrics. Tool outcomes (APPLIED/NOOP/FAILED) are counted exactly once at the
# Gateway boundary (`ccg.gateway_core`), which is where every tool outcome
# originates. `record_tool_outcome` here only mirrors that outcome into the
# finding's lifecycle status, so emitting again would double-count. Resolution
# is a lifecycle transition, not a tool outcome, and has no catalog metric; the
# finding's RESOLVED state is itself the operator-visible signal via the audit
# trail and the findings store. If a dedicated resolution counter is wanted
# later, add it to the `Metric` catalog first (do not reuse a tool metric).


@dataclass(frozen=True, slots=True)
class ReconcileContext:
    """Who/why context threaded through a reconciliation step.

    Bundles the correlation fields every transition needs so lifecycle methods
    stay small and callers pass one value instead of three positional args.
    """

    actor: str
    correlation_id: str
    request_id: str

# Explicit, monotonic-enough lifecycle. Each key lists the statuses a finding
# may move to from that key. Self-transitions are allowed where they represent
# an idempotent re-report (handled as no-ops by the service).
_ALLOWED_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.OPEN: frozenset(
        {FindingStatus.REMEDIATION_REQUESTED, FindingStatus.ACCEPTED_RISK}
    ),
    FindingStatus.REMEDIATION_REQUESTED: frozenset(
        {
            FindingStatus.REMEDIATION_SUCCEEDED,
            FindingStatus.REMEDIATION_NOOP,
            FindingStatus.REMEDIATION_FAILED,
        }
    ),
    # After a success/no-op, a confirming read resolves; a failed re-attempt can
    # be requested again; a fresh re-observation of drift reopens the finding.
    FindingStatus.REMEDIATION_SUCCEEDED: frozenset(
        {FindingStatus.RESOLVED, FindingStatus.OPEN}
    ),
    FindingStatus.REMEDIATION_NOOP: frozenset(
        {FindingStatus.RESOLVED, FindingStatus.OPEN}
    ),
    FindingStatus.REMEDIATION_FAILED: frozenset(
        {FindingStatus.REMEDIATION_REQUESTED, FindingStatus.OPEN}
    ),
    # A resolved finding can only reopen if drift is observed again.
    FindingStatus.RESOLVED: frozenset({FindingStatus.OPEN}),
    FindingStatus.ACCEPTED_RISK: frozenset({FindingStatus.OPEN}),
}

# Statuses from which a confirming (drift-gone) read is allowed to resolve.
_RESOLVABLE_FROM = frozenset(
    {FindingStatus.REMEDIATION_SUCCEEDED, FindingStatus.REMEDIATION_NOOP}
)

# Terminal / clean statuses for teardown reconciliation (spec task 6.5, Phase A).
# A finding in one of these states has no tool operation in flight: either it was
# never actioned (OPEN), it was explicitly accepted (ACCEPTED_RISK), or a
# confirming discovery read already closed it (RESOLVED). A finding in any
# in-flight state (REMEDIATION_REQUESTED / _SUCCEEDED / _NOOP / _FAILED) is NOT
# clean — a tool outcome has been recorded but not yet reconciled by a discovery
# read, so teardown must wait rather than delete under an uncertain outcome.
_TEARDOWN_CLEAN_STATUSES = frozenset(
    {FindingStatus.OPEN, FindingStatus.RESOLVED, FindingStatus.ACCEPTED_RISK}
)


def is_teardown_clean(status: FindingStatus) -> bool:
    """True when a single finding is in a terminal/clean state for teardown.

    Teardown (task 6.5 Phase A) may only proceed once no remediation is in
    flight. A finding mid-remediation (requested/succeeded/noop/failed but not
    yet confirmed by discovery) is deliberately treated as *not* clean, so the
    operator either waits for reconciliation or records an explicit decision.
    """
    return status in _TEARDOWN_CLEAN_STATUSES


def teardown_blocking_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Return the findings that block teardown because they are not clean.

    An empty list means every finding is in a terminal/clean state and the
    reconciliation gate (Phase A) is satisfied. This is a read-only check: it
    changes no state and performs no AWS calls.
    """
    return [finding for finding in findings if not is_teardown_clean(finding.status)]

_TOOL_OUTCOME_TO_STATUS: dict[ToolOutcome, FindingStatus] = {
    ToolOutcome.APPLIED: FindingStatus.REMEDIATION_SUCCEEDED,
    ToolOutcome.NOOP: FindingStatus.REMEDIATION_NOOP,
    ToolOutcome.FAILED: FindingStatus.REMEDIATION_FAILED,
}


class IllegalTransitionError(ValueError):
    """Raised when a requested status transition is not permitted."""


class ReconciliationError(LookupError):
    """Raised when reconciliation targets a finding that does not exist."""


def is_allowed_transition(current: FindingStatus, target: FindingStatus) -> bool:
    if current == target:
        return True
    return target in _ALLOWED_TRANSITIONS.get(current, frozenset())


class ReconciliationService:
    """Single authority for finding-status transitions."""

    def __init__(self, repository: FindingRepository, audit_sink: AuditSink | None = None) -> None:
        self._repository = repository
        self._audit_sink = audit_sink

    # --- lifecycle steps -------------------------------------------------

    def mark_requested(self, finding_id: str, context: ReconcileContext) -> Finding:
        """Record that a remediation was requested for a finding."""
        return self._transition(
            finding_id,
            FindingStatus.REMEDIATION_REQUESTED,
            context,
            event_type="reconcile.requested",
        )

    def record_tool_outcome(self, finding_id: str, outcome: ToolOutcome, context: ReconcileContext) -> Finding:
        """Record what the tool reported. This never resolves the finding."""
        target = _TOOL_OUTCOME_TO_STATUS[outcome]
        return self._transition(
            finding_id,
            target,
            context,
            event_type="reconcile.tool_outcome",
            details={"tool_outcome": outcome.value},
        )

    def confirm_from_discovery(
        self,
        finding_id: str,
        context: ReconcileContext,
        *,
        drift_still_present: bool,
    ) -> Finding:
        """Apply a confirming discovery read.

        If drift is gone and the finding is in a post-remediation success/no-op
        state, resolve it. If drift is still present, the finding is not
        resolved (left as-is); an uncertain/failed prior outcome therefore never
        becomes RESOLVED without a clean read.
        """
        finding = self._require(finding_id)
        if drift_still_present:
            # Nothing to resolve; a fresh discovery run already re-observed drift
            # and updated the finding via the normal merge path.
            return finding
        if finding.status not in _RESOLVABLE_FROM:
            # Not in a resolvable state (e.g. still OPEN, FAILED, or REQUESTED):
            # a clean read alone does not resolve it.
            return finding
        return self._transition(
            finding_id,
            FindingStatus.RESOLVED,
            context,
            event_type="reconcile.resolved",
            details={"confirmed_by": "discovery_read"},
        )

    # --- internals -------------------------------------------------------

    def _require(self, finding_id: str) -> Finding:
        finding = self._repository.get(finding_id)
        if finding is None:
            raise ReconciliationError(f"finding not found: {finding_id}")
        return finding

    def _transition(
        self,
        finding_id: str,
        target: FindingStatus,
        context: ReconcileContext,
        *,
        event_type: str,
        details: dict | None = None,
    ) -> Finding:
        finding = self._require(finding_id)
        if not is_allowed_transition(finding.status, target):
            raise IllegalTransitionError(f"{finding.status.value} -> {target.value} is not permitted")
        if finding.status == target:
            return finding  # idempotent no-op; no revision churn, no audit noise
        updated = replace(finding, status=target)
        self._repository.upsert(updated)
        if self._audit_sink is not None:
            self._audit_sink.record(
                AuditEvent(
                    event_id=str(uuid4()),
                    event_type=event_type,
                    actor=context.actor,
                    request_id=context.request_id,
                    correlation_id=context.correlation_id,
                    outcome=target.value,
                    occurred_at=datetime.now(timezone.utc),
                    details={
                        "finding_id": finding_id,
                        "from_status": finding.status.value,
                        "to_status": target.value,
                        **(details or {}),
                    },
                )
            )
        return updated
