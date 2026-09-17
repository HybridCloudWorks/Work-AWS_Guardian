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

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from uuid import uuid4

from .contracts import AuditEvent, Finding, FindingStatus, ToolOutcome
from .ports import AuditSink, FindingRepository


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
