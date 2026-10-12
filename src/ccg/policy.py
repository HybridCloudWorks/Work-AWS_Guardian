"""Audited AgentCore policy activation boundary.

This module does not decide whether a remediation is allowed. Remediation
authorization remains the responsibility of the remote AgentCore Gateway
Policy Engine. The control-plane transport only changes the separately
versioned policy enforcement state after the admin control-plane request is
validated and audited.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol
from uuid import uuid4

from .contracts import (
    ActivationOutcome,
    AuditEvent,
    PolicyActivationRequest,
    PolicyActivationResult,
    PolicyEnforcementMode,
    PolicyState,
)
from .observability import Metric, MetricSink, NullMetricSink
from .ports import AuditSink


#: Default number of ``confirm_propagation`` polls before an activation is
#: treated as uncertain. The real AgentCore ``UpdatePolicy`` is async (HTTP 202)
#: and eventually consistent within a few seconds (capability record §3); the
#: service polls ``GetPolicy.status`` until it reaches ``ACTIVE``. If it never
#: confirms within the bound, the activation is uncertain and we fail closed.
DEFAULT_PROPAGATION_ATTEMPTS: int = 5


class PropagationUncertainError(RuntimeError):
    """Raised when a control-plane update does not confirm as propagated.

    ``UpdatePolicy`` returns HTTP 202 immediately; the change is applied to the
    evaluation path asynchronously. If polling ``GetPolicy.status`` does not
    observe ``ACTIVE`` (for an activation) or ``LOG_ONLY`` (for a deactivation)
    within the attempt bound, the effective state is uncertain. The service
    treats this exactly like a failed update: reconcile to deny-safe and record
    ``ActivationOutcome.FAILED`` so mutations remain blocked.
    """


class PolicyControlPlaneTransport(Protocol):
    """Narrow control-plane seam. Every transport MUST implement all members.

    ``update_policy_set`` is part of the protocol (P1.2): the service calls it,
    so a real transport that omitted it would raise ``AttributeError`` at
    runtime. Declaring it here forces every implementation — including the live
    :class:`~ccg.control_plane.AgentCoreControlPlaneTransport` — to provide it.

    Generation-based optimistic concurrency is the single source of truth for
    concurrency: the service compares ``request.expected_generation`` against the
    current state's ``generation`` and the transport advances ``generation`` on
    every successful update. A transport MUST NOT invent a second, conflicting
    concurrency guard.
    """

    def get_state(self) -> PolicyState:
        """Return the current effective policy state (maps to ``GetPolicy``)."""
        ...

    def update_policy_set(
        self,
        request: PolicyActivationRequest,
        enforcement_mode: PolicyEnforcementMode,
    ) -> tuple[PolicyState, str]:
        """Apply the requested enforcement mode and return (state, request_id).

        Maps to the async control-plane update (``UpdatePolicy``). The returned
        ``PolicyState`` reflects the newly requested state and the string is the
        control-plane request ID (``x-amzn-RequestId``). The returned state is
        NOT yet guaranteed to be live — the service confirms propagation via
        :meth:`confirm_propagation` before treating the change as effective.
        """
        ...

    def confirm_propagation(
        self,
        expected_mode: PolicyEnforcementMode,
        attempts: int,
    ) -> PolicyState:
        """Poll until the effective state reflects ``expected_mode``.

        Maps to polling ``GetPolicy.status`` until it reaches ``ACTIVE`` (for an
        activation) or ``LOG_ONLY`` (for a deactivation). MUST raise
        :class:`PropagationUncertainError` if the state does not confirm within
        ``attempts`` polls. On confirmation it returns the propagated state.
        """
        ...

    def force_deny_safe(self) -> PolicyState:
        """Reconcile the remote policy engine to a non-authorizing mode."""
        ...


class PolicyActivationService:
    """Performs versioned, audited policy state changes through a control plane."""

    def __init__(
        self,
        transport: PolicyControlPlaneTransport,
        audit_sink: AuditSink,
        approved_versions: frozenset[str] | None = None,
        propagation_attempts: int = DEFAULT_PROPAGATION_ATTEMPTS,
        metrics: MetricSink | None = None,
    ) -> None:
        self._transport = transport
        self._audit_sink = audit_sink
        self._metrics = metrics or NullMetricSink()
        self._approved_versions = approved_versions or frozenset({"permits-inactive", "v1"})
        # Service-level idempotency guard: this is the real replay guard for an
        # activation request. The transport's own request-id set (if any) is a
        # test-double convenience, not the authority.
        self._processed_requests: dict[str, PolicyActivationResult] = {}
        if propagation_attempts < 1:
            raise ValueError("propagation_attempts must be at least 1")
        self._propagation_attempts = propagation_attempts

    def current_state(self) -> PolicyState:
        return self._transport.get_state()

    def apply(self, request: PolicyActivationRequest) -> PolicyActivationResult:
        if request.request_id in self._processed_requests:
            return self._processed_requests[request.request_id]
        current = self._transport.get_state()
        if request.requested_version not in self._approved_versions:
            return self._reject(request, current, "policy version is not approved")
        if not request.activate and request.requested_version != current.policy_set_version:
            return self._reject(request, current, "deactivation version does not match effective version")
        if request.expected_generation != current.generation:
            return self._reject(request, current, "stale policy generation")

        desired_mode = PolicyEnforcementMode.ACTIVE if request.activate else PolicyEnforcementMode.LOG_ONLY
        self._audit_sink.record(
            AuditEvent(
                event_id=str(uuid4()),
                event_type="policy.activation.intent",
                actor=request.actor,
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                outcome="REQUESTED",
                occurred_at=datetime.now(timezone.utc),
                details={
                    "requested_version": request.requested_version,
                    "expected_generation": request.expected_generation,
                    "desired_mode": desired_mode,
                    "reason": request.reason,
                },
            )
        )

        try:
            state, control_plane_request_id = self._transport.update_policy_set(request, desired_mode)
            # UpdatePolicy is async (HTTP 202). The returned state is not yet
            # guaranteed live: poll GetPolicy.status until it reflects the
            # requested mode. An unconfirmed propagation is uncertain and must
            # fail closed exactly like an update failure.
            state = self._transport.confirm_propagation(desired_mode, self._propagation_attempts)
        except PropagationUncertainError:
            return self._fail_closed(
                request,
                desired_mode,
                failure_detail="propagation",
                base_message="policy update propagation could not be confirmed",
            )
        except Exception:  # noqa: BLE001 - reconcile or fail closed at the control-plane boundary.
            return self._fail_closed(
                request,
                desired_mode,
                failure_detail="update",
                base_message="policy update failed",
            )

        outcome = ActivationOutcome.ACTIVATED if request.activate else ActivationOutcome.DEACTIVATED
        self._metrics.increment(
            Metric.ACTIVATION_SUCCESS, dimensions={"activate": str(request.activate).lower()}
        )
        self._audit_sink.record(
            AuditEvent(
                event_id=str(uuid4()),
                event_type="policy.activation.result",
                actor=request.actor,
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                outcome=outcome.value,
                occurred_at=datetime.now(timezone.utc),
                details={
                    "effective_version": state.policy_set_version,
                    "effective_mode": state.enforcement_mode,
                    "generation": state.generation,
                    "control_plane_request_id": control_plane_request_id,
                },
            )
        )
        result = PolicyActivationResult(
            outcome=outcome,
            request_id=request.request_id,
            correlation_id=request.correlation_id,
            state=state,
            control_plane_request_id=control_plane_request_id,
            message="policy state updated through the AgentCore control plane",
        )
        self._processed_requests[request.request_id] = result
        return result

    def _fail_closed(
        self,
        request: PolicyActivationRequest,
        desired_mode: PolicyEnforcementMode,
        *,
        failure_detail: str,
        base_message: str,
    ) -> PolicyActivationResult:
        """Reconcile to deny-safe and record a FAILED activation.

        Used for both a failed ``update_policy_set`` call and an uncertain
        propagation: in either case the effective state cannot be trusted, so we
        force the remote engine back to a non-authorizing (``LOG_ONLY``) posture.
        If even the reconciliation fails, the state is unknown and manual
        reconciliation is required — mutations must remain blocked.
        """
        try:
            reconciled = self._transport.force_deny_safe()
            message = f"{base_message}; remote policy reconciled to deny-safe mode"
        except Exception:  # noqa: BLE001 - manual reconciliation is required if rollback fails.
            reconciled = None
            message = f"{base_message}; effective state is unknown and mutations must remain blocked"
        self._metrics.increment(
            Metric.ACTIVATION_FAILURE, dimensions={"failure": failure_detail}
        )
        self._audit_sink.record(
            AuditEvent(
                event_id=str(uuid4()),
                event_type="policy.activation.result",
                actor=request.actor,
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                outcome=ActivationOutcome.FAILED.value,
                occurred_at=datetime.now(timezone.utc),
                details={
                    "desired_mode": desired_mode,
                    "failure": failure_detail,
                    "effective_state": "DENY_SAFE" if reconciled is not None else "UNKNOWN",
                },
            )
        )
        result = PolicyActivationResult(
            outcome=ActivationOutcome.FAILED,
            request_id=request.request_id,
            correlation_id=request.correlation_id,
            state=reconciled,
            control_plane_request_id=None,
            message=message,
        )
        self._processed_requests[request.request_id] = result
        return result

    def _reject(self, request: PolicyActivationRequest, current: PolicyState, reason: str) -> PolicyActivationResult:
        # The `reason` text stays out of the dimension (it is internal and could
        # evolve); only the stable outcome class is emitted.
        self._metrics.increment(
            Metric.ACTIVATION_REJECTED, dimensions={"activate": str(request.activate).lower()}
        )
        self._audit_sink.record(
            AuditEvent(
                event_id=str(uuid4()),
                event_type="policy.activation.result",
                actor=request.actor,
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                outcome=ActivationOutcome.REJECTED.value,
                occurred_at=datetime.now(timezone.utc),
                details={
                    "reason": reason,
                    "requested_version": request.requested_version,
                    "current_version": current.policy_set_version,
                    "current_generation": current.generation,
                },
            )
        )
        result = PolicyActivationResult(
            outcome=ActivationOutcome.REJECTED,
            request_id=request.request_id,
            correlation_id=request.correlation_id,
            state=current,
            control_plane_request_id=None,
            message=reason,
        )
        self._processed_requests[request.request_id] = result
        return result


class InMemoryPolicyControlPlane(PolicyControlPlaneTransport):
    """Test double; never use this as production policy enforcement.

    Concurrency is governed by ``generation`` — the same single source of truth
    the real control plane uses. The ``_request_ids`` set here is a
    **test-double-only** replay tripwire; the authoritative idempotency guard is
    :class:`PolicyActivationService`'s ``_processed_requests`` cache, which
    prevents a replayed request from ever reaching the transport a second time.

    ``update_policy_set`` records the newly requested state but leaves it
    *unpropagated* (``_pending_mode``) until :meth:`confirm_propagation` is
    polled — modelling the async HTTP-202 ``UpdatePolicy`` → poll
    ``GetPolicy.status`` contract. Set ``propagation_fails`` to simulate an
    update that is accepted (202) but never reaches ``ACTIVE`` within the bound.
    """

    def __init__(self, policy_engine_id: str = "test-engine") -> None:
        self._state = PolicyState(
            policy_engine_id=policy_engine_id,
            policy_set_version="permits-inactive",
            enforcement_mode=PolicyEnforcementMode.LOG_ONLY,
            generation=0,
            updated_by="system",
            updated_at=datetime.now(timezone.utc),
        )
        #: Simulate a failing control-plane update call (raises on next update).
        self.fail_next = False
        #: Simulate an accepted-but-never-propagated update (confirm never
        #: observes the requested mode within the attempt bound).
        self.propagation_fails = False
        self._request_ids: set[str] = set()
        self._pending_mode: PolicyEnforcementMode | None = None

    def get_state(self) -> PolicyState:
        return self._state

    def update_policy_set(
        self,
        request: PolicyActivationRequest,
        enforcement_mode: PolicyEnforcementMode,
    ) -> tuple[PolicyState, str]:
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("simulated control-plane failure")
        if request.request_id in self._request_ids:
            raise RuntimeError("replayed control-plane request")
        if request.expected_generation != self._state.generation:
            raise RuntimeError("stale control-plane generation")
        self._request_ids.add(request.request_id)
        self._state = PolicyState(
            policy_engine_id=self._state.policy_engine_id,
            policy_set_version=request.requested_version,
            enforcement_mode=enforcement_mode,
            generation=self._state.generation + 1,
            updated_by=request.actor,
            updated_at=datetime.now(timezone.utc),
        )
        # Model the async contract: the new state is accepted (HTTP 202) but is
        # only "confirmed propagated" once confirm_propagation observes it.
        self._pending_mode = enforcement_mode
        return self._state, f"cp-{uuid4()}"

    def confirm_propagation(
        self,
        expected_mode: PolicyEnforcementMode,
        attempts: int,
    ) -> PolicyState:
        if self.propagation_fails:
            # Accepted but never converges to the requested mode: uncertain.
            raise PropagationUncertainError(
                f"policy did not reach {expected_mode} within {attempts} attempts"
            )
        # In-memory convergence is immediate once accepted; a real transport
        # would poll GetPolicy.status up to ``attempts`` times.
        if self._pending_mode != expected_mode or self._state.enforcement_mode != expected_mode:
            raise PropagationUncertainError(
                f"effective mode {self._state.enforcement_mode} does not match requested {expected_mode}"
            )
        self._pending_mode = None
        return self._state

    def force_deny_safe(self) -> PolicyState:
        self._pending_mode = None
        if self._state.enforcement_mode is PolicyEnforcementMode.LOG_ONLY:
            return self._state
        request = PolicyActivationRequest(
            request_id=f"rollback-{uuid4()}",
            correlation_id=f"rollback-{uuid4()}",
            actor="system-reconciliation",
            requested_version=self._state.policy_set_version,
            expected_generation=self._state.generation,
            reason="automatic deny-safe reconciliation",
            activate=False,
        )
        state, _ = self.update_policy_set(request, PolicyEnforcementMode.LOG_ONLY)
        self._pending_mode = None
        return state
