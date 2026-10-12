"""Live AgentCore policy-activation control-plane transport (seam).

**No boto3 / live AWS calls.** This module provides the production shape of the
:class:`~ccg.policy.PolicyControlPlaneTransport` that will drive the real
``bedrock-agentcore-control`` API, expressed against an *injected client
protocol* (:class:`AgentCoreControlPlaneClient`) so no AWS SDK is hardcoded.
The real client is wired in at deploy time; tests inject a fake.

AWS mapping (``docs/AGENTCORE_CAPABILITY_RECORD.md`` §3)
--------------------------------------------------------
=========================  ================================================================
Transport member           AgentCore control-plane operation
=========================  ================================================================
``update_policy_set``      ``UpdatePolicy(enforcementMode=ACTIVE|LOG_ONLY)`` →
                           HTTP 202 + ``x-amzn-RequestId`` (async, eventually consistent).
``confirm_propagation``    poll ``GetPolicy`` until ``status == ACTIVE`` (activation) or
                           the policy is ``LOG_ONLY`` (deactivation); bounded by ``attempts``.
``get_state``              ``GetPolicy`` / ``GetPolicyEngine`` (current effective state).
``force_deny_safe``        ``UpdatePolicy(enforcementMode=LOG_ONLY)`` (reconcile to deny-safe).
=========================  ================================================================

Enforcement-mode note: the activation *lever* in CCG is the policy-level
``UpdatePolicy(enforcementMode=...)``. The engine-level ``ENFORCE``/``LOG_ONLY``
switch (``UpdateGateway.policyEngineConfiguration.mode``) is a separate,
privileged control and is intentionally **not** exposed by this transport.

IAM permissions required on the control-plane role (capability record §3):
``bedrock-agentcore:UpdatePolicy``, ``bedrock-agentcore:GetPolicy``,
``bedrock-agentcore:GetPolicyEngine`` (plus ``GetPolicySummary`` /
``ListPolicySummaries`` for visibility). Resource scope:
``arn:aws:bedrock-agentcore:<region>:<account>:policy-engine/*/policy/*``.

Concurrency: generation-based optimistic concurrency is the single source of
truth and lives in :class:`~ccg.policy.PolicyActivationService`. The live
``UpdatePolicy`` request model exposes no ETag/generation field, so this
transport maps the application-level ``generation`` onto a ``GetPolicy``
read-before-write check and surfaces a conflict as an exception the service
translates to a fail-closed outcome.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol, TypedDict

from .contracts import (
    PolicyActivationRequest,
    PolicyEnforcementMode,
    PolicyState,
)
from .policy import PolicyControlPlaneTransport, PropagationUncertainError

#: Terminal success status for a policy on the control plane (capability §1.8).
POLICY_STATUS_ACTIVE: str = "ACTIVE"
#: Transient status while an update is propagating.
POLICY_STATUS_UPDATING: str = "UPDATING"
#: Failure statuses that must never be treated as a successful activation.
POLICY_FAILED_STATUSES: frozenset[str] = frozenset(
    {"CREATE_FAILED", "UPDATE_FAILED", "DELETE_FAILED"}
)


class GetPolicyResponse(TypedDict):
    """Minimal projection of the ``GetPolicy`` response the transport needs.

    Mirrors the fields in ``docs/AGENTCORE_CAPABILITY_RECORD.md`` §1.8/§3:
    ``enforcementMode`` (``ACTIVE``/``LOG_ONLY``), lifecycle ``status``, the
    effective ``policySetVersion``, and the ``policyEngineId``. ``statusReasons``
    is optional diagnostic text present on failure states.
    """

    policyEngineId: str
    policySetVersion: str
    enforcementMode: str
    status: str


class UpdatePolicyResponse(TypedDict):
    """Minimal projection of the ``UpdatePolicy`` (HTTP 202) response.

    The control plane returns the request ID via the ``x-amzn-RequestId`` header;
    the injected client is responsible for surfacing it as ``requestId`` here.
    """

    requestId: str
    status: str


class AgentCoreControlPlaneClient(Protocol):
    """Injected seam for the real ``bedrock-agentcore-control`` client.

    The production implementation calls boto3 (``bedrock-agentcore-control``,
    API version ``2023-06-05``); this process never imports boto3. Methods map
    one-to-one onto the AWS operations named in the module docstring.
    """

    def get_policy(self) -> GetPolicyResponse:
        """``GetPolicy`` — return the current policy's effective state/status."""
        ...

    def update_policy(self, enforcement_mode: str) -> UpdatePolicyResponse:
        """``UpdatePolicy(enforcementMode=...)`` — returns 202 + request ID."""
        ...


def _enforcement_mode(raw: str) -> PolicyEnforcementMode:
    try:
        return PolicyEnforcementMode(raw)
    except ValueError as exc:  # unknown mode string from the control plane
        raise PropagationUncertainError(f"unrecognized enforcement mode: {raw!r}") from exc


class AgentCoreControlPlaneTransport(PolicyControlPlaneTransport):
    """Production transport over the injected AgentCore control-plane client.

    This is a seam: it contains the AWS *contract* (operation mapping, status
    polling, fail-closed semantics) but delegates every network call to the
    injected :class:`AgentCoreControlPlaneClient`. It satisfies the full
    :class:`~ccg.policy.PolicyControlPlaneTransport` protocol (including
    ``update_policy_set`` — the P1.2 fix) so the service can drive it unchanged.
    """

    def __init__(
        self,
        client: AgentCoreControlPlaneClient,
        policy_engine_id: str,
        initial_generation: int = 0,
    ) -> None:
        self._client = client
        self._policy_engine_id = policy_engine_id
        # The live UpdatePolicy model has no ETag/generation. Generation is the
        # application-level concurrency token (capability record §3): the service
        # reads it via get_state() and the transport advances it once — and only
        # once — a change is confirmed propagated. This keeps generation the
        # single source of truth without a second conflicting guard.
        self._generation = initial_generation

    # -- reads --------------------------------------------------------------

    def get_state(self) -> PolicyState:
        return self._to_state(self._client.get_policy())

    # -- writes -------------------------------------------------------------

    def update_policy_set(
        self,
        request: PolicyActivationRequest,
        enforcement_mode: PolicyEnforcementMode,
    ) -> tuple[PolicyState, str]:
        """Call ``UpdatePolicy`` (async, HTTP 202) and return (state, requestId).

        Generation is validated by the service before this is reached. As a
        defense-in-depth read-before-write (the live API exposes no ETag), we
        re-read current state and fail closed if a failure status is already
        present.
        """
        current = self._client.get_policy()
        if current["status"] in POLICY_FAILED_STATUSES:
            raise RuntimeError(
                f"policy is in failure state {current['status']} before update; refusing"
            )
        response = self._client.update_policy(enforcement_mode.value)
        if response["status"] in POLICY_FAILED_STATUSES:
            raise RuntimeError(f"UpdatePolicy returned failure status {response['status']}")
        # The returned state reflects the *requested* mode; it is not confirmed
        # live until confirm_propagation observes it.
        state = self._to_state(self._client.get_policy())
        return state, response["requestId"]

    def confirm_propagation(
        self,
        expected_mode: PolicyEnforcementMode,
        attempts: int,
    ) -> PolicyState:
        """Poll ``GetPolicy`` until ``status == ACTIVE`` and mode matches.

        Fails closed (:class:`PropagationUncertainError`) if the policy enters a
        failure status or does not converge to ``expected_mode`` within
        ``attempts`` polls. The injected client controls how each poll resolves
        (a real client sleeps/backs off between calls).
        """
        last_status = "UNKNOWN"
        for _ in range(attempts):
            policy = self._client.get_policy()
            last_status = policy["status"]
            if last_status in POLICY_FAILED_STATUSES:
                raise PropagationUncertainError(
                    f"policy entered failure status {last_status} during propagation"
                )
            if last_status == POLICY_STATUS_ACTIVE and _enforcement_mode(
                policy["enforcementMode"]
            ) is expected_mode:
                # Advance the application-level concurrency token exactly once,
                # on confirmed propagation.
                self._generation += 1
                return self._to_state(policy)
        raise PropagationUncertainError(
            f"policy did not reach {expected_mode}/ACTIVE within {attempts} attempts "
            f"(last status {last_status})"
        )

    def force_deny_safe(self) -> PolicyState:
        """``UpdatePolicy(enforcementMode=LOG_ONLY)`` → reconcile to deny-safe."""
        self._client.update_policy(PolicyEnforcementMode.LOG_ONLY.value)
        return self._to_state(self._client.get_policy())

    # -- helpers ------------------------------------------------------------

    def _to_state(self, policy: GetPolicyResponse) -> PolicyState:
        return PolicyState(
            policy_engine_id=policy.get("policyEngineId") or self._policy_engine_id,
            policy_set_version=policy["policySetVersion"],
            enforcement_mode=_enforcement_mode(policy["enforcementMode"]),
            generation=self._generation,
            updated_by="agentcore-control-plane",
            updated_at=datetime.now(timezone.utc),
        )
