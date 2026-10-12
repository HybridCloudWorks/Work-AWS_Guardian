"""Audited policy activation control-plane tests (spec task 4.3).

Covers CCG-REQ-015 .. CCG-REQ-017 and acceptance scenarios ACC-08, ACC-09:

* successful activation records intent BEFORE result, with effective
  version/mode and a control-plane request ID;
* the UI / a non-admin principal cannot grant access through the API, and a
  direct ``apply()`` still requires a valid generation (no bypass);
* stale generation is REJECTED and leaves state unchanged;
* a replayed request_id returns the cached result and triggers only one update;
* a schema/transport error FAILS and reconciles to deny-safe (LOG_ONLY);
* an *uncertain propagation* (update accepted but ``GetPolicy`` never reaches
  ACTIVE within the bound) FAILS to deny-safe and leaves mutations denied;
* the deactivation path moves ACTIVE -> LOG_ONLY;
* after any failed/ambiguous activation, a remediation request through the
  faithful Gateway + EffectivePolicyView is still DENIED — proving no
  propagation happened on failure.

Both the in-memory transport double and the live
``AgentCoreControlPlaneTransport`` seam (driven by a fake client — no boto3) are
exercised so the P1.2 protocol fix is proven against a "real transport" shape.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from uuid import uuid4

from ccg.api import AuthenticatedPrincipal, ComplianceApi, UnauthorizedError
from ccg.contracts import (
    ActivationOutcome,
    Decision,
    Finding,
    FindingStatus,
    PolicyActivationRequest,
    PolicyEnforcementMode,
    RemediationCommand,
    Severity,
    TargetRef,
)
from ccg.control_plane import (
    AgentCoreControlPlaneTransport,
    GetPolicyResponse,
    UpdatePolicyResponse,
    POLICY_STATUS_ACTIVE,
    POLICY_STATUS_UPDATING,
)
from ccg.gateway import (
    AgentCoreGatewayClient,
    EffectivePolicyView,
    FaithfulAgentCoreEmulator,
    GatewayEnforcementMode,
)
from ccg.policy import (
    InMemoryPolicyControlPlane,
    PolicyActivationService,
    PolicyControlPlaneTransport,
    PropagationUncertainError,
)
from ccg.testing import InMemoryFindingRepository, RecordingAuditSink
from ccg.tools import default_tool_handlers


# ---------------------------------------------------------------------------
# Fake live control-plane client (NO boto3) for the AgentCoreControlPlaneTransport
# ---------------------------------------------------------------------------


class FakeControlPlaneClient:
    """In-memory stand-in for the real ``bedrock-agentcore-control`` client.

    Models the async UpdatePolicy -> poll GetPolicy.status contract. By default,
    an update converges to ACTIVE immediately. Knobs let a test simulate:

    * ``raise_on_update`` — ``UpdatePolicy`` throws (schema/transport error);
    * ``stuck_status`` — ``GetPolicy.status`` never leaves this value
      (e.g. ``UPDATING``), so propagation is never confirmed (uncertain);
    * ``fail_status`` — ``GetPolicy.status`` reports a terminal failure.
    """

    def __init__(self, policy_engine_id: str = "pe-fake") -> None:
        self.policy_engine_id = policy_engine_id
        self.version = "permits-inactive"
        self.mode = PolicyEnforcementMode.LOG_ONLY.value
        self.status = POLICY_STATUS_ACTIVE
        self.update_calls = 0
        self.raise_on_update = False
        self.stuck_status: str | None = None
        self.fail_status: str | None = None

    def get_policy(self) -> GetPolicyResponse:
        return GetPolicyResponse(
            policyEngineId=self.policy_engine_id,
            policySetVersion=self.version,
            enforcementMode=self.mode,
            status=self.fail_status or self.stuck_status or self.status,
        )

    def update_policy(self, enforcement_mode: str) -> UpdatePolicyResponse:
        self.update_calls += 1
        # A schema error rejects the *activation* (ACTIVE) update; reverting to
        # the deny-safe LOG_ONLY posture still succeeds, so force_deny_safe can
        # reconcile. This models UPDATE_FAILED on a bad policy while rollback works.
        if self.raise_on_update and enforcement_mode != PolicyEnforcementMode.LOG_ONLY.value:
            raise RuntimeError("simulated UpdatePolicy schema error")
        self.mode = enforcement_mode
        # If a stuck/fail status is configured the mode changes but status never
        # reaches ACTIVE, so confirm_propagation times out / fails.
        if self.stuck_status is None and self.fail_status is None:
            self.status = POLICY_STATUS_ACTIVE
        return UpdatePolicyResponse(requestId=f"x-amzn-{uuid4()}", status="ACCEPTED")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _activation(
    *,
    activate: bool = True,
    version: str = "v1",
    generation: int = 0,
    actor: str = "admin",
    request_id: str | None = None,
) -> PolicyActivationRequest:
    return PolicyActivationRequest(
        request_id=request_id or str(uuid4()),
        correlation_id="corr-act",
        actor=actor,
        requested_version=version,
        expected_generation=generation,
        reason="activation control-plane test",
        activate=activate,
    )


def _demo_finding() -> Finding:
    now = datetime.now(timezone.utc)
    return Finding(
        finding_id="finding-act-1",
        rule_id="s3-encryption-missing",
        source="config",
        target=TargetRef("arn:aws:s3:::ccg-demo", "s3_bucket", {"CCGDemo": "true"}),
        severity=Severity.HIGH,
        title="S3 bucket missing default encryption",
        evidence_refs=("config:1",),
        status=FindingStatus.OPEN,
        first_seen_at=now,
        last_seen_at=now,
        correlation_id="corr-act",
    )


# ---------------------------------------------------------------------------
# 1. Successful activation — CCG-REQ-015
# ---------------------------------------------------------------------------


class SuccessfulActivationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = RecordingAuditSink()
        self.transport = InMemoryPolicyControlPlane()
        self.svc = PolicyActivationService(self.transport, self.audit)

    def test_intent_recorded_before_result(self) -> None:
        self.svc.apply(_activation())
        types = [e.event_type for e in self.audit.events]
        self.assertIn("policy.activation.intent", types)
        self.assertIn("policy.activation.result", types)
        self.assertLess(
            types.index("policy.activation.intent"),
            types.index("policy.activation.result"),
        )

    def test_effective_version_and_mode_recorded(self) -> None:
        result = self.svc.apply(_activation(version="v1"))
        self.assertEqual(result.outcome, ActivationOutcome.ACTIVATED)
        self.assertIsNotNone(result.state)
        self.assertEqual(result.state.policy_set_version, "v1")
        self.assertEqual(result.state.enforcement_mode, PolicyEnforcementMode.ACTIVE)

    def test_control_plane_request_id_present(self) -> None:
        result = self.svc.apply(_activation())
        self.assertTrue(result.control_plane_request_id)

    def test_result_event_carries_effective_fields(self) -> None:
        self.svc.apply(_activation(version="v1"))
        result_event = next(
            e for e in self.audit.events if e.event_type == "policy.activation.result"
        )
        self.assertEqual(result_event.outcome, ActivationOutcome.ACTIVATED.value)
        self.assertEqual(result_event.details["effective_version"], "v1")


# ---------------------------------------------------------------------------
# 2. UI / non-admin cannot grant access — CCG-REQ-009, ACC-09
# ---------------------------------------------------------------------------


class NonAdminCannotActivateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = RecordingAuditSink()
        self.transport = InMemoryPolicyControlPlane()
        self.svc = PolicyActivationService(self.transport, self.audit)
        self.repo = InMemoryFindingRepository()
        self.repo.upsert(_demo_finding())
        # A gateway is required by the API; a faithful (never-propagated) one.
        self.view = EffectivePolicyView()
        self.emulator = FaithfulAgentCoreEmulator(
            policy_view=self.view, registered_tools=frozenset(default_tool_handlers())
        )
        self.gateway = AgentCoreGatewayClient(self.emulator, self.audit)
        self.api = ComplianceApi(self.gateway, self.svc, self.repo)

    def test_non_admin_principal_cannot_activate_via_api(self) -> None:
        viewer = AuthenticatedPrincipal("viewer", frozenset())
        with self.assertRaises(UnauthorizedError):
            self.api.change_policy_state(viewer, _activation(actor="viewer"))
        # Nothing changed: still deny-safe, generation unchanged.
        self.assertEqual(self.transport.get_state().generation, 0)
        self.assertEqual(
            self.transport.get_state().enforcement_mode, PolicyEnforcementMode.LOG_ONLY
        )

    def test_remediator_without_admin_cannot_activate(self) -> None:
        remediator = AuthenticatedPrincipal("rem", frozenset({"CCGRemediator"}))
        with self.assertRaises(UnauthorizedError):
            self.api.change_policy_state(remediator, _activation(actor="rem"))

    def test_actor_mismatch_is_rejected(self) -> None:
        admin = AuthenticatedPrincipal("admin", frozenset({"CCGAdmin"}))
        with self.assertRaises(UnauthorizedError):
            # authenticated as admin, but request claims a different actor
            self.api.change_policy_state(admin, _activation(actor="someone-else"))

    def test_direct_apply_still_requires_valid_generation(self) -> None:
        """apply() trusts an already-authorized request but is NOT a bypass:
        the generation guard still blocks a stale/forged direct call."""
        result = self.svc.apply(_activation(generation=99))  # current is 0
        self.assertEqual(result.outcome, ActivationOutcome.REJECTED)
        self.assertEqual(self.transport.get_state().generation, 0)


# ---------------------------------------------------------------------------
# 3. Stale generation — CCG-REQ-017
# ---------------------------------------------------------------------------


class StaleGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = RecordingAuditSink()
        self.transport = InMemoryPolicyControlPlane()
        self.svc = PolicyActivationService(self.transport, self.audit)

    def test_stale_generation_rejected_state_unchanged(self) -> None:
        self.svc.apply(_activation(generation=0))  # -> generation 1
        before = self.transport.get_state()
        result = self.svc.apply(_activation(generation=0))  # stale now
        self.assertEqual(result.outcome, ActivationOutcome.REJECTED)
        after = self.transport.get_state()
        self.assertEqual(before.generation, after.generation)
        self.assertEqual(before.enforcement_mode, after.enforcement_mode)


# ---------------------------------------------------------------------------
# 4. Replay — CCG-REQ-017
# ---------------------------------------------------------------------------


class ReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = RecordingAuditSink()
        self.transport = InMemoryPolicyControlPlane()
        self.svc = PolicyActivationService(self.transport, self.audit)

    def test_replayed_request_id_returns_cached_result_single_update(self) -> None:
        rid = "req-replay"
        req = _activation(generation=0, request_id=rid)
        first = self.svc.apply(req)
        second = self.svc.apply(req)
        self.assertEqual(first.outcome, ActivationOutcome.ACTIVATED)
        self.assertEqual(second.outcome, ActivationOutcome.ACTIVATED)
        self.assertEqual(first.control_plane_request_id, second.control_plane_request_id)
        # Exactly one real control-plane mutation occurred.
        self.assertEqual(self.transport.get_state().generation, 1)

    def test_service_cache_blocks_transport_second_call(self) -> None:
        """The service-level cache — not the transport's own set — is the
        authoritative replay guard: a replay never reaches the transport again."""
        rid = "req-replay-2"
        req = _activation(generation=0, request_id=rid)
        self.svc.apply(req)
        gen_after_first = self.transport.get_state().generation
        self.svc.apply(req)  # cached; transport must not be called again
        self.assertEqual(self.transport.get_state().generation, gen_after_first)


# ---------------------------------------------------------------------------
# 5. Schema / transport error -> FAILED + deny-safe — CCG-REQ-016
# ---------------------------------------------------------------------------


class TransportErrorDenySafeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = RecordingAuditSink()
        self.transport = InMemoryPolicyControlPlane()
        self.svc = PolicyActivationService(self.transport, self.audit)

    def test_transport_exception_fails_and_reconciles_to_log_only(self) -> None:
        self.transport.fail_next = True
        result = self.svc.apply(_activation(generation=0))
        self.assertEqual(result.outcome, ActivationOutcome.FAILED)
        self.assertIsNotNone(result.state)
        self.assertEqual(result.state.enforcement_mode, PolicyEnforcementMode.LOG_ONLY)
        self.assertIsNone(result.control_plane_request_id)

    def test_failed_result_event_marks_deny_safe(self) -> None:
        self.transport.fail_next = True
        self.svc.apply(_activation(generation=0))
        result_event = next(
            e for e in self.audit.events if e.event_type == "policy.activation.result"
        )
        self.assertEqual(result_event.outcome, ActivationOutcome.FAILED.value)
        self.assertEqual(result_event.details["effective_state"], "DENY_SAFE")


# ---------------------------------------------------------------------------
# 6. Uncertain propagation -> FAILED + deny-safe — CCG-REQ-016, ACC-08
# ---------------------------------------------------------------------------


class UncertainPropagationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = RecordingAuditSink()
        self.transport = InMemoryPolicyControlPlane()
        self.svc = PolicyActivationService(self.transport, self.audit)

    def test_update_accepted_but_never_confirmed_is_fail_closed(self) -> None:
        self.transport.propagation_fails = True
        result = self.svc.apply(_activation(generation=0))
        self.assertEqual(result.outcome, ActivationOutcome.FAILED)
        self.assertIsNotNone(result.state)
        self.assertEqual(result.state.enforcement_mode, PolicyEnforcementMode.LOG_ONLY)

    def test_uncertain_propagation_result_event_names_failure(self) -> None:
        self.transport.propagation_fails = True
        self.svc.apply(_activation(generation=0))
        result_event = next(
            e for e in self.audit.events if e.event_type == "policy.activation.result"
        )
        self.assertEqual(result_event.outcome, ActivationOutcome.FAILED.value)
        self.assertEqual(result_event.details["failure"], "propagation")

    def test_live_transport_uncertain_propagation_fails_closed(self) -> None:
        client = FakeControlPlaneClient()
        client.stuck_status = POLICY_STATUS_UPDATING  # never reaches ACTIVE
        transport = AgentCoreControlPlaneTransport(client, "pe-fake")
        svc = PolicyActivationService(transport, self.audit, propagation_attempts=3)
        result = svc.apply(_activation(generation=0))
        self.assertEqual(result.outcome, ActivationOutcome.FAILED)
        self.assertIsNotNone(result.state)
        self.assertEqual(result.state.enforcement_mode, PolicyEnforcementMode.LOG_ONLY)


# ---------------------------------------------------------------------------
# 7. Deactivation path — CCG-REQ-016
# ---------------------------------------------------------------------------


class DeactivationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = RecordingAuditSink()
        self.transport = InMemoryPolicyControlPlane()
        self.svc = PolicyActivationService(self.transport, self.audit)

    def test_active_then_deactivate_returns_to_log_only(self) -> None:
        self.svc.apply(_activation(activate=True, generation=0))
        self.assertEqual(
            self.transport.get_state().enforcement_mode, PolicyEnforcementMode.ACTIVE
        )
        result = self.svc.apply(_activation(activate=False, generation=1))
        self.assertEqual(result.outcome, ActivationOutcome.DEACTIVATED)
        self.assertEqual(
            self.transport.get_state().enforcement_mode, PolicyEnforcementMode.LOG_ONLY
        )


# ---------------------------------------------------------------------------
# 8. Live transport (fake client) happy path + protocol conformance — P1.2
# ---------------------------------------------------------------------------


class LiveTransportSeamTests(unittest.TestCase):
    def test_transport_implements_all_protocol_members(self) -> None:
        # P1.2: a real transport MUST implement every protocol member, including
        # update_policy_set (whose omission was the P1.2 AttributeError risk).
        transport = AgentCoreControlPlaneTransport(FakeControlPlaneClient(), "pe-fake")
        for member in ("get_state", "update_policy_set", "confirm_propagation", "force_deny_safe"):
            with self.subTest(member=member):
                self.assertTrue(callable(getattr(transport, member, None)))

    def test_update_policy_set_is_declared_on_protocol(self) -> None:
        # The protocol itself declares update_policy_set so static checkers and
        # the service contract require it of every transport.
        self.assertIn("update_policy_set", PolicyControlPlaneTransport.__dict__)

    def test_live_activation_happy_path(self) -> None:
        audit = RecordingAuditSink()
        client = FakeControlPlaneClient()
        transport = AgentCoreControlPlaneTransport(client, "pe-fake")
        svc = PolicyActivationService(transport, audit)
        result = svc.apply(_activation(generation=0))
        self.assertEqual(result.outcome, ActivationOutcome.ACTIVATED)
        self.assertTrue(result.control_plane_request_id)
        self.assertEqual(client.update_calls, 1)
        # Generation advanced only on confirmed propagation.
        self.assertEqual(transport.get_state().generation, 1)

    def test_live_update_schema_error_fails_closed(self) -> None:
        audit = RecordingAuditSink()
        client = FakeControlPlaneClient()
        client.raise_on_update = True
        transport = AgentCoreControlPlaneTransport(client, "pe-fake")
        svc = PolicyActivationService(transport, audit)
        result = svc.apply(_activation(generation=0))
        self.assertEqual(result.outcome, ActivationOutcome.FAILED)
        self.assertIsNotNone(result.state)
        self.assertEqual(result.state.enforcement_mode, PolicyEnforcementMode.LOG_ONLY)

    def test_confirm_propagation_raises_when_stuck(self) -> None:
        client = FakeControlPlaneClient()
        client.stuck_status = POLICY_STATUS_UPDATING
        transport = AgentCoreControlPlaneTransport(client, "pe-fake")
        with self.assertRaises(PropagationUncertainError):
            transport.confirm_propagation(PolicyEnforcementMode.ACTIVE, attempts=2)


# ---------------------------------------------------------------------------
# 9. Failed/ambiguous activation leaves mutations denied — ACC-08
# ---------------------------------------------------------------------------


class MutationsRemainDeniedAfterFailureTests(unittest.TestCase):
    """Wires a faithful Gateway + EffectivePolicyView to prove the exit criterion:
    a failed or uncertain activation leaves remediation DENIED and never
    propagates an authorizing state to the Gateway."""

    def _wire(self) -> tuple[ComplianceApi, EffectivePolicyView, InMemoryPolicyControlPlane, PolicyActivationService]:
        audit = RecordingAuditSink()
        transport = InMemoryPolicyControlPlane()
        svc = PolicyActivationService(transport, audit)
        repo = InMemoryFindingRepository()
        repo.upsert(_demo_finding())
        view = EffectivePolicyView()
        handlers = default_tool_handlers()
        emulator = FaithfulAgentCoreEmulator(
            policy_view=view, registered_tools=frozenset(handlers)
        )
        gateway = AgentCoreGatewayClient(emulator, audit)
        for name, handler in handlers.items():
            gateway.register(name, lambda request, _h=handler: _h(request))
        api = ComplianceApi(gateway, svc, repo)
        return api, view, transport, svc

    def _command(self) -> RemediationCommand:
        return RemediationCommand(
            request_id="req-mut-1",
            correlation_id="corr-act",
            actor="admin",
            finding_id="finding-act-1",
            tool="s3_encryption_enablement",
            parameters={"algorithm": "AES256"},
            idempotency_key="idem-mut-1",
            expected_finding_version=0,
        )

    def _propagate_on_success(self, result, view: EffectivePolicyView) -> None:
        # Only an actually-ACTIVATED result would propagate to the Gateway.
        if result.outcome is ActivationOutcome.ACTIVATED and result.state is not None:
            view.propagate_activation(
                policy_set_version=result.state.policy_set_version,
                enforcement_mode=GatewayEnforcementMode.ENFORCE,
            )

    def test_mutations_denied_after_transport_failure(self) -> None:
        api, view, transport, _svc = self._wire()
        admin = AuthenticatedPrincipal("admin", frozenset({"CCGAdmin", "CCGRemediator"}))
        transport.fail_next = True
        result = api.change_policy_state(admin, _activation(generation=0))
        self.assertEqual(result.outcome, ActivationOutcome.FAILED)
        self._propagate_on_success(result, view)

        # The Gateway never received an active permit: remediation stays denied.
        self.assertFalse(view.permit_active)
        invocation = api.request_remediation(admin, self._command())
        self.assertEqual(invocation.decision.decision, Decision.DENY)
        self.assertIsNone(invocation.tool_result)

    def test_mutations_denied_after_uncertain_propagation(self) -> None:
        api, view, transport, _svc = self._wire()
        admin = AuthenticatedPrincipal("admin", frozenset({"CCGAdmin", "CCGRemediator"}))
        transport.propagation_fails = True
        result = api.change_policy_state(admin, _activation(generation=0))
        self.assertEqual(result.outcome, ActivationOutcome.FAILED)
        self._propagate_on_success(result, view)

        self.assertFalse(view.permit_active)
        invocation = api.request_remediation(admin, self._command())
        self.assertEqual(invocation.decision.decision, Decision.DENY)
        self.assertIsNone(invocation.tool_result)

    def test_mutations_allowed_only_after_confirmed_activation(self) -> None:
        """Positive control: a confirmed activation DOES propagate and allow,
        so the deny-after-failure result is meaningful, not vacuous."""
        api, view, _transport, _svc = self._wire()
        admin = AuthenticatedPrincipal("admin", frozenset({"CCGAdmin", "CCGRemediator"}))
        result = api.change_policy_state(admin, _activation(generation=0))
        self.assertEqual(result.outcome, ActivationOutcome.ACTIVATED)
        self._propagate_on_success(result, view)

        self.assertTrue(view.permit_active)
        invocation = api.request_remediation(admin, self._command())
        self.assertEqual(invocation.decision.decision, Decision.ALLOW)
        self.assertIsNotNone(invocation.tool_result)


if __name__ == "__main__":
    unittest.main()
