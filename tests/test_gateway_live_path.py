"""Shared scenario matrix run against BOTH gateway implementations.

This test proves the P0.3 requirement: no "green" claim rests solely on the
in-memory double. The *same* assertions run against:

* ``InMemoryCedarGateway`` — the local Cedar model double; and
* ``AgentCoreGatewayClient`` wired to ``FaithfulAgentCoreEmulator`` — the
  "real transport path" (a faithful AgentCore emulator, no live AWS).

Each scenario is executed by a single shared body (`_run_scenarios`) so the two
drivers cannot diverge: if the production client + emulator ever disagreed with
the double, the identical assertions would fail for one of them.

The matrix covers, for each driver:

* default-deny when permits inactive / engine LOG_ONLY;
* allow when ENFORCE + active permit + eligible target;
* forbid-overrides-permit (prod tag, missing demo tag, open CIDR, make_public);
* unknown tool denied;
* idempotent replay (no double execution);
* decision evidence completeness (full Cedar action_id, policy version, IDs);
* activation->enforcement propagation (denied before activation, allowed only
  after the control plane confirms ACTIVE and that state propagates).
"""

from __future__ import annotations

import unittest
from collections.abc import Callable

from ccg.authz import to_cedar_action_id
from ccg.contracts import (
    Decision,
    InvocationResult,
    RemediationRequest,
    TargetRef,
    ToolOutcome,
    ToolResult,
)
from ccg.gateway import (
    AgentCoreGatewayClient,
    EffectivePolicyView,
    FaithfulAgentCoreEmulator,
    GatewayEnforcementMode,
)
from ccg.gateway_core import AmbiguousDecisionError, GatewayInvocationSkeleton
from ccg.ports import GatewayInvocationPort
from ccg.testing import InMemoryCedarGateway, RecordingAuditSink

_TOOLS = ("s3_encryption_enablement", "security_group_correction", "compliant_tagging")


class _Driver:
    """A uniform surface over a concrete gateway for the shared matrix.

    ``gateway`` is the port under test; ``activate`` moves it from deny-safe to a
    confirmed+propagated active permit set; ``calls`` counts real tool executions.
    """

    def __init__(
        self,
        name: str,
        gateway: GatewayInvocationPort,
        activate: Callable[[str], None],
        audit: RecordingAuditSink,
        counter: Callable[[], int],
    ) -> None:
        self.name = name
        self.gateway = gateway
        self.activate = activate
        self.audit = audit
        self._counter = counter

    @property
    def calls(self) -> int:
        return self._counter()


def _make_counting_tool(counter: dict[str, int]) -> Callable[[RemediationRequest], ToolResult]:
    def tool(request: RemediationRequest) -> ToolResult:
        counter["n"] += 1
        return ToolResult(
            outcome=ToolOutcome.APPLIED,
            tool=request.tool,
            target_arn=request.target.arn,
            changed=True,
            message="sandbox change applied",
        )

    return tool


def _double_driver() -> _Driver:
    audit = RecordingAuditSink()
    counter = {"n": 0}
    gateway = InMemoryCedarGateway(audit)
    tool = _make_counting_tool(counter)
    for name in _TOOLS:
        gateway.register(name, tool)
    return _Driver(
        name="InMemoryCedarGateway",
        gateway=gateway,
        activate=lambda version: gateway.activate_permits(version),
        audit=audit,
        counter=lambda: counter["n"],
    )


def _emulator_driver() -> _Driver:
    audit = RecordingAuditSink()
    counter = {"n": 0}
    view = EffectivePolicyView()
    emulator = FaithfulAgentCoreEmulator(policy_view=view, registered_tools=frozenset(_TOOLS))
    client = AgentCoreGatewayClient(emulator, audit)
    tool = _make_counting_tool(counter)
    for name in _TOOLS:
        client.register(name, tool)

    def activate(version: str) -> None:
        # Propagation seam: the control plane confirmed ACTIVE; propagate to the
        # Gateway's effective view (engine ENFORCE + active permit set).
        view.propagate_activation(
            policy_set_version=version,
            enforcement_mode=GatewayEnforcementMode.ENFORCE,
        )

    return _Driver(
        name="AgentCoreGatewayClient+FaithfulAgentCoreEmulator",
        gateway=client,
        activate=activate,
        audit=audit,
        counter=lambda: counter["n"],
    )


def _request(
    *,
    tool: str = "s3_encryption_enablement",
    tags=None,
    parameters=None,
    key: str = "idem-1",
) -> RemediationRequest:
    return RemediationRequest(
        request_id=f"req-{key}",
        correlation_id="corr-1",
        actor="admin",
        tool=tool,
        target=TargetRef("arn:aws:s3:::ccg-demo", "s3_bucket", tags or {"CCGDemo": "true"}),
        parameters=parameters or {},
        idempotency_key=key,
    )


class SharedGatewayMatrixTests(unittest.TestCase):
    """Runs the identical matrix against every driver."""

    def drivers(self) -> list[_Driver]:
        return [_double_driver(), _emulator_driver()]

    # -- individual scenarios, each re-built fresh per driver ---------------

    def test_default_deny_when_inactive(self) -> None:
        for driver in self.drivers():
            with self.subTest(driver=driver.name):
                result = driver.gateway.invoke(_request())
                self.assertEqual(result.decision.decision, Decision.DENY)
                self.assertEqual(driver.calls, 0)
                self.assertIsNone(result.tool_result)

    def test_allow_after_activation(self) -> None:
        for driver in self.drivers():
            with self.subTest(driver=driver.name):
                driver.activate("v1")
                result = driver.gateway.invoke(_request())
                self.assertEqual(result.decision.decision, Decision.ALLOW)
                self.assertIsNotNone(result.tool_result)
                self.assertEqual(result.tool_result.outcome, ToolOutcome.APPLIED)
                self.assertEqual(driver.calls, 1)

    def test_forbid_overrides_permit_prod_tag(self) -> None:
        for driver in self.drivers():
            with self.subTest(driver=driver.name):
                driver.activate("v1")
                result = driver.gateway.invoke(
                    _request(tags={"CCGDemo": "true", "Environment": "prod"})
                )
                self.assertEqual(result.decision.decision, Decision.DENY)
                self.assertEqual(
                    result.decision.matched_policy_ids, ("always-deny-production-target",)
                )
                self.assertEqual(driver.calls, 0)

    def test_forbid_overrides_permit_missing_demo_tag(self) -> None:
        for driver in self.drivers():
            with self.subTest(driver=driver.name):
                driver.activate("v1")
                result = driver.gateway.invoke(_request(tags={"Environment": "sandbox"}))
                self.assertEqual(result.decision.decision, Decision.DENY)
                self.assertEqual(
                    result.decision.matched_policy_ids, ("always-deny-missing-demo-tag",)
                )
                self.assertEqual(driver.calls, 0)

    def test_forbid_overrides_permit_open_cidr(self) -> None:
        for driver in self.drivers():
            with self.subTest(driver=driver.name):
                driver.activate("v1")
                result = driver.gateway.invoke(
                    _request(
                        tool="security_group_correction",
                        parameters={"proposed_cidr": "0.0.0.0/0"},
                    )
                )
                self.assertEqual(result.decision.decision, Decision.DENY)
                self.assertEqual(
                    result.decision.matched_policy_ids, ("always-deny-global-open-ingress",)
                )
                self.assertEqual(driver.calls, 0)

    def test_forbid_overrides_permit_make_public(self) -> None:
        for driver in self.drivers():
            with self.subTest(driver=driver.name):
                driver.activate("v1")
                result = driver.gateway.invoke(
                    _request(
                        tool="s3_encryption_enablement",
                        parameters={"make_public": True},
                    )
                )
                self.assertEqual(result.decision.decision, Decision.DENY)
                self.assertEqual(result.decision.matched_policy_ids, ("always-deny-public-s3",))
                self.assertEqual(driver.calls, 0)

    def test_unknown_tool_denied(self) -> None:
        for driver in self.drivers():
            with self.subTest(driver=driver.name):
                driver.activate("v1")
                result = driver.gateway.invoke(_request(tool="disable_cloudtrail"))
                self.assertEqual(result.decision.decision, Decision.DENY)
                self.assertEqual(
                    result.decision.matched_policy_ids, ("always-deny-unregistered-tool",)
                )
                self.assertEqual(driver.calls, 0)

    def test_idempotent_replay_no_double_execution(self) -> None:
        for driver in self.drivers():
            with self.subTest(driver=driver.name):
                driver.activate("v1")
                first = driver.gateway.invoke(_request(key="idem-xyz"))
                second = driver.gateway.invoke(_request(key="idem-xyz"))
                self.assertEqual(first.tool_result.outcome, ToolOutcome.APPLIED)
                self.assertFalse(first.tool_result.idempotency_replayed)
                self.assertTrue(second.tool_result.idempotency_replayed)
                self.assertEqual(driver.calls, 1)

    def test_decision_evidence_completeness(self) -> None:
        for driver in self.drivers():
            with self.subTest(driver=driver.name):
                driver.activate("policy-v7")
                result = driver.gateway.invoke(_request())
                decision = result.decision
                self.assertEqual(
                    decision.action_id, to_cedar_action_id("s3_encryption_enablement")
                )
                self.assertEqual(decision.policy_set_version, "policy-v7")
                self.assertEqual(decision.request_id, "req-idem-1")
                self.assertEqual(decision.correlation_id, "corr-1")
                self.assertTrue(decision.matched_policy_ids)
                self.assertTrue(decision.reason)
                # audit trail: gateway.decision then remediation.execution on ALLOW
                self.assertEqual(
                    [e.event_type for e in driver.audit.events],
                    ["gateway.decision", "remediation.execution"],
                )
                decision_event = driver.audit.events[0]
                self.assertEqual(
                    decision_event.details["action_id"],
                    to_cedar_action_id("s3_encryption_enablement"),
                )
                self.assertEqual(decision_event.policy_set_version, "policy-v7")

    def test_activation_to_enforcement_propagation(self) -> None:
        """A request denied before activation becomes allowed only after the
        control plane confirms ACTIVE and that state propagates."""
        for driver in self.drivers():
            with self.subTest(driver=driver.name):
                before = driver.gateway.invoke(_request(key="prop-1"))
                self.assertEqual(before.decision.decision, Decision.DENY)
                self.assertEqual(driver.calls, 0)

                driver.activate("v1")

                after = driver.gateway.invoke(_request(key="prop-2"))
                self.assertEqual(after.decision.decision, Decision.ALLOW)
                self.assertEqual(driver.calls, 1)


class EmulatorSpecificTests(unittest.TestCase):
    """Semantics unique to the faithful transport path."""

    def test_log_only_engine_never_authorizes_even_with_active_permit(self) -> None:
        audit = RecordingAuditSink()
        # Permit marked active but engine remains LOG_ONLY: must still deny.
        view = EffectivePolicyView(
            permit_active=True,
            policy_set_version="v1",
            enforcement_mode=GatewayEnforcementMode.LOG_ONLY,
        )
        emulator = FaithfulAgentCoreEmulator(policy_view=view, registered_tools=frozenset(_TOOLS))
        client = AgentCoreGatewayClient(emulator, audit)
        counter = {"n": 0}
        client.register("s3_encryption_enablement", _make_counting_tool(counter))

        result = client.invoke(_request())
        self.assertEqual(result.decision.decision, Decision.DENY)
        self.assertIn("LOG_ONLY", result.decision.reason)
        self.assertEqual(counter["n"], 0)

    def test_gateway_request_id_is_populated(self) -> None:
        view = EffectivePolicyView()
        emulator = FaithfulAgentCoreEmulator(policy_view=view, registered_tools=frozenset(_TOOLS))
        response = emulator.authorize(_request())
        self.assertTrue(response.gateway_request_id)
        self.assertEqual(response.action_id, to_cedar_action_id("s3_encryption_enablement"))

    def test_client_fails_closed_on_allow_without_determining_policy(self) -> None:
        """An ALLOW with no determining policy from the transport must fail closed."""

        class _AmbiguousTransport:
            def authorize(self, request: RemediationRequest):
                from ccg.gateway import GatewayResponse

                return GatewayResponse(
                    decision=Decision.ALLOW,
                    determining_policy_ids=(),  # ambiguous: no determining policy
                    policy_set_version="v1",
                    enforcement_mode=GatewayEnforcementMode.ENFORCE,
                    gateway_request_id="gw-1",
                    reason="ambiguous",
                    action_id=to_cedar_action_id("s3_encryption_enablement"),
                )

        audit = RecordingAuditSink()
        client = AgentCoreGatewayClient(_AmbiguousTransport(), audit)
        counter = {"n": 0}
        client.register("s3_encryption_enablement", _make_counting_tool(counter))
        with self.assertRaises(AmbiguousDecisionError):
            client.invoke(_request())
        self.assertEqual(counter["n"], 0)


class SkeletonFailClosedTests(unittest.TestCase):
    """The shared skeleton fails closed on an ALLOW with no determining policy."""

    def test_skeleton_rejects_allow_without_matched_policy(self) -> None:
        from datetime import datetime, timezone

        from ccg.contracts import PolicyDecision

        audit = RecordingAuditSink()
        skeleton = GatewayInvocationSkeleton(audit)

        def bad_decider(request: RemediationRequest) -> PolicyDecision:
            return PolicyDecision(
                decision=Decision.ALLOW,
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                actor=request.actor,
                action_id=to_cedar_action_id(request.tool),
                target_arn=request.target.arn,
                matched_policy_ids=(),  # ambiguous
                policy_set_version="v1",
                reason="ambiguous allow",
                evaluated_at=datetime.now(timezone.utc),
            )

        with self.assertRaises(AmbiguousDecisionError):
            skeleton.run(_request(), bad_decider)


if __name__ == "__main__":
    unittest.main()
