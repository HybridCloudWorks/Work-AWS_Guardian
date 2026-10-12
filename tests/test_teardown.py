"""Teardown & rollback behavior that is testable offline (spec task 6.5).

Teardown must deactivate enforcement BEFORE deleting anything (fail-closed) and
can never select a production or out-of-scope resource by default. This suite
asserts the parts of that guarantee that have no live-AWS dependency:

* **Phase A — deactivate enforcement first.** Deactivating the permit set via
  ``PolicyActivationService`` (``activate=False``) returns ``LOG_ONLY`` and
  leaves mutations denied through the faithful Gateway. (The richer failure/
  propagation matrix already lives in ``tests/test_activation_control_plane.py``;
  here we assert the specific teardown step and its deny-after effect.)
* **Phase A — reconciliation gate.** Teardown only proceeds when every finding
  is in a terminal/clean state; a finding mid-remediation blocks it.
* **Phase B — bounded seed cleanup.** Cleanup refuses a non-self-created / prod
  target so it can never remove a resource it did not create. (The full seed
  cleanup matrix lives in ``tests/test_seed.py``; referenced here with a focused
  guard assertion.)
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from uuid import uuid4

from ccg.api import AuthenticatedPrincipal, ComplianceApi
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
from ccg.gateway import (
    AgentCoreGatewayClient,
    EffectivePolicyView,
    FaithfulAgentCoreEmulator,
    GatewayEnforcementMode,
)
from ccg.policy import InMemoryPolicyControlPlane, PolicyActivationService
from ccg.reconcile import (
    ReconcileContext,
    ReconciliationService,
    is_teardown_clean,
    teardown_blocking_findings,
)
from ccg.seed import (
    SEED_MARKER_TAG,
    SEED_NAME_PREFIX,
    SeedSafetyError,
    guard_cleanup_target,
)
from ccg.testing import InMemoryFindingRepository, RecordingAuditSink
from ccg.tools import default_tool_handlers

NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)


def _finding(finding_id: str = "finding-td-1", status: FindingStatus = FindingStatus.OPEN) -> Finding:
    return Finding(
        finding_id=finding_id,
        rule_id="s3-encryption-missing",
        source="config",
        target=TargetRef("arn:aws:s3:::ccg-demo", "s3_bucket", {"CCGDemo": "true"}),
        severity=Severity.HIGH,
        title="S3 bucket missing default encryption",
        evidence_refs=("config:1",),
        status=status,
        first_seen_at=NOW,
        last_seen_at=NOW,
        correlation_id="corr-td",
    )


def _activation(*, activate: bool, version: str, generation: int) -> PolicyActivationRequest:
    return PolicyActivationRequest(
        request_id=str(uuid4()),
        correlation_id="corr-td",
        actor="admin",
        requested_version=version,
        expected_generation=generation,
        reason="teardown test",
        activate=activate,
    )


# ---------------------------------------------------------------------------
# Phase A.1 — deactivate enforcement first (activate=False -> LOG_ONLY)
# ---------------------------------------------------------------------------


class DeactivateEnforcementFirstTests(unittest.TestCase):
    """Deactivation via the audited control plane returns LOG_ONLY and the
    Gateway then denies mutations — the first teardown step is fail-closed."""

    def _wire(self):
        audit = RecordingAuditSink()
        transport = InMemoryPolicyControlPlane()
        svc = PolicyActivationService(transport, audit)
        repo = InMemoryFindingRepository()
        repo.upsert(_finding())
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
            request_id="req-td-mut",
            correlation_id="corr-td",
            actor="admin",
            finding_id="finding-td-1",
            tool="s3_encryption_enablement",
            parameters={"algorithm": "AES256"},
            idempotency_key="idem-td-1",
            expected_finding_version=0,
        )

    def test_deactivation_returns_log_only(self) -> None:
        _api, _view, transport, svc = self._wire()
        # Activate first (so there is something to tear down), then deactivate.
        svc.apply(_activation(activate=True, version="v1", generation=0))
        self.assertEqual(
            transport.get_state().enforcement_mode, PolicyEnforcementMode.ACTIVE
        )
        result = svc.apply(_activation(activate=False, version="v1", generation=1))
        self.assertEqual(result.outcome, ActivationOutcome.DEACTIVATED)
        self.assertEqual(
            transport.get_state().enforcement_mode, PolicyEnforcementMode.LOG_ONLY
        )

    def test_mutations_denied_after_deactivation(self) -> None:
        api, view, _transport, svc = self._wire()
        admin = AuthenticatedPrincipal("admin", frozenset({"CCGAdmin", "CCGRemediator"}))
        # Activate + propagate so the Gateway would otherwise ALLOW.
        active = svc.apply(_activation(activate=True, version="v1", generation=0))
        self.assertEqual(active.outcome, ActivationOutcome.ACTIVATED)
        view.propagate_activation(
            policy_set_version=active.state.policy_set_version,
            enforcement_mode=GatewayEnforcementMode.ENFORCE,
        )
        self.assertTrue(view.permit_active)

        # Teardown step: deactivate, and reflect the deny-safe state to the
        # Gateway view (deactivation reconciles the engine to LOG_ONLY with no
        # active permit).
        result = svc.apply(_activation(activate=False, version="v1", generation=1))
        self.assertEqual(result.outcome, ActivationOutcome.DEACTIVATED)
        view.propagate_deny_safe(policy_set_version=result.state.policy_set_version)
        self.assertFalse(view.permit_active)
        self.assertEqual(view.enforcement_mode, GatewayEnforcementMode.LOG_ONLY)

        invocation = api.request_remediation(admin, self._command())
        self.assertEqual(invocation.decision.decision, Decision.DENY)
        self.assertIsNone(invocation.tool_result)


# ---------------------------------------------------------------------------
# Phase A.2 — reconciliation gate: teardown only on terminal/clean findings
# ---------------------------------------------------------------------------


class ReconciliationGateTests(unittest.TestCase):
    def test_clean_statuses_pass_in_flight_statuses_block(self) -> None:
        for clean in (
            FindingStatus.OPEN,
            FindingStatus.RESOLVED,
            FindingStatus.ACCEPTED_RISK,
        ):
            self.assertTrue(is_teardown_clean(clean))
        for in_flight in (
            FindingStatus.REMEDIATION_REQUESTED,
            FindingStatus.REMEDIATION_SUCCEEDED,
            FindingStatus.REMEDIATION_NOOP,
            FindingStatus.REMEDIATION_FAILED,
        ):
            self.assertFalse(is_teardown_clean(in_flight))

    def test_blocking_findings_empty_when_all_clean(self) -> None:
        findings = [
            _finding("f-open", FindingStatus.OPEN),
            _finding("f-resolved", FindingStatus.RESOLVED),
            _finding("f-accepted", FindingStatus.ACCEPTED_RISK),
        ]
        self.assertEqual(teardown_blocking_findings(findings), [])

    def test_in_flight_finding_blocks_teardown(self) -> None:
        findings = [
            _finding("f-open", FindingStatus.OPEN),
            _finding("f-inflight", FindingStatus.REMEDIATION_REQUESTED),
        ]
        blocking = teardown_blocking_findings(findings)
        self.assertEqual([f.finding_id for f in blocking], ["f-inflight"])

    def test_gate_clears_after_discovery_resolves(self) -> None:
        """A mid-remediation finding blocks the gate; once a confirming
        discovery read resolves it, the gate clears."""
        repo = InMemoryFindingRepository()
        audit = RecordingAuditSink()
        svc = ReconciliationService(repo, audit)
        repo.upsert(_finding("f-1", FindingStatus.OPEN))
        ctx = ReconcileContext(actor="admin", correlation_id="corr-td", request_id="r-1")
        svc.mark_requested("f-1", ctx)
        from ccg.contracts import ToolOutcome

        svc.record_tool_outcome("f-1", ToolOutcome.APPLIED, ctx)
        # In flight: gate blocked.
        self.assertTrue(teardown_blocking_findings(repo.list_findings()))
        # Confirming discovery read (drift gone) resolves it.
        svc.confirm_from_discovery("f-1", ctx, drift_still_present=False)
        self.assertEqual(repo.get("f-1").status, FindingStatus.RESOLVED)
        self.assertEqual(teardown_blocking_findings(repo.list_findings()), [])


# ---------------------------------------------------------------------------
# Phase B — bounded seed cleanup refuses non-self-created / prod targets
# ---------------------------------------------------------------------------


class SeedCleanupBoundaryTests(unittest.TestCase):
    """Focused teardown-facing assertions; the full matrix is in test_seed.py."""

    def test_cleanup_refuses_prod_target(self) -> None:
        prod = TargetRef(
            f"arn:aws:s3:::{SEED_NAME_PREFIX}p",
            "s3_bucket",
            {"CCGDemo": "true", "Environment": "prod", SEED_MARKER_TAG: "true"},
        )
        with self.assertRaises(SeedSafetyError):
            guard_cleanup_target(prod)

    def test_cleanup_refuses_non_self_created_target(self) -> None:
        not_ours = TargetRef("arn:aws:s3:::real-bucket", "s3_bucket", {"CCGDemo": "true"})
        with self.assertRaises(SeedSafetyError):
            guard_cleanup_target(not_ours)

    def test_cleanup_accepts_self_created_seed_target(self) -> None:
        ours = TargetRef(
            f"arn:aws:s3:::{SEED_NAME_PREFIX}x",
            "s3_bucket",
            {"CCGDemo": "true", SEED_MARKER_TAG: "true"},
        )
        guard_cleanup_target(ours)  # no raise


if __name__ == "__main__":
    unittest.main()
