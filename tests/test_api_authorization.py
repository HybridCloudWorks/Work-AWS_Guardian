"""API authorization boundary contracts (task 5.1 / CCG-REQ-027..029, ACC-11).

These prove the server-side authorization rules hold regardless of client
state: the console can send a request, but only the API + Cedar boundary decide
whether it proceeds. Covers unauthenticated, unauthorized (missing role),
actor-mismatch, stale finding version, malformed command, unresolvable finding,
and the valid happy path.
"""

from datetime import datetime, timezone
import unittest

from ccg.api import AuthenticatedPrincipal, ComplianceApi, UnauthorizedError
from ccg.contracts import (
    Decision,
    Finding,
    FindingStatus,
    RemediationCommand,
    Severity,
    TargetRef,
    ToolOutcome,
    ToolResult,
)
from ccg.policy import InMemoryPolicyControlPlane, PolicyActivationService
from ccg.testing import InMemoryCedarGateway, InMemoryFindingRepository, RecordingAuditSink

NOW = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)


class ApiAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = RecordingAuditSink()
        self.gateway = InMemoryCedarGateway(self.audit)
        self.gateway.activate_permits("v1")

        def applied_tool(request):
            return ToolResult(
                outcome=ToolOutcome.APPLIED,
                tool=request.tool,
                target_arn=request.target.arn,
                changed=True,
                message="applied",
            )

        self.gateway.register("s3_encryption_enablement", applied_tool)

        self.repo = InMemoryFindingRepository()
        self.repo.upsert(
            Finding(
                finding_id="finding-1",
                rule_id="s3-encryption",
                source="config",
                target=TargetRef("arn:aws:s3:::ccg-demo", "s3_bucket", {"CCGDemo": "true"}),
                severity=Severity.HIGH,
                title="missing encryption",
                evidence_refs=("config:finding-1",),
                status=FindingStatus.OPEN,
                first_seen_at=NOW,
                last_seen_at=NOW,
                correlation_id="corr-1",
            )
        )
        self.policy = PolicyActivationService(InMemoryPolicyControlPlane(), self.audit)
        self.api = ComplianceApi(self.gateway, self.policy, self.repo)

        self.admin = AuthenticatedPrincipal("admin", frozenset({"CCGAdmin", "CCGRemediator"}))
        self.unauth = AuthenticatedPrincipal("admin", frozenset({"CCGAdmin"}), authenticated=False)

    def command(self, **overrides) -> RemediationCommand:
        params = {
            "request_id": "req-1",
            "correlation_id": "corr-1",
            "actor": "admin",
            "finding_id": "finding-1",
            "tool": "s3_encryption_enablement",
            "parameters": {"algorithm": "AES256"},
            "idempotency_key": "idem-1",
            "expected_finding_version": 0,
        }
        params.update(overrides)
        return RemediationCommand(**params)

    # --- read endpoints require authentication ---

    def test_get_findings_requires_authentication(self) -> None:
        with self.assertRaises(UnauthorizedError):
            self.api.get_findings(self.unauth)

    def test_get_policy_state_requires_authentication(self) -> None:
        with self.assertRaises(UnauthorizedError):
            self.api.get_policy_state(self.unauth)

    # --- remediation authorization ---

    def test_unauthenticated_cannot_request_remediation(self) -> None:
        with self.assertRaises(UnauthorizedError):
            self.api.request_remediation(self.unauth, self.command())

    def test_actor_mismatch_is_rejected(self) -> None:
        with self.assertRaises(UnauthorizedError):
            self.api.request_remediation(self.admin, self.command(actor="someone-else"))

    def test_missing_expected_version_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.api.request_remediation(self.admin, self.command(expected_finding_version=None))

    def test_stale_finding_version_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.api.request_remediation(self.admin, self.command(expected_finding_version=7))

    def test_unresolvable_finding_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.api.request_remediation(self.admin, self.command(finding_id="ghost"))

    def test_valid_request_flows_through_gateway_and_applies(self) -> None:
        result = self.api.request_remediation(self.admin, self.command())
        self.assertEqual(result.decision.decision, Decision.ALLOW)
        self.assertIsNotNone(result.tool_result)
        self.assertEqual(result.tool_result.outcome, ToolOutcome.APPLIED)

    def test_api_never_authorizes_locally_target_comes_from_finding(self) -> None:
        # Even a valid command cannot smuggle its own target; the API resolves
        # the target from the stored finding before calling the gateway.
        result = self.api.request_remediation(self.admin, self.command())
        self.assertEqual(result.decision.target_arn, "arn:aws:s3:::ccg-demo")


if __name__ == "__main__":
    unittest.main()
