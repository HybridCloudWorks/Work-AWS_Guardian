from datetime import datetime, timezone
from io import StringIO
import unittest

from ccg.api import AuthenticatedPrincipal, ComplianceApi, UnauthorizedError
from ccg.audit import JsonLineAuditSink
from ccg.contracts import (
    ActivationOutcome,
    AuditEvent,
    Finding,
    FindingStatus,
    PolicyActivationRequest,
    PolicyEnforcementMode,
    RemediationCommand,
    Severity,
    TargetRef,
    VoiceStatus,
)
from ccg.policy import InMemoryPolicyControlPlane, PolicyActivationService
from ccg.testing import InMemoryCedarGateway, InMemoryFindingRepository, RecordingAuditSink
from ccg.voice import ReadOnlyVoiceAdapter


class PolicyApiVoiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = RecordingAuditSink()
        self.control_plane = InMemoryPolicyControlPlane()
        self.policy = PolicyActivationService(self.control_plane, self.audit)
        self.gateway = InMemoryCedarGateway(self.audit)
        self.findings = InMemoryFindingRepository()
        target = TargetRef("arn:demo", "bucket", {"CCGDemo": "true"})
        now = datetime.now(timezone.utc)
        self.findings.upsert(
            Finding(
                finding_id="finding-1",
                rule_id="s3-encryption-missing",
                source="test",
                target=target,
                severity=Severity.MEDIUM,
                title="Test finding",
                evidence_refs=("test:evidence",),
                status=FindingStatus.OPEN,
                first_seen_at=now,
                last_seen_at=now,
                correlation_id="corr-1",
            )
        )
        self.api = ComplianceApi(self.gateway, self.policy, self.findings)
        self.admin = AuthenticatedPrincipal("admin", frozenset({"CCGAdmin"}))
        self.viewer = AuthenticatedPrincipal("viewer", frozenset())

    def activation(
        self,
        *,
        activate=True,
        generation=0,
        actor="admin",
        request_id="activation-1",
    ) -> PolicyActivationRequest:
        return PolicyActivationRequest(
            request_id=request_id,
            correlation_id="corr-1",
            actor=actor,
            requested_version="v1",
            expected_generation=generation,
            reason="POC demo activation",
            activate=activate,
        )

    def test_activation_is_audited_and_changes_remote_policy_state(self) -> None:
        result = self.api.change_policy_state(self.admin, self.activation())
        self.assertEqual(result.outcome, ActivationOutcome.ACTIVATED)
        self.assertEqual(result.state.enforcement_mode, PolicyEnforcementMode.ACTIVE)
        self.assertEqual(self.control_plane.get_state().generation, 1)
        self.assertEqual(self.audit.events[0].event_type, "policy.activation.intent")
        self.assertEqual(self.audit.events[-1].event_type, "policy.activation.result")

    def test_stale_generation_is_rejected(self) -> None:
        self.api.change_policy_state(self.admin, self.activation())
        result = self.api.change_policy_state(self.admin, self.activation(generation=0, request_id="activation-2"))
        self.assertEqual(result.outcome, ActivationOutcome.REJECTED)
        self.assertEqual(self.control_plane.get_state().generation, 1)

    def test_activation_failure_is_deny_safe(self) -> None:
        self.control_plane.fail_next = True
        result = self.api.change_policy_state(self.admin, self.activation())
        self.assertEqual(result.outcome, ActivationOutcome.FAILED)
        self.assertEqual(result.state.enforcement_mode, PolicyEnforcementMode.LOG_ONLY)

    def test_non_admin_cannot_activate(self) -> None:
        with self.assertRaises(UnauthorizedError):
            self.api.change_policy_state(self.viewer, self.activation(actor="viewer"))

    def test_viewer_cannot_request_remediation(self) -> None:
        command = RemediationCommand(
            "req-1",
            "corr-1",
            "viewer",
            "finding-1",
            "unknown",
            {},
            "idem-1",
            0,
        )
        with self.assertRaises(UnauthorizedError):
            self.api.request_remediation(self.viewer, command)

    def test_api_resolves_target_from_finding_before_gateway(self) -> None:
        # The finding's rule_id maps to the s3 encryption tool; the command uses
        # that tool (so it passes API-layer rule validation) but the gateway has
        # no handler registered for it, so the gateway itself produces the DENY.
        command = RemediationCommand(
            "req-1",
            "corr-1",
            "admin",
            "finding-1",
            "s3_encryption_enablement",
            {"algorithm": "AES256"},
            "idem-1",
            0,
        )
        result = self.api.request_remediation(self.admin, command)
        self.assertEqual(result.decision.decision.value, "DENY")
        self.assertEqual(result.decision.reason, "unregistered tool")

    def test_voice_is_disabled_by_default_and_has_no_gateway(self) -> None:
        voice = ReadOnlyVoiceAdapter()
        result = voice.brief("corr-1", "one finding")
        self.assertEqual(voice.status, VoiceStatus.DISABLED)
        self.assertEqual(result.status, VoiceStatus.DISABLED)

    def test_json_audit_sink_redacts_sensitive_details(self) -> None:
        output = StringIO()
        sink = JsonLineAuditSink(output)
        sink.record(
            AuditEvent(
                "event-1",
                "test",
                "admin",
                "req-1",
                "corr-1",
                "OK",
                datetime.now(timezone.utc),
                {
                    "secretAccessKey": "secret-value",
                    "nested": {"audio": "raw-audio"},
                    "safe": "visible",
                },
            )
        )
        self.assertNotIn("secret-value", output.getvalue())
        self.assertNotIn("raw-audio", output.getvalue())
        self.assertIn("visible", output.getvalue())


if __name__ == "__main__":
    unittest.main()
