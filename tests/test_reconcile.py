from datetime import datetime, timezone
import unittest

from ccg.contracts import Finding, FindingStatus, Severity, TargetRef, ToolOutcome
from ccg.reconcile import (
    IllegalTransitionError,
    ReconcileContext,
    ReconciliationError,
    ReconciliationService,
    is_allowed_transition,
)
from ccg.testing import InMemoryFindingRepository, RecordingAuditSink

NOW = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)


def open_finding(finding_id: str = "f-1") -> Finding:
    return Finding(
        finding_id=finding_id,
        rule_id="s3-encryption",
        source="config",
        target=TargetRef("arn:aws:s3:::ccg-demo", "s3_bucket", {"CCGDemo": "true"}),
        severity=Severity.HIGH,
        title="missing encryption",
        evidence_refs=("config:f-1",),
        status=FindingStatus.OPEN,
        first_seen_at=NOW,
        last_seen_at=NOW,
        correlation_id="corr-1",
    )


class TransitionRuleTests(unittest.TestCase):
    def test_legal_and_illegal_transitions(self) -> None:
        self.assertTrue(is_allowed_transition(FindingStatus.OPEN, FindingStatus.REMEDIATION_REQUESTED))
        self.assertTrue(is_allowed_transition(FindingStatus.REMEDIATION_SUCCEEDED, FindingStatus.RESOLVED))
        self.assertFalse(is_allowed_transition(FindingStatus.OPEN, FindingStatus.RESOLVED))
        self.assertFalse(is_allowed_transition(FindingStatus.REMEDIATION_FAILED, FindingStatus.RESOLVED))


class ReconciliationServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = InMemoryFindingRepository()
        self.audit = RecordingAuditSink()
        self.svc = ReconciliationService(self.repo, self.audit)
        self.repo.upsert(open_finding())

    def _ctx(self, correlation_id="corr-1", request_id="req-1") -> ReconcileContext:
        return ReconcileContext(actor="admin", correlation_id=correlation_id, request_id=request_id)

    def _confirm_ctx(self) -> ReconcileContext:
        return ReconcileContext(actor="discovery-agent", correlation_id="corr-2", request_id="rec-1")

    def test_mark_requested_records_status(self) -> None:
        result = self.svc.mark_requested("f-1", self._ctx())
        self.assertEqual(result.status, FindingStatus.REMEDIATION_REQUESTED)
        self.assertEqual(self.audit.events[-1].event_type, "reconcile.requested")

    def test_success_needs_confirming_read_to_resolve(self) -> None:
        self.svc.mark_requested("f-1", self._ctx())
        after_tool = self.svc.record_tool_outcome("f-1", ToolOutcome.APPLIED, self._ctx())
        self.assertEqual(after_tool.status, FindingStatus.REMEDIATION_SUCCEEDED)  # not RESOLVED yet

        resolved = self.svc.confirm_from_discovery("f-1", self._confirm_ctx(), drift_still_present=False)
        self.assertEqual(resolved.status, FindingStatus.RESOLVED)

    def test_drift_still_present_does_not_resolve(self) -> None:
        self.svc.mark_requested("f-1", self._ctx())
        self.svc.record_tool_outcome("f-1", ToolOutcome.APPLIED, self._ctx())
        still = self.svc.confirm_from_discovery("f-1", self._confirm_ctx(), drift_still_present=True)
        self.assertEqual(still.status, FindingStatus.REMEDIATION_SUCCEEDED)

    def test_failed_outcome_never_resolves_on_clean_read(self) -> None:
        self.svc.mark_requested("f-1", self._ctx())
        self.svc.record_tool_outcome("f-1", ToolOutcome.FAILED, self._ctx())
        result = self.svc.confirm_from_discovery("f-1", self._confirm_ctx(), drift_still_present=False)
        self.assertEqual(result.status, FindingStatus.REMEDIATION_FAILED)

    def test_noop_outcome_resolves_on_clean_read(self) -> None:
        self.svc.mark_requested("f-1", self._ctx())
        self.svc.record_tool_outcome("f-1", ToolOutcome.NOOP, self._ctx())
        result = self.svc.confirm_from_discovery("f-1", self._confirm_ctx(), drift_still_present=False)
        self.assertEqual(result.status, FindingStatus.RESOLVED)

    def test_illegal_transition_is_rejected(self) -> None:
        # OPEN -> SUCCEEDED is not a legal step (must go through REQUESTED).
        with self.assertRaises(IllegalTransitionError):
            self.svc.record_tool_outcome("f-1", ToolOutcome.APPLIED, self._ctx())

    def test_repeated_request_is_idempotent_no_audit_noise(self) -> None:
        self.svc.mark_requested("f-1", self._ctx())
        events_after_first = len(self.audit.events)
        self.svc.mark_requested("f-1", self._ctx())  # same status again
        self.assertEqual(len(self.audit.events), events_after_first)

    def test_missing_finding_raises(self) -> None:
        with self.assertRaises(ReconciliationError):
            self.svc.mark_requested("does-not-exist", self._ctx())


if __name__ == "__main__":
    unittest.main()
