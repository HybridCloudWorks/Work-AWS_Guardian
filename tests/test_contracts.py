from datetime import datetime, timezone
import unittest

from ccg.contracts import (
    AUDIT_REDACTED_FIELDS,
    ActivationOutcome,
    AuditEvent,
    Decision,
    DecisionEvidence,
    DiscoveryRun,
    ErrorCode,
    ErrorDetail,
    Finding,
    FindingStatus,
    PolicyActivationRecord,
    PolicyEnforcementMode,
    RemediationRequest,
    Severity,
    SourceResult,
    TargetRef,
)
from ccg.reconcile import is_allowed_transition

NOW = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
LATER = datetime(2026, 9, 15, 13, 0, tzinfo=timezone.utc)


def _target(tags=None) -> TargetRef:
    return TargetRef(
        arn="arn:aws:s3:::ccg-demo",
        resource_type="s3_bucket",
        tags=tags or {"CCGDemo": "true"},
    )


def _finding(**overrides) -> Finding:
    params = dict(
        finding_id="f-1",
        rule_id="s3-encryption",
        source="config",
        target=_target(),
        severity=Severity.HIGH,
        title="missing encryption",
        evidence_refs=("config:f-1",),
        status=FindingStatus.OPEN,
        first_seen_at=NOW,
        last_seen_at=NOW,
        correlation_id="corr-1",
    )
    params.update(overrides)
    return Finding(**params)


class ContractTests(unittest.TestCase):
    def test_contract_serializes_enums_and_datetimes(self) -> None:
        target = TargetRef(
            arn="arn:aws:s3:::ccg-demo",
            resource_type="s3_bucket",
            tags={"CCGDemo": "true"},
        )
        request = RemediationRequest(
            request_id="req-1",
            correlation_id="corr-1",
            actor="admin@example.invalid",
            tool="s3_encryption_enablement",
            target=target,
            parameters={"algorithm": "AES256"},
            idempotency_key="idem-1",
        )
        record = request.to_record()
        self.assertEqual(record["target"]["tags"]["CCGDemo"], "true")
        self.assertEqual(request.to_json()[0], "{")
        self.assertEqual(Decision.DENY.value, "DENY")

    def test_naive_datetime_is_rejected_by_contract(self) -> None:
        with self.assertRaises(ValueError):
            from ccg.contracts import PolicyDecision

            PolicyDecision(
                decision=Decision.DENY,
                request_id="req-1",
                correlation_id="corr-1",
                actor="admin",
                action_id="tool",
                target_arn="arn:target",
                matched_policy_ids=(),
                policy_set_version="v0",
                reason="deny",
                evaluated_at=datetime.now(),
            )

    def test_target_safety_properties_are_exact(self) -> None:
        target = TargetRef(
            arn="arn:aws:lambda:us-east-1:123:function:demo",
            resource_type="lambda",
            tags={"CCGDemo": "true", "Environment": "prod"},
        )
        self.assertTrue(target.is_demo)
        self.assertTrue(target.is_production)


# ---------------------------------------------------------------------------
# §4.1 Finding — new fields and property aliases
# ---------------------------------------------------------------------------

class FindingFieldTests(unittest.TestCase):
    def test_required_fields_present_in_record(self) -> None:
        record = _finding().to_record()
        for key in (
            "finding_id", "rule_id", "source", "severity", "title",
            "status", "first_seen_at", "last_seen_at", "correlation_id",
            "schema_version", "evidence_refs", "accepted_risk", "revision",
            "source_event_id", "description",
        ):
            self.assertIn(key, record, f"missing field: {key}")

    def test_target_arn_property_delegates_to_target(self) -> None:
        f = _finding()
        self.assertEqual(f.target_arn, f.target.arn)

    def test_target_type_property_delegates_to_target(self) -> None:
        f = _finding()
        self.assertEqual(f.target_type, f.target.resource_type)

    def test_target_tags_property_delegates_to_target(self) -> None:
        f = _finding()
        self.assertEqual(f.target_tags, f.target.tags)

    def test_source_event_id_and_description_stored(self) -> None:
        f = _finding(source_event_id="se-42", description="S3 bucket lacks SSE.")
        self.assertEqual(f.source_event_id, "se-42")
        self.assertEqual(f.description, "S3 bucket lacks SSE.")
        record = f.to_record()
        self.assertEqual(record["source_event_id"], "se-42")
        self.assertEqual(record["description"], "S3 bucket lacks SSE.")

    def test_default_source_event_id_is_empty_string(self) -> None:
        self.assertEqual(_finding().source_event_id, "")

    def test_schema_version_default(self) -> None:
        self.assertEqual(_finding().schema_version, "1")

    def test_last_seen_before_first_seen_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _finding(first_seen_at=LATER, last_seen_at=NOW)

    def test_negative_revision_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _finding(revision=-1)

    def test_serialization_is_deterministic(self) -> None:
        self.assertEqual(_finding().to_json(), _finding().to_json())


# ---------------------------------------------------------------------------
# Status transition allow-list
# ---------------------------------------------------------------------------

class FindingStatusTransitionTests(unittest.TestCase):
    _VALID: list[tuple[FindingStatus, FindingStatus]] = [
        (FindingStatus.OPEN, FindingStatus.REMEDIATION_REQUESTED),
        (FindingStatus.OPEN, FindingStatus.ACCEPTED_RISK),
        (FindingStatus.REMEDIATION_REQUESTED, FindingStatus.REMEDIATION_SUCCEEDED),
        (FindingStatus.REMEDIATION_REQUESTED, FindingStatus.REMEDIATION_NOOP),
        (FindingStatus.REMEDIATION_REQUESTED, FindingStatus.REMEDIATION_FAILED),
        (FindingStatus.REMEDIATION_SUCCEEDED, FindingStatus.RESOLVED),
        (FindingStatus.REMEDIATION_SUCCEEDED, FindingStatus.OPEN),
        (FindingStatus.REMEDIATION_NOOP, FindingStatus.RESOLVED),
        (FindingStatus.REMEDIATION_NOOP, FindingStatus.OPEN),
        (FindingStatus.REMEDIATION_FAILED, FindingStatus.REMEDIATION_REQUESTED),
        (FindingStatus.REMEDIATION_FAILED, FindingStatus.OPEN),
        (FindingStatus.RESOLVED, FindingStatus.OPEN),
        (FindingStatus.ACCEPTED_RISK, FindingStatus.OPEN),
    ]

    _INVALID: list[tuple[FindingStatus, FindingStatus]] = [
        (FindingStatus.OPEN, FindingStatus.RESOLVED),
        (FindingStatus.OPEN, FindingStatus.REMEDIATION_SUCCEEDED),
        (FindingStatus.OPEN, FindingStatus.REMEDIATION_FAILED),
        (FindingStatus.REMEDIATION_REQUESTED, FindingStatus.RESOLVED),
        (FindingStatus.REMEDIATION_FAILED, FindingStatus.RESOLVED),
        (FindingStatus.RESOLVED, FindingStatus.REMEDIATION_SUCCEEDED),
    ]

    def test_all_valid_transitions_are_allowed(self) -> None:
        for src, dst in self._VALID:
            with self.subTest(src=src, dst=dst):
                self.assertTrue(
                    is_allowed_transition(src, dst),
                    f"expected {src} -> {dst} to be allowed",
                )

    def test_all_invalid_transitions_are_rejected(self) -> None:
        for src, dst in self._INVALID:
            with self.subTest(src=src, dst=dst):
                self.assertFalse(
                    is_allowed_transition(src, dst),
                    f"expected {src} -> {dst} to be rejected",
                )

    def test_self_transition_is_allowed(self) -> None:
        for status in FindingStatus:
            with self.subTest(status=status):
                self.assertTrue(is_allowed_transition(status, status))


# ---------------------------------------------------------------------------
# §4.2 DecisionEvidence
# ---------------------------------------------------------------------------

class DecisionEvidenceTests(unittest.TestCase):
    def _make(self, **overrides) -> DecisionEvidence:
        params = dict(
            decision_id="dec-1",
            request_id="req-1",
            correlation_id="corr-1",
            actor="admin",
            principal_attributes={"role": "admin"},
            gateway_id="gw-1",
            action_id="s3_encryption_enablement",
            target="arn:aws:s3:::ccg-demo",
            decision=Decision.ALLOW,
            determining_policy_ids=("permit-s3_encryption_enablement",),
            policy_set_version="v1",
            enforcement_mode=PolicyEnforcementMode.ACTIVE,
            validation_errors=(),
            created_at=NOW,
        )
        params.update(overrides)
        return DecisionEvidence(**params)

    def test_required_fields_in_record(self) -> None:
        record = self._make().to_record()
        for key in (
            "decision_id", "request_id", "correlation_id", "actor",
            "principal_attributes", "gateway_id", "action_id", "target",
            "decision", "determining_policy_ids", "policy_set_version",
            "enforcement_mode", "validation_errors", "created_at", "schema_version",
        ):
            self.assertIn(key, record, f"missing field: {key}")

    def test_determining_policy_ids_stored_as_tuple(self) -> None:
        ev = self._make(determining_policy_ids=["pol-a", "pol-b"])
        self.assertIsInstance(ev.determining_policy_ids, tuple)
        self.assertEqual(ev.determining_policy_ids, ("pol-a", "pol-b"))

    def test_validation_errors_stored_as_tuple(self) -> None:
        ev = self._make(validation_errors=["err-1"])
        self.assertEqual(ev.validation_errors, ("err-1",))

    def test_principal_attributes_stored_as_dict(self) -> None:
        ev = self._make(principal_attributes={"group": "ops"})
        self.assertIsInstance(ev.principal_attributes, dict)

    def test_naive_created_at_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._make(created_at=datetime(2026, 9, 15, 12, 0))

    def test_schema_version_default(self) -> None:
        self.assertEqual(self._make().schema_version, "1")

    def test_serialization_deterministic(self) -> None:
        self.assertEqual(self._make().to_json(), self._make().to_json())


# ---------------------------------------------------------------------------
# §4.3 AuditEvent — new fields
# ---------------------------------------------------------------------------

class AuditEventFieldTests(unittest.TestCase):
    def _make(self, **overrides) -> AuditEvent:
        params = dict(
            event_id="evt-1",
            event_type="remediation.execution",
            actor="admin",
            request_id="req-1",
            correlation_id="corr-1",
            outcome="APPLIED",
            occurred_at=NOW,
            details={"tool": "s3_encryption_enablement"},
        )
        params.update(overrides)
        return AuditEvent(**params)

    def test_schema_version_defaults_to_one(self) -> None:
        self.assertEqual(self._make().schema_version, "1")

    def test_component_field_stored(self) -> None:
        ev = self._make(component="discovery-agent")
        self.assertEqual(ev.component, "discovery-agent")
        self.assertEqual(ev.to_record()["component"], "discovery-agent")

    def test_target_field_stored(self) -> None:
        ev = self._make(target="arn:aws:s3:::ccg-demo")
        self.assertEqual(ev.target, "arn:aws:s3:::ccg-demo")

    def test_policy_set_version_field_stored(self) -> None:
        ev = self._make(policy_set_version="v1")
        self.assertEqual(ev.policy_set_version, "v1")

    def test_default_optional_fields_are_empty_strings(self) -> None:
        ev = self._make()
        self.assertEqual(ev.component, "")
        self.assertEqual(ev.target, "")
        self.assertEqual(ev.policy_set_version, "")

    def test_audit_redacted_fields_constant_non_empty(self) -> None:
        self.assertGreater(len(AUDIT_REDACTED_FIELDS), 0)
        self.assertIn("token", AUDIT_REDACTED_FIELDS)
        self.assertIn("password", AUDIT_REDACTED_FIELDS)


# ---------------------------------------------------------------------------
# §4.4 PolicyActivationRecord
# ---------------------------------------------------------------------------

class PolicyActivationRecordTests(unittest.TestCase):
    def _make(self, **overrides) -> PolicyActivationRecord:
        params = dict(
            activation_id="act-1",
            requested_version="v1",
            previous_version="permits-inactive",
            requested_mode=PolicyEnforcementMode.ACTIVE,
            actor="admin",
            reason="demo activation",
            expected_version="permits-inactive",
            intent_recorded_at=NOW,
            result=ActivationOutcome.ACTIVATED,
            effective_version="v1",
            effective_mode=PolicyEnforcementMode.ACTIVE,
            completed_at=LATER,
            correlation_id="corr-1",
        )
        params.update(overrides)
        return PolicyActivationRecord(**params)

    def test_required_fields_in_record(self) -> None:
        record = self._make().to_record()
        for key in (
            "activation_id", "requested_version", "previous_version",
            "requested_mode", "actor", "reason", "expected_version",
            "intent_recorded_at", "result", "effective_version",
            "effective_mode", "completed_at", "correlation_id", "schema_version",
        ):
            self.assertIn(key, record, f"missing field: {key}")

    def test_optional_control_plane_request_id_default_none(self) -> None:
        self.assertIsNone(self._make().control_plane_request_id)

    def test_control_plane_request_id_stored(self) -> None:
        rec = self._make(control_plane_request_id="cp-abc")
        self.assertEqual(rec.control_plane_request_id, "cp-abc")

    def test_completed_before_intent_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._make(intent_recorded_at=LATER, completed_at=NOW)

    def test_deny_safe_state_for_failed_activation(self) -> None:
        # A failed activation must record deny-safe mode (LOG_ONLY).
        rec = self._make(
            result=ActivationOutcome.FAILED,
            effective_mode=PolicyEnforcementMode.LOG_ONLY,
            effective_version="permits-inactive",
        )
        self.assertEqual(rec.effective_mode, PolicyEnforcementMode.LOG_ONLY)

    def test_schema_version_default(self) -> None:
        self.assertEqual(self._make().schema_version, "1")

    def test_serialization_deterministic(self) -> None:
        self.assertEqual(self._make().to_json(), self._make().to_json())


# ---------------------------------------------------------------------------
# DiscoveryRun — partial flag and source_results
# ---------------------------------------------------------------------------

class DiscoveryRunFieldTests(unittest.TestCase):
    def _make(self, **overrides) -> DiscoveryRun:
        params = dict(
            run_id="run-1",
            correlation_id="corr-1",
            started_at=NOW,
            completed_at=LATER,
            signals_seen=3,
            findings_upserted=2,
            failures=(),
        )
        params.update(overrides)
        return DiscoveryRun(**params)

    def test_partial_false_when_no_failures(self) -> None:
        run = self._make()
        self.assertFalse(run.partial)

    def test_partial_flag_stored(self) -> None:
        run = self._make(failures=("config: timeout",), partial=True)
        self.assertTrue(run.partial)
        self.assertEqual(run.to_record()["partial"], True)

    def test_source_results_stored_as_tuple(self) -> None:
        sr = SourceResult(source_name="config", succeeded=True, signals_collected=3, error="")
        run = self._make(source_results=(sr,))
        self.assertIsInstance(run.source_results, tuple)
        self.assertEqual(run.source_results[0].source_name, "config")

    def test_source_results_serialize(self) -> None:
        sr = SourceResult(source_name="security_hub", succeeded=False, signals_collected=0, error="throttled")
        record = self._make(source_results=(sr,)).to_record()
        self.assertIn("source_results", record)
        self.assertEqual(record["source_results"][0]["error"], "throttled")

    def test_source_result_negative_count_rejected(self) -> None:
        with self.assertRaises(ValueError):
            SourceResult(source_name="config", succeeded=True, signals_collected=-1, error="")


# ---------------------------------------------------------------------------
# RemediationRequest — idempotency key / expected_finding_version
# ---------------------------------------------------------------------------

class RemediationRequestFieldTests(unittest.TestCase):
    def _make(self, **overrides) -> RemediationRequest:
        params = dict(
            request_id="req-1",
            correlation_id="corr-1",
            actor="admin",
            tool="s3_encryption_enablement",
            target=_target(),
            parameters={},
            idempotency_key="idem-1",
        )
        params.update(overrides)
        return RemediationRequest(**params)

    def test_idempotency_key_required_and_stored(self) -> None:
        req = self._make()
        self.assertEqual(req.idempotency_key, "idem-1")
        self.assertIn("idempotency_key", req.to_record())

    def test_expected_finding_version_default_none(self) -> None:
        self.assertIsNone(self._make().expected_finding_version)

    def test_expected_finding_version_stored(self) -> None:
        req = self._make(expected_finding_version=3)
        self.assertEqual(req.expected_finding_version, 3)

    def test_negative_expected_finding_version_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._make(expected_finding_version=-1)

    def test_empty_idempotency_key_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._make(idempotency_key="  ")


# ---------------------------------------------------------------------------
# ErrorDetail
# ---------------------------------------------------------------------------

class ErrorDetailTests(unittest.TestCase):
    def _make(self, **overrides) -> ErrorDetail:
        params = dict(
            code=ErrorCode.VALIDATION_ERROR,
            message="field 'tool' is required",
            correlation_id="corr-1",
            request_id="req-1",
        )
        params.update(overrides)
        return ErrorDetail(**params)

    def test_required_fields_present_in_record(self) -> None:
        record = self._make().to_record()
        for key in ("code", "message", "correlation_id", "request_id"):
            self.assertIn(key, record)

    def test_code_enum_values_cover_all_failure_modes(self) -> None:
        codes = {e.value for e in ErrorCode}
        self.assertIn("VALIDATION_ERROR", codes)
        self.assertIn("NOT_FOUND", codes)
        self.assertIn("UNAUTHORIZED", codes)
        self.assertIn("STALE_VERSION", codes)
        self.assertIn("CONFLICT", codes)
        self.assertIn("INFRA_ERROR", codes)

    def test_field_errors_default_empty(self) -> None:
        self.assertEqual(self._make().field_errors, {})

    def test_field_errors_stored(self) -> None:
        err = self._make(field_errors={"tool": "unregistered value"})
        self.assertEqual(err.field_errors["tool"], "unregistered value")

    def test_message_empty_string_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._make(message="  ")

    def test_serialization_deterministic(self) -> None:
        self.assertEqual(self._make().to_json(), self._make().to_json())


if __name__ == "__main__":
    unittest.main()
