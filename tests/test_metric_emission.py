"""Emission tests: every component fires the right metric with safe dimensions.

The metric *catalog* and the `InMemoryMetricSink` are unit-tested in isolation
by `test_observability.py`. This module proves the wiring: each component is
given an `InMemoryMetricSink` and asserted to emit the expected metric, value,
and dimensions for the corresponding decision/outcome. A shared assertion
(`_assert_no_secrets_or_arns`) checks that no emitted dimension carries a
secret-shaped value or an ARN, satisfying the P1.4 "no secrets/ARNs in
dimensions" constraint.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from ccg.audit import AuditWriteError, FailClosedAuditSink
from ccg.contracts import (
    Decision,
    DiscoverySignal,
    Finding,
    FindingStatus,
    PolicyActivationRequest,
    RemediationRequest,
    Severity,
    TargetRef,
    ToolOutcome,
    ToolResult,
)
from ccg.discovery import DiscoveryCoordinator
from ccg.observability import InMemoryMetricSink, Metric
from ccg.policy import InMemoryPolicyControlPlane, PolicyActivationService
from ccg.seed import default_scenarios, run_cleanup
from ccg.seed import DryRunSeedEffector
from ccg.testing import (
    FailingDiscoverySource,
    InMemoryCedarGateway,
    InMemoryFindingRepository,
    RecordingAuditSink,
    StaticDiscoverySource,
)
from ccg.voice import MockNovaSonicTransport, ReadOnlyVoiceAdapter

# A representative ARN and a secret-shaped value used only to confirm neither
# ever leaks into an emitted dimension.
_SECRET_LIKE = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret
_ARN_LIKE = "arn:aws:s3:::ccg-demo-secret-bucket"


def _assert_no_secrets_or_arns(testcase: unittest.TestCase, sink: InMemoryMetricSink) -> None:
    """No emitted dimension key/value may carry an ARN or secret-shaped token."""
    for _, dims in list(sink.counters) + list(sink.gauges):
        for key, value in dims:
            for probe in (key, value):
                testcase.assertNotIn("arn:aws", probe, f"ARN leaked in dimension: {dims}")
                testcase.assertNotIn(_SECRET_LIKE, probe, f"secret leaked in dimension: {dims}")
                testcase.assertFalse(
                    probe.startswith("arn:"), f"ARN-shaped dimension value: {dims}"
                )


def _signal(correlation_id: str) -> DiscoverySignal:
    return DiscoverySignal(
        signal_id="sig-1",
        rule_id="s3-encryption-missing",
        source="config",
        target=TargetRef(_ARN_LIKE, "s3_bucket", {"CCGDemo": "true"}),
        severity=Severity.HIGH,
        title="S3 bucket is missing default encryption",
        evidence_refs=("config:sig-1",),
        detected_at=datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc),
        correlation_id=correlation_id,
        attributes={"expected_algorithm": "AES256"},
    )


def _finding() -> Finding:
    sig = _signal("corr-1")
    return Finding(
        finding_id="f-1",
        rule_id=sig.rule_id,
        source=sig.source,
        target=sig.target,
        severity=sig.severity,
        title=sig.title,
        evidence_refs=sig.evidence_refs,
        status=FindingStatus.OPEN,
        first_seen_at=sig.detected_at,
        last_seen_at=sig.detected_at,
        correlation_id="corr-1",
    )


def _request(tool: str = "s3_encryption_enablement", *, idem: str = "idem-1") -> RemediationRequest:
    return RemediationRequest(
        request_id="req-1",
        correlation_id="corr-1",
        actor="admin",
        tool=tool,
        target=TargetRef(_ARN_LIKE, "s3_bucket", {"CCGDemo": "true"}),
        parameters={"algorithm": "AES256"},
        idempotency_key=idem,
    )


class DiscoveryEmissionTests(unittest.TestCase):
    def test_successful_run_emits_run_and_findings_gauge(self) -> None:
        metrics = InMemoryMetricSink()
        repo = InMemoryFindingRepository()
        coordinator = DiscoveryCoordinator(
            [StaticDiscoverySource("config", [_signal("corr-1")])], repo, metrics=metrics
        )
        coordinator.run("corr-1")
        self.assertEqual(metrics.count(Metric.DISCOVERY_RUN, {"outcome": "succeeded"}), 1)
        self.assertEqual(metrics.count(Metric.DISCOVERY_PARTIAL), 0)
        self.assertEqual(metrics.gauges[("ccg.discovery.findings_upserted", ())], 1)
        _assert_no_secrets_or_arns(self, metrics)

    def test_partial_run_emits_partial_and_per_source_failure(self) -> None:
        metrics = InMemoryMetricSink()
        repo = InMemoryFindingRepository()
        coordinator = DiscoveryCoordinator(
            [
                StaticDiscoverySource("config", [_signal("corr-1")]),
                FailingDiscoverySource("securityhub"),
            ],
            repo,
            metrics=metrics,
        )
        coordinator.run("corr-1")
        self.assertEqual(metrics.count(Metric.DISCOVERY_RUN, {"outcome": "partial"}), 1)
        self.assertEqual(metrics.count(Metric.DISCOVERY_PARTIAL), 1)
        self.assertEqual(metrics.count(Metric.DISCOVERY_FAILURE, {"source": "securityhub"}), 1)
        _assert_no_secrets_or_arns(self, metrics)


class GatewayEmissionTests(unittest.TestCase):
    def test_deny_while_inactive_emits_gateway_deny(self) -> None:
        metrics = InMemoryMetricSink()
        gateway = InMemoryCedarGateway(RecordingAuditSink(), permit_active=False, metrics=metrics)
        gateway.register("s3_encryption_enablement", lambda r: _applied(r))
        result = gateway.invoke(_request())
        self.assertIs(result.decision.decision, Decision.DENY)
        self.assertEqual(metrics.count(Metric.GATEWAY_DENY, {"tool": "s3_encryption_enablement"}), 1)
        self.assertEqual(metrics.count(Metric.GATEWAY_ALLOW, {"tool": "s3_encryption_enablement"}), 0)
        _assert_no_secrets_or_arns(self, metrics)

    def test_allow_emits_gateway_allow_and_tool_applied(self) -> None:
        metrics = InMemoryMetricSink()
        gateway = InMemoryCedarGateway(RecordingAuditSink(), permit_active=True, metrics=metrics)
        gateway.activate_permits("v1")
        gateway.register("s3_encryption_enablement", lambda r: _applied(r))
        result = gateway.invoke(_request())
        self.assertIs(result.decision.decision, Decision.ALLOW)
        self.assertEqual(metrics.count(Metric.GATEWAY_ALLOW, {"tool": "s3_encryption_enablement"}), 1)
        self.assertEqual(metrics.count(Metric.TOOL_APPLIED, {"tool": "s3_encryption_enablement"}), 1)
        _assert_no_secrets_or_arns(self, metrics)

    def test_tool_noop_emits_tool_noop(self) -> None:
        metrics = InMemoryMetricSink()
        gateway = InMemoryCedarGateway(RecordingAuditSink(), permit_active=True, metrics=metrics)
        gateway.activate_permits("v1")
        gateway.register("s3_encryption_enablement", lambda r: _noop(r))
        gateway.invoke(_request())
        self.assertEqual(metrics.count(Metric.TOOL_NOOP, {"tool": "s3_encryption_enablement"}), 1)
        _assert_no_secrets_or_arns(self, metrics)

    def test_tool_failed_emits_tool_failed(self) -> None:
        metrics = InMemoryMetricSink()
        gateway = InMemoryCedarGateway(RecordingAuditSink(), permit_active=True, metrics=metrics)
        gateway.activate_permits("v1")
        gateway.register("s3_encryption_enablement", lambda r: _failed(r))
        gateway.invoke(_request())
        self.assertEqual(metrics.count(Metric.TOOL_FAILED, {"tool": "s3_encryption_enablement"}), 1)
        _assert_no_secrets_or_arns(self, metrics)

    def test_idempotent_replay_emits_tool_noop(self) -> None:
        metrics = InMemoryMetricSink()
        gateway = InMemoryCedarGateway(RecordingAuditSink(), permit_active=True, metrics=metrics)
        gateway.activate_permits("v1")
        gateway.register("s3_encryption_enablement", lambda r: _applied(r))
        gateway.invoke(_request())  # applied
        replay = gateway.invoke(_request())  # same idempotency key -> replay
        self.assertTrue(replay.tool_result.idempotency_replayed)
        self.assertEqual(metrics.count(Metric.TOOL_APPLIED, {"tool": "s3_encryption_enablement"}), 1)
        self.assertEqual(
            metrics.count(
                Metric.TOOL_NOOP,
                {"tool": "s3_encryption_enablement", "reason": "idempotent_replay"},
            ),
            1,
        )
        _assert_no_secrets_or_arns(self, metrics)


def _applied(request: RemediationRequest) -> ToolResult:
    return ToolResult(ToolOutcome.APPLIED, request.tool, request.target.arn, True, "applied")


def _noop(request: RemediationRequest) -> ToolResult:
    return ToolResult(ToolOutcome.NOOP, request.tool, request.target.arn, False, "already compliant")


def _failed(request: RemediationRequest) -> ToolResult:
    return ToolResult(ToolOutcome.FAILED, request.tool, request.target.arn, False, "failed")


class PolicyEmissionTests(unittest.TestCase):
    def _service(self, metrics: InMemoryMetricSink) -> tuple[PolicyActivationService, InMemoryPolicyControlPlane]:
        cp = InMemoryPolicyControlPlane(policy_engine_id="test-engine")
        service = PolicyActivationService(cp, RecordingAuditSink(), metrics=metrics)
        return service, cp

    def _activate(self, service: PolicyActivationService, cp: InMemoryPolicyControlPlane) -> PolicyActivationRequest:
        return PolicyActivationRequest(
            request_id="act-1",
            correlation_id="corr-1",
            actor="admin",
            requested_version="v1",
            expected_generation=cp.get_state().generation,
            reason="activate",
            activate=True,
        )

    def test_activation_success_emits_success(self) -> None:
        metrics = InMemoryMetricSink()
        service, cp = self._service(metrics)
        service.apply(self._activate(service, cp))
        self.assertEqual(metrics.count(Metric.ACTIVATION_SUCCESS, {"activate": "true"}), 1)
        _assert_no_secrets_or_arns(self, metrics)

    def test_activation_rejected_emits_rejected(self) -> None:
        metrics = InMemoryMetricSink()
        service, cp = self._service(metrics)
        stale = PolicyActivationRequest(
            request_id="act-2",
            correlation_id="corr-1",
            actor="admin",
            requested_version="v1",
            expected_generation=cp.get_state().generation + 99,  # stale generation
            reason="activate",
            activate=True,
        )
        service.apply(stale)
        self.assertEqual(metrics.count(Metric.ACTIVATION_REJECTED, {"activate": "true"}), 1)
        _assert_no_secrets_or_arns(self, metrics)

    def test_activation_failure_emits_failure(self) -> None:
        metrics = InMemoryMetricSink()
        service, cp = self._service(metrics)
        cp.fail_next = True  # control-plane update raises
        service.apply(self._activate(service, cp))
        self.assertEqual(metrics.count(Metric.ACTIVATION_FAILURE, {"failure": "update"}), 1)
        _assert_no_secrets_or_arns(self, metrics)


class _ExplodingSink:
    def record(self, event) -> None:  # noqa: ANN001 - test double
        raise RuntimeError("store down")


class AuditEmissionTests(unittest.TestCase):
    def test_write_failure_emits_audit_write_failure(self) -> None:
        from ccg.contracts import AuditEvent

        metrics = InMemoryMetricSink()
        sink = FailClosedAuditSink(_ExplodingSink(), metrics=metrics)
        event = AuditEvent(
            event_id="e-1",
            event_type="gateway.decision",
            actor="admin",
            request_id="req-1",
            correlation_id="corr-1",
            outcome="ALLOW",
            occurred_at=datetime(2026, 9, 15, tzinfo=timezone.utc),
            details={},
        )
        with self.assertRaises(AuditWriteError):
            sink.record(event)
        self.assertEqual(
            metrics.count(Metric.AUDIT_WRITE_FAILURE, {"event_type": "gateway.decision"}), 1
        )
        _assert_no_secrets_or_arns(self, metrics)


class VoiceEmissionTests(unittest.TestCase):
    def test_served_brief_emits_voice_session(self) -> None:
        metrics = InMemoryMetricSink()
        adapter = ReadOnlyVoiceAdapter(
            enabled=True, transport=MockNovaSonicTransport(), metrics=metrics
        )
        result = adapter.brief("corr-1", "2 findings open", consent_granted=True)
        self.assertEqual(result.status.value, "AVAILABLE")
        self.assertEqual(metrics.count(Metric.VOICE_SESSION, {"interrupted": "false"}), 1)
        self.assertEqual(metrics.count(Metric.VOICE_ERROR), 0)
        _assert_no_secrets_or_arns(self, metrics)

    def test_unavailable_transport_emits_voice_error(self) -> None:
        metrics = InMemoryMetricSink()
        adapter = ReadOnlyVoiceAdapter(
            enabled=True,
            transport=MockNovaSonicTransport(unavailable=True),
            metrics=metrics,
        )
        result = adapter.brief("corr-1", "briefing", consent_granted=True)
        self.assertEqual(result.status.value, "UNAVAILABLE")
        self.assertEqual(metrics.count(Metric.VOICE_ERROR), 1)
        self.assertEqual(metrics.count(Metric.VOICE_SESSION), 0)
        _assert_no_secrets_or_arns(self, metrics)


class CleanupEmissionTests(unittest.TestCase):
    def test_cleanup_run_emits_cleanup_run(self) -> None:
        metrics = InMemoryMetricSink()
        scenarios = default_scenarios()
        run_cleanup(scenarios, DryRunSeedEffector(), metrics=metrics)
        self.assertEqual(metrics.total(Metric.CLEANUP_RUN), len(scenarios))
        self.assertEqual(metrics.total(Metric.CLEANUP_FAILURE), 0)
        _assert_no_secrets_or_arns(self, metrics)


if __name__ == "__main__":
    unittest.main()
