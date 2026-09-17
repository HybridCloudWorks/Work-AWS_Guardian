import unittest

from ccg.contracts import Severity
from ccg.discovery import DiscoveryCoordinator
from ccg.sources import (
    MalformedRecordError,
    SourceThrottledError,
    SourceTransport,
    SourceUnauthorizedError,
    config_source,
    security_hub_source,
)
from ccg.testing import InMemoryFindingRepository, RecordingAuditSink


def good_record(**overrides):
    record = {
        "signal_id": "sig-1",
        "rule_id": "s3-encryption",
        "target_arn": "arn:aws:s3:::ccg-demo",
        "resource_type": "s3_bucket",
        "tags": {"CCGDemo": "true"},
        "title": "missing encryption",
        "severity": "high",
        "evidence_refs": ["config:sig-1"],
        "detected_at": "2026-09-15T12:00:00+00:00",
    }
    record.update(overrides)
    return record


class StaticTransport(SourceTransport):
    def __init__(self, records):
        self._records = records

    def read(self, correlation_id: str):
        return list(self._records)


class RaisingTransport(SourceTransport):
    def __init__(self, error: Exception):
        self._error = error

    def read(self, correlation_id: str):
        raise self._error


class SourceMappingTests(unittest.TestCase):
    def test_maps_records_to_signals(self) -> None:
        source = config_source(StaticTransport([good_record()]))
        signals = list(source.collect("corr-1"))
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].rule_id, "s3-encryption")
        self.assertEqual(signals[0].correlation_id, "corr-1")
        self.assertEqual(signals[0].severity, Severity.HIGH)

    def test_default_severity_applied_when_absent(self) -> None:
        record = good_record()
        del record["severity"]
        signals = list(security_hub_source(StaticTransport([record])).collect("corr-1"))
        self.assertEqual(signals[0].severity, Severity.HIGH)  # securityhub default

    def test_malformed_record_is_skipped_not_fabricated(self) -> None:
        bad = good_record()
        del bad["target_arn"]
        source = config_source(StaticTransport([bad, good_record()]))
        signals = list(source.collect("corr-1"))
        self.assertEqual(len(signals), 1)  # only the good one
        self.assertEqual(source.skipped_records, 1)

    def test_strict_mode_escalates_malformed_record(self) -> None:
        bad = good_record()
        del bad["title"]
        source = config_source(StaticTransport([bad]), strict=True)
        with self.assertRaises(MalformedRecordError):
            list(source.collect("corr-1"))

    def test_unknown_severity_is_malformed(self) -> None:
        source = config_source(StaticTransport([good_record(severity="apocalyptic")]))
        self.assertEqual(list(source.collect("corr-1")), [])
        self.assertEqual(source.skipped_records, 1)


class SourceFailureIsolationTests(unittest.TestCase):
    def test_throttled_source_propagates_for_partial_run(self) -> None:
        source = config_source(RaisingTransport(SourceThrottledError("slow down")))
        with self.assertRaises(SourceThrottledError):
            list(source.collect("corr-1"))

    def test_coordinator_marks_run_partial_on_source_error(self) -> None:
        repo = InMemoryFindingRepository()
        audit = RecordingAuditSink()
        healthy = config_source(StaticTransport([good_record()]))
        broken = security_hub_source(RaisingTransport(SourceUnauthorizedError("denied")))
        run = DiscoveryCoordinator([healthy, broken], repo, audit).run("corr-1")
        self.assertEqual(run.findings_upserted, 1)  # healthy source still produced
        self.assertEqual(run.failures, ("securityhub: SourceUnauthorizedError",))
        self.assertEqual(audit.events[-1].outcome, "PARTIAL")


if __name__ == "__main__":
    unittest.main()
