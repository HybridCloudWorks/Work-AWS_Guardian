import io
import json
import unittest
from datetime import datetime, timezone

from ccg.audit import (
    AuditWriteError,
    FailClosedAuditSink,
    JsonLineAuditSink,
    MultiplexAuditSink,
    redact_details,
)
from ccg.contracts import AuditEvent
from ccg.ports import AuditSink
from ccg.testing import RecordingAuditSink

NOW = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)


def event(**overrides) -> AuditEvent:
    params = {
        "event_id": "evt-1",
        "event_type": "remediation.execution",
        "actor": "admin",
        "request_id": "req-1",
        "correlation_id": "corr-1",
        "outcome": "APPLIED",
        "occurred_at": NOW,
        "details": {"tool": "s3_encryption_enablement"},
    }
    params.update(overrides)
    return AuditEvent(**params)


class ExplodingSink(AuditSink):
    def record(self, event: AuditEvent) -> None:
        raise OSError("disk full")


class RedactionTests(unittest.TestCase):
    def test_sensitive_keys_are_redacted(self) -> None:
        details = {
            "SecretAccessKey": "AKIA-super-secret",
            "session_token": "tok-123",
            "audio_blob": "base64...",
            "nested": {"password": "hunter2", "safe": "keep"},
            "safe_field": "visible",
        }
        redacted = redact_details(details)
        self.assertEqual(redacted["SecretAccessKey"], "[REDACTED]")
        self.assertEqual(redacted["session_token"], "[REDACTED]")
        self.assertEqual(redacted["audio_blob"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["password"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["safe"], "keep")
        self.assertEqual(redacted["safe_field"], "visible")

    def test_jsonline_sink_redacts_on_write(self) -> None:
        stream = io.StringIO()
        JsonLineAuditSink(stream).record(event(details={"token": "leak", "tool": "tagging"}))
        written = json.loads(stream.getvalue())
        self.assertEqual(written["details"]["token"], "[REDACTED]")
        self.assertEqual(written["details"]["tool"], "tagging")


class RequiredFieldsAndDeterminismTests(unittest.TestCase):
    def test_required_correlation_and_timestamp_fields_present(self) -> None:
        stream = io.StringIO()
        JsonLineAuditSink(stream).record(event())
        record = json.loads(stream.getvalue())
        for key in ("event_id", "event_type", "actor", "request_id", "correlation_id", "outcome", "occurred_at"):
            self.assertIn(key, record)
        self.assertTrue(record["occurred_at"].endswith("+00:00"))

    def test_json_is_deterministic(self) -> None:
        self.assertEqual(event().to_json(), event().to_json())


class FailClosedTests(unittest.TestCase):
    def test_storage_failure_raises_and_is_not_dropped(self) -> None:
        sink = FailClosedAuditSink(ExplodingSink())
        with self.assertRaises(AuditWriteError):
            sink.record(event())
        self.assertEqual(len(sink.dead_letter), 1)  # captured, not lost

    def test_healthy_sink_passes_through(self) -> None:
        recording = RecordingAuditSink()
        sink = FailClosedAuditSink(recording)
        sink.record(event())
        self.assertEqual(len(recording.events), 1)
        self.assertEqual(sink.dead_letter, [])


class MultiplexTests(unittest.TestCase):
    def test_fans_out_to_all_sinks(self) -> None:
        a, b = RecordingAuditSink(), RecordingAuditSink()
        MultiplexAuditSink(a, b).record(event())
        self.assertEqual(len(a.events), 1)
        self.assertEqual(len(b.events), 1)

    def test_one_failure_does_not_mask_and_others_still_written(self) -> None:
        healthy = RecordingAuditSink()
        mux = MultiplexAuditSink(healthy, ExplodingSink())
        with self.assertRaises(AuditWriteError):
            mux.record(event())
        self.assertEqual(len(healthy.events), 1)  # healthy sink still received it

    def test_requires_at_least_one_sink(self) -> None:
        with self.assertRaises(ValueError):
            MultiplexAuditSink()


if __name__ == "__main__":
    unittest.main()
