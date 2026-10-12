"""Tests for the read-only Nova Sonic voice adapter and its mock transport.

Covers task 5.3 exit criteria (ACC-12, ACC-13) and CCG-REQ-030..035:

* ACC-12 — voice off by default: DISABLED, no transport call, no mic/stream.
* ACC-13 — flag on + consent: read-only summary, barge-in sets interrupted and
  the session continues, and no mutation capability is exposed.
* Consent required (CCG-REQ-032): flag on, no consent → refused, no call.
* Unavailable fallback (CCG-REQ-033): transport raises → UNAVAILABLE, no raise.
* Redaction (CCG-REQ-035): secret in briefing never reaches summary or state.
* Correlation IDs: the input correlation_id rides through to the result.
* No raw audio retained (CCG-REQ-035): mock holds no audio after a session.
* No mutation path (CCG-REQ-030): adapter/transport expose no gateway/tool attr.
"""

import unittest

from ccg.contracts import VoiceStatus
from ccg.voice import MockNovaSonicTransport, ReadOnlyVoiceAdapter


class _CountingTransport:
    """Transport that records whether it was ever called (for ACC-12 proof)."""

    def __init__(self) -> None:
        self.calls = 0

    def summarize_read_only(self, correlation_id: str, briefing: str) -> str:
        self.calls += 1
        return f"summary for {correlation_id}"


class VoiceDisabledTests(unittest.TestCase):
    def test_acc12_disabled_by_default_no_transport_call(self) -> None:
        transport = _CountingTransport()
        # enabled defaults to False even though a transport is wired.
        adapter = ReadOnlyVoiceAdapter(transport=transport)

        result = adapter.brief("corr-1", "one finding", consent_granted=True)

        self.assertEqual(adapter.status, VoiceStatus.DISABLED)
        self.assertEqual(result.status, VoiceStatus.DISABLED)
        self.assertEqual(result.correlation_id, "corr-1")
        self.assertFalse(result.interrupted)
        # No transport call and therefore no microphone/stream started.
        self.assertEqual(transport.calls, 0)

    def test_disabled_takes_precedence_over_missing_consent(self) -> None:
        transport = _CountingTransport()
        adapter = ReadOnlyVoiceAdapter(transport=transport)
        result = adapter.brief("corr-1", "finding", consent_granted=False)
        self.assertEqual(result.status, VoiceStatus.DISABLED)
        self.assertEqual(transport.calls, 0)


class VoiceConsentTests(unittest.TestCase):
    def test_consent_required_when_enabled(self) -> None:
        transport = _CountingTransport()
        adapter = ReadOnlyVoiceAdapter(enabled=True, transport=transport)

        # Flag on but consent not granted → refused, no transport call.
        result = adapter.brief("corr-9", "finding", consent_granted=False)

        self.assertEqual(result.status, VoiceStatus.DISABLED)
        self.assertEqual(result.correlation_id, "corr-9")
        self.assertEqual(transport.calls, 0)

    def test_consent_defaults_to_not_granted(self) -> None:
        transport = _CountingTransport()
        adapter = ReadOnlyVoiceAdapter(enabled=True, transport=transport)
        # Omitting the kwarg must behave as "no consent".
        result = adapter.brief("corr-9", "finding")
        self.assertEqual(result.status, VoiceStatus.DISABLED)
        self.assertEqual(transport.calls, 0)


class VoiceAvailableTests(unittest.TestCase):
    def test_acc13_enabled_with_consent_streams_summary(self) -> None:
        adapter = ReadOnlyVoiceAdapter(enabled=True, transport=MockNovaSonicTransport())

        result = adapter.brief("corr-2", "two findings open", consent_granted=True)

        self.assertEqual(adapter.status, VoiceStatus.AVAILABLE)
        self.assertEqual(result.status, VoiceStatus.AVAILABLE)
        self.assertFalse(result.interrupted)
        self.assertIn("two findings open", result.summary)

    def test_acc13_interruption_sets_flag_and_session_continues(self) -> None:
        transport = MockNovaSonicTransport(interrupt=True)
        adapter = ReadOnlyVoiceAdapter(enabled=True, transport=transport)

        result = adapter.brief("corr-3", "a finding", consent_granted=True)

        # Barge-in surfaced to the caller; maps to contentEnd.stopReason=INTERRUPTED.
        self.assertTrue(result.interrupted)
        self.assertEqual(transport.last_stop_reason, "INTERRUPTED")
        # Session still produced a usable (non-mutating) summary and did not error.
        self.assertEqual(result.status, VoiceStatus.AVAILABLE)
        self.assertTrue(result.summary)

        # The same adapter continues to serve a subsequent, non-interrupted turn.
        follow_up = adapter.brief("corr-4", "another finding", consent_granted=True)
        self.assertEqual(follow_up.status, VoiceStatus.AVAILABLE)
        self.assertFalse(follow_up.interrupted)

    def test_acc13_no_mutation_capability_exposed(self) -> None:
        transport = MockNovaSonicTransport()
        adapter = ReadOnlyVoiceAdapter(enabled=True, transport=transport)

        # Structural guarantee: neither the adapter nor the transport exposes a
        # path to the Gateway, tool handlers, or remediation (CCG-REQ-030).
        for forbidden in ("gateway", "invoke", "tool", "tools", "remediate", "mutate"):
            self.assertFalse(
                hasattr(adapter, forbidden),
                f"adapter must not expose '{forbidden}'",
            )
            self.assertFalse(
                hasattr(transport, forbidden),
                f"transport must not expose '{forbidden}'",
            )
        # The transport contract carries only a briefing string + correlation id.
        self.assertEqual(
            MockNovaSonicTransport.summarize_read_only.__code__.co_varnames[:3],
            ("self", "correlation_id", "briefing"),
        )


class VoiceUnavailableTests(unittest.TestCase):
    def test_unavailable_when_transport_missing(self) -> None:
        adapter = ReadOnlyVoiceAdapter(enabled=True, transport=None)
        result = adapter.brief("corr-5", "finding", consent_granted=True)
        self.assertEqual(result.status, VoiceStatus.UNAVAILABLE)
        self.assertEqual(adapter.status, VoiceStatus.UNAVAILABLE)

    def test_unavailable_when_transport_raises_no_exception_propagates(self) -> None:
        transport = MockNovaSonicTransport(unavailable=True)
        adapter = ReadOnlyVoiceAdapter(enabled=True, transport=transport)

        # Must not raise; must fall back to a safe UNAVAILABLE result.
        result = adapter.brief("corr-6", "finding", consent_granted=True)

        self.assertEqual(result.status, VoiceStatus.UNAVAILABLE)
        self.assertEqual(result.correlation_id, "corr-6")
        self.assertFalse(result.interrupted)


class VoiceRedactionTests(unittest.TestCase):
    def test_secret_in_briefing_not_in_summary_or_state(self) -> None:
        secret = "AKIAIOSFODNN7EXAMPLE"
        transport = MockNovaSonicTransport()
        adapter = ReadOnlyVoiceAdapter(enabled=True, transport=transport)

        result = adapter.brief(
            "corr-7",
            f"finding exposes access key {secret} in a public bucket",
            consent_granted=True,
        )

        self.assertEqual(result.status, VoiceStatus.AVAILABLE)
        self.assertNotIn(secret, result.summary)
        self.assertIn("[REDACTED]", result.summary)
        # Nothing secret-shaped is retained in the transport's trace either.
        self.assertNotIn(secret, repr(transport.__dict__))

    def test_bearer_token_redacted(self) -> None:
        transport = MockNovaSonicTransport()
        adapter = ReadOnlyVoiceAdapter(enabled=True, transport=transport)
        result = adapter.brief(
            "corr-8",
            "credential leak token=supersecretvalue123 found",
            consent_granted=True,
        )
        self.assertNotIn("supersecretvalue123", result.summary)


class VoiceCorrelationTests(unittest.TestCase):
    def test_result_carries_input_correlation_id(self) -> None:
        transport = MockNovaSonicTransport()
        adapter = ReadOnlyVoiceAdapter(enabled=True, transport=transport)
        result = adapter.brief("trace-xyz", "finding", consent_granted=True)
        self.assertEqual(result.correlation_id, "trace-xyz")
        # And the transport observed/propagated the same id.
        self.assertEqual(transport.correlation_ids, ["trace-xyz"])


class VoiceNoRawAudioTests(unittest.TestCase):
    def test_mock_retains_no_audio_after_session(self) -> None:
        transport = MockNovaSonicTransport()
        adapter = ReadOnlyVoiceAdapter(enabled=True, transport=transport)
        adapter.brief("corr-a", "finding", consent_granted=True)

        # The mock exposes no audio buffer/attribute at all.
        state_keys = {k.lower() for k in vars(transport)}
        self.assertFalse(
            any("audio" in k or "pcm" in k or "frame" in k for k in state_keys),
            f"mock must not retain audio state; found {state_keys}",
        )
        for forbidden in ("audio", "audio_buffer", "frames", "pcm"):
            self.assertFalse(hasattr(transport, forbidden))


if __name__ == "__main__":
    unittest.main()
