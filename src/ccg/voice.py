"""Optional read-only Nova Sonic adapter boundary.

Voice is OFF by default (project rule + ADR). Even when enabled it is a
read-only briefing path: it summarizes findings aloud and can be barged in on,
but it has **no** access to the AgentCore Gateway, the remediation tool
handlers, or any mutation operation. This is enforced structurally — the
``NovaSonicTransport`` protocol carries only a ``briefing`` string and returns a
summary string; there is no parameter for a tool name, tool input, or Gateway
handle (capability record §4.8 security invariant).

Gate-0.3 decision (§4.7): the first implementation uses a **mock** transport
(:class:`MockNovaSonicTransport`). A real ``InvokeModelWithBidirectionalStream``
transport remains a documented future seam; it must satisfy the same protocol
with no change to :class:`ReadOnlyVoiceAdapter` or its callers.
"""

from __future__ import annotations

import logging
from typing import Protocol

from .audit import redact_text
from .contracts import VoiceBriefingResult, VoiceStatus
from .observability import Metric, MetricSink, NullMetricSink

logger = logging.getLogger(__name__)


class NovaSonicTransport(Protocol):
    """Transport for a validated bidirectional Nova Sonic session.

    The transport receives only a read-only briefing prompt. It has no
    remediation-tool registry and therefore cannot bypass the Gateway
    (§4.8 security invariant). The protocol intentionally has no tool-name,
    tool-input, or Gateway parameter.
    """

    def summarize_read_only(self, correlation_id: str, briefing: str) -> str:
        ...


class VoiceConsentError(RuntimeError):
    """Raised internally when a session is attempted without microphone consent.

    Never propagates to callers: :meth:`ReadOnlyVoiceAdapter.brief` turns a
    missing consent into a DISABLED result so the console stays functional
    (CCG-REQ-032, CCG-REQ-033).
    """


class MockNovaSonicTransport:
    """Deterministic, read-only mock satisfying the §4.8 contract.

    Structural guarantees (not runtime checks):

    * No tool registry and no mutation path — the only input is the briefing
      string, mirroring the real transport's ``toolConfiguration``-omitted
      session (§4.8 security invariant, CCG-REQ-030).
    * No raw audio is ever retained. The mock models a text-only summary; it
      stores none of the input and exposes no audio buffer (CCG-REQ-035).

    Test knobs:

    * ``unavailable=True`` makes :meth:`summarize_read_only` raise, exercising
      the UNAVAILABLE fallback (model/region/quota/API outage).
    * ``interrupt=True`` models a single barge-in on the **next** turn: that
      turn's summary is cut short and the transport reports it via
      :attr:`last_stop_reason` = ``"INTERRUPTED"``, mapping to the real
      ``contentEnd.stopReason = "INTERRUPTED"`` signal (§4.6, CCG-REQ-031).
      The barge-in is consumed after one turn so a subsequent turn on the same
      session completes normally — modelling "the session continues".
    """

    def __init__(self, *, unavailable: bool = False, interrupt: bool = False) -> None:
        self._unavailable = unavailable
        self._interrupt = interrupt
        # Observable, non-sensitive session trace for tests. Deliberately holds
        # NO audio and NO raw briefing — only correlation IDs and the terminal
        # stop reason, so "no raw audio retained" is assertable.
        self.correlation_ids: list[str] = []
        self.last_stop_reason: str = "END_TURN"

    @property
    def interrupted(self) -> bool:
        """True when the most recent session ended on a barge-in."""
        return self.last_stop_reason == "INTERRUPTED"

    def summarize_read_only(self, correlation_id: str, briefing: str) -> str:
        # Propagate/log the correlation id for traceability (§4.8 guidance).
        self.correlation_ids.append(correlation_id)
        logger.info("voice.summary.start", extra={"correlation_id": correlation_id})

        if self._unavailable:
            # Models model/region/quota/API unavailability. The adapter maps any
            # exception to VoiceStatus.UNAVAILABLE (CCG-REQ-033).
            self.last_stop_reason = "FAILED"
            raise RuntimeError("nova sonic session unavailable")

        # Defense in depth: redact any secret-shaped material before it is ever
        # "spoken" or returned. The adapter also redacts the briefing on the way
        # in; the transport never trusts that it received clean text (CCG-REQ-035).
        safe_briefing = redact_text(briefing)
        summary = f"Read-only compliance briefing: {safe_briefing}"

        if self._interrupt:
            # Barge-in: user spoke over playback. The real transport receives
            # contentEnd.stopReason="INTERRUPTED", clears its audio queue, and
            # continues the session without authorizing any mutation (§4.6).
            # Consume the one-shot knob so the next turn completes normally.
            self._interrupt = False
            self.last_stop_reason = "INTERRUPTED"
            summary = f"{summary} [interrupted]"
            logger.info(
                "voice.summary.interrupted",
                extra={"correlation_id": correlation_id, "stop_reason": "INTERRUPTED"},
            )
        else:
            self.last_stop_reason = "END_TURN"

        return summary


class ReadOnlyVoiceAdapter:
    """Feature-flagged, consent-gated, read-only voice briefing adapter.

    A session can only start when BOTH the feature flag is enabled AND explicit
    microphone consent has been granted for the call (CCG-REQ-032). Consent is
    an explicit per-call argument — never a stored default. Without the flag or
    without consent, no transport call is made and no microphone/stream is
    started; the result is DISABLED and the console stays functional.
    """

    def __init__(
        self,
        *,
        enabled: bool = False,
        transport: NovaSonicTransport | None = None,
        metrics: MetricSink | None = None,
    ) -> None:
        self._enabled = enabled
        self._transport = transport
        self._metrics = metrics or NullMetricSink()

    @property
    def status(self) -> VoiceStatus:
        if not self._enabled:
            return VoiceStatus.DISABLED
        return VoiceStatus.AVAILABLE if self._transport is not None else VoiceStatus.UNAVAILABLE

    def brief(
        self,
        correlation_id: str,
        briefing: str,
        *,
        consent_granted: bool = False,
    ) -> VoiceBriefingResult:
        """Produce a read-only spoken summary of ``briefing``.

        ``consent_granted`` must be explicitly ``True`` (microphone consent for
        this session). The flag-off and consent-missing paths return DISABLED
        without touching the transport — no microphone or stream is started.
        A missing/raising transport returns UNAVAILABLE. The ``correlation_id``
        is carried through to the result in every path.
        """
        # ACC-12: flag off → DISABLED, no transport call, no mic/stream started.
        if not self._enabled:
            return VoiceBriefingResult(VoiceStatus.DISABLED, correlation_id, "Voice is disabled.")

        # CCG-REQ-032: consent is mandatory. Without it we refuse before any
        # transport interaction; no microphone is opened.
        if not consent_granted:
            return VoiceBriefingResult(
                VoiceStatus.DISABLED,
                correlation_id,
                "Voice requires explicit microphone consent.",
            )

        # CCG-REQ-033: transport missing → safe UNAVAILABLE, console unaffected.
        if self._transport is None:
            return VoiceBriefingResult(VoiceStatus.UNAVAILABLE, correlation_id, "Voice is unavailable.")

        # CCG-REQ-035: redact secret-shaped material from the briefing before it
        # is handed to the transport (and thus before it is ever spoken).
        safe_briefing = redact_text(briefing)

        try:
            summary = self._transport.summarize_read_only(correlation_id, safe_briefing)
        except Exception:  # noqa: BLE001 - unavailable voice must not affect authorization.
            logger.warning("voice.summary.unavailable", extra={"correlation_id": correlation_id})
            # Operationally meaningful voice failure (model/region/quota/API).
            self._metrics.increment(Metric.VOICE_ERROR)
            return VoiceBriefingResult(VoiceStatus.UNAVAILABLE, correlation_id, "Voice is unavailable.")

        # CCG-REQ-031: surface a barge-in to the caller when the transport
        # exposes one. The session is reported as AVAILABLE and interrupted; the
        # adapter never authorizes a mutation on any path.
        interrupted = bool(getattr(self._transport, "interrupted", False))

        # A brief was served. Dimension records whether it was interrupted —
        # a low-cardinality operational signal, never any briefing content.
        self._metrics.increment(
            Metric.VOICE_SESSION, dimensions={"interrupted": str(interrupted).lower()}
        )

        # Belt-and-braces redaction of the returned summary (CCG-REQ-035): even
        # a buggy transport must not surface a secret through the summary.
        safe_summary = redact_text(summary)
        return VoiceBriefingResult(
            VoiceStatus.AVAILABLE,
            correlation_id,
            safe_summary,
            interrupted=interrupted,
        )
