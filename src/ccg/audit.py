"""Structured, redacted audit sinks."""

from __future__ import annotations

from dataclasses import replace
from typing import TextIO, cast

from .contracts import AuditEvent, JsonValue
from .ports import AuditSink

_SENSITIVE_KEY_PARTS = (
    "password",
    "secret",
    "token",
    "authorization",
    "accesskey",
    "credential",
    "privatekey",
    "cookie",
    "audio",
    "transcript",
)


def _redact(value: JsonValue, key: str | None = None) -> JsonValue:
    if key is not None:
        normalized_key = "".join(character for character in key.casefold() if character.isalnum())
        if any(part in normalized_key for part in _SENSITIVE_KEY_PARTS):
            return "[REDACTED]"
    if isinstance(value, dict):
        return {item_key: _redact(item, item_key) for item_key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def redact_details(details: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """Redact sensitive keys in an audit event's details. Public for reuse."""
    return cast(dict[str, JsonValue], _redact(details))


class JsonLineAuditSink(AuditSink):
    """Writes one redacted JSON object per line to a configured sink."""

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def record(self, event: AuditEvent) -> None:
        redacted_details = redact_details(dict(event.details))
        self._stream.write(replace(event, details=redacted_details).to_json())
        self._stream.write("\n")
        self._stream.flush()


class AuditWriteError(RuntimeError):
    """Raised when an audit event could not be durably recorded.

    Decision and audit evidence must never be silently discarded (design §7).
    The caller (Gateway/tool/control-plane) treats this as fail-closed: a
    mutation must not be reported as successful if its evidence was lost.
    """


class FailClosedAuditSink(AuditSink):
    """Wraps a sink so a storage failure surfaces instead of being swallowed.

    On failure the event is buffered in `dead_letter` for operator inspection
    and an `AuditWriteError` is raised. This models the requirement that a
    mutation cannot proceed without its decision/audit path (CCG-REQ-005,
    design failure behavior). It does not retry; retry/backoff belongs to the
    durable transport implementation added at gate 0.2.
    """

    def __init__(self, inner: AuditSink) -> None:
        self._inner = inner
        self.dead_letter: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        try:
            self._inner.record(event)
        except Exception as exc:  # noqa: BLE001 - reclassify as a fail-closed audit error.
            self.dead_letter.append(event)
            raise AuditWriteError(
                f"failed to record audit event '{event.event_type}' ({event.event_id})"
            ) from exc


class MultiplexAuditSink(AuditSink):
    """Fans one event out to several sinks (e.g. current-state log + S3 audit).

    Writes are attempted for every sink; if any sink fails the others still
    receive the event and a single `AuditWriteError` is raised afterward so the
    failure is never masked.
    """

    def __init__(self, *sinks: AuditSink) -> None:
        if not sinks:
            raise ValueError("at least one sink is required")
        self._sinks = sinks

    def record(self, event: AuditEvent) -> None:
        failures: list[str] = []
        for sink in self._sinks:
            try:
                sink.record(event)
            except Exception as exc:  # noqa: BLE001 - collect and re-raise below.
                failures.append(type(exc).__name__)
        if failures:
            raise AuditWriteError(
                f"audit fan-out failed for {len(failures)} of {len(self._sinks)} sinks: {failures}"
            )
