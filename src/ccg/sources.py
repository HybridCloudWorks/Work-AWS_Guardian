"""Read-only discovery source adapters for Config, Security Hub, CloudTrail.

These adapters translate raw provider records into normalized `DiscoverySignal`
values. They are deliberately **read-only** and contain **no AWS SDK calls**:
the actual API read is delegated to an injected `SourceTransport`, which a real
boto3-backed implementation fills in behind the discovery IAM role once gate 0.2
provides the account. The mapping from provider record to signal lives in a
`RecordMapper` seam so rules can evolve without touching transport code.

Error handling follows the safety rule that an unknown result must never become
a compliant result (CCG-REQ-006):

- **Whole-source failures** — throttling, missing permission, or a transport
  error — raise a typed `SourceError` from `collect()`. The coordinator catches
  it and marks the run partial, retaining the failure as evidence. The source
  contributes no signals rather than a false "all clear".
- **Per-record problems** — a single malformed record is skipped and counted,
  not fabricated into a signal and not allowed to abort the whole source. If
  `strict=True`, malformed records instead escalate to a source failure.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from datetime import datetime, timezone
from typing import Protocol

from .contracts import DiscoverySignal, JsonValue, Severity, TargetRef


class SourceError(RuntimeError):
    """Base class for a whole-source read failure."""


class SourceThrottledError(SourceError):
    """The provider throttled the read; the run is partial, not compliant."""


class SourceUnauthorizedError(SourceError):
    """The discovery role lacked permission for this source."""


class SourceUnavailableError(SourceError):
    """The provider was unreachable or returned a transport-level error."""


class MalformedRecordError(ValueError):
    """A single record could not be mapped to a signal."""


RawRecord = Mapping[str, JsonValue]


class SourceTransport(Protocol):
    """Narrow read seam for one provider.

    A real implementation performs a paginated, read-only API call under the
    discovery role and yields raw records. It must translate provider throttle/
    access errors into the typed `SourceError` subclasses above.
    """

    def read(self, correlation_id: str) -> Iterable[RawRecord]:
        ...


RecordMapper = Callable[[RawRecord, str], DiscoverySignal]


def _require(record: RawRecord, key: str) -> JsonValue:
    if key not in record or record[key] in (None, ""):
        raise MalformedRecordError(f"record missing required field '{key}'")
    return record[key]


def _tags(record: RawRecord) -> Mapping[str, str]:
    raw = record.get("tags", {})
    if not isinstance(raw, Mapping):
        raise MalformedRecordError("record 'tags' must be an object")
    tags: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise MalformedRecordError("tag keys and values must be strings")
        tags[key] = value
    return tags


def _severity(record: RawRecord, default: Severity) -> Severity:
    raw = record.get("severity")
    if raw is None:
        return default
    try:
        return Severity(str(raw).upper())
    except ValueError as exc:
        raise MalformedRecordError(f"unknown severity '{raw}'") from exc


def _target(record: RawRecord) -> TargetRef:
    return TargetRef(
        arn=str(_require(record, "target_arn")),
        resource_type=str(_require(record, "resource_type")),
        tags=_tags(record),
    )


def make_mapper(source_name: str, default_severity: Severity) -> RecordMapper:
    """Build a mapper that normalizes one provider's records into signals.

    The provider-specific shape is small and shared here; when the live schemas
    are captured (gate 0.2) each provider can supply its own mapper without
    changing the adapter or coordinator.
    """

    def _map(record: RawRecord, correlation_id: str) -> DiscoverySignal:
        detected_raw = record.get("detected_at")
        detected_at = (
            datetime.fromisoformat(str(detected_raw))
            if detected_raw
            else datetime.now(timezone.utc)
        )
        if detected_at.tzinfo is None:
            raise MalformedRecordError("detected_at must be timezone-aware")
        evidence = record.get("evidence_refs", ())
        if isinstance(evidence, str) or not isinstance(evidence, Sequence):
            raise MalformedRecordError("evidence_refs must be a list")
        return DiscoverySignal(
            signal_id=str(_require(record, "signal_id")),
            rule_id=str(_require(record, "rule_id")),
            source=source_name,
            target=_target(record),
            severity=_severity(record, default_severity),
            title=str(_require(record, "title")),
            evidence_refs=tuple(str(item) for item in evidence),
            detected_at=detected_at,
            correlation_id=correlation_id,
            attributes={"provider": source_name},
        )

    return _map


class NormalizingSource:
    """A `DiscoverySource` that reads via a transport and maps to signals.

    Satisfies the `DiscoverySource` protocol (has `name` and `collect`).
    """

    def __init__(
        self,
        name: str,
        transport: SourceTransport,
        mapper: RecordMapper,
        *,
        strict: bool = False,
    ) -> None:
        self.name = name
        self._transport = transport
        self._mapper = mapper
        self._strict = strict
        self.skipped_records = 0

    def collect(self, correlation_id: str) -> Iterator[DiscoverySignal]:
        # A transport error (throttle/unauthorized/unavailable) propagates so the
        # coordinator records a whole-source failure. We must not swallow it.
        records = self._transport.read(correlation_id)
        signals: list[DiscoverySignal] = []
        for record in records:
            try:
                signals.append(self._mapper(record, correlation_id))
            except MalformedRecordError:
                self.skipped_records += 1
                if self._strict:
                    raise
                # Non-strict: skip the bad record; never fabricate a signal.
                continue
        return iter(signals)


def config_source(transport: SourceTransport, *, strict: bool = False) -> NormalizingSource:
    return NormalizingSource("config", transport, make_mapper("config", Severity.MEDIUM), strict=strict)


def security_hub_source(transport: SourceTransport, *, strict: bool = False) -> NormalizingSource:
    return NormalizingSource("securityhub", transport, make_mapper("securityhub", Severity.HIGH), strict=strict)


def cloudtrail_source(transport: SourceTransport, *, strict: bool = False) -> NormalizingSource:
    return NormalizingSource("cloudtrail", transport, make_mapper("cloudtrail", Severity.MEDIUM), strict=strict)
