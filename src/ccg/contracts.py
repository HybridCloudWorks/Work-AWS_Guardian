"""Typed, serializable contracts shared by CCG components.

These contracts deliberately contain no AWS SDK calls. Runtime adapters must
translate to and from these values at a trust boundary.

Schema versions are string literals incremented on breaking changes. Every
top-level contract type carries a ``schema_version`` field defaulting to the
current version so consumers can gate on changes without hard-coupling to the
Python class hierarchy.

Redaction: sensitive-field detection is centralised in ``audit.redact_details``.
Contracts that contain fields which could carry secrets document those fields
via the ``REDACTED_FIELDS`` class attribute – a ``frozenset[str]`` of top-level
field names whose values must be treated as sensitive.  The attribute is
informational; callers still need to invoke ``audit.redact_details`` on the
``details`` mapping of an ``AuditEvent`` before serialising.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import StrEnum
import json
from typing import Mapping, TypeAlias

JsonValue: TypeAlias = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    REMEDIATION_REQUESTED = "REMEDIATION_REQUESTED"
    REMEDIATION_SUCCEEDED = "REMEDIATION_SUCCEEDED"
    REMEDIATION_NOOP = "REMEDIATION_NOOP"
    REMEDIATION_FAILED = "REMEDIATION_FAILED"
    RESOLVED = "RESOLVED"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ToolOutcome(StrEnum):
    APPLIED = "APPLIED"
    NOOP = "NOOP"
    FAILED = "FAILED"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class PolicyEnforcementMode(StrEnum):
    LOG_ONLY = "LOG_ONLY"
    ACTIVE = "ACTIVE"


class ActivationOutcome(StrEnum):
    ACTIVATED = "ACTIVATED"
    DEACTIVATED = "DEACTIVATED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


class VoiceStatus(StrEnum):
    DISABLED = "DISABLED"
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


def _require_text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _jsonable(value: object) -> JsonValue:
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if is_dataclass(value):
        return {field.name: _jsonable(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise TypeError(f"Unsupported JSON value: {type(value).__name__}")


class JsonContract:
    def to_record(self) -> dict[str, JsonValue]:
        record = _jsonable(self)
        if not isinstance(record, dict):
            raise TypeError("Contract did not serialize to an object")
        return record

    def to_json(self) -> str:
        return json.dumps(self.to_record(), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class TargetRef(JsonContract):
    arn: str
    resource_type: str
    tags: Mapping[str, str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "arn", _require_text(self.arn, "arn"))
        object.__setattr__(self, "resource_type", _require_text(self.resource_type, "resource_type"))
        normalized = dict(self.tags)
        if any(not isinstance(key, str) or not key.strip() for key in normalized):
            raise ValueError("target tags must have non-empty string keys")
        if any(not isinstance(value, str) for value in normalized.values()):
            raise ValueError("target tag values must be strings")
        object.__setattr__(self, "tags", normalized)

    @property
    def is_demo(self) -> bool:
        return self.tags.get("CCGDemo") == "true"

    @property
    def is_production(self) -> bool:
        return self.tags.get("Environment", "").casefold() == "prod"


@dataclass(frozen=True, slots=True)
class RemediationRequest(JsonContract):
    request_id: str
    correlation_id: str
    actor: str
    tool: str
    target: TargetRef
    parameters: Mapping[str, JsonValue]
    idempotency_key: str
    expected_finding_version: int | None = None

    def __post_init__(self) -> None:
        for field_name in ("request_id", "correlation_id", "actor", "tool", "idempotency_key"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        if self.expected_finding_version is not None and self.expected_finding_version < 0:
            raise ValueError("expected_finding_version must be non-negative")
        object.__setattr__(self, "parameters", dict(self.parameters))


@dataclass(frozen=True, slots=True)
class RemediationCommand(JsonContract):
    """Untrusted API command; target identity is resolved server-side."""

    request_id: str
    correlation_id: str
    actor: str
    finding_id: str
    tool: str
    parameters: Mapping[str, JsonValue]
    idempotency_key: str
    expected_finding_version: int | None = None

    def __post_init__(self) -> None:
        for field_name in (
            "request_id",
            "correlation_id",
            "actor",
            "finding_id",
            "tool",
            "idempotency_key",
        ):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        if self.expected_finding_version is not None and self.expected_finding_version < 0:
            raise ValueError("expected_finding_version must be non-negative")
        object.__setattr__(self, "parameters", dict(self.parameters))


@dataclass(frozen=True, slots=True)
class PolicyDecision(JsonContract):
    decision: Decision
    request_id: str
    correlation_id: str
    actor: str
    action_id: str
    target_arn: str
    matched_policy_ids: tuple[str, ...]
    policy_set_version: str
    reason: str
    evaluated_at: datetime

    def __post_init__(self) -> None:
        for field_name in (
            "request_id",
            "correlation_id",
            "actor",
            "action_id",
            "target_arn",
            "policy_set_version",
            "reason",
        ):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        object.__setattr__(self, "evaluated_at", _require_aware(self.evaluated_at, "evaluated_at"))
        object.__setattr__(self, "matched_policy_ids", tuple(self.matched_policy_ids))


@dataclass(frozen=True, slots=True)
class ToolResult(JsonContract):
    outcome: ToolOutcome
    tool: str
    target_arn: str
    changed: bool
    message: str
    idempotency_replayed: bool = False
    details: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in ("tool", "target_arn", "message"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        object.__setattr__(self, "details", dict(self.details or {}))


@dataclass(frozen=True, slots=True)
class InvocationResult(JsonContract):
    decision: PolicyDecision
    tool_result: ToolResult | None = None


@dataclass(frozen=True, slots=True)
class AuditEvent(JsonContract):
    """Immutable audit record emitted for every meaningful system event.

    Design §4.3 required fields: ``event_id``, ``event_type``, ``actor``,
    ``component``, ``request_id``, ``correlation_id``, ``target``,
    ``outcome``, ``policy_set_version``, ``timestamp`` (``occurred_at``),
    a redacted ``details`` object, and ``schema_version``.

    ``component``, ``target``, and ``policy_set_version`` are optional to
    preserve backward compatibility with existing callers that pre-date the
    §4.3 field requirement; they default to empty-string sentinels.

    Sensitive field names (those that must be redacted before storage) are
    enumerated in the module-level ``AUDIT_REDACTED_FIELDS`` constant rather
    than a class attribute to avoid slot conflicts; see ``audit.redact_details``.
    """

    # Always-required identity / tracing fields
    event_id: str
    event_type: str
    actor: str
    request_id: str
    correlation_id: str
    outcome: str
    occurred_at: datetime
    details: Mapping[str, JsonValue]

    # §4.3 additional fields (optional for backward compat; prefer to populate)
    component: str = ""
    target: str = ""
    policy_set_version: str = ""
    schema_version: str = "1"

    def __post_init__(self) -> None:
        for field_name in ("event_id", "event_type", "actor", "request_id", "correlation_id", "outcome"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        object.__setattr__(self, "occurred_at", _require_aware(self.occurred_at, "occurred_at"))
        object.__setattr__(self, "details", dict(self.details))


# Sensitive top-level field names in AuditEvent.details that must be redacted
# before storage. ``audit.redact_details`` uses key-normalisation logic instead
# of an exact match; this constant is the canonical reference for callers and tests.
AUDIT_REDACTED_FIELDS: frozenset[str] = frozenset(
    {
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
    }
)


@dataclass(frozen=True, slots=True)
class DiscoverySignal(JsonContract):
    signal_id: str
    rule_id: str
    source: str
    target: TargetRef
    severity: Severity
    title: str
    evidence_refs: tuple[str, ...]
    detected_at: datetime
    correlation_id: str
    attributes: Mapping[str, JsonValue]

    def __post_init__(self) -> None:
        for field_name in ("signal_id", "rule_id", "source", "title", "correlation_id"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        object.__setattr__(self, "detected_at", _require_aware(self.detected_at, "detected_at"))
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))
        object.__setattr__(self, "attributes", dict(self.attributes))


@dataclass(frozen=True, slots=True)
class Finding(JsonContract):
    """Normalized finding contract.

    Design §4.1 required fields: ``finding_id``, ``rule_id``, ``source``,
    ``source_event_id``, ``target_arn``, ``target_type``, ``target_tags``,
    ``severity``, ``title``, ``description``, ``evidence_refs``, ``status``,
    ``first_seen_at``, ``last_seen_at``, ``accepted_risk``,
    ``correlation_id``, ``schema_version``.

    The canonical target identity is stored as a ``TargetRef`` (``target``).
    The flat convenience aliases ``target_arn``, ``target_type``, and
    ``target_tags`` are properties that delegate to ``target``.

    ``source_event_id`` and ``description`` are optional with sentinel defaults
    so existing call sites do not need to be updated immediately.
    """

    finding_id: str
    rule_id: str
    source: str
    target: TargetRef
    severity: Severity
    title: str
    evidence_refs: tuple[str, ...]
    status: FindingStatus
    first_seen_at: datetime
    last_seen_at: datetime
    correlation_id: str
    # §4.1 fields added to meet spec; defaults preserve backward compatibility
    source_event_id: str = ""
    description: str = ""
    schema_version: str = "1"
    accepted_risk: Mapping[str, JsonValue] | None = None
    revision: int = 0

    def __post_init__(self) -> None:
        for field_name in ("finding_id", "rule_id", "source", "title", "correlation_id", "schema_version"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        object.__setattr__(self, "first_seen_at", _require_aware(self.first_seen_at, "first_seen_at"))
        object.__setattr__(self, "last_seen_at", _require_aware(self.last_seen_at, "last_seen_at"))
        if self.last_seen_at < self.first_seen_at:
            raise ValueError("last_seen_at cannot precede first_seen_at")
        if self.revision < 0:
            raise ValueError("revision must be non-negative")
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))
        object.__setattr__(self, "accepted_risk", dict(self.accepted_risk or {}))

    # --- flat-field aliases for design §4.1 convenience ---

    @property
    def target_arn(self) -> str:
        """Alias for ``target.arn`` (§4.1 ``target_arn``)."""
        return self.target.arn

    @property
    def target_type(self) -> str:
        """Alias for ``target.resource_type`` (§4.1 ``target_type``)."""
        return self.target.resource_type

    @property
    def target_tags(self) -> Mapping[str, str]:
        """Alias for ``target.tags`` (§4.1 ``target_tags``)."""
        return self.target.tags


@dataclass(frozen=True, slots=True)
class SourceResult(JsonContract):
    """Per-source success/failure evidence for a discovery run (§CCG-REQ-006)."""

    source_name: str
    succeeded: bool
    signals_collected: int
    error: str  # empty string when succeeded

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_name", _require_text(self.source_name, "source_name"))
        if self.signals_collected < 0:
            raise ValueError("signals_collected must be non-negative")


@dataclass(frozen=True, slots=True)
class DiscoveryRun(JsonContract):
    """Summary of one scheduled discovery run.

    ``partial`` is ``True`` when at least one source failed; it is derived from
    ``failures`` but stored explicitly for fast query filtering.

    ``source_results`` carries per-source evidence so consumers can distinguish
    a source outage from a legitimately empty source (§CCG-REQ-006).
    """

    run_id: str
    correlation_id: str
    started_at: datetime
    completed_at: datetime
    signals_seen: int
    findings_upserted: int
    failures: tuple[str, ...]
    # §CCG-REQ-006 evidence fields; optional for backward compatibility
    partial: bool = False
    source_results: tuple[SourceResult, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        for field_name in ("run_id", "correlation_id"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        object.__setattr__(self, "started_at", _require_aware(self.started_at, "started_at"))
        object.__setattr__(self, "completed_at", _require_aware(self.completed_at, "completed_at"))
        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot precede started_at")
        if self.signals_seen < 0 or self.findings_upserted < 0:
            raise ValueError("discovery counts must be non-negative")
        object.__setattr__(self, "failures", tuple(self.failures))
        object.__setattr__(self, "source_results", tuple(self.source_results))


@dataclass(frozen=True, slots=True)
class PolicyState(JsonContract):
    policy_engine_id: str
    policy_set_version: str
    enforcement_mode: PolicyEnforcementMode
    generation: int
    updated_by: str
    updated_at: datetime

    def __post_init__(self) -> None:
        for field_name in ("policy_engine_id", "policy_set_version", "updated_by"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        if self.generation < 0:
            raise ValueError("generation must be non-negative")
        object.__setattr__(self, "updated_at", _require_aware(self.updated_at, "updated_at"))


@dataclass(frozen=True, slots=True)
class PolicyActivationRequest(JsonContract):
    request_id: str
    correlation_id: str
    actor: str
    requested_version: str
    expected_generation: int
    reason: str
    activate: bool

    def __post_init__(self) -> None:
        for field_name in ("request_id", "correlation_id", "actor", "requested_version", "reason"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        if self.expected_generation < 0:
            raise ValueError("expected_generation must be non-negative")


@dataclass(frozen=True, slots=True)
class PolicyActivationResult(JsonContract):
    outcome: ActivationOutcome
    request_id: str
    correlation_id: str
    state: PolicyState | None
    control_plane_request_id: str | None
    message: str

    def __post_init__(self) -> None:
        for field_name in ("request_id", "correlation_id", "message"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        if self.control_plane_request_id is not None:
            object.__setattr__(
                self,
                "control_plane_request_id",
                _require_text(self.control_plane_request_id, "control_plane_request_id"),
            )


@dataclass(frozen=True, slots=True)
class VoiceBriefingResult(JsonContract):
    status: VoiceStatus
    correlation_id: str
    summary: str
    interrupted: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "correlation_id", _require_text(self.correlation_id, "correlation_id"))
        object.__setattr__(self, "summary", _require_text(self.summary, "summary"))


# ---------------------------------------------------------------------------
# §4.2 DecisionEvidence — full Gateway evaluation record
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class DecisionEvidence(JsonContract):
    """Complete decision evidence record retained per Gateway evaluation.

    Design §4.2 required fields: ``decision_id``, ``request_id``,
    ``correlation_id``, ``actor``, ``principal_attributes``,
    ``gateway_id``, ``action_id``, ``target``, ``decision``,
    ``determining_policy_ids``, ``policy_set_version``,
    ``enforcement_mode``, ``validation_errors``, ``created_at``,
    ``schema_version``.

    ``PolicyDecision`` is retained for the lightweight in-process
    authorization path; ``DecisionEvidence`` is the durable audit record.
    """

    decision_id: str
    request_id: str
    correlation_id: str
    actor: str
    principal_attributes: Mapping[str, JsonValue]
    gateway_id: str
    action_id: str
    target: str          # target ARN
    decision: Decision
    determining_policy_ids: tuple[str, ...]
    policy_set_version: str
    enforcement_mode: PolicyEnforcementMode
    validation_errors: tuple[str, ...]
    created_at: datetime
    schema_version: str = "1"

    def __post_init__(self) -> None:
        for field_name in (
            "decision_id",
            "request_id",
            "correlation_id",
            "actor",
            "gateway_id",
            "action_id",
            "target",
            "policy_set_version",
        ):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        object.__setattr__(self, "created_at", _require_aware(self.created_at, "created_at"))
        object.__setattr__(self, "principal_attributes", dict(self.principal_attributes))
        object.__setattr__(self, "determining_policy_ids", tuple(self.determining_policy_ids))
        object.__setattr__(self, "validation_errors", tuple(self.validation_errors))


# ---------------------------------------------------------------------------
# §4.4 PolicyActivationRecord — full audited activation log entry
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class PolicyActivationRecord(JsonContract):
    """Durable record of one audited policy activation/deactivation attempt.

    Design §4.4 required fields: ``activation_id``, ``requested_version``,
    ``previous_version``, ``requested_mode``, ``actor``, ``reason``,
    ``expected_version``, ``intent_recorded_at``, ``control_plane_request_id``,
    ``result``, ``effective_version``, ``effective_mode``, ``completed_at``,
    ``correlation_id``.

    A failed or uncertain activation records a deny-safe state: ``effective_mode``
    is ``LOG_ONLY`` and ``effective_version`` reflects the last confirmed version.
    ``control_plane_request_id`` is ``None`` when the control-plane call was
    not reached (validation rejection or pre-flight failure).
    """

    activation_id: str
    requested_version: str
    previous_version: str
    requested_mode: PolicyEnforcementMode
    actor: str
    reason: str
    expected_version: str
    intent_recorded_at: datetime
    result: ActivationOutcome
    effective_version: str
    effective_mode: PolicyEnforcementMode
    completed_at: datetime
    correlation_id: str
    control_plane_request_id: str | None = None
    schema_version: str = "1"

    def __post_init__(self) -> None:
        for field_name in (
            "activation_id",
            "requested_version",
            "previous_version",
            "actor",
            "reason",
            "expected_version",
            "effective_version",
            "correlation_id",
        ):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        object.__setattr__(
            self, "intent_recorded_at", _require_aware(self.intent_recorded_at, "intent_recorded_at")
        )
        object.__setattr__(self, "completed_at", _require_aware(self.completed_at, "completed_at"))
        if self.completed_at < self.intent_recorded_at:
            raise ValueError("completed_at cannot precede intent_recorded_at")
        if self.control_plane_request_id is not None:
            object.__setattr__(
                self,
                "control_plane_request_id",
                _require_text(self.control_plane_request_id, "control_plane_request_id"),
            )


# ---------------------------------------------------------------------------
# Error contracts — typed error/result covering all API failure modes
# ---------------------------------------------------------------------------

class ErrorCode(StrEnum):
    """Stable error discriminant for typed error handling."""

    VALIDATION_ERROR = "VALIDATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    UNAUTHORIZED = "UNAUTHORIZED"
    STALE_VERSION = "STALE_VERSION"
    CONFLICT = "CONFLICT"
    INFRA_ERROR = "INFRA_ERROR"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class ErrorDetail(JsonContract):
    """Typed error response included in every API failure path.

    Carries a stable ``code`` for programmatic handling, a human-readable
    ``message``, a ``correlation_id`` for log correlation, a ``request_id``
    to trace the original request, and optional ``field_errors`` for
    validation failures.

    ``hint`` is an optional operator-facing suggestion (never user-facing
    authorization rationale — that would be an information leak).
    """

    code: ErrorCode
    message: str
    correlation_id: str
    request_id: str
    field_errors: Mapping[str, str] = field(default_factory=dict)
    hint: str = ""

    def __post_init__(self) -> None:
        for field_name in ("message", "correlation_id", "request_id"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        object.__setattr__(self, "field_errors", dict(self.field_errors))
