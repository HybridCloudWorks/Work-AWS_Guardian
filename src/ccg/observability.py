"""Metric-emission seam and the CCG metric catalog.

Components emit named metrics through a `MetricSink` so operational signals are
decoupled from any specific backend. A real implementation forwards to
CloudWatch EMF/PutMetricData under the observability role; the default is a
no-op, and tests use `InMemoryMetricSink`.

The metric names are a **stable catalog** (`Metric`) covering the operational
signals required by CCG-REQ-037: discovery outcomes, Gateway allow/deny,
policy activation success/failure, tool outcomes, voice sessions/errors, and
cleanup. Dimensions carry low-cardinality context (e.g. source name, tool,
decision reason class) — never secrets, ARNs, or free-form user input.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from enum import StrEnum
from typing import Protocol


class Metric(StrEnum):
    """Stable metric names. Renaming these is a breaking dashboard change."""

    DISCOVERY_RUN = "ccg.discovery.run"
    DISCOVERY_PARTIAL = "ccg.discovery.partial"
    DISCOVERY_FAILURE = "ccg.discovery.failure"
    FINDINGS_UPSERTED = "ccg.discovery.findings_upserted"

    GATEWAY_ALLOW = "ccg.gateway.allow"
    GATEWAY_DENY = "ccg.gateway.deny"

    ACTIVATION_SUCCESS = "ccg.policy.activation_success"
    ACTIVATION_FAILURE = "ccg.policy.activation_failure"
    ACTIVATION_REJECTED = "ccg.policy.activation_rejected"

    TOOL_APPLIED = "ccg.tool.applied"
    TOOL_NOOP = "ccg.tool.noop"
    TOOL_FAILED = "ccg.tool.failed"

    VOICE_SESSION = "ccg.voice.session"
    VOICE_ERROR = "ccg.voice.error"

    CLEANUP_RUN = "ccg.cleanup.run"
    CLEANUP_FAILURE = "ccg.cleanup.failure"

    AUDIT_WRITE_FAILURE = "ccg.audit.write_failure"


Dimensions = Mapping[str, str]


class MetricSink(Protocol):
    """Narrow seam for emitting operational metrics."""

    def increment(self, metric: Metric, *, value: int = 1, dimensions: Dimensions | None = None) -> None:
        ...

    def gauge(self, metric: Metric, value: float, *, dimensions: Dimensions | None = None) -> None:
        ...


def _key(metric: Metric, dimensions: Dimensions | None) -> tuple[str, tuple[tuple[str, str], ...]]:
    dims = tuple(sorted((dimensions or {}).items()))
    return (metric.value, dims)


def _validate_dimensions(dimensions: Dimensions | None) -> None:
    if dimensions is None:
        return
    for key, value in dimensions.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("metric dimensions must be string key/value pairs")


class NullMetricSink(MetricSink):
    """Default no-op sink. Safe to use before a backend is wired."""

    def increment(self, metric: Metric, *, value: int = 1, dimensions: Dimensions | None = None) -> None:
        return None

    def gauge(self, metric: Metric, value: float, *, dimensions: Dimensions | None = None) -> None:
        return None


class InMemoryMetricSink(MetricSink):
    """Aggregating recorder for tests and offline demos.

    Counters aggregate by (metric name, sorted dimensions). Gauges retain the
    last value per key.
    """

    def __init__(self) -> None:
        self.counters: dict[tuple[str, tuple[tuple[str, str], ...]], int] = defaultdict(int)
        self.gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}

    def increment(self, metric: Metric, *, value: int = 1, dimensions: Dimensions | None = None) -> None:
        _validate_dimensions(dimensions)
        self.counters[_key(metric, dimensions)] += value

    def gauge(self, metric: Metric, value: float, *, dimensions: Dimensions | None = None) -> None:
        _validate_dimensions(dimensions)
        self.gauges[_key(metric, dimensions)] = value

    def count(self, metric: Metric, dimensions: Dimensions | None = None) -> int:
        return self.counters.get(_key(metric, dimensions), 0)

    def total(self, metric: Metric) -> int:
        """Sum a metric across all dimension combinations."""
        return sum(count for (name, _), count in self.counters.items() if name == metric.value)
