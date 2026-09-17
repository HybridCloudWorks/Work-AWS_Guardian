"""Read-only discovery orchestration over typed source adapters.

Normalization is deterministic and replay-safe. A finding's identity is derived
from stable rule and target attributes so that repeated discovery updates the
same record rather than creating duplicates. Merge rules preserve
`first_seen_at`, monotonically advance `last_seen_at`, and bump `revision` only
when the observed drift content actually changes. An unchanged re-observation is
a true no-op (no revision churn), which keeps the API's optimistic-concurrency
check (`expected_finding_version`) stable across benign re-runs.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
import hashlib
from uuid import uuid4

from .contracts import (
    AuditEvent,
    DiscoveryRun,
    DiscoverySignal,
    Finding,
    FindingStatus,
)
from .ports import AuditSink, DiscoverySource, FindingRepository

# Statuses that represent an in-flight or terminal remediation lifecycle. A
# fresh discovery observation must not silently drag these back to OPEN; only a
# confirming read (handled by the reconciliation path) may resolve a finding.
_ACTIVE_LIFECYCLE_STATUSES = frozenset(
    {
        FindingStatus.REMEDIATION_REQUESTED,
        FindingStatus.REMEDIATION_SUCCEEDED,
        FindingStatus.REMEDIATION_NOOP,
        FindingStatus.REMEDIATION_FAILED,
        FindingStatus.RESOLVED,
        FindingStatus.ACCEPTED_RISK,
    }
)


def derive_finding_id(rule_id: str, target_arn: str) -> str:
    """Deterministic finding identity from stable rule + target attributes."""
    stable_key = f"{rule_id}:{target_arn}"
    return hashlib.sha256(stable_key.encode("utf-8")).hexdigest()[:32]


def _content_fingerprint(finding: Finding) -> str:
    """Hash of the drift-defining content, excluding volatile bookkeeping.

    Two findings with the same fingerprint describe the same drift state, so a
    re-observation should not bump the revision.
    """
    parts = [
        finding.rule_id,
        finding.source,
        finding.severity.value,
        finding.title,
        finding.target.arn,
        finding.target.resource_type,
        "|".join(sorted(finding.evidence_refs)),
        "|".join(f"{key}={value}" for key, value in sorted(finding.target.tags.items())),
    ]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def normalize_signal(signal: DiscoverySignal) -> Finding:
    """Turn a raw source signal into a normalized, OPEN candidate finding."""
    return Finding(
        finding_id=derive_finding_id(signal.rule_id, signal.target.arn),
        rule_id=signal.rule_id,
        source=signal.source,
        target=signal.target,
        severity=signal.severity,
        title=signal.title,
        evidence_refs=signal.evidence_refs,
        status=FindingStatus.OPEN,
        first_seen_at=signal.detected_at,
        last_seen_at=signal.detected_at,
        correlation_id=signal.correlation_id,
    )


def merge_finding(existing: Finding | None, candidate: Finding) -> tuple[Finding, bool]:
    """Merge a freshly normalized candidate with the stored finding.

    Returns the finding to persist and whether it represents a real change.
    Idempotent: merging the same candidate twice yields no further change.
    """
    if existing is None:
        return candidate, True

    # Preserve the earliest first_seen and never regress last_seen.
    first_seen_at = min(existing.first_seen_at, candidate.last_seen_at)
    last_seen_at = max(existing.last_seen_at, candidate.last_seen_at)

    # An in-flight/terminal finding keeps its lifecycle status; a still-OPEN one
    # stays OPEN. Discovery never authors remediation transitions.
    status = existing.status if existing.status in _ACTIVE_LIFECYCLE_STATUSES else FindingStatus.OPEN

    content_changed = _content_fingerprint(existing) != _content_fingerprint(candidate)
    revision = existing.revision + 1 if content_changed else existing.revision

    merged = Finding(
        finding_id=existing.finding_id,
        rule_id=candidate.rule_id,
        source=candidate.source,
        target=candidate.target,
        severity=candidate.severity,
        title=candidate.title,
        evidence_refs=candidate.evidence_refs,
        status=status,
        first_seen_at=first_seen_at,
        last_seen_at=last_seen_at,
        correlation_id=candidate.correlation_id,
        schema_version=existing.schema_version,
        accepted_risk=existing.accepted_risk,
        revision=revision,
    )
    changed = content_changed or last_seen_at != existing.last_seen_at
    return merged, changed


class DiscoveryCoordinator:
    """Collects signals and upserts current findings without mutation access."""

    def __init__(
        self,
        sources: Sequence[DiscoverySource],
        repository: FindingRepository,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self._sources = tuple(sources)
        self._repository = repository
        self._audit_sink = audit_sink

    def run(self, correlation_id: str) -> DiscoveryRun:
        run_id = str(uuid4())
        started_at = datetime.now(timezone.utc)
        signals_seen = 0
        findings_upserted = 0
        findings_changed = 0
        failures: list[str] = []
        # Dedup identical signals within a single run so a source that emits a
        # duplicate cannot inflate counts or double-bump a revision.
        seen_in_run: set[str] = set()

        for source in self._sources:
            try:
                signals: Iterable[DiscoverySignal] = source.collect(correlation_id)
                for signal in signals:
                    if signal.correlation_id != correlation_id:
                        failures.append(f"{source.name}: correlation mismatch")
                        continue
                    signals_seen += 1
                    candidate = normalize_signal(signal)
                    if candidate.finding_id in seen_in_run:
                        continue
                    seen_in_run.add(candidate.finding_id)
                    existing = self._repository.get(candidate.finding_id)
                    merged, changed = merge_finding(existing, candidate)
                    self._repository.upsert(merged)
                    findings_upserted += 1
                    if changed:
                        findings_changed += 1
            except Exception as exc:  # noqa: BLE001 - source isolation is intentional.
                failures.append(f"{source.name}: {type(exc).__name__}")

        completed_at = datetime.now(timezone.utc)
        result = DiscoveryRun(
            run_id=run_id,
            correlation_id=correlation_id,
            started_at=started_at,
            completed_at=completed_at,
            signals_seen=signals_seen,
            findings_upserted=findings_upserted,
            failures=tuple(failures),
        )
        if self._audit_sink is not None:
            self._audit_sink.record(
                AuditEvent(
                    event_id=str(uuid4()),
                    event_type="discovery.run",
                    actor="discovery-agent",
                    request_id=run_id,
                    correlation_id=correlation_id,
                    outcome="PARTIAL" if failures else "SUCCEEDED",
                    occurred_at=completed_at,
                    details={
                        "signals_seen": signals_seen,
                        "findings_upserted": findings_upserted,
                        "findings_changed": findings_changed,
                        "failure_count": len(failures),
                        "failures": list(failures),
                    },
                )
            )
        return result
