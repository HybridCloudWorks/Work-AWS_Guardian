"""Test doubles for contract and authorization-boundary tests.

`InMemoryCedarGateway` is intentionally not a production authorizer. It models
only the safety semantics required to test callers until a live AgentCore
Gateway schema and policy engine are available.
"""

from __future__ import annotations

from collections.abc import Iterable

from .authz import decide
from .contracts import (
    AuditEvent,
    DecisionEvidence,
    Finding,
    InvocationResult,
    PolicyDecision,
    RemediationRequest,
    TargetRef,
)
from .gateway_core import GatewayInvocationSkeleton, ToolHandler
from .observability import MetricSink
from .ports import (
    AuditSink,
    DecisionEvidenceRepository,
    DiscoverySource,
    FindingRepository,
    GatewayInvocationPort,
)


class RecordingAuditSink(AuditSink):
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)


class InMemoryFindingRepository(FindingRepository):
    def __init__(self) -> None:
        self.findings: dict[str, Finding] = {}

    def get(self, finding_id: str) -> Finding | None:
        return self.findings.get(finding_id)

    def upsert(self, finding: Finding) -> None:
        self.findings[finding.finding_id] = finding

    def resolve_finding(self, finding_id: str) -> Finding | None:
        return self.findings.get(finding_id)

    def resolve_target(self, finding_id: str) -> TargetRef | None:
        finding = self.resolve_finding(finding_id)
        return finding.target if finding is not None else None

    def list_findings(self) -> list[Finding]:
        return list(self.findings.values())


class InMemoryDecisionEvidenceRepository(DecisionEvidenceRepository):
    """In-memory decision-evidence store indexed by request_id and finding_id.

    The ``finding_id`` is not a field on :class:`DecisionEvidence` (that record
    mirrors the Gateway's view, which is target-centric), so callers that know
    the finding supply it at record time. Both indexes are append-only; the API
    read path never mutates stored evidence.
    """

    def __init__(self) -> None:
        self._by_request: dict[str, list[DecisionEvidence]] = {}
        self._by_finding: dict[str, list[DecisionEvidence]] = {}
        self.records: list[DecisionEvidence] = []

    def record(self, evidence: DecisionEvidence, finding_id: str | None = None) -> None:
        self.records.append(evidence)
        self._by_request.setdefault(evidence.request_id, []).append(evidence)
        if finding_id:
            self._by_finding.setdefault(finding_id, []).append(evidence)

    def by_request_id(self, request_id: str) -> list[DecisionEvidence]:
        return list(self._by_request.get(request_id, ()))

    def by_finding_id(self, finding_id: str) -> list[DecisionEvidence]:
        return list(self._by_finding.get(finding_id, ()))


class StaticDiscoverySource(DiscoverySource):
    def __init__(self, name: str, signals: Iterable) -> None:
        self.name = name
        self._signals = tuple(signals)

    def collect(self, correlation_id: str):
        return self._signals


class FailingDiscoverySource(DiscoverySource):
    def __init__(self, name: str, error: Exception | None = None) -> None:
        self.name = name
        self._error = error or RuntimeError("source unavailable")

    def collect(self, correlation_id: str):
        raise self._error


class InMemoryCedarGateway(GatewayInvocationPort):
    """Minimal test-only model of the external Gateway/Cedar boundary.

    The double shares the exact evidence/audit/idempotency/ordering flow with
    the production client via :class:`~ccg.gateway_core.GatewayInvocationSkeleton`;
    only the *decision source* differs. The double decides locally through the
    shared :mod:`ccg.authz` model (it is a faithful stand-in for the remote
    engine), whereas the production client defers to the transport.
    """

    def __init__(
        self,
        audit_sink: AuditSink,
        *,
        permit_active: bool = False,
        metrics: MetricSink | None = None,
    ) -> None:
        self._skeleton = GatewayInvocationSkeleton(audit_sink, metrics)
        self._permit_active = permit_active
        self._policy_version = "permits-inactive"

    def register(self, tool: str, handler: ToolHandler) -> None:
        self._skeleton.register(tool, handler)

    def activate_permits(self, version: str) -> None:
        self._permit_active = True
        self._policy_version = version

    def invoke(self, request: RemediationRequest) -> InvocationResult:
        return self._skeleton.run(request, self._evaluate)

    def _evaluate(self, request: RemediationRequest) -> PolicyDecision:
        # Delegate to the shared authz engine so the double enforces exactly the
        # same forbid-overrides-permit ordering the console/API rely on.
        return decide(
            request,
            permit_active=self._permit_active,
            registered_tools=self._skeleton.registered_tools,
            policy_set_version=self._policy_version,
        )
