"""Ports for AWS, AgentCore, persistence, and audit adapters."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from .contracts import (
    AuditEvent,
    DecisionEvidence,
    DiscoverySignal,
    Finding,
    InvocationResult,
    RemediationRequest,
    TargetRef,
)

class GatewayInvocationPort(Protocol):
    """End-to-end mutation boundary.

    A production implementation must send the request to AgentCore Gateway.
    It must not make a local allow/deny decision and then call an AWS SDK tool.
    """

    def invoke(self, request: RemediationRequest) -> InvocationResult:
        ...


class DiscoverySource(Protocol):
    name: str

    def collect(self, correlation_id: str) -> Iterable[DiscoverySignal]:
        ...


class FindingRepository(Protocol):
    def get(self, finding_id: str) -> Finding | None:
        """Return the current stored finding, or None if it has never been seen."""
        ...

    def upsert(self, finding: Finding) -> None:
        ...


class FindingTargetResolver(Protocol):
    def resolve_finding(self, finding_id: str) -> Finding | None:
        ...

    def resolve_target(self, finding_id: str) -> TargetRef | None:
        ...

    def list_findings(self) -> list[Finding]:
        ...


class AuditSink(Protocol):
    def record(self, event: AuditEvent) -> None:
        ...


class DecisionEvidenceRepository(Protocol):
    """Read/append store for durable Gateway decision evidence (§4.2).

    A production implementation is backed by the audit S3/DynamoDB store. The
    API exposes a *read-only, authenticated* view of it (``get_decision_evidence``);
    the Gateway invocation path records evidence into it. The port is deliberately
    append + query: the API never mutates stored evidence.
    """

    def record(self, evidence: DecisionEvidence, finding_id: str | None = None) -> None:
        """Append decision evidence, optionally associating it with a finding.

        ``finding_id`` is not a field on :class:`DecisionEvidence` (that record
        is target-centric, mirroring the Gateway view); callers that know the
        originating finding pass it so the read path can retrieve evidence by
        finding as well as by request.
        """
        ...

    def by_request_id(self, request_id: str) -> list[DecisionEvidence]:
        ...

    def by_finding_id(self, finding_id: str) -> list[DecisionEvidence]:
        ...
