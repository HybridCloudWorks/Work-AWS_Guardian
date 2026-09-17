"""Ports for AWS, AgentCore, persistence, and audit adapters."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from .contracts import (
    AuditEvent,
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
