"""Framework-neutral API service boundary for console and Lambda adapters."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from .contracts import (
    DecisionEvidence,
    InvocationResult,
    PolicyActivationRequest,
    PolicyActivationResult,
    PolicyDecision,
    PolicyEnforcementMode,
    PolicyState,
    RemediationCommand,
    RemediationRequest,
)
from .finding_rules import FindingRuleError, validate_command_against_rule
from .policy import PolicyActivationService
from .ports import DecisionEvidenceRepository, FindingTargetResolver, GatewayInvocationPort


class UnauthorizedError(PermissionError):
    """The caller was not authenticated or lacked the admin control role."""


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    actor: str
    roles: frozenset[str]
    authenticated: bool = True

    def __post_init__(self) -> None:
        if not self.actor.strip():
            raise ValueError("actor must be non-empty")


class ComplianceApi:
    """API service with no direct AWS mutation capability.

    Remediation requests are delegated to the AgentCore Gateway port. This
    service never evaluates a local permit or UI flag to authorize a mutation.
    """

    def __init__(
        self,
        gateway: GatewayInvocationPort,
        policy: PolicyActivationService,
        findings: FindingTargetResolver,
        decision_evidence: DecisionEvidenceRepository | None = None,
    ) -> None:
        self._gateway = gateway
        self._policy = policy
        self._findings = findings
        self._decision_evidence = decision_evidence

    def get_policy_state(self, principal: AuthenticatedPrincipal) -> PolicyState:
        self._require_authenticated(principal)
        return self._policy.current_state()

    def get_findings(self, principal: AuthenticatedPrincipal):
        self._require_authenticated(principal)
        return self._findings.list_findings()

    def request_remediation(
        self,
        principal: AuthenticatedPrincipal,
        command: RemediationCommand,
    ) -> InvocationResult:
        self._require_authenticated(principal)
        if "CCGAdmin" not in principal.roles and "CCGRemediator" not in principal.roles:
            raise UnauthorizedError("CCGRemediator role is required for remediation requests")
        if principal.actor != command.actor:
            raise UnauthorizedError("request actor does not match authenticated principal")
        if command.expected_finding_version is None:
            raise ValueError("expected finding version is required")
        finding = self._findings.resolve_finding(command.finding_id)
        if finding is None:
            raise ValueError("finding target could not be resolved")
        if command.expected_finding_version != finding.revision:
            raise ValueError("finding version is stale")
        # P0.4c/d — API-layer defense in depth. The target is already resolved
        # server-side from the stored finding; now cross-check that the command's
        # tool is the one sanctioned for the finding's rule_id and that every
        # parameter is within that tool's bounded allow-list. A command whose
        # tool/params are inconsistent with the resolved finding is rejected
        # BEFORE the Gateway is called. The tool layer (tools.py) and the Cedar
        # boundary remain independent downstream checks; this never substitutes
        # for them.
        try:
            validate_command_against_rule(finding.rule_id, command.tool, command.parameters)
        except FindingRuleError as exc:
            # VALIDATION_ERROR semantics; surfaced as a 400 at the HTTP adapter.
            raise ValueError(str(exc)) from exc
        request = RemediationRequest(
            request_id=command.request_id,
            correlation_id=command.correlation_id,
            actor=command.actor,
            tool=command.tool,
            target=finding.target,
            parameters=command.parameters,
            idempotency_key=command.idempotency_key,
            expected_finding_version=command.expected_finding_version,
        )
        result = self._gateway.invoke(request)
        self._record_decision_evidence(finding.finding_id, result)
        return result

    def get_decision_evidence(
        self,
        principal: AuthenticatedPrincipal,
        *,
        finding_id: str | None = None,
        request_id: str | None = None,
    ) -> list[DecisionEvidence]:
        """Return stored decision evidence for a finding or request (read-only).

        Authenticated read; no mutation. Exactly one of ``finding_id`` or
        ``request_id`` must be supplied. Returns an empty list when no evidence
        has been recorded for the key.
        """
        self._require_authenticated(principal)
        if self._decision_evidence is None:
            raise ValueError("decision evidence store is not configured")
        if bool(finding_id) == bool(request_id):
            raise ValueError("exactly one of finding_id or request_id is required")
        if finding_id:
            return self._decision_evidence.by_finding_id(finding_id)
        assert request_id is not None
        return self._decision_evidence.by_request_id(request_id)

    def _record_decision_evidence(self, finding_id: str, result: InvocationResult) -> None:
        if self._decision_evidence is None:
            return
        self._decision_evidence.record(
            _evidence_from_decision(result.decision),
            finding_id=finding_id,
        )

    def change_policy_state(
        self,
        principal: AuthenticatedPrincipal,
        request: PolicyActivationRequest,
    ) -> PolicyActivationResult:
        self._require_authenticated(principal)
        if "CCGAdmin" not in principal.roles:
            raise UnauthorizedError("CCGAdmin role is required for policy activation")
        if principal.actor != request.actor:
            raise UnauthorizedError("request actor does not match authenticated principal")
        return self._policy.apply(request)

    @staticmethod
    def _require_authenticated(principal: AuthenticatedPrincipal) -> None:
        if not principal.authenticated:
            raise UnauthorizedError("authentication is required")


def _evidence_from_decision(decision: PolicyDecision) -> DecisionEvidence:
    """Project a lightweight :class:`PolicyDecision` into durable evidence.

    The in-process authorization path returns a :class:`PolicyDecision`; the
    durable §4.2 record is :class:`DecisionEvidence`. Fields the lightweight
    decision does not carry (principal attributes, gateway id, enforcement mode)
    are filled with safe, non-authorizing defaults so the stored record is
    well-formed. The authoritative enforcement mode lives on policy state, not
    on an individual decision, so evidence records it as ``LOG_ONLY`` unless a
    richer source is wired.
    """
    return DecisionEvidence(
        decision_id=str(uuid4()),
        request_id=decision.request_id,
        correlation_id=decision.correlation_id,
        actor=decision.actor,
        principal_attributes={},
        gateway_id="agentcore-gateway",
        action_id=decision.action_id,
        target=decision.target_arn,
        decision=decision.decision,
        determining_policy_ids=decision.matched_policy_ids,
        policy_set_version=decision.policy_set_version,
        enforcement_mode=PolicyEnforcementMode.LOG_ONLY,
        validation_errors=(),
        created_at=decision.evaluated_at or datetime.now(timezone.utc),
    )
