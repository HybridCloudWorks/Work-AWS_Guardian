"""Deterministic, offline end-to-end demo harness.

This proves the full CCG safety flow with **no AWS calls**, wiring the real
discovery, authorization, tool, activation, and API components against in-memory
doubles. It exists to de-risk the demo rehearsal (spec task 6.4) and to give
reviewers something runnable today, in CI, that exercises the Cedar-first
guarantee end to end.

Flow demonstrated (mirrors requirements ACC-01 .. ACC-08, ACC-14):

1. Discovery finds a tagged sandbox finding (deterministic ID).
2. A remediation request is DENIED while the permit set is inactive.
3. An authenticated admin activates a versioned permit set through the audited
   control plane.
4. The same request is now ALLOWED and the tool executes exactly once.
5. A repeat of the request is idempotent (no second mutation).
6. A confirming discovery run (drift gone) reconciles the finding to RESOLVED.

Nothing here authorizes a real mutation: the tool effector is a dry-run
recorder and the policy engine is an in-memory double.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .api import AuthenticatedPrincipal, ComplianceApi
from .contracts import (
    Decision,
    DiscoverySignal,
    Finding,
    PolicyActivationRequest,
    RemediationCommand,
    Severity,
    TargetRef,
)
from .policy import InMemoryPolicyControlPlane, PolicyActivationService
from .reconcile import ReconcileContext, ReconciliationService
from .testing import (
    InMemoryCedarGateway,
    InMemoryFindingRepository,
    RecordingAuditSink,
    StaticDiscoverySource,
)
from .tools import default_tool_handlers
from .discovery import DiscoveryCoordinator

DEMO_TARGET = TargetRef("arn:aws:s3:::ccg-demo-bucket", "s3_bucket", {"CCGDemo": "true"})
DEMO_RULE = "s3-encryption-missing"


@dataclass(frozen=True, slots=True)
class DemoResult:
    """Structured evidence of the demonstrated flow."""

    finding_id: str
    denied_before_activation: bool
    deny_reason: str
    activation_outcome: str
    allowed_after_activation: bool
    tool_outcome: str
    tool_executions: int
    idempotent_replay: bool
    final_status: str
    audit_event_types: tuple[str, ...]


def _signal(correlation_id: str, detected_at: datetime) -> DiscoverySignal:
    return DiscoverySignal(
        signal_id="sig-demo-1",
        rule_id=DEMO_RULE,
        source="config",
        target=DEMO_TARGET,
        severity=Severity.HIGH,
        title="S3 bucket is missing default encryption",
        evidence_refs=("config:sig-demo-1",),
        detected_at=detected_at,
        correlation_id=correlation_id,
        attributes={"expected_algorithm": "AES256"},
    )


def run_demo() -> DemoResult:
    audit = RecordingAuditSink()
    repo = InMemoryFindingRepository()
    control_plane = InMemoryPolicyControlPlane(policy_engine_id="demo-engine")
    policy = PolicyActivationService(control_plane, audit)

    gateway = InMemoryCedarGateway(audit)
    for name, handler in default_tool_handlers().items():
        # Adapt (request, effector=None) handler to the ToolHandler signature.
        gateway.register(name, lambda request, _h=handler: _h(request))

    api = ComplianceApi(gateway=gateway, policy=policy, findings=repo)
    reconciler = ReconciliationService(repo, audit)
    admin = AuthenticatedPrincipal(actor="admin", roles=frozenset({"CCGAdmin", "CCGRemediator"}))

    # 1. Discovery.
    t0 = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
    DiscoveryCoordinator([StaticDiscoverySource("config", [_signal("corr-demo", t0)])], repo, audit).run("corr-demo")
    finding = next(iter(repo.list_findings()))

    def command() -> RemediationCommand:
        return RemediationCommand(
            request_id="req-demo-1",
            correlation_id="corr-demo",
            actor="admin",
            finding_id=finding.finding_id,
            tool="s3_encryption_enablement",
            parameters={"algorithm": "AES256"},
            idempotency_key="idem-demo-1",
            expected_finding_version=finding.revision,
        )

    # 2. Deny while permits inactive.
    denied = api.request_remediation(admin, command())

    # 3. Audited activation.
    activation = api.change_policy_state(
        admin,
        PolicyActivationRequest(
            request_id="act-demo-1",
            correlation_id="corr-demo",
            actor="admin",
            requested_version="v1",
            expected_generation=policy.current_state().generation,
            reason="demo: activate permit set",
            activate=True,
        ),
    )

    # Propagate the control-plane activation to the Gateway enforcement point.
    # In AWS this is AgentCore propagating policy state to the Gateway; with the
    # in-memory doubles the demo makes that propagation explicit and only does so
    # when the audited activation actually succeeded.
    if activation.outcome.value == "ACTIVATED" and activation.state is not None:
        gateway.activate_permits(activation.state.policy_set_version)

    # Record remediation intent through the reconciler (lifecycle authority).
    rec_ctx = ReconcileContext(actor="admin", correlation_id="corr-demo", request_id="req-demo-1")
    reconciler.mark_requested(finding.finding_id, rec_ctx)

    # 4. Allow + single execution.
    allowed = api.request_remediation(admin, command())
    tool_executions = 1 if (allowed.tool_result and allowed.tool_result.changed) else 0
    if allowed.tool_result is not None:
        reconciler.record_tool_outcome(finding.finding_id, allowed.tool_result.outcome, rec_ctx)

    # 5. Idempotent replay.
    replay = api.request_remediation(admin, command())
    idempotent = bool(replay.tool_result and replay.tool_result.idempotency_replayed)

    # 6. Confirming discovery run: drift is gone, so no signal is produced. The
    #    reconciler resolves the finding only because a clean read confirms it.
    DiscoveryCoordinator([StaticDiscoverySource("config", [])], repo, audit).run("corr-demo-2")
    reconciler.confirm_from_discovery(
        finding.finding_id,
        ReconcileContext(actor="discovery-agent", correlation_id="corr-demo-2", request_id="reconcile-demo-1"),
        drift_still_present=False,
    )

    final: Finding = repo.get(finding.finding_id)  # type: ignore[assignment]

    return DemoResult(
        finding_id=finding.finding_id,
        denied_before_activation=denied.decision.decision is Decision.DENY,
        deny_reason=denied.decision.reason,
        activation_outcome=activation.outcome.value,
        allowed_after_activation=allowed.decision.decision is Decision.ALLOW,
        tool_outcome=allowed.tool_result.outcome.value if allowed.tool_result else "NONE",
        tool_executions=tool_executions,
        idempotent_replay=idempotent,
        final_status=final.status.value,
        audit_event_types=tuple(event.event_type for event in audit.events),
    )


def _format(result: DemoResult) -> str:
    lines = [
        "Continuous Compliance Guardian — offline end-to-end demo",
        "=" * 56,
        f"finding_id                 : {result.finding_id}",
        f"1. denied before activation: {result.denied_before_activation} ({result.deny_reason})",
        f"2. activation outcome       : {result.activation_outcome}",
        f"3. allowed after activation : {result.allowed_after_activation}",
        f"4. tool outcome / executions: {result.tool_outcome} / {result.tool_executions}",
        f"5. idempotent replay        : {result.idempotent_replay}",
        f"6. final finding status     : {result.final_status}",
        f"audit trail                 : {' -> '.join(result.audit_event_types)}",
    ]
    return "\n".join(lines)


def main() -> int:
    result = run_demo()
    print(_format(result))
    ok = (
        result.denied_before_activation
        and result.activation_outcome == "ACTIVATED"
        and result.allowed_after_activation
        and result.tool_outcome == "APPLIED"
        and result.tool_executions == 1
        and result.idempotent_replay
        and result.final_status == "RESOLVED"
    )
    if not ok:
        print("\nDEMO INVARIANTS FAILED", flush=True)
        return 1
    print("\nAll demo invariants held (Cedar-first deny->activate->allow->reconcile).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
