"""Complete offline demo rehearsal for spec task 6.4.

Where :mod:`ccg.demo` proves the Cedar-first chain for a *single* finding, this
module runs the **full demo script** over the four seeded drift scenarios
(:mod:`ccg.seed`) end to end, with no AWS calls:

1. Seed the four drift scenarios (dry-run via :class:`~ccg.seed.DryRunSeedEffector`).
2. Discover -> normalized findings with correlation IDs.
3. Request a remediation while permits are inactive -> DENIED (decision evidence).
4. Activate the versioned permit set through the audited control plane ->
   ACTIVATED (intent + result audit events, effective version).
5. Repeat the same request -> ALLOWED, the tool applies once (or a safe no-op on
   an already-compliant target).
6. Idempotent replay -> no second mutation.
7. Rediscover (drift gone) -> reconcile to RESOLVED.
8. Collect the decision/audit evidence.
9. Optionally run an interruptible read-only voice briefing (flag on + consent)
   and surface the barge-in.
10. Emit every operational signal through an :class:`~ccg.observability.InMemoryMetricSink`.

The chain logic is **not** re-implemented here: each scenario is driven through
the same production :class:`~ccg.gateway.AgentCoreGatewayClient` + faithful
AgentCore emulator, :class:`~ccg.api.ComplianceApi`,
:class:`~ccg.policy.PolicyActivationService`, and
:class:`~ccg.reconcile.ReconciliationService` that :mod:`ccg.demo` uses.

Nothing here authorizes a real mutation: the seed effector is a dry-run
recorder, the tool effector is a dry-run recorder, and the policy engine is the
in-memory faithful emulator. The live sandbox rehearsal (real AWS) is a separate
step gated on 0.2 and documented in ``docs/DEMO_REHEARSAL.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .api import AuthenticatedPrincipal, ComplianceApi
from .contracts import (
    Decision,
    DiscoverySignal,
    Finding,
    JsonValue,
    PolicyActivationRequest,
    RemediationCommand,
    Severity,
)
from .discovery import DiscoveryCoordinator
from .finding_rules import tool_for_rule
from .gateway import (
    AgentCoreGatewayClient,
    EffectivePolicyView,
    FaithfulAgentCoreEmulator,
    GatewayEnforcementMode,
)
from .observability import InMemoryMetricSink, Metric
from .policy import InMemoryPolicyControlPlane, PolicyActivationService
from .reconcile import ReconcileContext, ReconciliationService
from .seed import (
    DryRunSeedEffector,
    SeedScenario,
    default_scenarios,
    run_seed,
    validate_scenarios,
)
from .testing import (
    InMemoryDecisionEvidenceRepository,
    InMemoryFindingRepository,
    RecordingAuditSink,
    StaticDiscoverySource,
)
from .tools import default_tool_handlers
from .voice import MockNovaSonicTransport, ReadOnlyVoiceAdapter

CORRELATION_ID = "corr-rehearsal"
POLICY_VERSION = "v1"
PERMIT_SET_VERSION = "permits-v1"


@dataclass(frozen=True, slots=True)
class _ScenarioPlan:
    """How one seed scenario is driven through discovery + remediation.

    Maps a :class:`~ccg.seed.SeedScenario` to a discovery ``rule_id`` whose
    family resolves (via :func:`ccg.finding_rules.tool_for_rule`) to exactly the
    scenario's ``remediation_tool``, plus the bounded tool parameters the demo
    sends. ``noop`` marks the compliant-target scenario that must produce a safe
    no-op (ACC: allow + no-op), proving the chain works even when nothing needs
    changing.
    """

    rule_id: str
    title: str
    severity: Severity
    parameters: dict[str, JsonValue]
    noop: bool = False


# Per-scenario discovery/remediation plan. Every rule_id resolves to the
# scenario's own remediation_tool (asserted in _build_plans), so a command can
# never be routed to the wrong tool. The access-key scenario stays a safe
# dry-run no-op (confirm omitted); the tagging scenario is driven as an
# already-compliant no-op to exercise the allow+no-op path.
_SCENARIO_PLANS: dict[str, _ScenarioPlan] = {
    "unencrypted-s3": _ScenarioPlan(
        rule_id="s3-encryption-missing",
        title="S3 bucket is missing default encryption",
        severity=Severity.HIGH,
        parameters={"algorithm": "AES256"},
    ),
    "untagged-resource": _ScenarioPlan(
        rule_id="missing-tag-owner",
        title="Resource is missing the required Owner tag",
        severity=Severity.MEDIUM,
        # The seed target already carries CCGDemo/CCGSeed; asking to (re)apply
        # exactly those tags is an allow + safe no-op (nothing to change).
        parameters={"desired_tags": {"CCGDemo": "true", "CCGSeed": "true"}},
        noop=True,
    ),
    "old-test-access-key": _ScenarioPlan(
        rule_id="access-key-age",
        title="IAM access key is older than the rotation threshold",
        severity=Severity.MEDIUM,
        # No confirm=true -> the tool returns a dry-run NOOP plan, never rotating.
        parameters={"identity": "ccg-seed-test-user", "old_access_key_id": "AKIAEXAMPLESEED"},
        noop=True,
    ),
    "permissive-security-group": _ScenarioPlan(
        rule_id="security-group-open-ingress",
        title="Security group allows overly-permissive ingress",
        severity=Severity.HIGH,
        parameters={"rule_id": "ingress-0", "proposed_cidr": "10.0.0.0/16"},
    ),
}


@dataclass(frozen=True, slots=True)
class ScenarioEvidence:
    """Per-scenario evidence proving every invariant held for that finding."""

    scenario_id: str
    finding_id: str
    rule_id: str
    tool: str
    target_arn: str
    denied_before_activation: bool
    deny_reason: str
    allowed_after_activation: bool
    tool_outcome: str
    tool_executions: int
    idempotent_replay: bool
    final_status: str

    @property
    def ok(self) -> bool:
        """True only when every per-scenario demo invariant held."""
        return (
            self.denied_before_activation
            and self.allowed_after_activation
            and self.tool_outcome in {"APPLIED", "NOOP"}
            and self.tool_executions == (1 if self.tool_outcome == "APPLIED" else 0)
            and self.idempotent_replay
            and self.final_status == "RESOLVED"
        )


@dataclass(frozen=True, slots=True)
class VoiceEvidence:
    """Evidence from the optional read-only voice briefing."""

    requested: bool
    status: str
    interrupted: bool
    summary: str


@dataclass(slots=True)
class RehearsalResult:
    """Structured, printable evidence for the whole rehearsal."""

    scenarios: list[ScenarioEvidence] = field(default_factory=list)
    activation_outcome: str = "NONE"
    effective_policy_version: str = ""
    seed_plan: list[dict[str, JsonValue]] = field(default_factory=list)
    audit_event_types: tuple[str, ...] = ()
    metrics: dict[str, int] = field(default_factory=dict)
    voice: VoiceEvidence | None = None

    @property
    def ok(self) -> bool:
        """True only when every invariant across every scenario held."""
        return (
            bool(self.scenarios)
            and self.activation_outcome == "ACTIVATED"
            and all(scenario.ok for scenario in self.scenarios)
        )


def _build_plans(scenarios: tuple[SeedScenario, ...]) -> list[tuple[SeedScenario, _ScenarioPlan]]:
    """Pair each scenario with its plan and assert the tool routing is correct.

    The rule_id in every plan must resolve to the scenario's own
    ``remediation_tool``; a mismatch is a wiring bug, caught here before any
    chain runs rather than surfacing as a confusing API validation error.
    """
    plans: list[tuple[SeedScenario, _ScenarioPlan]] = []
    for scenario in scenarios:
        plan = _SCENARIO_PLANS.get(scenario.scenario_id)
        if plan is None:
            raise KeyError(f"no rehearsal plan for seed scenario '{scenario.scenario_id}'")
        resolved = tool_for_rule(plan.rule_id)
        if resolved != scenario.remediation_tool:
            raise ValueError(
                f"scenario '{scenario.scenario_id}' plan rule_id '{plan.rule_id}' resolves to "
                f"'{resolved}', not the scenario tool '{scenario.remediation_tool}'"
            )
        plans.append((scenario, plan))
    return plans


def _signal(scenario: SeedScenario, plan: _ScenarioPlan, detected_at: datetime) -> DiscoverySignal:
    return DiscoverySignal(
        signal_id=f"sig-{scenario.scenario_id}",
        rule_id=plan.rule_id,
        source="config",
        target=scenario.target,
        severity=plan.severity,
        title=plan.title,
        evidence_refs=(f"config:{scenario.scenario_id}",),
        detected_at=detected_at,
        correlation_id=CORRELATION_ID,
        attributes=dict(scenario.drift),
    )


def run_rehearsal(*, with_voice: bool = False) -> RehearsalResult:
    """Run the full offline demo rehearsal over the four seed scenarios.

    When ``with_voice`` is True, a flag-on, consent-granted read-only briefing is
    run with a one-shot barge-in to prove the interruptible path. Voice has no
    Gateway or tool access on any path.
    """
    scenarios = default_scenarios()
    validate_scenarios(scenarios)
    plans = _build_plans(scenarios)

    metrics = InMemoryMetricSink()
    audit = RecordingAuditSink()
    repo = InMemoryFindingRepository()
    evidence_repo = InMemoryDecisionEvidenceRepository()

    # 1. Seed the drift scenarios (dry-run: records a plan, mutates nothing).
    seed_effector = DryRunSeedEffector()
    run_seed(scenarios, seed_effector)

    # Shared control plane + Gateway wired exactly as the single-finding demo.
    control_plane = InMemoryPolicyControlPlane(policy_engine_id="rehearsal-engine")
    policy = PolicyActivationService(control_plane, audit)
    policy_view = EffectivePolicyView()
    handlers = default_tool_handlers()
    emulator = FaithfulAgentCoreEmulator(
        policy_view=policy_view,
        registered_tools=frozenset(handlers),
    )
    gateway = AgentCoreGatewayClient(emulator, audit, metrics=metrics)
    for name, handler in handlers.items():
        gateway.register(name, lambda request, _h=handler: _h(request))

    api = ComplianceApi(
        gateway=gateway, policy=policy, findings=repo, decision_evidence=evidence_repo
    )
    reconciler = ReconciliationService(repo, audit)
    admin = AuthenticatedPrincipal(actor="admin", roles=frozenset({"CCGAdmin", "CCGRemediator"}))

    # 2. Discovery over all seeded scenarios in one run (correlation propagated).
    t0 = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
    signals = [_signal(scenario, plan, t0 + timedelta(seconds=i)) for i, (scenario, plan) in enumerate(plans)]
    DiscoveryCoordinator(
        [StaticDiscoverySource("config", signals)], repo, audit, metrics=metrics
    ).run(CORRELATION_ID)

    findings_by_rule: dict[str, Finding] = {f.rule_id: f for f in repo.list_findings()}

    def command(scenario: SeedScenario, plan: _ScenarioPlan, finding: Finding) -> RemediationCommand:
        return RemediationCommand(
            request_id=f"req-{scenario.scenario_id}",
            correlation_id=CORRELATION_ID,
            actor="admin",
            finding_id=finding.finding_id,
            tool=scenario.remediation_tool,
            parameters=dict(plan.parameters),
            idempotency_key=f"idem-{scenario.scenario_id}",
            expected_finding_version=finding.revision,
        )

    # 3. Deny every scenario while permits are inactive.
    denials: dict[str, tuple[bool, str]] = {}
    for scenario, plan in plans:
        finding = findings_by_rule[plan.rule_id]
        denied = api.request_remediation(admin, command(scenario, plan, finding))
        denials[scenario.scenario_id] = (
            denied.decision.decision is Decision.DENY,
            denied.decision.reason,
        )

    # 4. One audited activation flips the whole permit set (versioned, server-confirmed).
    activation = api.change_policy_state(
        admin,
        PolicyActivationRequest(
            request_id="act-rehearsal-1",
            correlation_id=CORRELATION_ID,
            actor="admin",
            requested_version=POLICY_VERSION,
            expected_generation=policy.current_state().generation,
            reason="demo rehearsal: activate narrow permit set",
            activate=True,
        ),
    )
    effective_version = ""
    if activation.outcome.value == "ACTIVATED" and activation.state is not None:
        effective_version = activation.state.policy_set_version
        policy_view.propagate_activation(
            policy_set_version=activation.state.policy_set_version,
            enforcement_mode=GatewayEnforcementMode.ENFORCE,
        )

    # 5-7. For each scenario: allow (apply/no-op), idempotent replay, resolve.
    scenario_evidence: list[ScenarioEvidence] = []
    for scenario, plan in plans:
        finding = findings_by_rule[plan.rule_id]
        rec_ctx = ReconcileContext(
            actor="admin", correlation_id=CORRELATION_ID, request_id=f"req-{scenario.scenario_id}"
        )
        reconciler.mark_requested(finding.finding_id, rec_ctx)

        allowed = api.request_remediation(admin, command(scenario, plan, finding))
        tool_result = allowed.tool_result
        tool_executions = 1 if (tool_result and tool_result.changed) else 0
        if tool_result is not None:
            reconciler.record_tool_outcome(finding.finding_id, tool_result.outcome, rec_ctx)

        # 6. Idempotent replay: same idempotency key -> no second mutation.
        replay = api.request_remediation(admin, command(scenario, plan, finding))
        idempotent = bool(replay.tool_result and replay.tool_result.idempotency_replayed)

        denied_before, deny_reason = denials[scenario.scenario_id]
        scenario_evidence.append(
            ScenarioEvidence(
                scenario_id=scenario.scenario_id,
                finding_id=finding.finding_id,
                rule_id=plan.rule_id,
                tool=scenario.remediation_tool,
                target_arn=scenario.target.arn,
                denied_before_activation=denied_before,
                deny_reason=deny_reason,
                allowed_after_activation=allowed.decision.decision is Decision.ALLOW,
                tool_outcome=tool_result.outcome.value if tool_result else "NONE",
                tool_executions=tool_executions,
                idempotent_replay=idempotent,
                final_status="",  # filled after the confirming discovery read
            )
        )

    # 7. Rediscover with the drift gone (no signals) and reconcile to RESOLVED.
    DiscoveryCoordinator(
        [StaticDiscoverySource("config", [])], repo, audit, metrics=metrics
    ).run(f"{CORRELATION_ID}-2")
    resolved_evidence: list[ScenarioEvidence] = []
    for evidence in scenario_evidence:
        reconciler.confirm_from_discovery(
            evidence.finding_id,
            ReconcileContext(
                actor="discovery-agent",
                correlation_id=f"{CORRELATION_ID}-2",
                request_id=f"reconcile-{evidence.scenario_id}",
            ),
            drift_still_present=False,
        )
        final: Finding = repo.get(evidence.finding_id)  # type: ignore[assignment]
        resolved_evidence.append(
            ScenarioEvidence(
                scenario_id=evidence.scenario_id,
                finding_id=evidence.finding_id,
                rule_id=evidence.rule_id,
                tool=evidence.tool,
                target_arn=evidence.target_arn,
                denied_before_activation=evidence.denied_before_activation,
                deny_reason=evidence.deny_reason,
                allowed_after_activation=evidence.allowed_after_activation,
                tool_outcome=evidence.tool_outcome,
                tool_executions=evidence.tool_executions,
                idempotent_replay=evidence.idempotent_replay,
                final_status=final.status.value,
            )
        )

    # 9. Optional interruptible read-only voice briefing.
    voice_evidence: VoiceEvidence | None = None
    if with_voice:
        transport = MockNovaSonicTransport(interrupt=True)
        adapter = ReadOnlyVoiceAdapter(enabled=True, transport=transport, metrics=metrics)
        briefing = "; ".join(
            f"{ev.rule_id} on {ev.target_arn} is {ev.final_status}" for ev in resolved_evidence
        )
        result = adapter.brief(CORRELATION_ID, briefing, consent_granted=True)
        voice_evidence = VoiceEvidence(
            requested=True,
            status=result.status.value,
            interrupted=result.interrupted,
            summary=result.summary,
        )

    return RehearsalResult(
        scenarios=resolved_evidence,
        activation_outcome=activation.outcome.value,
        effective_policy_version=effective_version,
        seed_plan=list(seed_effector.planned),
        audit_event_types=tuple(event.event_type for event in audit.events),
        metrics=_metric_counts(metrics),
        voice=voice_evidence,
    )


def _metric_counts(metrics: InMemoryMetricSink) -> dict[str, int]:
    """Collect per-metric totals (summed across dimensions) for the report."""
    return {
        metric.value: metrics.total(metric)
        for metric in (
            Metric.DISCOVERY_RUN,
            Metric.GATEWAY_DENY,
            Metric.GATEWAY_ALLOW,
            Metric.ACTIVATION_SUCCESS,
            Metric.TOOL_APPLIED,
            Metric.TOOL_NOOP,
            Metric.TOOL_FAILED,
            Metric.VOICE_SESSION,
        )
        if metrics.total(metric) > 0
    }


def _format(result: RehearsalResult) -> str:
    lines = [
        "Continuous Compliance Guardian — offline demo rehearsal (task 6.4)",
        "=" * 66,
        f"seeded scenarios            : {len(result.seed_plan)} (dry-run; nothing mutated)",
        f"activation outcome          : {result.activation_outcome}"
        f" (effective version {result.effective_policy_version or 'n/a'})",
        "",
        "per-scenario evidence:",
    ]
    for ev in result.scenarios:
        lines.append(f"  - {ev.scenario_id} [{ev.tool}] -> {ev.target_arn}")
        lines.append(
            f"      denied-before={ev.denied_before_activation} ({ev.deny_reason}) | "
            f"allowed-after={ev.allowed_after_activation} | "
            f"outcome={ev.tool_outcome} execs={ev.tool_executions} | "
            f"idempotent={ev.idempotent_replay} | status={ev.final_status}"
        )
    lines.append("")
    lines.append("metrics:")
    for name, count in sorted(result.metrics.items()):
        lines.append(f"  {name:<34} {count}")
    if result.voice is not None:
        lines.append("")
        lines.append(
            f"voice briefing              : status={result.voice.status} "
            f"interrupted={result.voice.interrupted}"
        )
    lines.append("")
    lines.append(f"audit trail ({len(result.audit_event_types)} events):")
    lines.append("  " + " -> ".join(result.audit_event_types))
    return "\n".join(lines)


def main(*, with_voice: bool = True) -> int:
    result = run_rehearsal(with_voice=with_voice)
    print(_format(result))
    if not result.ok:
        print("\nREHEARSAL INVARIANTS FAILED", flush=True)
        return 1
    print("\nAll rehearsal invariants held across every seeded scenario.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
