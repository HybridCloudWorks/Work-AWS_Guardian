"""Reversible, sandbox-only drift seeding model (no AWS SDK).

This module is the reviewable core behind the ``scripts/seed_drift.py`` CLI. It
defines the drift scenarios the demo relies on, a typed effector seam, a
dry-run recorder, and the hard target-safety guard. It deliberately contains
**no boto3 / AWS SDK calls**: the actual mutation is delegated to an injected
``SeedEffector`` so the committed default can only ever record a plan. A real
boto3-backed effector may be substituted later, and only under the live
sandbox gate.

Safety invariants enforced here (independent of the CLI gate):

- **Never prod, always demo.** Every seeded or cleaned target must carry
  ``CCGDemo=true`` and must never carry ``Environment=prod``. The guard reuses
  ``TargetRef.is_demo`` / ``TargetRef.is_production`` from contracts and runs
  for both dry-run and apply.
- **Bounded cleanup.** Cleanup only ever touches resources that carry this
  script's own seed marker (``CCGSeed=true``) *and* the known name prefix. A
  target without the marker is refused, so the workflow can never delete a
  resource it did not create.
- **Real dry-run.** The default effector records intended operations and
  performs none; ``applied`` is always empty for a dry run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Protocol

from .contracts import JsonValue, TargetRef
from .observability import Metric, MetricSink, NullMetricSink

# Marker + naming convention identifying resources this script created. Cleanup
# is bounded to targets that carry BOTH the marker tag and the name prefix.
SEED_MARKER_TAG = "CCGSeed"
SEED_MARKER_VALUE = "true"
SEED_NAME_PREFIX = "ccg-seed-"

# Operation discriminants recorded by the dry-run effector.
OP_CREATE = "CREATE"
OP_DELETE = "DELETE"


class SeedSafetyError(ValueError):
    """Raised when a seed/cleanup target violates a hard safety invariant."""


@dataclass(frozen=True, slots=True)
class SeedScenario:
    """One drift scenario to seed, as typed data (no side effects).

    ``target`` must be demo-tagged and seed-marked; ``drift`` describes the
    intentional misconfiguration the discovery path should later detect, and
    ``remediation_tool`` names the narrow tool that would correct it.
    """

    scenario_id: str
    description: str
    target: TargetRef
    drift: Mapping[str, JsonValue]
    remediation_tool: str

    def __post_init__(self) -> None:
        if not self.scenario_id.strip():
            raise ValueError("scenario_id must be a non-empty string")
        if not self.description.strip():
            raise ValueError("description must be a non-empty string")
        object.__setattr__(self, "drift", dict(self.drift))


class SeedEffector(Protocol):
    """Seam for the eventual least-privilege sandbox mutation.

    A real effector performs the single approved create/delete; the dry-run
    default records the intended operation without contacting AWS.
    """

    def create(self, scenario_id: str, target: TargetRef, drift: Mapping[str, JsonValue]) -> None:
        ...

    def delete(self, target: TargetRef) -> None:
        ...


@dataclass(slots=True)
class DryRunSeedEffector(SeedEffector):
    """Records intended create/delete operations instead of performing them.

    This is the default effector. ``applied`` stays empty for a dry run; a real
    effector substituted under the live sandbox gate is what would populate an
    equivalent record of performed mutations.
    """

    planned: list[dict[str, JsonValue]] = field(default_factory=list)
    applied: list[dict[str, JsonValue]] = field(default_factory=list)

    def create(self, scenario_id: str, target: TargetRef, drift: Mapping[str, JsonValue]) -> None:
        self.planned.append(
            {
                "op": OP_CREATE,
                "scenario_id": scenario_id,
                "target_arn": target.arn,
                "resource_type": target.resource_type,
                "drift": dict(drift),
            }
        )

    def delete(self, target: TargetRef) -> None:
        self.planned.append(
            {
                "op": OP_DELETE,
                "target_arn": target.arn,
                "resource_type": target.resource_type,
            }
        )


def guard_target(target: TargetRef) -> None:
    """Hard refusal for any unsafe seed/cleanup target.

    Runs for both dry-run and apply. A target that is ``Environment=prod`` or
    is missing ``CCGDemo=true`` must never be seeded or deleted.
    """
    if target.is_production:
        raise SeedSafetyError(f"refusing target '{target.arn}': Environment=prod")
    if not target.is_demo:
        raise SeedSafetyError(f"refusing target '{target.arn}': missing CCGDemo=true")


def is_self_created(target: TargetRef) -> bool:
    """True only when a target carries this script's own seed convention.

    Cleanup is bounded to targets that carry the ``CCGSeed=true`` marker tag AND
    whose ARN contains the known name prefix. Both are required so cleanup can
    never remove a resource the script did not create.
    """
    marked = target.tags.get(SEED_MARKER_TAG) == SEED_MARKER_VALUE
    named = SEED_NAME_PREFIX in target.arn
    return marked and named


def guard_cleanup_target(target: TargetRef) -> None:
    """Hard refusal for any cleanup target not provably self-created."""
    guard_target(target)
    if not is_self_created(target):
        raise SeedSafetyError(
            f"refusing to delete '{target.arn}': not tagged {SEED_MARKER_TAG}={SEED_MARKER_VALUE} "
            f"with name prefix '{SEED_NAME_PREFIX}' (only self-created seed resources may be removed)"
        )


def _demo_target(arn: str, resource_type: str, extra_tags: Mapping[str, str] | None = None) -> TargetRef:
    tags: dict[str, str] = {"CCGDemo": "true", SEED_MARKER_TAG: SEED_MARKER_VALUE}
    if extra_tags:
        tags.update(extra_tags)
    return TargetRef(arn=arn, resource_type=resource_type, tags=tags)


def default_scenarios() -> tuple[SeedScenario, ...]:
    """The four demo drift scenarios, all demo-tagged and seed-marked.

    Mirrors the stub's intent: unencrypted S3, an untagged resource, an old
    test access key, and an overly-permissive security group. Every target is
    ``CCGDemo=true`` and ``CCGSeed=true`` and none is ``Environment=prod``.
    """
    return (
        SeedScenario(
            scenario_id="unencrypted-s3",
            description="S3 bucket with default encryption disabled",
            target=_demo_target(
                f"arn:aws:s3:::{SEED_NAME_PREFIX}unencrypted-bucket",
                "s3_bucket",
            ),
            drift={"encryption": "disabled"},
            remediation_tool="s3_encryption_enablement",
        ),
        SeedScenario(
            scenario_id="untagged-resource",
            description="Resource missing required Owner compliance tag",
            target=_demo_target(
                f"arn:aws:s3:::{SEED_NAME_PREFIX}untagged-bucket",
                "s3_bucket",
            ),
            drift={"missing_tags": ["Owner"]},
            remediation_tool="compliant_tagging",
        ),
        SeedScenario(
            scenario_id="old-test-access-key",
            description="IAM test user with an aged access key eligible for rotation",
            target=_demo_target(
                f"arn:aws:iam::000000000000:user/{SEED_NAME_PREFIX}test-user",
                "iam_user",
            ),
            drift={"access_key_age_days": 400},
            remediation_tool="access_key_rotation",
        ),
        SeedScenario(
            scenario_id="permissive-security-group",
            description="Security group with an overly-permissive ingress rule",
            target=_demo_target(
                f"arn:aws:ec2:us-east-1:000000000000:security-group/{SEED_NAME_PREFIX}open-sg",
                "security_group",
            ),
            drift={"ingress_cidr": "0.0.0.0/0", "rule_id": "ingress-0"},
            remediation_tool="security_group_correction",
        ),
    )


def validate_scenarios(scenarios: tuple[SeedScenario, ...]) -> None:
    """Validate scenario count and per-target safety.

    There must be 3-5 scenarios (demo bound) and every target must pass both the
    general safety guard and the self-created convention so cleanup can later
    find exactly these resources.
    """
    if not 3 <= len(scenarios) <= 5:
        raise SeedSafetyError(f"expected 3-5 scenarios, got {len(scenarios)}")
    seen: set[str] = set()
    for scenario in scenarios:
        if scenario.scenario_id in seen:
            raise SeedSafetyError(f"duplicate scenario_id '{scenario.scenario_id}'")
        seen.add(scenario.scenario_id)
        guard_target(scenario.target)
        if not is_self_created(scenario.target):
            raise SeedSafetyError(
                f"scenario '{scenario.scenario_id}' target is not seed-marked for later cleanup"
            )


def plan_seed(scenarios: tuple[SeedScenario, ...]) -> list[dict[str, JsonValue]]:
    """Return the human-readable create plan without touching any effector."""
    return [
        {
            "op": OP_CREATE,
            "scenario_id": scenario.scenario_id,
            "description": scenario.description,
            "target_arn": scenario.target.arn,
            "resource_type": scenario.target.resource_type,
            "drift": dict(scenario.drift),
        }
        for scenario in scenarios
    ]


def plan_cleanup(scenarios: tuple[SeedScenario, ...]) -> list[dict[str, JsonValue]]:
    """Return the human-readable delete plan for self-created seed resources."""
    return [
        {
            "op": OP_DELETE,
            "scenario_id": scenario.scenario_id,
            "target_arn": scenario.target.arn,
            "resource_type": scenario.target.resource_type,
        }
        for scenario in scenarios
    ]


def run_seed(scenarios: tuple[SeedScenario, ...], effector: SeedEffector) -> None:
    """Guard then create every scenario through the effector.

    Guards run before any effector call; a single unsafe target aborts the whole
    run before any mutation.
    """
    validate_scenarios(scenarios)
    for scenario in scenarios:
        guard_target(scenario.target)
        effector.create(scenario.scenario_id, scenario.target, scenario.drift)


def run_cleanup(
    scenarios: tuple[SeedScenario, ...],
    effector: SeedEffector,
    metrics: MetricSink | None = None,
) -> None:
    """Guard then delete every self-created scenario target through the effector.

    Emits ``CLEANUP_RUN`` once the whole bounded cleanup completes, or
    ``CLEANUP_FAILURE`` if any target is refused or the effector raises. The
    dimension is a stable ``resource_type`` (never an ARN or secret).
    """
    sink = metrics or NullMetricSink()
    try:
        for scenario in scenarios:
            guard_cleanup_target(scenario.target)
            effector.delete(scenario.target)
    except Exception:
        sink.increment(Metric.CLEANUP_FAILURE)
        raise
    sink.increment(Metric.CLEANUP_RUN, value=len(scenarios))
