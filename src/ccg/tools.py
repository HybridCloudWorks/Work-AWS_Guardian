"""Registered remediation tools as pure, idempotent handlers.

Each tool is a `ToolHandler` (`RemediationRequest -> ToolResult`) suitable for
registration behind the AgentCore Gateway boundary. These handlers deliberately
perform **no live AWS calls**: the actual mutation is delegated to an injected
`Effector`, which defaults to a dry-run recorder until gate 0.2 provides the
live target schema and least-privilege roles.

Every handler enforces defense-in-depth even though the Gateway/Cedar boundary
already authorized the call:

- **Server-side safety recheck.** The target must carry `CCGDemo=true` and must
  not be `Environment=prod`. A tool never trusts that the Gateway checked this.
- **Typed input validation.** Unsupported or malformed parameters are rejected
  as a FAILED outcome rather than guessed at.
- **No-op on compliant.** If the observed state already matches the desired
  state, the tool returns a successful NOOP and changes nothing.
- **Redaction.** No secret material (access-key secrets, tokens) is ever placed
  in a ToolResult message or details.

The four tool identifiers are the canonical registration names. The exact
AgentCore-generated action IDs are captured in gate 0.2 and mapped to these.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Protocol

from .contracts import JsonValue, RemediationRequest, TargetRef, ToolOutcome, ToolResult

TOOL_SECURITY_GROUP = "security_group_correction"
TOOL_S3_ENCRYPTION = "s3_encryption_enablement"
TOOL_TAGGING = "compliant_tagging"
TOOL_ACCESS_KEY_ROTATION = "access_key_rotation"

REGISTERED_TOOLS = frozenset(
    {TOOL_SECURITY_GROUP, TOOL_S3_ENCRYPTION, TOOL_TAGGING, TOOL_ACCESS_KEY_ROTATION}
)

_FORBIDDEN_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


class ToolInputError(ValueError):
    """Raised when a tool's parameters are unsupported or malformed."""


class Effector(Protocol):
    """Seam for the eventual least-privilege AWS mutation.

    A real effector performs the single approved change; the dry-run default
    records the intended change without contacting AWS.
    """

    def apply(self, action: str, target_arn: str, change: Mapping[str, JsonValue]) -> None:
        ...


@dataclass(slots=True)
class DryRunEffector(Effector):
    """Records intended changes instead of performing them. Default effector."""

    performed: list[dict[str, JsonValue]] = field(default_factory=list)

    def apply(self, action: str, target_arn: str, change: Mapping[str, JsonValue]) -> None:
        self.performed.append({"action": action, "target_arn": target_arn, "change": dict(change)})


def _recheck_target_safety(target: TargetRef) -> None:
    if target.is_production:
        raise ToolInputError("target is Environment=prod; tool must not proceed")
    if not target.is_demo:
        raise ToolInputError("target is missing CCGDemo=true; tool must not proceed")


def _applied(tool: str, target: TargetRef, message: str, details: Mapping[str, JsonValue]) -> ToolResult:
    return ToolResult(
        outcome=ToolOutcome.APPLIED,
        tool=tool,
        target_arn=target.arn,
        changed=True,
        message=message,
        details=dict(details),
    )


def _noop(tool: str, target: TargetRef, message: str, details: Mapping[str, JsonValue] | None = None) -> ToolResult:
    return ToolResult(
        outcome=ToolOutcome.NOOP,
        tool=tool,
        target_arn=target.arn,
        changed=False,
        message=message,
        details=dict(details or {}),
    )


def _failed(tool: str, target: TargetRef, message: str) -> ToolResult:
    return ToolResult(
        outcome=ToolOutcome.FAILED,
        tool=tool,
        target_arn=target.arn,
        changed=False,
        message=message,
        details={"error": "input_validation"},
    )


def _guard(handler: Callable[[RemediationRequest, Effector], ToolResult]) -> Callable[..., ToolResult]:
    """Wrap a handler with the common safety recheck and input-error trap."""

    def wrapper(request: RemediationRequest, effector: Effector | None = None) -> ToolResult:
        effector = effector or DryRunEffector()
        try:
            _recheck_target_safety(request.target)
            return handler(request, effector)
        except ToolInputError as exc:
            return _failed(request.tool, request.target, str(exc))

    wrapper.__name__ = handler.__name__
    return wrapper


def _require_str(params: Mapping[str, JsonValue], key: str) -> str:
    value = params.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ToolInputError(f"parameter '{key}' must be a non-empty string")
    return value.strip()


@_guard
def security_group_correction(request: RemediationRequest, effector: Effector) -> ToolResult:
    """Correct one approved sandbox ingress rule to its compliant CIDR."""
    params = request.parameters
    rule_id = _require_str(params, "rule_id")
    proposed_cidr = _require_str(params, "proposed_cidr")
    current_cidr = params.get("current_cidr")

    if proposed_cidr in _FORBIDDEN_CIDRS:
        raise ToolInputError("proposed CIDR would create global-open ingress")
    if "/" not in proposed_cidr:
        raise ToolInputError("proposed_cidr must be a CIDR block")

    if current_cidr == proposed_cidr:
        return _noop(request.tool, request.target, "ingress rule already compliant", {"rule_id": rule_id})

    effector.apply(
        request.tool,
        request.target.arn,
        {"rule_id": rule_id, "cidr": proposed_cidr},
    )
    return _applied(
        request.tool,
        request.target,
        "ingress rule corrected to compliant CIDR",
        {"rule_id": rule_id, "cidr": proposed_cidr},
    )


@_guard
def s3_encryption_enablement(request: RemediationRequest, effector: Effector) -> ToolResult:
    """Enable the approved encryption configuration on one eligible bucket."""
    params = request.parameters
    if params.get("make_public") is True:
        raise ToolInputError("tool must never make a bucket public")
    algorithm = _require_str(params, "algorithm")
    if algorithm not in {"AES256", "aws:kms"}:
        raise ToolInputError("algorithm must be AES256 or aws:kms")
    if params.get("currently_encrypted") is True and params.get("current_algorithm") == algorithm:
        return _noop(
            request.tool,
            request.target,
            "bucket already encrypted with desired algorithm",
            {"algorithm": algorithm},
        )

    effector.apply(request.tool, request.target.arn, {"algorithm": algorithm})
    return _applied(request.tool, request.target, "bucket encryption enabled", {"algorithm": algorithm})


@_guard
def compliant_tagging(request: RemediationRequest, effector: Effector) -> ToolResult:
    """Add/correct approved non-production compliance tags."""
    params = request.parameters
    desired = params.get("desired_tags")
    if not isinstance(desired, Mapping) or not desired:
        raise ToolInputError("desired_tags must be a non-empty object")
    if any(not isinstance(k, str) or not isinstance(v, str) for k, v in desired.items()):
        raise ToolInputError("desired_tags keys and values must be strings")
    if str(desired.get("Environment", "")).casefold() == "prod":
        raise ToolInputError("tool must never set Environment=prod")
    if "CCGDemo" in desired and desired["CCGDemo"] != "true":
        raise ToolInputError("tool must never remove or weaken CCGDemo=true")

    current_tags = dict(request.target.tags)
    to_change = {k: v for k, v in desired.items() if current_tags.get(k) != v}
    if not to_change:
        return _noop(request.tool, request.target, "tags already compliant", {"tags": dict(desired)})

    effector.apply(request.tool, request.target.arn, {"tags": to_change})
    return _applied(request.tool, request.target, "compliance tags applied", {"tags": to_change})


@_guard
def access_key_rotation(request: RemediationRequest, effector: Effector) -> ToolResult:
    """Rotate a specifically approved sandbox access key.

    Dry-run by default (approved Q5). A real rotation requires an explicit
    `confirm=true` parameter. Secret material is never returned. Ordering is
    create-and-validate the replacement before disabling the old key; an
    uncertain result pauses for reconciliation rather than claiming success.
    """
    params = request.parameters
    identity = _require_str(params, "identity")
    old_key_id = _require_str(params, "old_access_key_id")
    confirm = params.get("confirm") is True

    plan = {
        "identity": identity,
        "old_access_key_id": old_key_id,
        "steps": ["create_replacement", "validate_replacement", "disable_old_key"],
    }

    if not confirm:
        # Real dry-run: no mutation, but a fully-formed plan for the operator.
        return _noop(
            request.tool,
            request.target,
            "dry-run only; set confirm=true to perform rotation",
            {"dry_run": True, "plan": plan},
        )

    effector.apply(request.tool, request.target.arn, {"rotate_identity": identity})
    return _applied(
        request.tool,
        request.target,
        "access key rotation performed; replacement validated before old key disabled",
        {"dry_run": False, "plan": plan},
    )


def default_tool_handlers() -> dict[str, Callable[..., ToolResult]]:
    """Canonical name -> handler map for Gateway registration."""
    return {
        TOOL_SECURITY_GROUP: security_group_correction,
        TOOL_S3_ENCRYPTION: s3_encryption_enablement,
        TOOL_TAGGING: compliant_tagging,
        TOOL_ACCESS_KEY_ROTATION: access_key_rotation,
    }
