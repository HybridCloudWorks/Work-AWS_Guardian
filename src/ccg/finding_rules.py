"""Finding rule_id -> tool mapping and per-tool bounded parameter allow-lists.

This module is the **API-layer** half of a defense-in-depth stack that keeps a
remediation command from mutating something inconsistent with the finding it
claims to fix (remediation items P0.4c / P0.4d).

Layering (each layer is independent and fail-closed on its own):

1. **API layer (this module + ``api.ComplianceApi.request_remediation``).**
   After the target is resolved server-side from the stored finding, the API
   cross-checks that ``command.tool`` is the one tool allowed for the finding's
   ``rule_id`` and that every supplied parameter is within a bounded allow-list
   for that tool. A command whose tool/params are inconsistent with the resolved
   finding is rejected *before* the Gateway is ever called. This stops a caller
   from, e.g., sending an ``access_key_rotation`` tool against an
   ``s3-encryption-missing`` finding, or smuggling an unexpected parameter.

2. **Tool layer (``tools.py``).** Each handler re-validates its own typed
   parameters and re-checks target safety (``CCGDemo=true`` / not
   ``Environment=prod``). It never trusts that the API or Gateway checked this.

3. **Cedar boundary (AgentCore Gateway / ``authz.py``).** The external policy
   engine makes the authoritative allow/deny decision. No application boolean or
   this mapping substitutes for it.

The rule_id matching is intentionally prefix/family based: discovery sources
emit rule identifiers like ``s3-encryption-missing`` or ``s3-encryption``; a
single family (``s3-encryption*``) maps to exactly one tool. The allow-list is a
*bounded set of permitted parameter names* per tool — unknown or dangerous
parameters are rejected at the API layer in addition to the tool layer.
"""

from __future__ import annotations

from collections.abc import Mapping

from .tools import (
    TOOL_ACCESS_KEY_ROTATION,
    TOOL_S3_ENCRYPTION,
    TOOL_SECURITY_GROUP,
    TOOL_TAGGING,
)


class FindingRuleError(ValueError):
    """Raised when a command's tool/params are inconsistent with the finding.

    Carries ``VALIDATION_ERROR`` semantics (see ``contracts.ErrorCode``): the
    request is malformed with respect to the resolved finding and must be
    rejected before any Gateway call.
    """


#: Ordered rule_id prefix -> tool mapping. The first matching prefix wins, so
#: more specific prefixes should precede more general ones. Discovery rule_ids
#: are matched case-insensitively against these family prefixes.
_RULE_PREFIX_TO_TOOL: tuple[tuple[str, str], ...] = (
    ("s3-encryption", TOOL_S3_ENCRYPTION),
    ("s3-default-encryption", TOOL_S3_ENCRYPTION),
    ("security-group", TOOL_SECURITY_GROUP),
    ("sg-", TOOL_SECURITY_GROUP),
    ("ingress", TOOL_SECURITY_GROUP),
    ("tagging", TOOL_TAGGING),
    ("tag-", TOOL_TAGGING),
    ("missing-tag", TOOL_TAGGING),
    ("required-tags", TOOL_TAGGING),
    ("access-key-age", TOOL_ACCESS_KEY_ROTATION),
    ("access-key", TOOL_ACCESS_KEY_ROTATION),
    ("iam-access-key", TOOL_ACCESS_KEY_ROTATION),
)


#: Bounded parameter allow-list per tool. A command parameter whose key is not
#: in the tool's set is rejected at the API layer. These mirror (a superset is
#: never allowed) the parameters each handler in ``tools.py`` actually reads, so
#: the API layer cannot be looser than the tool layer.
_TOOL_PARAM_ALLOWLIST: Mapping[str, frozenset[str]] = {
    TOOL_SECURITY_GROUP: frozenset({"rule_id", "proposed_cidr", "current_cidr"}),
    TOOL_S3_ENCRYPTION: frozenset(
        {"algorithm", "make_public", "currently_encrypted", "current_algorithm"}
    ),
    TOOL_TAGGING: frozenset({"desired_tags"}),
    TOOL_ACCESS_KEY_ROTATION: frozenset(
        {"identity", "old_access_key_id", "confirm"}
    ),
}


def tool_for_rule(rule_id: str) -> str:
    """Return the single tool allowed to remediate ``rule_id``.

    Raises :class:`FindingRuleError` if the rule family has no mapped tool, so a
    finding with no sanctioned remediation can never be acted on by guessing a
    tool.
    """
    normalized = rule_id.strip().casefold()
    if not normalized:
        raise FindingRuleError("finding rule_id is empty; no tool can be derived")
    for prefix, tool in _RULE_PREFIX_TO_TOOL:
        if normalized.startswith(prefix):
            return tool
    raise FindingRuleError(f"no remediation tool is mapped for rule_id '{rule_id}'")


def validate_command_against_rule(
    rule_id: str,
    tool: str,
    parameters: Mapping[str, object],
) -> None:
    """Reject a command whose tool/params are inconsistent with the finding.

    Enforces P0.4c/d at the API layer:

    * ``tool`` must be exactly the tool mapped to the finding's ``rule_id``.
    * every key in ``parameters`` must be in that tool's bounded allow-list.

    Raises :class:`FindingRuleError` (``VALIDATION_ERROR`` semantics) on any
    mismatch. Does not mutate anything and makes no Gateway call.
    """
    expected_tool = tool_for_rule(rule_id)
    if tool != expected_tool:
        raise FindingRuleError(
            f"tool '{tool}' is not valid for finding rule_id '{rule_id}'; "
            f"expected '{expected_tool}'"
        )
    allowed = _TOOL_PARAM_ALLOWLIST.get(expected_tool, frozenset())
    unexpected = sorted(key for key in parameters if key not in allowed)
    if unexpected:
        raise FindingRuleError(
            f"parameters {unexpected} are not permitted for tool '{expected_tool}'"
        )
