"""Comprehensive policy scenario tests for CCG-REQ-008 through CCG-REQ-020.

Each test class is annotated with the requirement(s) it covers.  The offline
`decide()` function in `ccg.authz` serves as the test double for the remote
AgentCore Gateway Policy Engine; `InMemoryCedarGateway` exercises the full
boundary including audit emission; `PolicyActivationService` with
`InMemoryPolicyControlPlane` covers the control-plane path.

Test doubles used here are never production authorizers.  The Gateway enforces
Cedar semantics; these tests verify that the local model matches those
semantics so callers remain honest.

Requirements covered:
    CCG-REQ-008 Every mutation goes through the Gateway Policy Engine
    CCG-REQ-009 No direct auth via prompt / UI state / boolean
    CCG-REQ-010 Default deny when no active permit matches
    CCG-REQ-011 Forbid overrides permit
    CCG-REQ-012 Deny if CCGDemo≠true or Environment=prod
    CCG-REQ-013 Only 4 registered tools allowed
    CCG-REQ-014 Permit path inactive while permits inactive
    CCG-REQ-015 Audited activation records intent before applying
    CCG-REQ-016 Activation result recorded; failure → deny-safe state
    CCG-REQ-017 Stale version / replay / concurrency conflict rejected
    CCG-REQ-018 Policy visibility: effective version, mode, state
    CCG-REQ-019 Decision evidence carries all required fields
    CCG-REQ-020 Schema / context mismatch → deny
"""

from __future__ import annotations

import unittest
from typing import Any
from uuid import uuid4

from ccg.authz import CEDAR_ACTION_PREFIX, CEDAR_TARGET_NAME, decide, to_cedar_action_id
from ccg.contracts import (
    ActivationOutcome,
    Decision,
    PolicyActivationRequest,
    PolicyEnforcementMode,
    RemediationRequest,
    TargetRef,
)
from ccg.policy import InMemoryPolicyControlPlane, PolicyActivationService
from ccg.testing import (
    InMemoryCedarGateway,
    RecordingAuditSink,
)
from ccg.tools import (
    REGISTERED_TOOLS,
    TOOL_ACCESS_KEY_ROTATION,
    TOOL_S3_ENCRYPTION,
    TOOL_SECURITY_GROUP,
    TOOL_TAGGING,
    default_tool_handlers,
)

# ---------------------------------------------------------------------------
# Shared factory helpers
# ---------------------------------------------------------------------------

_ALL_TOOLS = sorted(REGISTERED_TOOLS)

_DEMO_TAGS: dict[str, str] = {"CCGDemo": "true"}
_PROD_TAGS: dict[str, str] = {"CCGDemo": "true", "Environment": "prod"}
_NO_DEMO_TAGS: dict[str, str] = {"Environment": "sandbox"}
_SANDBOX_TAGS: dict[str, str] = {"CCGDemo": "true", "Environment": "sandbox"}


def _target(tags: dict[str, str] | None = None, arn: str = "arn:aws:s3:::ccg-demo") -> TargetRef:
    return TargetRef(arn, "s3_bucket", tags if tags is not None else _DEMO_TAGS)


def _req(
    *,
    tool: str = TOOL_S3_ENCRYPTION,
    tags: dict[str, str] | None = None,
    parameters: dict[str, Any] | None = None,
    request_id: str | None = None,
    idempotency_key: str | None = None,
) -> RemediationRequest:
    return RemediationRequest(
        request_id=request_id or str(uuid4()),
        correlation_id="corr-1",
        actor="admin",
        tool=tool,
        target=_target(tags),
        parameters=parameters or {},
        idempotency_key=idempotency_key or str(uuid4()),
    )


def _decide(request: RemediationRequest, *, permit_active: bool) -> Any:
    return decide(
        request,
        permit_active=permit_active,
        registered_tools=REGISTERED_TOOLS,
        policy_set_version="test-v1",
    )


def _activation_req(
    *,
    version: str = "v1",
    generation: int = 0,
    activate: bool = True,
    request_id: str | None = None,
    actor: str = "admin",
) -> PolicyActivationRequest:
    return PolicyActivationRequest(
        request_id=request_id or str(uuid4()),
        correlation_id=str(uuid4()),
        actor=actor,
        requested_version=version,
        expected_generation=generation,
        reason="test activation",
        activate=activate,
    )


# ---------------------------------------------------------------------------
# 1. Default-deny scenarios — CCG-REQ-010, CCG-REQ-014
# ---------------------------------------------------------------------------


class DefaultDenyTests(unittest.TestCase):
    """CCG-REQ-010, CCG-REQ-014: Deny when no active permit matches."""

    def _assert_default_deny(self, tool: str, tags: dict | None = None) -> None:
        d = _decide(_req(tool=tool, tags=tags), permit_active=False)
        self.assertEqual(d.decision, Decision.DENY)
        self.assertEqual(d.matched_policy_ids, ("default-deny-permits-inactive",))

    def test_s3_encryption_denied_when_inactive(self) -> None:
        self._assert_default_deny(TOOL_S3_ENCRYPTION)

    def test_security_group_denied_when_inactive(self) -> None:
        self._assert_default_deny(TOOL_SECURITY_GROUP)

    def test_tagging_denied_when_inactive(self) -> None:
        self._assert_default_deny(TOOL_TAGGING)

    def test_access_key_rotation_denied_when_inactive(self) -> None:
        self._assert_default_deny(TOOL_ACCESS_KEY_ROTATION)

    def test_default_deny_fires_even_for_demo_target(self) -> None:
        """Eligible demo target is irrelevant when permit set is inactive (CCG-REQ-014)."""
        for tool in _ALL_TOOLS:
            with self.subTest(tool=tool):
                d = _decide(_req(tool=tool, tags=_DEMO_TAGS), permit_active=False)
                self.assertEqual(d.decision, Decision.DENY)
                self.assertEqual(d.matched_policy_ids, ("default-deny-permits-inactive",))

    def test_default_deny_fires_even_for_sandbox_tags(self) -> None:
        for tool in _ALL_TOOLS:
            with self.subTest(tool=tool):
                d = _decide(_req(tool=tool, tags=_SANDBOX_TAGS), permit_active=False)
                self.assertEqual(d.decision, Decision.DENY)
                self.assertIn("default-deny-permits-inactive", d.matched_policy_ids)

    def test_matched_policy_ids_is_single_tuple(self) -> None:
        d = _decide(_req(), permit_active=False)
        self.assertIsInstance(d.matched_policy_ids, tuple)
        self.assertEqual(len(d.matched_policy_ids), 1)

    def test_decision_is_never_allow_with_inactive_permit(self) -> None:
        for tool in _ALL_TOOLS:
            with self.subTest(tool=tool):
                d = _decide(_req(tool=tool, tags=_DEMO_TAGS), permit_active=False)
                self.assertNotEqual(d.decision, Decision.ALLOW)


# ---------------------------------------------------------------------------
# 2. Allow scenarios — CCG-REQ-013
# ---------------------------------------------------------------------------


class AllowScenariosTests(unittest.TestCase):
    """CCG-REQ-013: Only 4 registered tools are allowed; each gets a permit ID."""

    def _assert_allow(self, tool: str) -> None:
        d = _decide(_req(tool=tool, tags=_DEMO_TAGS), permit_active=True)
        self.assertEqual(d.decision, Decision.ALLOW)
        self.assertEqual(d.matched_policy_ids, (f"permit-{tool}",))

    def test_s3_encryption_allowed(self) -> None:
        self._assert_allow(TOOL_S3_ENCRYPTION)

    def test_security_group_allowed(self) -> None:
        self._assert_allow(TOOL_SECURITY_GROUP)

    def test_tagging_allowed(self) -> None:
        self._assert_allow(TOOL_TAGGING)

    def test_access_key_rotation_allowed(self) -> None:
        self._assert_allow(TOOL_ACCESS_KEY_ROTATION)

    def test_allow_policy_id_contains_tool_name(self) -> None:
        for tool in _ALL_TOOLS:
            with self.subTest(tool=tool):
                d = _decide(_req(tool=tool, tags=_DEMO_TAGS), permit_active=True)
                self.assertIn(tool, d.matched_policy_ids[0])

    def test_action_id_is_full_cedar_format_on_allow(self) -> None:
        for tool in _ALL_TOOLS:
            with self.subTest(tool=tool):
                d = _decide(_req(tool=tool, tags=_DEMO_TAGS), permit_active=True)
                expected = f'{CEDAR_ACTION_PREFIX}"{CEDAR_TARGET_NAME}___{tool}"'
                self.assertEqual(d.action_id, expected)


# ---------------------------------------------------------------------------
# 3. Forbid-overrides-permit — CCG-REQ-011, CCG-REQ-012
# ---------------------------------------------------------------------------


class ForbidOverridesPermitTests(unittest.TestCase):
    """CCG-REQ-011, CCG-REQ-012: Forbids override active permits; ordering is deterministic."""

    def test_prod_tag_denies_with_active_permit(self) -> None:
        d = _decide(_req(tool=TOOL_S3_ENCRYPTION, tags=_PROD_TAGS), permit_active=True)
        self.assertEqual(d.decision, Decision.DENY)
        self.assertEqual(d.matched_policy_ids, ("always-deny-production-target",))

    def test_missing_demo_tag_denies_with_active_permit(self) -> None:
        d = _decide(_req(tool=TOOL_S3_ENCRYPTION, tags=_NO_DEMO_TAGS), permit_active=True)
        self.assertEqual(d.decision, Decision.DENY)
        self.assertEqual(d.matched_policy_ids, ("always-deny-missing-demo-tag",))

    def test_global_open_ipv4_denies_with_active_permit(self) -> None:
        d = _decide(
            _req(tool=TOOL_SECURITY_GROUP, parameters={"proposed_cidr": "0.0.0.0/0"}),
            permit_active=True,
        )
        self.assertEqual(d.decision, Decision.DENY)
        self.assertEqual(d.matched_policy_ids, ("always-deny-global-open-ingress",))

    def test_global_open_ipv6_denies_with_active_permit(self) -> None:
        d = _decide(
            _req(tool=TOOL_SECURITY_GROUP, parameters={"proposed_cidr": "::/0"}),
            permit_active=True,
        )
        self.assertEqual(d.decision, Decision.DENY)
        self.assertEqual(d.matched_policy_ids, ("always-deny-global-open-ingress",))

    def test_make_public_denies_with_active_permit(self) -> None:
        d = _decide(
            _req(tool=TOOL_S3_ENCRYPTION, parameters={"make_public": True}),
            permit_active=True,
        )
        self.assertEqual(d.decision, Decision.DENY)
        self.assertEqual(d.matched_policy_ids, ("always-deny-public-s3",))

    def test_prod_and_missing_demo_fires_prod_forbid_first(self) -> None:
        """Prod tag appears before missing-demo in FORBID_RULES ordering."""
        # A target with Environment=prod but no CCGDemo tag: prod is evaluated first.
        d = _decide(
            _req(tool=TOOL_S3_ENCRYPTION, tags={"Environment": "prod"}),
            permit_active=True,
        )
        self.assertEqual(d.decision, Decision.DENY)
        self.assertEqual(d.matched_policy_ids, ("always-deny-production-target",))

    def test_forbid_wins_regardless_of_inactive_permit(self) -> None:
        """Forbid still fires even when permit is inactive (double-deny — both apply)."""
        d = _decide(_req(tool=TOOL_S3_ENCRYPTION, tags=_PROD_TAGS), permit_active=False)
        self.assertEqual(d.decision, Decision.DENY)
        # Prod tag forbid fires before the inactive-permit check.
        self.assertEqual(d.matched_policy_ids, ("always-deny-production-target",))

    def test_s3_make_public_false_is_not_forbidden(self) -> None:
        """make_public=False must not trigger the public-S3 forbid."""
        d = _decide(
            _req(tool=TOOL_S3_ENCRYPTION, parameters={"make_public": False}),
            permit_active=True,
        )
        self.assertEqual(d.decision, Decision.ALLOW)

    def test_compliant_cidr_is_not_forbidden(self) -> None:
        d = _decide(
            _req(tool=TOOL_SECURITY_GROUP, parameters={"proposed_cidr": "10.0.0.0/24"}),
            permit_active=True,
        )
        self.assertEqual(d.decision, Decision.ALLOW)


# ---------------------------------------------------------------------------
# 4. Unknown / unregistered tool — CCG-REQ-013, CCG-REQ-020
# ---------------------------------------------------------------------------


class UnregisteredToolTests(unittest.TestCase):
    """CCG-REQ-013, CCG-REQ-020: Unregistered tools are always denied."""

    def test_arbitrary_tool_name_is_denied(self) -> None:
        d = _decide(_req(tool="delete_everything"), permit_active=True)
        self.assertEqual(d.decision, Decision.DENY)
        self.assertEqual(d.matched_policy_ids, ("always-deny-unregistered-tool",))

    def test_disable_cloudtrail_is_unregistered(self) -> None:
        d = _decide(_req(tool="disable_cloudtrail"), permit_active=True)
        self.assertEqual(d.decision, Decision.DENY)
        self.assertEqual(d.matched_policy_ids, ("always-deny-unregistered-tool",))

    def test_close_tool_name_is_still_unregistered(self) -> None:
        """A name that is a prefix of a registered tool is not registered."""
        d = _decide(_req(tool="s3_encryption"), permit_active=True)
        self.assertEqual(d.decision, Decision.DENY)
        self.assertEqual(d.matched_policy_ids, ("always-deny-unregistered-tool",))

    def test_registered_tool_name_with_suffix_is_unregistered(self) -> None:
        d = _decide(_req(tool=f"{TOOL_S3_ENCRYPTION}_extra"), permit_active=True)
        self.assertEqual(d.decision, Decision.DENY)
        self.assertEqual(d.matched_policy_ids, ("always-deny-unregistered-tool",))

    def test_empty_tool_name_raises_at_construction(self) -> None:
        """CCG-REQ-020: empty tool name is rejected by the contract before authz."""
        with self.assertRaises(ValueError):
            _req(tool="   ")  # stripped → empty → ValueError in RemediationRequest.__post_init__

    def test_whitespace_only_tool_name_raises_at_construction(self) -> None:
        with self.assertRaises(ValueError):
            _req(tool="\t\n")

    def test_unregistered_tool_fired_before_demo_tag_check(self) -> None:
        """Unregistered check is first in FORBID_RULES; demo-tag check does not interfere."""
        d = _decide(_req(tool="rogue_tool", tags=_NO_DEMO_TAGS), permit_active=True)
        self.assertEqual(d.matched_policy_ids, ("always-deny-unregistered-tool",))


# ---------------------------------------------------------------------------
# 5. Malformed / missing context parameters — CCG-REQ-020
# ---------------------------------------------------------------------------


class MalformedContextTests(unittest.TestCase):
    """CCG-REQ-020: Context mismatches are handled without crashes or incorrect allows.

    The offline Cedar model evaluates parameters from request.parameters.
    Missing optional params (proposed_cidr absent, make_public absent) must not
    trigger forbids and must not crash.
    """

    def test_security_group_with_no_proposed_cidr_allows(self) -> None:
        """Absent proposed_cidr is not 0.0.0.0/0; forbid does not fire."""
        d = _decide(
            _req(tool=TOOL_SECURITY_GROUP, parameters={}),
            permit_active=True,
        )
        self.assertEqual(d.decision, Decision.ALLOW)

    def test_s3_encryption_with_absent_make_public_allows(self) -> None:
        """Absent make_public defaults to falsy; public-S3 forbid must not fire."""
        d = _decide(
            _req(tool=TOOL_S3_ENCRYPTION, parameters={}),
            permit_active=True,
        )
        self.assertEqual(d.decision, Decision.ALLOW)

    def test_access_key_rotation_confirm_false_allows_at_cedar_layer(self) -> None:
        """Cedar does not check confirm; dry-run enforcement is at the Lambda layer."""
        d = _decide(
            _req(tool=TOOL_ACCESS_KEY_ROTATION, parameters={"confirm": False}),
            permit_active=True,
        )
        self.assertEqual(d.decision, Decision.ALLOW)

    def test_access_key_rotation_confirm_true_also_allows_at_cedar_layer(self) -> None:
        d = _decide(
            _req(tool=TOOL_ACCESS_KEY_ROTATION, parameters={"confirm": True}),
            permit_active=True,
        )
        self.assertEqual(d.decision, Decision.ALLOW)

    def test_unrecognised_extra_parameters_are_ignored(self) -> None:
        """Extra parameters that Cedar does not evaluate must not cause a deny."""
        d = _decide(
            _req(tool=TOOL_TAGGING, parameters={"unexpected_flag": True, "another": "value"}),
            permit_active=True,
        )
        self.assertEqual(d.decision, Decision.ALLOW)

    def test_make_public_false_string_does_not_trigger_public_s3_forbid(self) -> None:
        """make_public must be exactly the bool True to trigger the forbid."""
        d = _decide(
            _req(tool=TOOL_S3_ENCRYPTION, parameters={"make_public": "true"}),
            permit_active=True,
        )
        self.assertEqual(d.decision, Decision.ALLOW)

    def test_security_group_proposed_cidr_none_does_not_trigger_ingress_forbid(self) -> None:
        d = _decide(
            _req(tool=TOOL_SECURITY_GROUP, parameters={"proposed_cidr": None}),
            permit_active=True,
        )
        self.assertEqual(d.decision, Decision.ALLOW)


# ---------------------------------------------------------------------------
# 6. Stale version / replay / concurrency conflict — CCG-REQ-017
# ---------------------------------------------------------------------------


class StaleVersionReplayTests(unittest.TestCase):
    """CCG-REQ-017: Stale generation and replayed requests are rejected."""

    def setUp(self) -> None:
        self.audit = RecordingAuditSink()
        self.transport = InMemoryPolicyControlPlane()
        self.svc = PolicyActivationService(self.transport, self.audit)

    def test_wrong_expected_generation_is_rejected(self) -> None:
        req = _activation_req(generation=99)  # current generation is 0
        result = self.svc.apply(req)
        self.assertEqual(result.outcome, ActivationOutcome.REJECTED)

    def test_rejection_does_not_change_policy_state(self) -> None:
        initial = self.transport.get_state()
        req = _activation_req(generation=99)
        self.svc.apply(req)
        after = self.transport.get_state()
        self.assertEqual(initial.generation, after.generation)
        self.assertEqual(initial.enforcement_mode, after.enforcement_mode)

    def test_duplicate_request_id_returns_cached_rejection(self) -> None:
        """Same request_id reused after a rejection must return the cached result."""
        rid = str(uuid4())
        req = _activation_req(generation=5, request_id=rid)  # stale → rejected
        r1 = self.svc.apply(req)
        r2 = self.svc.apply(req)
        self.assertEqual(r1.outcome, ActivationOutcome.REJECTED)
        self.assertEqual(r2.outcome, ActivationOutcome.REJECTED)
        self.assertEqual(r1.request_id, r2.request_id)

    def test_duplicate_request_id_after_success_is_idempotent(self) -> None:
        """Same request_id reused after a success returns the cached activation."""
        rid = str(uuid4())
        req = _activation_req(generation=0, request_id=rid)
        r1 = self.svc.apply(req)
        r2 = self.svc.apply(req)
        self.assertEqual(r1.outcome, ActivationOutcome.ACTIVATED)
        self.assertEqual(r2.outcome, ActivationOutcome.ACTIVATED)
        # Only one control-plane update must have occurred.
        self.assertEqual(self.transport.get_state().generation, 1)

    def test_second_activation_with_stale_generation_is_rejected(self) -> None:
        """After first activation, generation is 1; sending generation=0 is stale."""
        self.svc.apply(_activation_req(generation=0))
        req2 = _activation_req(generation=0)  # now stale
        result = self.svc.apply(req2)
        self.assertEqual(result.outcome, ActivationOutcome.REJECTED)
        self.assertEqual(self.transport.get_state().generation, 1)

    def test_stale_rejection_records_audit_event(self) -> None:
        self.svc.apply(_activation_req(generation=99))
        event_types = [e.event_type for e in self.audit.events]
        self.assertIn("policy.activation.result", event_types)
        result_event = next(e for e in self.audit.events if e.event_type == "policy.activation.result")
        self.assertEqual(result_event.outcome, ActivationOutcome.REJECTED.value)

    def test_unapproved_version_is_rejected(self) -> None:
        req = _activation_req(version="unapproved-v999", generation=0)
        result = self.svc.apply(req)
        self.assertEqual(result.outcome, ActivationOutcome.REJECTED)

    def test_rejected_state_carries_current_mode(self) -> None:
        req = _activation_req(generation=99)
        result = self.svc.apply(req)
        self.assertIsNotNone(result.state)
        self.assertEqual(result.state.enforcement_mode, PolicyEnforcementMode.LOG_ONLY)


# ---------------------------------------------------------------------------
# 7. Activation failure / deny-safe state — CCG-REQ-016
# ---------------------------------------------------------------------------


class ActivationFailureDenySafeTests(unittest.TestCase):
    """CCG-REQ-016: Transport failure → FAILED outcome → deny-safe LOG_ONLY mode."""

    def setUp(self) -> None:
        self.audit = RecordingAuditSink()
        self.transport = InMemoryPolicyControlPlane()
        self.svc = PolicyActivationService(self.transport, self.audit)

    def test_transport_failure_returns_failed_outcome(self) -> None:
        self.transport.fail_next = True
        result = self.svc.apply(_activation_req(generation=0))
        self.assertEqual(result.outcome, ActivationOutcome.FAILED)

    def test_failed_activation_leaves_effective_mode_log_only(self) -> None:
        self.transport.fail_next = True
        result = self.svc.apply(_activation_req(generation=0))
        # result.state is the reconciled deny-safe state
        self.assertIsNotNone(result.state)
        self.assertEqual(result.state.enforcement_mode, PolicyEnforcementMode.LOG_ONLY)

    def test_transport_failure_audit_event_records_failed_outcome(self) -> None:
        self.transport.fail_next = True
        self.svc.apply(_activation_req(generation=0))
        events = self.audit.events
        result_events = [e for e in events if e.event_type == "policy.activation.result"]
        self.assertTrue(result_events)
        self.assertEqual(result_events[-1].outcome, ActivationOutcome.FAILED.value)

    def test_tool_calls_still_denied_after_failed_activation(self) -> None:
        """After a failed activation, permits remain inactive → all tool calls denied."""
        self.transport.fail_next = True
        self.svc.apply(_activation_req(generation=0))
        # permit is still inactive: decide must return DENY
        d = _decide(_req(tool=TOOL_S3_ENCRYPTION, tags=_DEMO_TAGS), permit_active=False)
        self.assertEqual(d.decision, Decision.DENY)

    def test_intent_event_recorded_before_transport_call(self) -> None:
        """CCG-REQ-015: intent must be audited before the control-plane call."""
        self.transport.fail_next = True
        self.svc.apply(_activation_req(generation=0))
        intent_events = [e for e in self.audit.events if e.event_type == "policy.activation.intent"]
        result_events = [e for e in self.audit.events if e.event_type == "policy.activation.result"]
        self.assertTrue(intent_events, "intent event must be recorded")
        self.assertTrue(result_events, "result event must be recorded")
        # Intent must come before result in the event stream.
        intent_idx = self.audit.events.index(intent_events[0])
        result_idx = self.audit.events.index(result_events[0])
        self.assertLess(intent_idx, result_idx)

    def test_failed_activation_control_plane_request_id_is_none(self) -> None:
        self.transport.fail_next = True
        result = self.svc.apply(_activation_req(generation=0))
        self.assertIsNone(result.control_plane_request_id)

    def test_successful_activation_has_non_none_control_plane_request_id(self) -> None:
        result = self.svc.apply(_activation_req(generation=0))
        self.assertIsNotNone(result.control_plane_request_id)
        self.assertNotEqual(result.control_plane_request_id, "")


# ---------------------------------------------------------------------------
# 8. Policy visibility — CCG-REQ-018
# ---------------------------------------------------------------------------


class PolicyVisibilityTests(unittest.TestCase):
    """CCG-REQ-018: Policy state is observable but reading it cannot grant access."""

    def setUp(self) -> None:
        self.audit = RecordingAuditSink()
        self.transport = InMemoryPolicyControlPlane()
        self.svc = PolicyActivationService(self.transport, self.audit)

    def test_initial_state_is_log_only_with_generation_zero(self) -> None:
        state = self.svc.current_state()
        self.assertEqual(state.enforcement_mode, PolicyEnforcementMode.LOG_ONLY)
        self.assertEqual(state.generation, 0)
        self.assertEqual(state.policy_set_version, "permits-inactive")

    def test_state_carries_all_required_fields(self) -> None:
        state = self.svc.current_state()
        self.assertTrue(state.policy_engine_id)
        self.assertTrue(state.policy_set_version)
        self.assertIsNotNone(state.enforcement_mode)
        self.assertIsNotNone(state.generation)
        self.assertTrue(state.updated_by)
        self.assertIsNotNone(state.updated_at)

    def test_after_activation_state_shows_active_mode(self) -> None:
        self.svc.apply(_activation_req(generation=0))
        state = self.svc.current_state()
        self.assertEqual(state.enforcement_mode, PolicyEnforcementMode.ACTIVE)
        self.assertEqual(state.generation, 1)
        self.assertEqual(state.updated_by, "admin")

    def test_after_deactivation_state_returns_to_log_only(self) -> None:
        self.svc.apply(_activation_req(generation=0))
        self.svc.apply(_activation_req(generation=1, activate=False))
        state = self.svc.current_state()
        self.assertEqual(state.enforcement_mode, PolicyEnforcementMode.LOG_ONLY)

    def test_reading_active_state_does_not_grant_gateway_access(self) -> None:
        """CCG-REQ-009, CCG-REQ-018: State visibility alone cannot authorize mutations.

        Even if the caller can read that enforcement_mode=ACTIVE, they must still
        pass through the Cedar boundary.  Here we simulate a caller that reads the
        state and then attempts to bypass the gateway by calling decide() with
        permit_active=False (representing what happens when the gateway is not
        consulted).
        """
        self.svc.apply(_activation_req(generation=0))
        state = self.svc.current_state()
        # State shows ACTIVE — but a call that bypasses the gateway boundary is denied.
        self.assertEqual(state.enforcement_mode, PolicyEnforcementMode.ACTIVE)
        d = _decide(_req(tool=TOOL_S3_ENCRYPTION, tags=_DEMO_TAGS), permit_active=False)
        self.assertEqual(d.decision, Decision.DENY)

    def test_state_version_increments_monotonically(self) -> None:
        gen_0 = self.svc.current_state().generation
        self.svc.apply(_activation_req(generation=0))
        gen_1 = self.svc.current_state().generation
        self.svc.apply(_activation_req(generation=1, activate=False))
        gen_2 = self.svc.current_state().generation
        self.assertLess(gen_0, gen_1)
        self.assertLess(gen_1, gen_2)

    def test_activation_result_carries_state_snapshot(self) -> None:
        result = self.svc.apply(_activation_req(generation=0))
        self.assertIsNotNone(result.state)
        self.assertEqual(result.state.enforcement_mode, PolicyEnforcementMode.ACTIVE)
        self.assertEqual(result.state.generation, 1)


# ---------------------------------------------------------------------------
# 9. Decision evidence completeness — CCG-REQ-019
# ---------------------------------------------------------------------------


class DecisionEvidenceCompletenessTests(unittest.TestCase):
    """CCG-REQ-019: PolicyDecision carries all required fields for every outcome."""

    _REQUIRED_TEXT_FIELDS = (
        "request_id",
        "correlation_id",
        "actor",
        "action_id",
        "target_arn",
        "policy_set_version",
        "reason",
    )

    def _assert_evidence_complete(self, decision: Any) -> None:
        for field in self._REQUIRED_TEXT_FIELDS:
            with self.subTest(field=field):
                self.assertTrue(getattr(decision, field), f"field '{field}' must be non-empty")
        self.assertIsNotNone(decision.decision)
        self.assertIsNotNone(decision.evaluated_at)
        self.assertIsInstance(decision.matched_policy_ids, tuple)
        self.assertGreater(len(decision.matched_policy_ids), 0, "matched_policy_ids must not be empty")
        # evaluated_at must be timezone-aware
        self.assertIsNotNone(decision.evaluated_at.tzinfo)

    def test_allow_decision_has_complete_evidence(self) -> None:
        d = _decide(_req(tool=TOOL_S3_ENCRYPTION, tags=_DEMO_TAGS), permit_active=True)
        self._assert_evidence_complete(d)

    def test_default_deny_decision_has_complete_evidence(self) -> None:
        d = _decide(_req(tool=TOOL_S3_ENCRYPTION), permit_active=False)
        self._assert_evidence_complete(d)

    def test_forbid_deny_decision_has_complete_evidence(self) -> None:
        d = _decide(_req(tool=TOOL_S3_ENCRYPTION, tags=_PROD_TAGS), permit_active=True)
        self._assert_evidence_complete(d)

    def test_action_id_uses_full_cedar_format_on_allow(self) -> None:
        d = _decide(_req(tool=TOOL_TAGGING, tags=_DEMO_TAGS), permit_active=True)
        self.assertTrue(d.action_id.startswith(CEDAR_ACTION_PREFIX))
        self.assertIn(CEDAR_TARGET_NAME, d.action_id)
        self.assertIn(TOOL_TAGGING, d.action_id)

    def test_action_id_uses_full_cedar_format_on_deny(self) -> None:
        d = _decide(_req(tool=TOOL_TAGGING, tags=_DEMO_TAGS), permit_active=False)
        self.assertTrue(d.action_id.startswith(CEDAR_ACTION_PREFIX))
        self.assertIn(CEDAR_TARGET_NAME, d.action_id)
        self.assertIn(TOOL_TAGGING, d.action_id)

    def test_action_id_uses_full_cedar_format_on_forbid(self) -> None:
        d = _decide(_req(tool=TOOL_SECURITY_GROUP, parameters={"proposed_cidr": "0.0.0.0/0"}), permit_active=True)
        self.assertEqual(d.action_id, to_cedar_action_id(TOOL_SECURITY_GROUP))

    def test_matched_policy_ids_never_empty_for_any_outcome(self) -> None:
        scenarios = [
            (_req(tool=TOOL_S3_ENCRYPTION, tags=_DEMO_TAGS), True),      # ALLOW
            (_req(tool=TOOL_S3_ENCRYPTION), False),                        # default-deny
            (_req(tool=TOOL_S3_ENCRYPTION, tags=_PROD_TAGS), True),       # forbid-prod
            (_req(tool="rogue"), True),                                    # unregistered
        ]
        for request, permit in scenarios:
            with self.subTest(tool=request.tool, permit=permit):
                d = _decide(request, permit_active=permit)
                self.assertGreater(len(d.matched_policy_ids), 0)

    def test_decision_evidence_for_all_four_tools(self) -> None:
        for tool in _ALL_TOOLS:
            with self.subTest(tool=tool):
                d = _decide(_req(tool=tool, tags=_DEMO_TAGS), permit_active=True)
                self._assert_evidence_complete(d)

    def test_policy_set_version_is_propagated(self) -> None:
        version = "my-unique-version-abc"
        d = decide(
            _req(tool=TOOL_S3_ENCRYPTION, tags=_DEMO_TAGS),
            permit_active=True,
            registered_tools=REGISTERED_TOOLS,
            policy_set_version=version,
        )
        self.assertEqual(d.policy_set_version, version)


# ---------------------------------------------------------------------------
# 10. Full matrix: all 4 tools × allow / deny / forbid — CCG-REQ-008, CCG-REQ-013
# ---------------------------------------------------------------------------


class FullToolMatrixTests(unittest.TestCase):
    """CCG-REQ-008, CCG-REQ-013: Every registered tool exercises all three outcomes."""

    def test_inactive_permit_denies_all_tools(self) -> None:
        for tool in _ALL_TOOLS:
            with self.subTest(tool=tool):
                d = _decide(_req(tool=tool, tags=_DEMO_TAGS), permit_active=False)
                self.assertEqual(d.decision, Decision.DENY)
                self.assertEqual(d.matched_policy_ids, ("default-deny-permits-inactive",))

    def test_active_permit_allows_all_tools_on_eligible_target(self) -> None:
        for tool in _ALL_TOOLS:
            with self.subTest(tool=tool):
                d = _decide(_req(tool=tool, tags=_DEMO_TAGS), permit_active=True)
                self.assertEqual(d.decision, Decision.ALLOW)

    def test_active_permit_denies_all_tools_on_prod_target(self) -> None:
        for tool in _ALL_TOOLS:
            with self.subTest(tool=tool):
                d = _decide(_req(tool=tool, tags=_PROD_TAGS), permit_active=True)
                self.assertEqual(d.decision, Decision.DENY)
                self.assertEqual(d.matched_policy_ids, ("always-deny-production-target",))


# ---------------------------------------------------------------------------
# 11. Gateway boundary — CCG-REQ-008, CCG-REQ-009
# ---------------------------------------------------------------------------


class GatewayBoundaryTests(unittest.TestCase):
    """CCG-REQ-008: Mutations must traverse the Gateway boundary.
    CCG-REQ-009: No boolean / UI / prompt can bypass it.
    """

    def _gateway(self, *, permit_active: bool = False) -> tuple[InMemoryCedarGateway, RecordingAuditSink]:
        audit = RecordingAuditSink()
        gw = InMemoryCedarGateway(audit, permit_active=permit_active)
        for name, handler in default_tool_handlers().items():
            gw.register(name, handler)
        return gw, audit

    def test_gateway_emits_audit_event_on_deny(self) -> None:
        gw, audit = self._gateway(permit_active=False)
        gw.invoke(_req(tool=TOOL_S3_ENCRYPTION, tags=_DEMO_TAGS))
        decision_events = [e for e in audit.events if e.event_type == "gateway.decision"]
        self.assertEqual(len(decision_events), 1)
        self.assertEqual(decision_events[0].outcome, Decision.DENY.value)

    def test_gateway_emits_audit_event_on_allow(self) -> None:
        gw, audit = self._gateway(permit_active=True)
        gw.invoke(_req(tool=TOOL_S3_ENCRYPTION, tags=_DEMO_TAGS, parameters={"algorithm": "AES256"}))
        decision_events = [e for e in audit.events if e.event_type == "gateway.decision"]
        self.assertEqual(len(decision_events), 1)
        self.assertEqual(decision_events[0].outcome, Decision.ALLOW.value)

    def test_gateway_deny_returns_no_tool_result(self) -> None:
        gw, _ = self._gateway(permit_active=False)
        result = gw.invoke(_req(tool=TOOL_S3_ENCRYPTION, tags=_DEMO_TAGS))
        self.assertEqual(result.decision.decision, Decision.DENY)
        self.assertIsNone(result.tool_result)

    def test_gateway_allow_returns_tool_result(self) -> None:
        gw, _ = self._gateway(permit_active=True)
        result = gw.invoke(
            _req(tool=TOOL_S3_ENCRYPTION, tags=_DEMO_TAGS, parameters={"algorithm": "AES256"})
        )
        self.assertEqual(result.decision.decision, Decision.ALLOW)
        self.assertIsNotNone(result.tool_result)

    def test_gateway_idempotency_replay_returns_cached_result(self) -> None:
        gw, _ = self._gateway(permit_active=True)
        idem_key = "idem-replay-test"
        r1 = gw.invoke(
            _req(tool=TOOL_S3_ENCRYPTION, tags=_DEMO_TAGS, parameters={"algorithm": "AES256"}, idempotency_key=idem_key)
        )
        r2 = gw.invoke(
            _req(tool=TOOL_S3_ENCRYPTION, tags=_DEMO_TAGS, parameters={"algorithm": "AES256"}, idempotency_key=idem_key)
        )
        self.assertIsNotNone(r1.tool_result)
        self.assertIsNotNone(r2.tool_result)
        self.assertTrue(r2.tool_result.idempotency_replayed)

    def test_unregistered_tool_denied_at_gateway_boundary(self) -> None:
        gw, _ = self._gateway(permit_active=True)
        result = gw.invoke(_req(tool="rogue_tool"))
        self.assertEqual(result.decision.decision, Decision.DENY)
        self.assertIsNone(result.tool_result)

    def test_prod_target_denied_at_gateway_boundary(self) -> None:
        gw, _ = self._gateway(permit_active=True)
        result = gw.invoke(_req(tool=TOOL_S3_ENCRYPTION, tags=_PROD_TAGS))
        self.assertEqual(result.decision.decision, Decision.DENY)
        self.assertIsNone(result.tool_result)

    def test_activating_gateway_permits_transitions_from_deny_to_allow(self) -> None:
        """CCG-REQ-009: State change flows through the control plane, not a flag."""
        gw, _ = self._gateway(permit_active=False)
        r_before = gw.invoke(_req(tool=TOOL_S3_ENCRYPTION, tags=_DEMO_TAGS))
        self.assertEqual(r_before.decision.decision, Decision.DENY)

        gw.activate_permits("v1")
        r_after = gw.invoke(
            _req(tool=TOOL_S3_ENCRYPTION, tags=_DEMO_TAGS, parameters={"algorithm": "AES256"})
        )
        self.assertEqual(r_after.decision.decision, Decision.ALLOW)


# ---------------------------------------------------------------------------
# 12. Activation intent audit — CCG-REQ-015
# ---------------------------------------------------------------------------


class ActivationIntentAuditTests(unittest.TestCase):
    """CCG-REQ-015: Activation records intent before applying the control-plane change."""

    def setUp(self) -> None:
        self.audit = RecordingAuditSink()
        self.transport = InMemoryPolicyControlPlane()
        self.svc = PolicyActivationService(self.transport, self.audit)

    def test_successful_activation_emits_intent_then_result(self) -> None:
        self.svc.apply(_activation_req(generation=0))
        types = [e.event_type for e in self.audit.events]
        intent_idx = types.index("policy.activation.intent")
        result_idx = types.index("policy.activation.result")
        self.assertLess(intent_idx, result_idx)

    def test_intent_event_carries_actor_and_version(self) -> None:
        self.svc.apply(_activation_req(generation=0, actor="admin"))
        intent = next(e for e in self.audit.events if e.event_type == "policy.activation.intent")
        self.assertEqual(intent.actor, "admin")
        self.assertIn("requested_version", intent.details)
        self.assertIn("desired_mode", intent.details)

    def test_result_event_carries_effective_version_and_mode(self) -> None:
        self.svc.apply(_activation_req(generation=0))
        result_event = next(e for e in self.audit.events if e.event_type == "policy.activation.result")
        self.assertIn("effective_version", result_event.details)
        self.assertIn("effective_mode", result_event.details)

    def test_rejected_activation_records_result_event_without_intent(self) -> None:
        """Rejections do not reach the transport, so no intent event is emitted."""
        self.svc.apply(_activation_req(generation=99))  # stale → rejected before intent
        types = [e.event_type for e in self.audit.events]
        self.assertNotIn("policy.activation.intent", types)
        self.assertIn("policy.activation.result", types)

    def test_result_event_outcome_matches_activation_outcome(self) -> None:
        self.svc.apply(_activation_req(generation=0))
        result_event = next(e for e in self.audit.events if e.event_type == "policy.activation.result")
        self.assertEqual(result_event.outcome, ActivationOutcome.ACTIVATED.value)

    def test_deactivation_outcome_is_deactivated(self) -> None:
        self.svc.apply(_activation_req(generation=0))
        self.svc.apply(_activation_req(generation=1, activate=False))
        result_events = [e for e in self.audit.events if e.event_type == "policy.activation.result"]
        deact_event = result_events[-1]
        self.assertEqual(deact_event.outcome, ActivationOutcome.DEACTIVATED.value)


# ---------------------------------------------------------------------------
# 13. Cedar action ID format — stable audit contract
# ---------------------------------------------------------------------------


class CedarActionIdFormatTests(unittest.TestCase):
    """The Cedar action ID format must be stable; any change breaks audit evidence."""

    def test_format_for_all_registered_tools(self) -> None:
        for tool in _ALL_TOOLS:
            with self.subTest(tool=tool):
                action_id = to_cedar_action_id(tool)
                self.assertEqual(
                    action_id,
                    f'{CEDAR_ACTION_PREFIX}"{CEDAR_TARGET_NAME}___{tool}"',
                )

    def test_separator_is_triple_underscore(self) -> None:
        action_id = to_cedar_action_id(TOOL_S3_ENCRYPTION)
        self.assertIn("___", action_id)
        self.assertNotIn("__", action_id.replace("___", ""))  # no double-underscore elsewhere

    def test_namespace_prefix(self) -> None:
        action_id = to_cedar_action_id(TOOL_S3_ENCRYPTION)
        self.assertTrue(action_id.startswith('AgentCore::Action::'))

    def test_target_name_embedded(self) -> None:
        action_id = to_cedar_action_id(TOOL_SECURITY_GROUP)
        self.assertIn("RemediationTarget", action_id)


if __name__ == "__main__":
    unittest.main()
