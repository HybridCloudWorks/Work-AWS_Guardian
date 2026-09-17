import unittest

from ccg.authz import decide
from ccg.contracts import Decision, RemediationRequest, TargetRef
from ccg.tools import REGISTERED_TOOLS


def req(*, tool="s3_encryption_enablement", tags=None, parameters=None) -> RemediationRequest:
    return RemediationRequest(
        request_id="req-1",
        correlation_id="corr-1",
        actor="admin",
        tool=tool,
        target=TargetRef("arn:aws:s3:::ccg-demo", "s3_bucket", tags if tags is not None else {"CCGDemo": "true"}),
        parameters=parameters or {},
        idempotency_key="idem-1",
    )


def decide_with(request, *, permit_active):
    return decide(
        request,
        permit_active=permit_active,
        registered_tools=REGISTERED_TOOLS,
        policy_set_version="test-v1",
    )


class AuthzOrderingTests(unittest.TestCase):
    def test_inactive_permit_denies(self) -> None:
        d = decide_with(req(), permit_active=False)
        self.assertEqual(d.decision, Decision.DENY)
        self.assertEqual(d.matched_policy_ids, ("default-deny-permits-inactive",))

    def test_active_permit_allows_eligible_target(self) -> None:
        d = decide_with(req(), permit_active=True)
        self.assertEqual(d.decision, Decision.ALLOW)
        self.assertEqual(d.matched_policy_ids, ("permit-s3_encryption_enablement",))

    def test_forbid_overrides_active_permit_for_prod(self) -> None:
        d = decide_with(req(tags={"CCGDemo": "true", "Environment": "prod"}), permit_active=True)
        self.assertEqual(d.decision, Decision.DENY)
        self.assertEqual(d.matched_policy_ids, ("always-deny-production-target",))

    def test_missing_demo_tag_denies_even_with_permit(self) -> None:
        d = decide_with(req(tags={"Environment": "sandbox"}), permit_active=True)
        self.assertEqual(d.decision, Decision.DENY)
        self.assertEqual(d.matched_policy_ids, ("always-deny-missing-demo-tag",))

    def test_global_open_ingress_forbidden_even_with_permit(self) -> None:
        d = decide_with(
            req(tool="security_group_correction", parameters={"proposed_cidr": "0.0.0.0/0"}),
            permit_active=True,
        )
        self.assertEqual(d.decision, Decision.DENY)
        self.assertEqual(d.matched_policy_ids, ("always-deny-global-open-ingress",))

    def test_unregistered_tool_denies_first(self) -> None:
        d = decide_with(req(tool="disable_cloudtrail"), permit_active=True)
        self.assertEqual(d.decision, Decision.DENY)
        # unregistered is checked before the more specific cloudtrail forbid
        self.assertEqual(d.matched_policy_ids, ("always-deny-unregistered-tool",))

    def test_decision_evidence_is_populated(self) -> None:
        d = decide_with(req(), permit_active=True)
        self.assertEqual(d.action_id, "s3_encryption_enablement")
        self.assertEqual(d.target_arn, "arn:aws:s3:::ccg-demo")
        self.assertEqual(d.policy_set_version, "test-v1")
        self.assertTrue(d.reason)


if __name__ == "__main__":
    unittest.main()
