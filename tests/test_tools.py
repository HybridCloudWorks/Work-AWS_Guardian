import unittest

from ccg.contracts import RemediationRequest, TargetRef, ToolOutcome
from ccg.tools import (
    TOOL_ACCESS_KEY_ROTATION,
    TOOL_S3_ENCRYPTION,
    TOOL_SECURITY_GROUP,
    TOOL_TAGGING,
    DryRunEffector,
    access_key_rotation,
    compliant_tagging,
    s3_encryption_enablement,
    security_group_correction,
)


def req(tool: str, *, tags=None, parameters=None, arn="arn:aws:s3:::ccg-demo", rtype="s3_bucket") -> RemediationRequest:
    return RemediationRequest(
        request_id="req-1",
        correlation_id="corr-1",
        actor="admin",
        tool=tool,
        target=TargetRef(arn, rtype, tags if tags is not None else {"CCGDemo": "true"}),
        parameters=parameters or {},
        idempotency_key="idem-1",
    )


class SafetyRecheckTests(unittest.TestCase):
    def test_missing_demo_tag_fails_regardless_of_gateway(self) -> None:
        result = s3_encryption_enablement(req(TOOL_S3_ENCRYPTION, tags={}, parameters={"algorithm": "AES256"}))
        self.assertEqual(result.outcome, ToolOutcome.FAILED)
        self.assertFalse(result.changed)

    def test_prod_tag_fails_regardless_of_gateway(self) -> None:
        result = s3_encryption_enablement(
            req(TOOL_S3_ENCRYPTION, tags={"CCGDemo": "true", "Environment": "prod"}, parameters={"algorithm": "AES256"})
        )
        self.assertEqual(result.outcome, ToolOutcome.FAILED)


class SecurityGroupTests(unittest.TestCase):
    def test_corrects_non_compliant_rule(self) -> None:
        eff = DryRunEffector()
        result = security_group_correction(
            req(TOOL_SECURITY_GROUP, arn="arn:aws:ec2:...:sg/sg-1", rtype="security_group",
                parameters={"rule_id": "r1", "proposed_cidr": "10.0.0.0/24", "current_cidr": "0.0.0.0/0"}),
            eff,
        )
        self.assertEqual(result.outcome, ToolOutcome.APPLIED)
        self.assertEqual(len(eff.performed), 1)

    def test_already_compliant_is_noop(self) -> None:
        eff = DryRunEffector()
        result = security_group_correction(
            req(TOOL_SECURITY_GROUP, rtype="security_group",
                parameters={"rule_id": "r1", "proposed_cidr": "10.0.0.0/24", "current_cidr": "10.0.0.0/24"}),
            eff,
        )
        self.assertEqual(result.outcome, ToolOutcome.NOOP)
        self.assertEqual(eff.performed, [])

    def test_global_open_cidr_is_rejected(self) -> None:
        result = security_group_correction(
            req(TOOL_SECURITY_GROUP, rtype="security_group",
                parameters={"rule_id": "r1", "proposed_cidr": "0.0.0.0/0"}),
        )
        self.assertEqual(result.outcome, ToolOutcome.FAILED)


class S3EncryptionTests(unittest.TestCase):
    def test_enables_encryption(self) -> None:
        result = s3_encryption_enablement(req(TOOL_S3_ENCRYPTION, parameters={"algorithm": "AES256"}))
        self.assertEqual(result.outcome, ToolOutcome.APPLIED)

    def test_already_encrypted_is_noop(self) -> None:
        params = {"algorithm": "AES256", "currently_encrypted": True, "current_algorithm": "AES256"}
        result = s3_encryption_enablement(req(TOOL_S3_ENCRYPTION, parameters=params))
        self.assertEqual(result.outcome, ToolOutcome.NOOP)

    def test_make_public_is_rejected(self) -> None:
        params = {"algorithm": "AES256", "make_public": True}
        result = s3_encryption_enablement(req(TOOL_S3_ENCRYPTION, parameters=params))
        self.assertEqual(result.outcome, ToolOutcome.FAILED)


class TaggingTests(unittest.TestCase):
    def test_applies_missing_tags(self) -> None:
        result = compliant_tagging(req(TOOL_TAGGING, parameters={"desired_tags": {"Owner": "team-sec"}}))
        self.assertEqual(result.outcome, ToolOutcome.APPLIED)

    def test_already_tagged_is_noop(self) -> None:
        result = compliant_tagging(
            req(
                TOOL_TAGGING,
                tags={"CCGDemo": "true", "Owner": "team-sec"},
                parameters={"desired_tags": {"Owner": "team-sec"}},
            )
        )
        self.assertEqual(result.outcome, ToolOutcome.NOOP)

    def test_cannot_set_prod(self) -> None:
        result = compliant_tagging(req(TOOL_TAGGING, parameters={"desired_tags": {"Environment": "prod"}}))
        self.assertEqual(result.outcome, ToolOutcome.FAILED)

    def test_cannot_weaken_demo_tag(self) -> None:
        result = compliant_tagging(req(TOOL_TAGGING, parameters={"desired_tags": {"CCGDemo": "false"}}))
        self.assertEqual(result.outcome, ToolOutcome.FAILED)


class AccessKeyRotationTests(unittest.TestCase):
    def test_dry_run_by_default_performs_no_mutation(self) -> None:
        eff = DryRunEffector()
        result = access_key_rotation(
            req(TOOL_ACCESS_KEY_ROTATION, arn="arn:aws:iam::...:user/ccg-demo", rtype="iam_user",
                parameters={"identity": "ccg-demo", "old_access_key_id": "AKIAEXAMPLE"}),
            eff,
        )
        self.assertEqual(result.outcome, ToolOutcome.NOOP)
        self.assertTrue(result.details["dry_run"])
        self.assertEqual(eff.performed, [])

    def test_confirm_true_performs_rotation(self) -> None:
        eff = DryRunEffector()
        result = access_key_rotation(
            req(TOOL_ACCESS_KEY_ROTATION, arn="arn:aws:iam::...:user/ccg-demo", rtype="iam_user",
                parameters={"identity": "ccg-demo", "old_access_key_id": "AKIAEXAMPLE", "confirm": True}),
            eff,
        )
        self.assertEqual(result.outcome, ToolOutcome.APPLIED)
        self.assertEqual(len(eff.performed), 1)

    def test_no_secret_material_in_result(self) -> None:
        result = access_key_rotation(
            req(TOOL_ACCESS_KEY_ROTATION, arn="arn:aws:iam::...:user/ccg-demo", rtype="iam_user",
                parameters={"identity": "ccg-demo", "old_access_key_id": "AKIAEXAMPLE", "confirm": True}),
        )
        serialized = result.to_json()
        self.assertNotIn("SecretAccessKey", serialized)
        self.assertNotIn("secret", serialized.casefold())


if __name__ == "__main__":
    unittest.main()
