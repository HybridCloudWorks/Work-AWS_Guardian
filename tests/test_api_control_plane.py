"""Task 5.1 control-plane coverage: JWT auth, P0.4c/d validation, evidence read.

These complement ``test_api_authorization.py`` (which proves the core
authentication/authorization/stale/actor rules) with the additional 5.1
surface:

* P0.4c/d — a command whose tool is inconsistent with the finding's rule_id, or
  whose parameters are outside the per-tool bounded allow-list, is rejected at
  the API layer *before* the Gateway is called (defense in depth above the
  tool-layer and Cedar checks).
* Decision-evidence read endpoint — authenticated read returns stored evidence;
  unauthenticated is rejected.
* Cognito JWT principal resolver seam — valid claims map to the right roles;
  an unknown/invalid token resolves to unauthenticated (fail closed).
* Correlation propagation — the correlation id from the request flows through
  the service to the audit and decision records.
"""

from datetime import datetime, timezone
import json
import unittest

from ccg.api import AuthenticatedPrincipal, ComplianceApi, UnauthorizedError
from ccg.auth import FakeTokenVerifier, InvalidTokenError, PrincipalResolver
from ccg.contracts import (
    Decision,
    Finding,
    FindingStatus,
    RemediationCommand,
    Severity,
    TargetRef,
    ToolOutcome,
    ToolResult,
)
from ccg.http import ApiHttpAdapter
from ccg.policy import InMemoryPolicyControlPlane, PolicyActivationService
from ccg.testing import (
    InMemoryCedarGateway,
    InMemoryDecisionEvidenceRepository,
    InMemoryFindingRepository,
    RecordingAuditSink,
)

NOW = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)


def _applied_tool(request):
    return ToolResult(
        outcome=ToolOutcome.APPLIED,
        tool=request.tool,
        target_arn=request.target.arn,
        changed=True,
        message="applied",
    )


class ControlPlaneTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = RecordingAuditSink()
        self.gateway = InMemoryCedarGateway(self.audit)
        self.gateway.activate_permits("v1")
        self.gateway.register("s3_encryption_enablement", _applied_tool)
        self.gateway.register("security_group_correction", _applied_tool)

        self.repo = InMemoryFindingRepository()
        self.repo.upsert(
            Finding(
                finding_id="finding-1",
                rule_id="s3-encryption-missing",
                source="config",
                target=TargetRef("arn:aws:s3:::ccg-demo", "s3_bucket", {"CCGDemo": "true"}),
                severity=Severity.HIGH,
                title="missing encryption",
                evidence_refs=("config:finding-1",),
                status=FindingStatus.OPEN,
                first_seen_at=NOW,
                last_seen_at=NOW,
                correlation_id="corr-1",
            )
        )
        self.evidence = InMemoryDecisionEvidenceRepository()
        self.policy = PolicyActivationService(InMemoryPolicyControlPlane(), self.audit)
        self.api = ComplianceApi(self.gateway, self.policy, self.repo, self.evidence)

        self.admin = AuthenticatedPrincipal("admin", frozenset({"CCGAdmin", "CCGRemediator"}))

    def command(self, **overrides) -> RemediationCommand:
        params = {
            "request_id": "req-1",
            "correlation_id": "corr-1",
            "actor": "admin",
            "finding_id": "finding-1",
            "tool": "s3_encryption_enablement",
            "parameters": {"algorithm": "AES256"},
            "idempotency_key": "idem-1",
            "expected_finding_version": 0,
        }
        params.update(overrides)
        return RemediationCommand(**params)


class RuleToolValidationTests(ControlPlaneTestBase):
    """P0.4c/d — tool/param consistency with the resolved finding."""

    def test_tool_rule_mismatch_is_rejected_before_gateway(self) -> None:
        # access_key_rotation is not the tool for an s3-encryption finding.
        with self.assertRaises(ValueError) as ctx:
            self.api.request_remediation(
                self.admin,
                self.command(
                    tool="access_key_rotation",
                    parameters={"identity": "u", "old_access_key_id": "AKIA"},
                ),
            )
        self.assertIn("not valid for finding", str(ctx.exception))
        # Nothing reached the gateway: no decision was audited.
        self.assertEqual([e.event_type for e in self.audit.events], [])

    def test_out_of_allowlist_parameter_is_rejected(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self.api.request_remediation(
                self.admin,
                self.command(parameters={"algorithm": "AES256", "make_bucket_public": True}),
            )
        self.assertIn("not permitted", str(ctx.exception))

    def test_valid_tool_and_params_pass_validation_and_apply(self) -> None:
        result = self.api.request_remediation(self.admin, self.command())
        self.assertEqual(result.decision.decision, Decision.ALLOW)
        self.assertEqual(result.tool_result.outcome, ToolOutcome.APPLIED)

    def test_security_group_finding_requires_sg_tool(self) -> None:
        self.repo.upsert(
            Finding(
                finding_id="finding-sg",
                rule_id="security-group-open-ingress",
                source="config",
                target=TargetRef("arn:aws:ec2:::sg/ccg", "security_group", {"CCGDemo": "true"}),
                severity=Severity.HIGH,
                title="open ingress",
                evidence_refs=("config:finding-sg",),
                status=FindingStatus.OPEN,
                first_seen_at=NOW,
                last_seen_at=NOW,
                correlation_id="corr-1",
            )
        )
        # Wrong tool for an SG finding is rejected.
        with self.assertRaises(ValueError):
            self.api.request_remediation(
                self.admin,
                self.command(
                    finding_id="finding-sg",
                    tool="s3_encryption_enablement",
                    parameters={"algorithm": "AES256"},
                ),
            )
        # Correct tool + allowed params passes.
        result = self.api.request_remediation(
            self.admin,
            self.command(
                finding_id="finding-sg",
                tool="security_group_correction",
                parameters={"rule_id": "r1", "proposed_cidr": "10.0.0.0/24"},
                idempotency_key="idem-sg",
                request_id="req-sg",
            ),
        )
        self.assertEqual(result.decision.decision, Decision.ALLOW)


class DecisionEvidenceReadTests(ControlPlaneTestBase):
    def test_authenticated_read_returns_recorded_evidence(self) -> None:
        self.api.request_remediation(self.admin, self.command())
        by_finding = self.api.get_decision_evidence(self.admin, finding_id="finding-1")
        self.assertEqual(len(by_finding), 1)
        self.assertEqual(by_finding[0].decision, Decision.ALLOW)
        by_request = self.api.get_decision_evidence(self.admin, request_id="req-1")
        self.assertEqual(len(by_request), 1)

    def test_unauthenticated_cannot_read_evidence(self) -> None:
        unauth = AuthenticatedPrincipal("admin", frozenset({"CCGAdmin"}), authenticated=False)
        with self.assertRaises(UnauthorizedError):
            self.api.get_decision_evidence(unauth, finding_id="finding-1")

    def test_exactly_one_selector_required(self) -> None:
        with self.assertRaises(ValueError):
            self.api.get_decision_evidence(self.admin)
        with self.assertRaises(ValueError):
            self.api.get_decision_evidence(self.admin, finding_id="f", request_id="r")

    def test_unknown_key_returns_empty(self) -> None:
        self.assertEqual(self.api.get_decision_evidence(self.admin, finding_id="ghost"), [])


class JwtPrincipalResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = FakeTokenVerifier(
            {
                "admin-token": {"sub": "admin-sub", "cognito:groups": ["CCGAdmin", "CCGRemediator"]},
                "viewer-token": {"sub": "viewer-sub", "cognito:groups": ["CCGViewer"]},
                "no-group-token": {"sub": "nobody-sub"},
            }
        )
        self.resolver = PrincipalResolver(self.verifier)

    def _event(self, token: str | None) -> dict:
        headers = {"authorization": f"Bearer {token}"} if token is not None else {}
        return {"headers": headers}

    def test_valid_claims_map_to_roles(self) -> None:
        principal = self.resolver.resolve(self._event("admin-token"))
        self.assertTrue(principal.authenticated)
        self.assertEqual(principal.actor, "admin-sub")
        self.assertEqual(principal.roles, frozenset({"CCGAdmin", "CCGRemediator"}))

    def test_viewer_group_maps_to_viewer_role(self) -> None:
        principal = self.resolver.resolve(self._event("viewer-token"))
        self.assertEqual(principal.roles, frozenset({"CCGViewer"}))

    def test_no_groups_claim_yields_authenticated_but_no_roles(self) -> None:
        principal = self.resolver.resolve(self._event("no-group-token"))
        self.assertTrue(principal.authenticated)
        self.assertEqual(principal.roles, frozenset())

    def test_invalid_token_is_unauthenticated(self) -> None:
        principal = self.resolver.resolve(self._event("bogus-token"))
        self.assertFalse(principal.authenticated)
        self.assertEqual(principal.roles, frozenset())

    def test_missing_header_is_unauthenticated(self) -> None:
        principal = self.resolver.resolve(self._event(None))
        self.assertFalse(principal.authenticated)

    def test_fake_verifier_raises_on_unknown_token(self) -> None:
        with self.assertRaises(InvalidTokenError):
            self.verifier.verify("nope")


class HttpAdapterCognitoTests(unittest.TestCase):
    """End-to-end through the HTTP adapter wired with the Cognito seam."""

    def setUp(self) -> None:
        self.audit = RecordingAuditSink()
        self.gateway = InMemoryCedarGateway(self.audit)
        self.gateway.activate_permits("v1")
        self.gateway.register("s3_encryption_enablement", _applied_tool)
        self.repo = InMemoryFindingRepository()
        self.repo.upsert(
            Finding(
                finding_id="finding-1",
                rule_id="s3-encryption-missing",
                source="config",
                target=TargetRef("arn:aws:s3:::ccg-demo", "s3_bucket", {"CCGDemo": "true"}),
                severity=Severity.HIGH,
                title="missing encryption",
                evidence_refs=("config:finding-1",),
                status=FindingStatus.OPEN,
                first_seen_at=NOW,
                last_seen_at=NOW,
                correlation_id="corr-1",
            )
        )
        self.evidence = InMemoryDecisionEvidenceRepository()
        self.policy = PolicyActivationService(InMemoryPolicyControlPlane(), self.audit)
        self.api = ComplianceApi(self.gateway, self.policy, self.repo, self.evidence)
        self.verifier = FakeTokenVerifier(
            {"admin-token": {"sub": "admin", "cognito:groups": ["CCGAdmin", "CCGRemediator"]}}
        )
        self.adapter = ApiHttpAdapter.with_cognito_auth(self.api, self.verifier)

    def test_findings_require_valid_token(self) -> None:
        resp = self.adapter.handle({"httpMethod": "GET", "path": "/findings", "headers": {}})
        self.assertEqual(resp["statusCode"], 403)

    def test_findings_with_valid_token(self) -> None:
        resp = self.adapter.handle(
            {
                "httpMethod": "GET",
                "path": "/findings",
                "headers": {"authorization": "Bearer admin-token"},
            }
        )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(len(body["findings"]), 1)

    def test_remediation_and_decision_read_through_adapter(self) -> None:
        remediation = self.adapter.handle(
            {
                "httpMethod": "POST",
                "path": "/remediation",
                "headers": {"authorization": "Bearer admin-token", "x-correlation-id": "corr-xyz"},
                "body": json.dumps(
                    {
                        "request_id": "req-9",
                        "finding_id": "finding-1",
                        "tool": "s3_encryption_enablement",
                        "parameters": {"algorithm": "AES256"},
                        "idempotency_key": "idem-9",
                        "expected_finding_version": 0,
                    }
                ),
            }
        )
        self.assertEqual(remediation["statusCode"], 200)

        decisions = self.adapter.handle(
            {
                "httpMethod": "GET",
                "path": "/decisions",
                "headers": {"authorization": "Bearer admin-token"},
                "queryStringParameters": {"finding_id": "finding-1"},
            }
        )
        self.assertEqual(decisions["statusCode"], 200)
        body = json.loads(decisions["body"])
        self.assertEqual(len(body["decisions"]), 1)
        self.assertEqual(body["decisions"][0]["decision"], "ALLOW")

    def test_decisions_read_requires_auth(self) -> None:
        resp = self.adapter.handle(
            {
                "httpMethod": "GET",
                "path": "/decisions",
                "headers": {},
                "queryStringParameters": {"finding_id": "finding-1"},
            }
        )
        self.assertEqual(resp["statusCode"], 403)

    def test_tool_rule_mismatch_through_adapter_is_400(self) -> None:
        resp = self.adapter.handle(
            {
                "httpMethod": "POST",
                "path": "/remediation",
                "headers": {"authorization": "Bearer admin-token"},
                "body": json.dumps(
                    {
                        "request_id": "req-10",
                        "finding_id": "finding-1",
                        "tool": "access_key_rotation",
                        "parameters": {"identity": "u", "old_access_key_id": "AKIA"},
                        "idempotency_key": "idem-10",
                        "expected_finding_version": 0,
                    }
                ),
            }
        )
        self.assertEqual(resp["statusCode"], 400)


class CorrelationPropagationTests(ControlPlaneTestBase):
    def test_correlation_id_propagates_to_decision_and_audit(self) -> None:
        self.api.request_remediation(self.admin, self.command(correlation_id="corr-trace"))
        evidence = self.api.get_decision_evidence(self.admin, finding_id="finding-1")
        self.assertEqual(evidence[0].correlation_id, "corr-trace")
        gateway_events = [e for e in self.audit.events if e.event_type == "gateway.decision"]
        self.assertTrue(gateway_events)
        self.assertTrue(all(e.correlation_id == "corr-trace" for e in gateway_events))

    def test_adapter_propagates_correlation_header(self) -> None:
        verifier = FakeTokenVerifier(
            {"admin-token": {"sub": "admin", "cognito:groups": ["CCGAdmin", "CCGRemediator"]}}
        )
        adapter = ApiHttpAdapter.with_cognito_auth(self.api, verifier)
        adapter.handle(
            {
                "httpMethod": "POST",
                "path": "/remediation",
                "headers": {"authorization": "Bearer admin-token", "x-correlation-id": "hdr-corr"},
                "body": json.dumps(
                    {
                        "request_id": "req-h",
                        "finding_id": "finding-1",
                        "tool": "s3_encryption_enablement",
                        "parameters": {"algorithm": "AES256"},
                        "idempotency_key": "idem-h",
                        "expected_finding_version": 0,
                    }
                ),
            }
        )
        evidence = self.api.get_decision_evidence(self.admin, request_id="req-h")
        self.assertEqual(evidence[0].correlation_id, "hdr-corr")


if __name__ == "__main__":
    unittest.main()
