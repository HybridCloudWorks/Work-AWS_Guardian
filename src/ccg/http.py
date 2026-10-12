"""Small HTTP/Lambda-neutral adapter for the typed compliance API.

A deployment adapter can pass API Gateway events into this class. It does not
contain AWS clients or local authorization decisions for remediation.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import json
from uuid import uuid4

from .api import AuthenticatedPrincipal, ComplianceApi, UnauthorizedError
from .auth import PrincipalResolver, TokenVerifier
from .contracts import PolicyActivationRequest, RemediationCommand


class ApiHttpAdapter:
    def __init__(
        self,
        service: ComplianceApi,
        principal_resolver: Callable[[Mapping[str, object]], AuthenticatedPrincipal],
    ) -> None:
        self._service = service
        self._principal_resolver = principal_resolver

    @classmethod
    def with_cognito_auth(
        cls,
        service: ComplianceApi,
        verifier: TokenVerifier,
    ) -> "ApiHttpAdapter":
        """Build an adapter whose principal is resolved from a Cognito JWT.

        The ``verifier`` validates the bearer token (RS256 signature against the
        Cognito JWKS plus ``iss``/``aud``/``exp`` in production). A failed or
        missing token resolves to an unauthenticated principal, which the
        service rejects — the adapter fails closed with a 403.
        """
        return cls(service, PrincipalResolver(verifier))

    def handle(self, event: Mapping[str, object]) -> dict[str, object]:
        try:
            principal = self._principal_resolver(event)
            method = str(event.get("httpMethod", "")).upper()
            path = str(event.get("path", ""))
            if method == "GET" and path == "/policy":
                return self._response(200, self._service.get_policy_state(principal).to_record())
            if method == "GET" and path == "/findings":
                findings = [finding.to_record() for finding in self._service.get_findings(principal)]
                return self._response(200, {"findings": findings})
            if method == "GET" and path == "/decisions":
                query = self._query(event)
                finding_id = query.get("finding_id")
                request_id = query.get("request_id")
                evidence = self._service.get_decision_evidence(
                    principal,
                    finding_id=str(finding_id) if finding_id else None,
                    request_id=str(request_id) if request_id else None,
                )
                return self._response(
                    200, {"decisions": [record.to_record() for record in evidence]}
                )
            if method == "POST" and path == "/policy/activation":
                body = self._body(event)
                request = PolicyActivationRequest(
                    request_id=str(body.get("request_id", uuid4())),
                    correlation_id=self._correlation_id(event),
                    actor=principal.actor,
                    requested_version=str(body["requested_version"]),
                    expected_generation=int(body["expected_generation"]),
                    reason=str(body["reason"]),
                    activate=self._strict_bool(body["activate"]),
                )
                return self._response(200, self._service.change_policy_state(principal, request).to_record())
            if method == "POST" and path == "/remediation":
                body = self._body(event)
                parameters = body.get("parameters", {})
                if not isinstance(parameters, Mapping):
                    raise ValueError("parameters must be an object")
                command = RemediationCommand(
                    request_id=str(body.get("request_id", uuid4())),
                    correlation_id=self._correlation_id(event),
                    actor=principal.actor,
                    finding_id=str(body["finding_id"]),
                    tool=str(body["tool"]),
                    parameters=dict(parameters),
                    idempotency_key=str(body["idempotency_key"]),
                    expected_finding_version=self._strict_int(body["expected_finding_version"]),
                )
                result = self._service.request_remediation(principal, command)
                return self._response(200, result.to_record())
            return self._response(404, {"error": "not found"})
        except UnauthorizedError as exc:
            return self._response(403, {"error": str(exc)})
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return self._response(400, {"error": f"invalid request: {type(exc).__name__}"})

    @staticmethod
    def _body(event: Mapping[str, object]) -> dict[str, object]:
        raw_body = event.get("body", {})
        if isinstance(raw_body, str):
            parsed = json.loads(raw_body)
        else:
            parsed = raw_body
        if not isinstance(parsed, dict):
            raise ValueError("body must be an object")
        return parsed

    @staticmethod
    def _query(event: Mapping[str, object]) -> Mapping[str, object]:
        params = event.get("queryStringParameters") or {}
        if not isinstance(params, Mapping):
            raise ValueError("queryStringParameters must be an object")
        return params

    @staticmethod
    def _correlation_id(event: Mapping[str, object]) -> str:
        headers = event.get("headers", {})
        if isinstance(headers, Mapping):
            return str(headers.get("x-correlation-id") or headers.get("X-Correlation-Id") or uuid4())
        return str(uuid4())

    @staticmethod
    def _response(status_code: int, body: Mapping[str, object]) -> dict[str, object]:
        return {
            "statusCode": status_code,
            "headers": {"content-type": "application/json"},
            "body": json.dumps(body, sort_keys=True, separators=(",", ":")),
        }

    @staticmethod
    def _strict_bool(value: object) -> bool:
        if not isinstance(value, bool):
            raise ValueError("boolean value required")
        return value

    @staticmethod
    def _strict_int(value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("integer value required")
        return value
