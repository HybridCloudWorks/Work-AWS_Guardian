"""AWS Lambda entrypoint for the read/control-plane API.

Invoked by API Gateway (modules/console-api). Wraps :class:`ccg.api.ComplianceApi`.
The API performs NO local authorization of mutations and cannot invoke tool
Lambdas directly — remediation is delegated to the AgentCore Gateway port, and
activation goes through the audited control plane.

SCOPE NOTE (gate-0.2): the live DynamoDB finding resolver, the AgentCore Gateway
transport, and the policy control-plane transport are injected here once their
contracts are captured. Until then the handler returns a structured
"not yet wired" response rather than fabricating AWS behavior.
"""

from __future__ import annotations

import json
import os


def lambda_handler(event=None, context=None) -> dict:
    """Minimal API router stub.

    Routes are documented here; the live ComplianceApi wiring (Cognito claims ->
    AuthenticatedPrincipal, DynamoDB resolver, Gateway + control-plane
    transports) is connected at gate-0.2. Returns 503 until then so the
    deployed endpoint is honest rather than silently empty.
    """
    path = (event or {}).get("rawPath") or (event or {}).get("path") or "/"
    return {
        "statusCode": 503,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(
            {
                "status": "not_yet_wired",
                "detail": "API Lambda deployed; live transports connected at gate-0.2.",
                "path": path,
                "user_pool": os.environ.get("USER_POOL_ID", ""),
            }
        ),
    }
