"""AWS Lambda entrypoint for the read-only Nova Sonic voice adapter.

Invoked by the console (modules/voice-adapter), OFF by default (CCG-REQ-032).
Provides read-only finding summaries only; exposes no mutation tool and cannot
reach the Gateway mutation surface. Raw audio is not retained (RETAIN_AUDIO).

SCOPE NOTE (gate-0.3): the live Nova Sonic bidirectional stream + browser
transport are wired here once the model/region/quota contract is verified.
Until then the handler returns a disabled/unavailable response.
"""

from __future__ import annotations

import json
import os


def lambda_handler(event=None, context=None) -> dict:
    """Return a safe unavailable response until gate-0.3 wires Nova Sonic."""
    return {
        "statusCode": 503,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(
            {
                "status": "voice_unavailable",
                "detail": "Voice adapter deployed but off; Nova Sonic wired at gate-0.3.",
                "retain_audio": os.environ.get("RETAIN_AUDIO", "false"),
            }
        ),
    }
