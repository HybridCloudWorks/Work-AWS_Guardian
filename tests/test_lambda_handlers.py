"""Tests for the Lambda handler entrypoints and the package build."""

from __future__ import annotations

import base64
import subprocess
import sys
from pathlib import Path

from ccg import api_handler, discovery_handler, voice_handler
from ccg.contracts import ToolOutcome
from ccg.tools import (
    key_rotation_handler,
    s3_encryption_handler,
    sg_correction_handler,
    tagging_handler,
)

REPO = Path(__file__).resolve().parents[1]


def _event(tool, parameters, tags=None):
    return {
        "request_id": "req-1",
        "correlation_id": "corr-1",
        "actor": "admin",
        "tool": tool,
        "target": {
            "arn": "arn:aws:s3:::acme-ccg-demo",
            "resource_type": "s3_bucket",
            "tags": tags if tags is not None else {"CCGDemo": "true"},
        },
        "parameters": parameters,
        "idempotency_key": "idem-1",
    }



def test_s3_handler_noop_on_compliant():
    params = {"algorithm": "AES256", "currently_encrypted": True, "current_algorithm": "AES256"}
    out = s3_encryption_handler(_event("s3_encryption_enablement", params))
    assert out["outcome"] == ToolOutcome.NOOP.value


def test_s3_handler_applies_via_dry_run():
    out = s3_encryption_handler(_event("s3_encryption_enablement", {"algorithm": "AES256"}))
    assert out["outcome"] in (ToolOutcome.APPLIED.value, ToolOutcome.NOOP.value)


def test_tool_handler_rejects_prod_target():
    out = sg_correction_handler(
        _event("security_group_correction", {"rule_id": "r1", "proposed_cidr": "10.0.0.0/24"},
               tags={"CCGDemo": "true", "Environment": "prod"})
    )
    assert out["outcome"] == ToolOutcome.FAILED.value


def test_tool_handler_malformed_event_fails_safely():
    out = tagging_handler({"not": "an event"})
    assert out["outcome"] == ToolOutcome.FAILED.value
    assert out["changed"] is False


def test_key_rotation_handler_dry_run_default():
    out = key_rotation_handler(
        _event("access_key_rotation", {"identity": "ccg-demo", "old_access_key_id": "AKIAEXAMPLE"},
               tags={"CCGDemo": "true"})
    )
    assert out["outcome"] == ToolOutcome.NOOP.value  # dry-run unless confirm=true
    assert "SecretAccessKey" not in str(out)


def test_discovery_handler_runs_empty_and_reports():
    out = discovery_handler.lambda_handler({"correlation_id": "c-1"})
    assert out["correlation_id"] == "c-1"
    assert out["findings_upserted"] == 0
    assert out["live_adapters_wired"] is False


def test_api_handler_returns_503_until_wired():
    out = api_handler.lambda_handler({"rawPath": "/findings"})
    assert out["statusCode"] == 503


def test_voice_handler_returns_unavailable():
    out = voice_handler.lambda_handler({})
    assert out["statusCode"] == 503


def test_package_build_is_deterministic_and_excludes_doubles():
    import zipfile
    out = REPO / "dist" / "ccg_lambda_test.zip"
    script = REPO / "scripts" / "build_lambda_package.py"
    r1 = subprocess.run([sys.executable, str(script), "--out", str(out)], capture_output=True, text=True)
    assert r1.returncode == 0, r1.stderr
    names = zipfile.ZipFile(out).namelist()
    assert "ccg/discovery_handler.py" in names
    assert "ccg/testing.py" not in names  # test double excluded
    assert "ccg/demo.py" not in names
    h1 = base64.b64encode((out).read_bytes())
    r2 = subprocess.run([sys.executable, str(script), "--out", str(out)], capture_output=True, text=True)
    assert r2.returncode == 0
    h2 = base64.b64encode((out).read_bytes())
    assert h1 == h2  # byte-identical rebuild
    out.unlink()
