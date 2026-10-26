"""Tests for the gate-0.2 capability-capture probes (fake AWS output)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

_SPEC = importlib.util.spec_from_file_location(
    "gate02_capture", Path(__file__).resolve().parents[1] / "scripts" / "gate02_capture.py"
)
cap = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = cap
_SPEC.loader.exec_module(cap)


def _runner(stdout="", returncode=0, stderr=""):
    def run(*args, **kwargs):
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)
    return run


def _have_aws(_):
    return "/usr/bin/aws"


def test_identity_masks_account():
    out = json.dumps({"Account": "936361168441"})
    item = cap.capture_identity(runner=_runner(out), which=_have_aws)
    assert item.captured
    assert "8441" in item.value and "936361168441" not in item.value


def test_identity_no_credentials_is_pending():
    item = cap.capture_identity(runner=_runner(returncode=255, stderr="Unable to locate credentials"), which=_have_aws)
    assert not item.captured


def test_oidc_provider_detected():
    out = json.dumps({"OpenIDConnectProviderList": [{"Arn": "arn:aws:iam::1:oidc-provider/app.terraform.io"}]})
    item = cap.capture_oidc_provider(runner=_runner(out), which=_have_aws)
    assert item.captured and "present" in item.value


def test_oidc_rejects_spoofed_lookalike_host():
    # CodeQL py/incomplete-url-substring-sanitization guard: a lookalike host
    # must NOT be treated as the real app.terraform.io provider.
    out = json.dumps({"OpenIDConnectProviderList": [{"Arn": "arn:aws:iam::1:oidc-provider/app.terraform.io.evil.com"}]})
    item = cap.capture_oidc_provider(runner=_runner(out), which=_have_aws)
    assert not item.captured


def test_oidc_access_denied_is_actionable():
    item = cap.capture_oidc_provider(runner=_runner(returncode=254, stderr="AccessDenied ..."), which=_have_aws)
    assert not item.captured
    assert "admin/console" in item.value  # tells the operator how to verify


def test_gateways_none_yet():
    item = cap.capture_gateways(runner=_runner(json.dumps({"items": []})), which=_have_aws)
    assert not item.captured
    assert "none deployed" in item.value


def test_gateways_present_captures_arn():
    out = json.dumps({"items": [{"gatewayArn": "arn:aws:bedrock-agentcore:us-east-1:1:gateway/gw-abc"}]})
    item = cap.capture_gateways(runner=_runner(out), which=_have_aws)
    assert item.captured and "gw-abc" in item.value


def test_nova_sonic_available():
    out = json.dumps({"modelSummaries": [{"modelId": "amazon.nova-2-sonic-v1:0"}, {"modelId": "amazon.nova-pro-v1:0"}]})
    item = cap.capture_nova_sonic(runner=_runner(out), which=_have_aws)
    assert item.captured and "nova-2-sonic" in item.value


def test_nova_sonic_absent_in_region():
    out = json.dumps({"modelSummaries": [{"modelId": "amazon.nova-pro-v1:0"}]})
    item = cap.capture_nova_sonic(runner=_runner(out), which=_have_aws)
    assert not item.captured


def test_missing_cli_is_pending_not_crash():
    item = cap.capture_identity(runner=_runner(), which=lambda _: None)
    assert not item.captured and "not installed" in item.value


def test_report_and_main_exit_zero():
    items = cap.run_all(runner=_runner(returncode=255, stderr="no creds"), which=_have_aws)
    report = cap.format_report(items)
    assert "capability capture" in report
    assert cap.main() == 0
