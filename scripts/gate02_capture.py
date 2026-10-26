#!/usr/bin/env python3
"""Gate 0.2 capability capture.

Runs the READ-ONLY AWS probes that fill the still-open items in
`docs/AGENTCORE_CAPABILITY_RECORD.md`, and prints a paste-ready report so the
record can be completed in one pass once a sandbox session is active.

It performs NO mutation: only describe/list/get calls. If a live Gateway exists
(created by a reviewed deploy) it captures the gateway-ARN / tool-limit / policy
facts that are "BLOCKED — needs first deploy"; otherwise it reports those as
still-pending and captures everything that is available pre-deploy (identity,
OIDC provider existence, Nova Sonic availability, control-plane model facts).

Usage:
    aws sso login --profile ccg-sandbox      # if the token expired
    AWS_PROFILE=ccg-sandbox python scripts/gate02_capture.py

Exit code is always 0 (status report, not a gate). Every external call is
read-only; the AWS CLI commands are listed in each item for auditability.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class CaptureItem:
    record_section: str   # which AGENTCORE_CAPABILITY_RECORD section/item
    label: str
    captured: bool
    value: str
    command: str          # the read-only command used (for audit)


def _aws(args: list[str], runner=subprocess.run, which=shutil.which) -> tuple[bool, str]:
    """Run a read-only aws CLI command. Returns (ok, stdout-or-error)."""
    if which("aws") is None:
        return False, "AWS CLI not installed"
    try:
        completed = runner(
            ["aws", *args, "--output", "json"],
            capture_output=True, text=True, timeout=60, check=False,
        )
    except Exception as exc:  # noqa: BLE001 - any transport error is non-fatal here.
        return False, f"{type(exc).__name__}"
    if completed.returncode != 0:
        # First line of stderr is the useful bit (rate limit, auth, access denied).
        err = (completed.stderr or "").strip().splitlines()
        return False, (err[0] if err else f"exit {completed.returncode}")
    return True, completed.stdout


def capture_identity(runner=subprocess.run, which=shutil.which) -> CaptureItem:
    cmd = "aws sts get-caller-identity"
    ok, out = _aws(["sts", "get-caller-identity"], runner, which)
    if not ok:
        return CaptureItem("§0", "Caller identity", False, out, cmd)
    acct = str(json.loads(out).get("Account", ""))
    masked = f"...{acct[-4:]}" if len(acct) >= 4 else acct
    return CaptureItem("§0", "Caller identity", True, f"account {masked}", cmd)


def capture_oidc_provider(runner=subprocess.run, which=shutil.which) -> CaptureItem:
    cmd = "aws iam list-open-id-connect-providers"
    ok, out = _aws(["iam", "list-open-id-connect-providers"], runner, which)
    if not ok:
        detail = "AccessDenied (scoped role) - verify via admin/console" if "AccessDenied" in out else out
        return CaptureItem("§0 OIDC provider", "app.terraform.io OIDC provider", False, detail, cmd)
    arns = [p.get("Arn", "") for p in json.loads(out).get("OpenIDConnectProviderList", [])]
    # Match the exact OIDC provider host at the end of the ARN
    # (arn:aws:iam::<acct>:oidc-provider/app.terraform.io), not a loose
    # substring — a substring check would also match e.g. app.terraform.io.evil.
    hit = any(a.endswith("/app.terraform.io") or a.endswith(":oidc-provider/app.terraform.io") for a in arns)
    return CaptureItem("§0 OIDC provider", "app.terraform.io OIDC provider", hit,
                       "present" if hit else f"not found among {len(arns)} providers", cmd)


def capture_gateways(runner=subprocess.run, which=shutil.which) -> CaptureItem:
    cmd = "aws bedrock-agentcore-control list-gateways"
    ok, out = _aws(["bedrock-agentcore-control", "list-gateways", "--max-results", "20"], runner, which)
    if not ok:
        return CaptureItem("§1 Gateway ARN", "Deployed gateway(s)", False, out, cmd)
    items = json.loads(out).get("items", [])
    if not items:
        return CaptureItem("§1 Gateway ARN", "Deployed gateway(s)", False,
                           "none deployed yet (gateway ARN / tool limits still BLOCKED until first deploy)", cmd)
    first = items[0]
    arn = first.get("gatewayArn") or first.get("gatewayId") or "unknown"
    return CaptureItem("§1 Gateway ARN", "Deployed gateway(s)", True,
                       f"{len(items)} gateway(s); first ARN/id: {arn}", cmd)


def capture_policy_engines(runner=subprocess.run, which=shutil.which) -> CaptureItem:
    cmd = "aws bedrock-agentcore-control list-policy-engines"
    ok, out = _aws(["bedrock-agentcore-control", "list-policy-engines", "--max-results", "20"], runner, which)
    if not ok:
        return CaptureItem("§1.7 Policy engine", "Deployed policy engine(s)", False, out, cmd)
    engines = json.loads(out).get("policyEngines", [])
    return CaptureItem("§1.7 Policy engine", "Deployed policy engine(s)", bool(engines),
                       f"{len(engines)} engine(s)" if engines else "none deployed yet", cmd)


def capture_nova_sonic(runner=subprocess.run, which=shutil.which) -> CaptureItem:
    cmd = "aws bedrock list-foundation-models (filter nova-sonic)"
    ok, out = _aws(["bedrock", "list-foundation-models"], runner, which)
    if not ok:
        return CaptureItem("§4.1 Nova Sonic", "Nova Sonic model availability", False, out, cmd)
    ids = [m.get("modelId", "") for m in json.loads(out).get("modelSummaries", [])]
    sonic = [m for m in ids if "nova-2-sonic" in m or "nova-sonic" in m]
    return CaptureItem("§4.1 Nova Sonic", "Nova Sonic model availability", bool(sonic),
                       (", ".join(sonic) if sonic else "no nova-sonic model in this region"), cmd)


def run_all(runner=subprocess.run, which=shutil.which) -> list[CaptureItem]:
    return [
        capture_identity(runner, which),
        capture_oidc_provider(runner, which),
        capture_gateways(runner, which),
        capture_policy_engines(runner, which),
        capture_nova_sonic(runner, which),
    ]


def format_report(items: list[CaptureItem]) -> str:
    lines = ["Gate 0.2 capability capture (read-only)", "=" * 40]
    for it in items:
        mark = "CAPTURED" if it.captured else "PENDING "
        lines.append(f"[{mark}] {it.record_section}: {it.label}")
        lines.append(f"           value : {it.value}")
        lines.append(f"           via   : {it.command}")
    pending = [it.label for it in items if not it.captured]
    lines.append("")
    if pending:
        lines.append(f"{len(pending)} item(s) still pending: {', '.join(pending)}.")
        lines.append("Items needing a live Gateway resolve after the reviewed schema-capture deploy.")
    else:
        lines.append("All probes captured. Paste values into docs/AGENTCORE_CAPABILITY_RECORD.md.")
    return "\n".join(lines)


def main() -> int:
    print(format_report(run_all()))
    return 0  # status report, never a gate


if __name__ == "__main__":
    raise SystemExit(main())
