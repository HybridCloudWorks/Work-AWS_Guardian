#!/usr/bin/env python3
"""Gate 0.2 readiness preflight.

Reports whether the local environment is ready to begin the capability-capture
work described in `docs/AGENTCORE_CAPABILITY_RECORD.md`. It is a **status
report, not a gate**: it is read-only, performs no mutation, and always exits 0
so it can run informationally in CI. Each check prints READY or BLOCKED with a
reason, and a final summary lists what still blocks live capture.

The only external command it may run is `aws sts get-caller-identity`, which is
read-only. If the AWS CLI is absent (the expected state until a sandbox account
is configured), the identity check reports BLOCKED rather than failing.

Run:  python scripts/gate02_preflight.py
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
LOCK_FILE = ROOT / ".terraform.lock.hcl"
CAPABILITY_RECORD = ROOT / "docs" / "AGENTCORE_CAPABILITY_RECORD.md"
POLICIES_DIR = ROOT / "policies"

PINNED_PROVIDER = "6.64.0"


@dataclass(frozen=True)
class CheckResult:
    name: str
    ready: bool
    detail: str


def check_aws_identity(runner=subprocess.run, which=shutil.which) -> CheckResult:
    """Read-only: report the caller identity if the AWS CLI is configured."""
    if which("aws") is None:
        return CheckResult("aws_identity", False, "AWS CLI not installed; no sandbox account configured")
    try:
        completed = runner(
            ["aws", "sts", "get-caller-identity", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001 - any transport error is a BLOCKED, not a crash.
        return CheckResult("aws_identity", False, f"could not run get-caller-identity: {type(exc).__name__}")
    if completed.returncode != 0:
        return CheckResult("aws_identity", False, "get-caller-identity failed; no valid credentials")
    try:
        identity = json.loads(completed.stdout)
        account = str(identity.get("Account", ""))
    except (ValueError, AttributeError):
        return CheckResult("aws_identity", False, "get-caller-identity returned unparseable output")
    if not account:
        return CheckResult("aws_identity", False, "no account id in caller identity")
    masked = f"…{account[-4:]}" if len(account) >= 4 else account
    return CheckResult("aws_identity", True, f"authenticated to account {masked}")


def check_terraform(which=shutil.which) -> CheckResult:
    if which("terraform") is None:
        return CheckResult("terraform_cli", False, "terraform not installed")
    return CheckResult("terraform_cli", True, "terraform CLI present")


def check_provider_lock(lock_file: Path = LOCK_FILE) -> CheckResult:
    if not lock_file.exists():
        return CheckResult("provider_lock", False, ".terraform.lock.hcl is missing")
    text = lock_file.read_text(encoding="utf-8")
    pinned = f'version = "{PINNED_PROVIDER}"' in text
    constrained = re.search(rf'constraints\s*=\s*"{re.escape(PINNED_PROVIDER)}"', text) is not None
    if pinned or constrained:
        return CheckResult("provider_lock", True, f"aws provider pinned to {PINNED_PROVIDER}")
    return CheckResult("provider_lock", False, f"aws provider not pinned to {PINNED_PROVIDER}")


def check_capability_record(record: Path = CAPABILITY_RECORD) -> CheckResult:
    if not record.exists():
        return CheckResult("capability_record", False, "capability-record template is missing")
    return CheckResult("capability_record", True, "capability-record template present and ready to fill in")


def check_policies_present(policies_dir: Path = POLICIES_DIR) -> CheckResult:
    guardrails = policies_dir / "guardrails.cedar"
    permits = policies_dir / "remediation-permits.cedar"
    if guardrails.exists() and permits.exists():
        return CheckResult(
            "cedar_intent",
            True,
            "guardrail + permit intent files present (schema reconciliation gated on 0.2)",
        )
    return CheckResult("cedar_intent", False, "cedar intent files missing")


def run_all_checks() -> list[CheckResult]:
    return [
        check_aws_identity(),
        check_terraform(),
        check_provider_lock(),
        check_capability_record(),
        check_policies_present(),
    ]


def format_report(results: list[CheckResult]) -> str:
    lines = ["Gate 0.2 readiness preflight", "=" * 32]
    for result in results:
        marker = "READY  " if result.ready else "BLOCKED"
        lines.append(f"[{marker}] {result.name}: {result.detail}")
    blocked = [r.name for r in results if not r.ready]
    lines.append("")
    if blocked:
        lines.append(f"Live capture BLOCKED. Outstanding: {', '.join(blocked)}.")
        lines.append("The dedicated sandbox AWS account is the primary unblock; fill in")
        lines.append("docs/AGENTCORE_CAPABILITY_RECORD.md once it is configured.")
    else:
        lines.append("All local preflight checks READY. Proceed to capture the live")
        lines.append("AgentCore schema into docs/AGENTCORE_CAPABILITY_RECORD.md.")
    return "\n".join(lines)


def main() -> int:
    print(format_report(run_all_checks()))
    return 0  # status report, never a gate


if __name__ == "__main__":
    raise SystemExit(main())
