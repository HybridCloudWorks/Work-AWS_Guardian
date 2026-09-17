import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

# Load the script module directly (scripts/ is not a package). Register it in
# sys.modules before exec so @dataclass can resolve its own module (required on
# Python 3.14).
_SPEC = importlib.util.spec_from_file_location(
    "gate02_preflight",
    Path(__file__).resolve().parents[1] / "scripts" / "gate02_preflight.py",
)
gate02 = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = gate02
_SPEC.loader.exec_module(gate02)


class AwsIdentityCheckTests(unittest.TestCase):
    def test_blocked_when_cli_absent(self) -> None:
        result = gate02.check_aws_identity(which=lambda _: None)
        self.assertFalse(result.ready)
        self.assertIn("not installed", result.detail)

    def test_ready_and_masks_account(self) -> None:
        def fake_run(*args, **kwargs):
            return SimpleNamespace(returncode=0, stdout=json.dumps({"Account": "123456789012"}), stderr="")

        result = gate02.check_aws_identity(runner=fake_run, which=lambda _: "/usr/bin/aws")
        self.assertTrue(result.ready)
        self.assertIn("9012", result.detail)  # masked to last 4
        self.assertNotIn("123456789012", result.detail)  # full id not leaked

    def test_blocked_on_nonzero_exit(self) -> None:
        def fake_run(*args, **kwargs):
            return SimpleNamespace(returncode=255, stdout="", stderr="denied")

        result = gate02.check_aws_identity(runner=fake_run, which=lambda _: "/usr/bin/aws")
        self.assertFalse(result.ready)

    def test_blocked_on_unparseable_output(self) -> None:
        def fake_run(*args, **kwargs):
            return SimpleNamespace(returncode=0, stdout="not-json", stderr="")

        result = gate02.check_aws_identity(runner=fake_run, which=lambda _: "/usr/bin/aws")
        self.assertFalse(result.ready)


class ProviderLockCheckTests(unittest.TestCase):
    def test_ready_when_pinned(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            lock = Path(d) / ".terraform.lock.hcl"
            lock.write_text('provider "x" {\n  version = "6.64.0"\n}\n', encoding="utf-8")
            result = gate02.check_provider_lock(lock)
            self.assertTrue(result.ready)

    def test_blocked_when_missing(self) -> None:
        result = gate02.check_provider_lock(Path("/nonexistent/.terraform.lock.hcl"))
        self.assertFalse(result.ready)


class ReportTests(unittest.TestCase):
    def test_report_lists_blocked_checks(self) -> None:
        results = [
            gate02.CheckResult("a", True, "ok"),
            gate02.CheckResult("b", False, "nope"),
        ]
        report = gate02.format_report(results)
        self.assertIn("[READY  ] a", report)
        self.assertIn("[BLOCKED] b", report)
        self.assertIn("Outstanding: b", report)

    def test_main_always_exits_zero(self) -> None:
        self.assertEqual(gate02.main(), 0)

    def test_real_repo_checks_run(self) -> None:
        # Against the real repo: terraform lock, capability record, cedar files
        # should all be READY; aws identity is expected BLOCKED locally.
        results = {r.name: r for r in gate02.run_all_checks()}
        self.assertTrue(results["provider_lock"].ready)
        self.assertTrue(results["capability_record"].ready)
        self.assertTrue(results["cedar_intent"].ready)


if __name__ == "__main__":
    unittest.main()
