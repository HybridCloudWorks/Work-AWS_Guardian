import importlib.util
import io
import json
import os
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

from ccg.contracts import TargetRef
from ccg.seed import (
    SEED_MARKER_TAG,
    SEED_NAME_PREFIX,
    DryRunSeedEffector,
    SeedSafetyError,
    default_scenarios,
    guard_cleanup_target,
    guard_target,
    is_self_created,
    run_cleanup,
    run_seed,
    validate_scenarios,
)

# Load the CLI module by path (scripts/ is not an importable package).
_CLI_PATH = Path(__file__).resolve().parents[1] / "scripts" / "seed_drift.py"
_spec = importlib.util.spec_from_file_location("seed_drift_cli", _CLI_PATH)
assert _spec and _spec.loader
seed_cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(seed_cli)


def _demo_seed_target(arn: str = f"arn:aws:s3:::{SEED_NAME_PREFIX}x") -> TargetRef:
    return TargetRef(arn, "s3_bucket", {"CCGDemo": "true", SEED_MARKER_TAG: "true"})


class TargetGuardTests(unittest.TestCase):
    def test_rejects_prod_target(self) -> None:
        target = TargetRef(
            f"arn:aws:s3:::{SEED_NAME_PREFIX}p",
            "s3_bucket",
            {"CCGDemo": "true", "Environment": "prod", SEED_MARKER_TAG: "true"},
        )
        with self.assertRaises(SeedSafetyError):
            guard_target(target)

    def test_rejects_missing_demo_tag(self) -> None:
        target = TargetRef(f"arn:aws:s3:::{SEED_NAME_PREFIX}n", "s3_bucket", {SEED_MARKER_TAG: "true"})
        with self.assertRaises(SeedSafetyError):
            guard_target(target)

    def test_accepts_demo_seed_target(self) -> None:
        guard_target(_demo_seed_target())  # no raise


class CleanupBoundTests(unittest.TestCase):
    def test_self_created_requires_marker_and_prefix(self) -> None:
        self.assertTrue(is_self_created(_demo_seed_target()))
        # Missing marker tag.
        self.assertFalse(
            is_self_created(TargetRef(f"arn:aws:s3:::{SEED_NAME_PREFIX}x", "s3_bucket", {"CCGDemo": "true"}))
        )
        # Missing name prefix.
        self.assertFalse(
            is_self_created(
                TargetRef(
                    "arn:aws:s3:::real-bucket",
                    "s3_bucket",
                    {"CCGDemo": "true", SEED_MARKER_TAG: "true"},
                )
            )
        )

    def test_cleanup_refuses_target_without_seed_convention(self) -> None:
        unmarked = TargetRef("arn:aws:s3:::real-bucket", "s3_bucket", {"CCGDemo": "true"})
        with self.assertRaises(SeedSafetyError):
            guard_cleanup_target(unmarked)

    def test_cleanup_only_targets_seed_tagged_resources(self) -> None:
        effector = DryRunSeedEffector()
        run_cleanup(default_scenarios(), effector)
        self.assertTrue(effector.planned)
        for op in effector.planned:
            self.assertEqual(op["op"], "DELETE")
            self.assertIn(SEED_NAME_PREFIX, str(op["target_arn"]))


class ScenarioTests(unittest.TestCase):
    def test_three_to_five_scenarios(self) -> None:
        self.assertTrue(3 <= len(default_scenarios()) <= 5)

    def test_all_scenarios_demo_tagged_none_prod(self) -> None:
        for scenario in default_scenarios():
            self.assertTrue(scenario.target.is_demo)
            self.assertFalse(scenario.target.is_production)
            self.assertTrue(is_self_created(scenario.target))

    def test_validate_rejects_prod_scenario(self) -> None:
        good = default_scenarios()
        from dataclasses import replace

        bad_target = TargetRef(
            good[0].target.arn,
            good[0].target.resource_type,
            {**dict(good[0].target.tags), "Environment": "prod"},
        )
        tampered = (replace(good[0], target=bad_target),) + good[1:]
        with self.assertRaises(SeedSafetyError):
            validate_scenarios(tampered)

    def test_validate_rejects_scenario_missing_demo_tag(self) -> None:
        good = default_scenarios()
        from dataclasses import replace

        bad_target = TargetRef(good[0].target.arn, good[0].target.resource_type, {SEED_MARKER_TAG: "true"})
        tampered = (replace(good[0], target=bad_target),) + good[1:]
        with self.assertRaises(SeedSafetyError):
            validate_scenarios(tampered)


class DryRunEffectorTests(unittest.TestCase):
    def test_dry_run_records_plan_but_applies_nothing(self) -> None:
        effector = DryRunSeedEffector()
        run_seed(default_scenarios(), effector)
        self.assertEqual(len(effector.planned), len(default_scenarios()))
        self.assertEqual(effector.applied, [])


class CliSandboxGateTests(unittest.TestCase):
    def _run(self, argv, env):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env, clear=False):
            with redirect_stdout(out), redirect_stderr(err):
                code = seed_cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_apply_refused_without_sandbox_env(self) -> None:
        env = {k: v for k, v in os.environ.items()}
        env.pop("CCG_SANDBOX", None)
        code, _, err = self._run(["--apply", "--sandbox-confirmation", "I_UNDERSTAND"], env)
        self.assertEqual(code, seed_cli.EXIT_GATE_REFUSED)
        self.assertIn("Refusing", err)

    def test_apply_refused_without_confirmation(self) -> None:
        code, _, err = self._run(["--apply"], {"CCG_SANDBOX": "true"})
        self.assertEqual(code, seed_cli.EXIT_GATE_REFUSED)
        self.assertIn("Refusing", err)

    def test_dry_run_performs_no_mutation_and_needs_no_gate(self) -> None:
        env = {k: v for k, v in os.environ.items()}
        env.pop("CCG_SANDBOX", None)
        code, out, _ = self._run([], env)
        self.assertEqual(code, seed_cli.EXIT_OK)
        self.assertIn("DRY RUN", out)
        self.assertIn("nothing was changed", out)

    def test_apply_allowed_with_full_gate(self) -> None:
        code, out, _ = self._run(
            ["--apply", "--sandbox-confirmation", "I_UNDERSTAND"],
            {"CCG_SANDBOX": "true"},
        )
        self.assertEqual(code, seed_cli.EXIT_OK)
        self.assertIn("APPLY", out)
        # Default recorder applies nothing even on the apply path.
        self.assertIn("applied 0", out)

    def test_correlation_id_present_in_structured_log(self) -> None:
        env = {k: v for k, v in os.environ.items()}
        env.pop("CCG_SANDBOX", None)
        code, out, err = self._run([], env)
        self.assertEqual(code, seed_cli.EXIT_OK)
        # Structured JSON log lines go to stderr and carry a correlation_id.
        log_lines = [line for line in err.splitlines() if line.strip().startswith("{")]
        self.assertTrue(log_lines)
        for line in log_lines:
            record = json.loads(line)
            self.assertIn("correlation_id", record)
            self.assertTrue(record["correlation_id"])
        # The same correlation id is surfaced to the operator on stdout.
        self.assertIn("correlation_id=", out)


if __name__ == "__main__":
    unittest.main()
