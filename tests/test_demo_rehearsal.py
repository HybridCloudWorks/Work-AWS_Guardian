"""End-to-end tests for the offline demo rehearsal (spec task 6.4).

These assert the whole demo script runs offline over the four seeded drift
scenarios and that every invariant holds: denied-before-activation, audited
activation, allowed-after, single-execution-vs-safe-no-op, idempotent replay,
and reconciliation to RESOLVED. They also assert the evidence report carries
each required artifact (decision outcomes, audit event types, metric counts,
finding status, voice barge-in flag) and that every seeded resource is
attributable to the POC and bounded for cleanup.
"""

from __future__ import annotations

import unittest

from ccg.rehearsal import run_rehearsal
from ccg.seed import (
    SEED_MARKER_TAG,
    SEED_MARKER_VALUE,
    SEED_NAME_PREFIX,
    default_scenarios,
)


class RehearsalEndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = run_rehearsal(with_voice=True)

    def test_overall_rehearsal_passes(self) -> None:
        self.assertTrue(self.result.ok)
        self.assertEqual(self.result.activation_outcome, "ACTIVATED")
        self.assertEqual(self.result.effective_policy_version, "v1")

    def test_all_four_scenarios_present(self) -> None:
        ids = {ev.scenario_id for ev in self.result.scenarios}
        self.assertEqual(
            ids,
            {
                "unencrypted-s3",
                "untagged-resource",
                "old-test-access-key",
                "permissive-security-group",
            },
        )

    def test_every_scenario_denied_before_activation(self) -> None:
        for ev in self.result.scenarios:
            with self.subTest(scenario=ev.scenario_id):
                self.assertTrue(ev.denied_before_activation)

    def test_every_scenario_allowed_after_activation(self) -> None:
        for ev in self.result.scenarios:
            with self.subTest(scenario=ev.scenario_id):
                self.assertTrue(ev.allowed_after_activation)

    def test_single_execution_or_safe_noop(self) -> None:
        # APPLIED scenarios mutate exactly once; NOOP scenarios never mutate.
        for ev in self.result.scenarios:
            with self.subTest(scenario=ev.scenario_id):
                self.assertIn(ev.tool_outcome, {"APPLIED", "NOOP"})
                expected = 1 if ev.tool_outcome == "APPLIED" else 0
                self.assertEqual(ev.tool_executions, expected)

    def test_every_scenario_idempotent(self) -> None:
        for ev in self.result.scenarios:
            with self.subTest(scenario=ev.scenario_id):
                self.assertTrue(ev.idempotent_replay)

    def test_every_scenario_resolves(self) -> None:
        for ev in self.result.scenarios:
            with self.subTest(scenario=ev.scenario_id):
                self.assertEqual(ev.final_status, "RESOLVED")

    def test_both_apply_and_noop_paths_exercised(self) -> None:
        # The rehearsal must prove BOTH the apply path and the safe no-op path,
        # not accidentally collapse to one of them.
        outcomes = {ev.tool_outcome for ev in self.result.scenarios}
        self.assertIn("APPLIED", outcomes)
        self.assertIn("NOOP", outcomes)

    def test_audit_trail_orders_deny_before_activation_before_execution(self) -> None:
        types = self.result.audit_event_types
        self.assertIn("gateway.decision", types)
        self.assertIn("policy.activation.result", types)
        self.assertIn("remediation.execution", types)
        first_decision = types.index("gateway.decision")
        activation = types.index("policy.activation.result")
        first_execution = types.index("remediation.execution")
        self.assertLess(first_decision, activation)  # denied before activation
        self.assertLess(activation, first_execution)  # executed only after activation

    def test_audit_trail_contains_resolution_per_scenario(self) -> None:
        resolved = [t for t in self.result.audit_event_types if t == "reconcile.resolved"]
        self.assertEqual(len(resolved), len(self.result.scenarios))

    def test_metrics_show_expected_counts(self) -> None:
        metrics = self.result.metrics
        n = len(self.result.scenarios)
        # One deny per scenario while permits were inactive.
        self.assertEqual(metrics["ccg.gateway.deny"], n)
        # Two allowed invocations per scenario after activation (apply/no-op + replay).
        self.assertEqual(metrics["ccg.gateway.allow"], 2 * n)
        # Two discovery runs: the initial detection and the confirming re-read.
        self.assertEqual(metrics["ccg.discovery.run"], 2)
        # Applied-count matches the APPLIED scenarios; the rest are no-ops/replays.
        applied = sum(1 for ev in self.result.scenarios if ev.tool_outcome == "APPLIED")
        self.assertEqual(metrics["ccg.tool.applied"], applied)
        # No tool ever failed.
        self.assertEqual(metrics.get("ccg.tool.failed", 0), 0)

    def test_voice_barge_in_path(self) -> None:
        self.assertIsNotNone(self.result.voice)
        assert self.result.voice is not None
        self.assertTrue(self.result.voice.requested)
        self.assertEqual(self.result.voice.status, "AVAILABLE")
        self.assertTrue(self.result.voice.interrupted)
        self.assertEqual(self.result.metrics["ccg.voice.session"], 1)

    def test_voice_is_optional(self) -> None:
        no_voice = run_rehearsal(with_voice=False)
        self.assertIsNone(no_voice.voice)
        self.assertNotIn("ccg.voice.session", no_voice.metrics)
        # The chain itself still passes without voice.
        self.assertTrue(no_voice.ok)

    def test_seed_plan_covers_all_scenarios_as_dry_run(self) -> None:
        # The seed step records a create plan for every scenario and mutates
        # nothing (dry-run effector).
        self.assertEqual(len(self.result.seed_plan), len(default_scenarios()))
        for entry in self.result.seed_plan:
            self.assertEqual(entry["op"], "CREATE")

    def test_all_seeded_resources_are_attributable_and_bounded(self) -> None:
        # Every seeded target must carry CCGDemo=true + CCGSeed=true and the
        # ccg-seed- name prefix, so all resources are attributable to the POC
        # and bounded for cleanup.
        for scenario in default_scenarios():
            with self.subTest(scenario=scenario.scenario_id):
                target = scenario.target
                self.assertEqual(target.tags.get("CCGDemo"), "true")
                self.assertEqual(target.tags.get(SEED_MARKER_TAG), SEED_MARKER_VALUE)
                self.assertIn(SEED_NAME_PREFIX, target.arn)
                self.assertFalse(target.is_production)

    def test_rehearsal_targets_match_seeded_targets(self) -> None:
        seeded = {s.target.arn for s in default_scenarios()}
        rehearsed = {ev.target_arn for ev in self.result.scenarios}
        self.assertEqual(rehearsed, seeded)


if __name__ == "__main__":
    unittest.main()
