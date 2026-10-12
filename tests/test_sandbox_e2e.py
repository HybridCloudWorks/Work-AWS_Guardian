"""Gated, sandbox-only end-to-end test scaffold (spec task 6.1).

This module documents and scaffolds the ONE flow that the offline matrix cannot
prove on its own: the full chain executed against a *live* AWS sandbox account —

    discovery -> deny (permits inactive) -> audited activation ->
    allow / safe no-op -> rediscovery reflects the result.

It is **skipped by default** and makes **no AWS calls** unless explicitly opted
in. Running it requires BOTH:

* ``CCG_SANDBOX_E2E=1`` — the operator intent flag (mirrors the ``CCG_SANDBOX``
  gate used by ``scripts/seed_drift.py`` / ``tests/test_seed.py``); and
* the live-AWS wiring from implementation gate **0.2** (real AgentCore Gateway
  schema + control-plane activation API, Cognito, Terraform-applied sandbox).

Until 0.2 is complete the body is intentionally a scaffold: it records the exact
ordered steps and assertions so the live test is a mechanical fill-in, not a
redesign. The offline ``tests/test_demo.py`` (which already runs the same chain
through the *faithful AgentCore transport emulator*) is this test's faithful
stand-in in CI today — see ``docs/TEST_TRACEABILITY.md``.

NOTHING here calls boto3 or touches AWS. The scaffold asserts only on its own
plan structure so that, when skipped, it is inert, and when un-skipped before
0.2, it fails loudly with a clear "gated on 0.2" message instead of silently
passing.
"""

from __future__ import annotations

import os
import unittest

# Operator intent flag. Default (unset / not "1") => the whole module is skipped.
_E2E_ENABLED = os.environ.get("CCG_SANDBOX_E2E") == "1"

# The ordered steps the live sandbox e2e MUST perform, each tied to the
# acceptance scenario(s) it proves against real AWS. Kept as data so the plan is
# reviewable now and the live implementation is a mechanical fill-in post-0.2.
E2E_STEPS: tuple[tuple[str, str], ...] = (
    ("discover", "ACC-01: a seeded CCGDemo finding is discovered with one correlation id"),
    ("deny_inactive", "ACC-02: a registered mutation is denied while permits are inactive"),
    ("activate", "ACC-08: an admin activates a versioned permit set via the control plane"),
    ("allow_or_noop", "ACC-03/ACC-07: the same request is allowed and the tool applies once (or safe no-op)"),
    ("rediscover", "ACC-14: a subsequent discovery confirms the desired state before marking resolved"),
)


@unittest.skipUnless(
    _E2E_ENABLED,
    "sandbox e2e is skipped unless CCG_SANDBOX_E2E=1 (and gated on implementation gate 0.2)",
)
class SandboxEndToEndTests(unittest.TestCase):
    """Live-sandbox chain. Skipped by default; no AWS calls in this scaffold."""

    def test_e2e_is_gated_on_0_2(self) -> None:
        # Reaching here means CCG_SANDBOX_E2E=1 was set. The live wiring is gated
        # on 0.2; fail loudly rather than pretend to exercise AWS. Replace this
        # body with the real chain once the 0.2 contract is captured.
        self.fail(
            "Sandbox e2e requested (CCG_SANDBOX_E2E=1) but the live-AWS path is "
            "gated on implementation gate 0.2 (AgentCore Gateway schema + "
            "control-plane activation API, Cognito, Terraform-applied sandbox). "
            "Until then, tests/test_demo.py is the faithful offline stand-in. "
            "Implement the ordered steps documented in E2E_STEPS here."
        )


class SandboxEndToEndPlanTests(unittest.TestCase):
    """Always-on, offline guards on the e2e *plan* (no AWS, never skipped).

    These keep the scaffold honest: the documented chain stays complete and in
    the discover -> deny -> activate -> allow/no-op -> rediscover order even
    before the live body exists.
    """

    def test_plan_covers_full_chain_in_order(self) -> None:
        names = [name for name, _ in E2E_STEPS]
        self.assertEqual(
            names,
            ["discover", "deny_inactive", "activate", "allow_or_noop", "rediscover"],
        )

    def test_every_step_names_a_covering_acceptance_scenario(self) -> None:
        for _name, description in E2E_STEPS:
            self.assertIn("ACC-", description)

    def test_disabled_by_default(self) -> None:
        # In the normal CI/dev environment the opt-in flag is absent, so the
        # live class is skipped and no AWS calls can occur.
        if "CCG_SANDBOX_E2E" not in os.environ:
            self.assertFalse(_E2E_ENABLED)


if __name__ == "__main__":
    unittest.main()
