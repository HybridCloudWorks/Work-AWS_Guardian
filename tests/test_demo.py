import unittest

from ccg.demo import run_demo


class EndToEndDemoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.result = run_demo()

    def test_denied_before_activation(self) -> None:
        self.assertTrue(self.result.denied_before_activation)
        self.assertEqual(self.result.deny_reason, "permit set is inactive")

    def test_activation_then_allow(self) -> None:
        self.assertEqual(self.result.activation_outcome, "ACTIVATED")
        self.assertTrue(self.result.allowed_after_activation)

    def test_tool_executes_exactly_once(self) -> None:
        self.assertEqual(self.result.tool_outcome, "APPLIED")
        self.assertEqual(self.result.tool_executions, 1)

    def test_repeat_is_idempotent(self) -> None:
        self.assertTrue(self.result.idempotent_replay)

    def test_reconciles_to_resolved(self) -> None:
        self.assertEqual(self.result.final_status, "RESOLVED")

    def test_audit_trail_ordering(self) -> None:
        # deny decision must precede activation; execution must follow activation.
        types = self.result.audit_event_types
        self.assertIn("policy.activation.result", types)
        self.assertIn("remediation.execution", types)
        first_decision = types.index("gateway.decision")
        activation = types.index("policy.activation.result")
        execution = types.index("remediation.execution")
        self.assertLess(first_decision, activation)  # denied before activation
        self.assertLess(activation, execution)  # executed only after activation


if __name__ == "__main__":
    unittest.main()
