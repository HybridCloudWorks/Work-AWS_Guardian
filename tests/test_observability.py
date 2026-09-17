import unittest

from ccg.observability import InMemoryMetricSink, Metric, NullMetricSink


class MetricCatalogTests(unittest.TestCase):
    def test_catalog_names_are_stable_and_namespaced(self) -> None:
        self.assertEqual(Metric.GATEWAY_DENY.value, "ccg.gateway.deny")
        self.assertEqual(Metric.ACTIVATION_FAILURE.value, "ccg.policy.activation_failure")
        for metric in Metric:
            self.assertTrue(metric.value.startswith("ccg."))

    def test_catalog_covers_required_signal_families(self) -> None:
        names = {m.value for m in Metric}
        # spot-check each CCG-REQ-037 family is represented
        self.assertTrue(any("discovery" in n for n in names))
        self.assertTrue(any("gateway" in n for n in names))
        self.assertTrue(any("activation" in n for n in names))
        self.assertTrue(any("tool" in n for n in names))
        self.assertTrue(any("voice" in n for n in names))
        self.assertTrue(any("cleanup" in n for n in names))


class InMemoryMetricSinkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sink = InMemoryMetricSink()

    def test_increment_default_value(self) -> None:
        self.sink.increment(Metric.GATEWAY_DENY)
        self.assertEqual(self.sink.count(Metric.GATEWAY_DENY), 1)

    def test_increment_aggregates_by_dimensions(self) -> None:
        self.sink.increment(Metric.TOOL_FAILED, dimensions={"tool": "s3_encryption_enablement"})
        self.sink.increment(Metric.TOOL_FAILED, dimensions={"tool": "s3_encryption_enablement"})
        self.sink.increment(Metric.TOOL_FAILED, dimensions={"tool": "compliant_tagging"})
        self.assertEqual(self.sink.count(Metric.TOOL_FAILED, {"tool": "s3_encryption_enablement"}), 2)
        self.assertEqual(self.sink.count(Metric.TOOL_FAILED, {"tool": "compliant_tagging"}), 1)
        self.assertEqual(self.sink.total(Metric.TOOL_FAILED), 3)

    def test_dimension_order_does_not_matter(self) -> None:
        self.sink.increment(Metric.GATEWAY_DENY, dimensions={"a": "1", "b": "2"})
        self.assertEqual(self.sink.count(Metric.GATEWAY_DENY, {"b": "2", "a": "1"}), 1)

    def test_gauge_retains_last_value(self) -> None:
        self.sink.gauge(Metric.FINDINGS_UPSERTED, 3)
        self.sink.gauge(Metric.FINDINGS_UPSERTED, 5)
        key = ("ccg.discovery.findings_upserted", ())
        self.assertEqual(self.sink.gauges[key], 5)

    def test_non_string_dimensions_rejected(self) -> None:
        with self.assertRaises(TypeError):
            self.sink.increment(Metric.GATEWAY_DENY, dimensions={"count": 3})  # type: ignore[dict-item]


class NullMetricSinkTests(unittest.TestCase):
    def test_null_sink_is_noop(self) -> None:
        sink = NullMetricSink()
        sink.increment(Metric.GATEWAY_ALLOW)
        sink.gauge(Metric.FINDINGS_UPSERTED, 10)
        # nothing to assert other than no exception; it holds no state


if __name__ == "__main__":
    unittest.main()
