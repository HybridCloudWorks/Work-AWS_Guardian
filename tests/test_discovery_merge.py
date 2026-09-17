from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from ccg.contracts import DiscoverySignal, FindingStatus, Severity, TargetRef
from ccg.discovery import (
    DiscoveryCoordinator,
    derive_finding_id,
    merge_finding,
    normalize_signal,
)
from ccg.testing import InMemoryFindingRepository, StaticDiscoverySource

BASE = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)


def make_signal(**overrides) -> DiscoverySignal:
    params = {
        "signal_id": "signal-1",
        "rule_id": "s3-encryption",
        "source": "config",
        "target": TargetRef("arn:aws:s3:::ccg-demo", "s3_bucket", {"CCGDemo": "true"}),
        "severity": Severity.HIGH,
        "title": "Bucket encryption is missing",
        "evidence_refs": ("config:signal-1",),
        "detected_at": BASE,
        "correlation_id": "corr-1",
        "attributes": {},
    }
    params.update(overrides)
    return DiscoverySignal(**params)


class NormalizeAndMergeTests(unittest.TestCase):
    def test_finding_id_is_deterministic_from_rule_and_arn(self) -> None:
        signal = make_signal()
        self.assertEqual(
            normalize_signal(signal).finding_id,
            derive_finding_id("s3-encryption", "arn:aws:s3:::ccg-demo"),
        )

    def test_new_finding_starts_at_revision_zero(self) -> None:
        merged, changed = merge_finding(None, normalize_signal(make_signal()))
        self.assertTrue(changed)
        self.assertEqual(merged.revision, 0)
        self.assertEqual(merged.status, FindingStatus.OPEN)

    def test_identical_reobservation_is_a_noop(self) -> None:
        first, _ = merge_finding(None, normalize_signal(make_signal()))
        merged, changed = merge_finding(first, normalize_signal(make_signal()))
        self.assertFalse(changed)
        self.assertEqual(merged.revision, 0)
        self.assertEqual(merged.last_seen_at, first.last_seen_at)

    def test_later_reobservation_advances_last_seen_without_revision_bump(self) -> None:
        first, _ = merge_finding(None, normalize_signal(make_signal()))
        later = make_signal(detected_at=BASE + timedelta(minutes=15))
        merged, changed = merge_finding(first, normalize_signal(later))
        self.assertTrue(changed)  # last_seen advanced
        self.assertEqual(merged.revision, 0)  # but content is identical
        self.assertEqual(merged.first_seen_at, first.first_seen_at)
        self.assertEqual(merged.last_seen_at, BASE + timedelta(minutes=15))

    def test_content_change_bumps_revision_and_preserves_first_seen(self) -> None:
        first, _ = merge_finding(None, normalize_signal(make_signal()))
        escalated = make_signal(severity=Severity.CRITICAL, detected_at=BASE + timedelta(minutes=15))
        merged, changed = merge_finding(first, normalize_signal(escalated))
        self.assertTrue(changed)
        self.assertEqual(merged.revision, 1)
        self.assertEqual(merged.severity, Severity.CRITICAL)
        self.assertEqual(merged.first_seen_at, first.first_seen_at)

    def test_never_regresses_last_seen_for_out_of_order_signal(self) -> None:
        first, _ = merge_finding(None, normalize_signal(make_signal(detected_at=BASE)))
        stale = make_signal(detected_at=BASE - timedelta(hours=1))
        merged, _ = merge_finding(first, normalize_signal(stale))
        self.assertEqual(merged.last_seen_at, BASE)

    def test_inflight_lifecycle_status_is_preserved_by_discovery(self) -> None:
        first, _ = merge_finding(None, normalize_signal(make_signal()))
        in_flight = replace(first, status=FindingStatus.REMEDIATION_REQUESTED)
        merged, _ = merge_finding(in_flight, normalize_signal(make_signal(detected_at=BASE + timedelta(minutes=1))))
        self.assertEqual(merged.status, FindingStatus.REMEDIATION_REQUESTED)


class CoordinatorDedupTests(unittest.TestCase):
    def test_repeated_runs_do_not_duplicate_or_churn_revision(self) -> None:
        repo = InMemoryFindingRepository()
        source = StaticDiscoverySource("config", [make_signal()])
        DiscoveryCoordinator([source], repo).run("corr-1")
        DiscoveryCoordinator([source], repo).run("corr-1")
        self.assertEqual(len(repo.findings), 1)
        self.assertEqual(next(iter(repo.findings.values())).revision, 0)

    def test_duplicate_signal_within_one_run_is_deduplicated(self) -> None:
        repo = InMemoryFindingRepository()
        source = StaticDiscoverySource("config", [make_signal(), make_signal()])
        run = DiscoveryCoordinator([source], repo).run("corr-1")
        self.assertEqual(run.signals_seen, 2)
        self.assertEqual(run.findings_upserted, 1)
        self.assertEqual(len(repo.findings), 1)
        self.assertEqual(next(iter(repo.findings.values())).revision, 0)


if __name__ == "__main__":
    unittest.main()
