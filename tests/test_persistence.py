from datetime import datetime, timezone
import unittest

from ccg.contracts import Finding, FindingStatus, Severity, TargetRef
from ccg.testing import InMemoryFindingRepository

NOW = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)


def finding(**overrides) -> Finding:
    params = {
        "finding_id": "f-1",
        "rule_id": "s3-encryption",
        "source": "config",
        "target": TargetRef("arn:aws:s3:::ccg-demo", "s3_bucket", {"CCGDemo": "true"}),
        "severity": Severity.HIGH,
        "title": "missing encryption",
        "evidence_refs": ("config:f-1",),
        "status": FindingStatus.OPEN,
        "first_seen_at": NOW,
        "last_seen_at": NOW,
        "correlation_id": "corr-1",
    }
    params.update(overrides)
    return Finding(**params)


class RepositoryIdempotencyTests(unittest.TestCase):
    def test_reupsert_same_id_replaces_not_duplicates(self) -> None:
        repo = InMemoryFindingRepository()
        repo.upsert(finding())
        repo.upsert(finding(title="updated title"))
        self.assertEqual(len(repo.list_findings()), 1)
        self.assertEqual(repo.get("f-1").title, "updated title")

    def test_get_missing_returns_none(self) -> None:
        self.assertIsNone(InMemoryFindingRepository().get("nope"))

    def test_resolve_target_matches_stored_finding(self) -> None:
        repo = InMemoryFindingRepository()
        repo.upsert(finding())
        self.assertEqual(repo.resolve_target("f-1").arn, "arn:aws:s3:::ccg-demo")


class RetentionAndSerializationTests(unittest.TestCase):
    def test_finding_record_carries_retention_relevant_fields(self) -> None:
        # These fields drive the finding lifecycle and the audit-history record
        # (30-day S3 audit / DynamoDB current state). Their presence in the
        # serialized contract is a stability guarantee for storage consumers.
        record = finding().to_record()
        for key in (
            "finding_id",
            "schema_version",
            "first_seen_at",
            "last_seen_at",
            "revision",
            "status",
            "correlation_id",
        ):
            self.assertIn(key, record)

    def test_timestamps_serialize_as_utc_iso(self) -> None:
        record = finding().to_record()
        self.assertTrue(str(record["first_seen_at"]).endswith("+00:00"))
        self.assertTrue(str(record["last_seen_at"]).endswith("+00:00"))

    def test_default_schema_version_and_revision(self) -> None:
        f = finding()
        self.assertEqual(f.schema_version, "1")
        self.assertEqual(f.revision, 0)

    def test_serialization_is_deterministic(self) -> None:
        self.assertEqual(finding().to_json(), finding().to_json())


if __name__ == "__main__":
    unittest.main()
