"""AWS Lambda entrypoint for the scheduled discovery run.

Invoked by EventBridge (modules/discovery). Wraps the pure
:class:`ccg.discovery.DiscoveryCoordinator`. Read-only by construction.

SCOPE NOTE (gate-0.2): the live source adapters (Config / Security Hub /
CloudTrail via boto3) and the DynamoDB/S3 persistence adapters are injected
here once gate-0.2 confirms the read-only discovery role and source behavior.
Until then the handler wires the coordinator with no sources and emits a
structured run summary, so the package is real and deployable while performing
no live AWS calls.
"""

from __future__ import annotations

import os
from uuid import uuid4

from .discovery import DiscoveryCoordinator
from .observability import NullMetricSink
from .testing import InMemoryFindingRepository, RecordingAuditSink


def lambda_handler(event=None, context=None) -> dict:
    """Run one discovery pass and return a JSON-able summary.

    Environment (set by Terraform): FINDINGS_TABLE_NAME, AUDIT_BUCKET_NAME,
    LOG_GROUP_NAME. The live adapters replace the in-memory doubles at gate-0.2.
    """
    correlation_id = str((event or {}).get("correlation_id") or uuid4())

    # gate-0.2: construct boto3-backed source adapters + DynamoDB/S3 repos here,
    # keyed off the environment below. Until then, run with no sources so the
    # handler is a valid, inert entrypoint (no AWS calls, no fabricated findings).
    sources: list = []
    repository = InMemoryFindingRepository()
    audit = RecordingAuditSink()

    coordinator = DiscoveryCoordinator(
        sources, repository, audit_sink=audit, metrics=NullMetricSink()
    )
    run = coordinator.run(correlation_id)
    return {
        "run_id": run.run_id,
        "correlation_id": run.correlation_id,
        "signals_seen": run.signals_seen,
        "findings_upserted": run.findings_upserted,
        "failures": list(run.failures),
        "findings_table": os.environ.get("FINDINGS_TABLE_NAME", ""),
        "live_adapters_wired": False,  # flips true at gate-0.2
    }
