#!/usr/bin/env python3
"""Sandbox-only drift seed/cleanup CLI for the CCG demo.

Reviewable workflow replacing the earlier plan-only stub (spec task 3.4). The
dangerous surface is fully gated:

- **Sandbox gate (strict).** Requires ``CCG_SANDBOX=true`` in the environment
  AND ``--sandbox-confirmation I_UNDERSTAND``. Any apply/cleanup is refused
  otherwise.
- **Real dry-run (default ON).** Without ``--apply`` the CLI prints the exact
  resources it WOULD create or delete and performs nothing. The default
  effector is a recorder that cannot contact AWS.
- **Target guard.** Any target carrying ``Environment=prod`` or lacking
  ``CCGDemo=true`` is refused, for both dry-run and apply.
- **Bounded cleanup.** ``--cleanup`` only removes resources this script created,
  identified by the ``CCGSeed=true`` tag plus a known name prefix.

No boto3 call is hardcoded: the mutation seam (``SeedEffector``) defaults to a
dry-run recorder. A real sandbox effector may be injected later under the live
gate. This script never imports the AWS SDK.

Exit codes:
    0  success (plan printed, or apply/cleanup completed)
    2  sandbox gate refused (env or confirmation missing)
    3  target-safety violation (prod / missing demo tag / unbounded cleanup)
    4  usage / configuration error
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import uuid
from typing import Sequence

# Allow running directly from a source checkout (scripts/ sibling to src/).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ccg.seed import (  # noqa: E402  (import after sys.path shim)
    DryRunSeedEffector,
    SeedSafetyError,
    default_scenarios,
    plan_cleanup,
    plan_seed,
    run_cleanup,
    run_seed,
    validate_scenarios,
)

EXIT_OK = 0
EXIT_GATE_REFUSED = 2
EXIT_UNSAFE_TARGET = 3
EXIT_USAGE = 4

CONFIRMATION_PHRASE = "I_UNDERSTAND"
SANDBOX_ENV = "CCG_SANDBOX"


class _JsonLogFormatter(logging.Formatter):
    """Structured JSON log line carrying the run correlation ID."""

    def __init__(self, correlation_id: str) -> None:
        super().__init__()
        self._correlation_id = correlation_id

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "level": record.levelname,
            "component": "seed_drift",
            "correlation_id": self._correlation_id,
            "event": record.getMessage(),
        }
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            payload.update(extra)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _make_logger(correlation_id: str) -> logging.Logger:
    logger = logging.getLogger(f"ccg.seed.{correlation_id}")
    logger.handlers.clear()
    logger.propagate = False
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_JsonLogFormatter(correlation_id))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


def _log(logger: logging.Logger, event: str, **fields: object) -> None:
    logger.info(event, extra={"fields": dict(fields)})


def _sandbox_gate_ok(args: argparse.Namespace) -> bool:
    return (
        os.getenv(SANDBOX_ENV) == "true"
        and args.sandbox_confirmation == CONFIRMATION_PHRASE
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="seed_drift",
        description="Seed or clean up sandbox-only CCG drift scenarios.",
    )
    parser.add_argument(
        "--sandbox-confirmation",
        default="",
        help=f"must be '{CONFIRMATION_PHRASE}' to perform a real apply/cleanup",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="perform the mutation (requires the sandbox gate); default is dry-run",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="delete self-created seed resources instead of creating them",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    correlation_id = str(uuid.uuid4())
    logger = _make_logger(correlation_id)

    action = "cleanup" if args.cleanup else "seed"
    scenarios = default_scenarios()

    # Scenario safety is validated up front for both seed and cleanup paths.
    try:
        validate_scenarios(scenarios)
    except SeedSafetyError as exc:
        _log(logger, "scenario_validation_failed", error=str(exc))
        print(f"Refusing: {exc}", file=sys.stderr)
        return EXIT_UNSAFE_TARGET

    plan = plan_cleanup(scenarios) if args.cleanup else plan_seed(scenarios)
    _log(logger, "plan_computed", action=action, resource_count=len(plan))

    # Dry-run (default): print the plan and perform nothing. The effector is a
    # recorder, so even here no mutation can occur.
    if not args.apply:
        effector = DryRunSeedEffector()
        try:
            if args.cleanup:
                run_cleanup(scenarios, effector)
            else:
                run_seed(scenarios, effector)
        except SeedSafetyError as exc:
            _log(logger, "target_guard_refused", action=action, error=str(exc))
            print(f"Refusing: {exc}", file=sys.stderr)
            return EXIT_UNSAFE_TARGET
        _log(logger, "dry_run_complete", action=action, applied=len(effector.applied))
        print(f"DRY RUN ({action}) — correlation_id={correlation_id}")
        print(f"Would affect {len(plan)} resource(s); nothing was changed. Pass --apply to execute.")
        for entry in plan:
            print("  " + json.dumps(entry, sort_keys=True))
        return EXIT_OK

    # Apply path requires the strict sandbox gate.
    if not _sandbox_gate_ok(args):
        _log(logger, "sandbox_gate_refused", action=action)
        print(
            "Refusing: a dedicated sandbox and explicit confirmation are required "
            f"({SANDBOX_ENV}=true and --sandbox-confirmation {CONFIRMATION_PHRASE}).",
            file=sys.stderr,
        )
        return EXIT_GATE_REFUSED

    effector = DryRunSeedEffector()
    try:
        if args.cleanup:
            run_cleanup(scenarios, effector)
        else:
            run_seed(scenarios, effector)
    except SeedSafetyError as exc:
        _log(logger, "target_guard_refused", action=action, error=str(exc))
        print(f"Refusing: {exc}", file=sys.stderr)
        return EXIT_UNSAFE_TARGET

    _log(
        logger,
        "apply_complete",
        action=action,
        planned=len(effector.planned),
        applied=len(effector.applied),
    )
    print(f"APPLY ({action}) — correlation_id={correlation_id}")
    print(
        "No live effector is wired in this build; the default recorder planned "
        f"{len(effector.planned)} operation(s) and applied {len(effector.applied)}."
    )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
