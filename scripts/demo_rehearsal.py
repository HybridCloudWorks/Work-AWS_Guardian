#!/usr/bin/env python3
"""Run the complete offline CCG demo rehearsal (spec task 6.4).

Thin CLI wrapper over :func:`ccg.rehearsal.run_rehearsal`. It chains all demo
steps across the four seeded drift scenarios through the faithful AgentCore
emulator with **no AWS calls**, prints a structured evidence report, and exits
non-zero if any invariant fails.

The live sandbox rehearsal (real AWS targets, real Gateway decision, real
CloudWatch metrics) is a separate step gated on 0.2 and documented in
``docs/DEMO_REHEARSAL.md``; it is not executed here.

Usage::

    PYTHONPATH=src python scripts/demo_rehearsal.py            # with voice briefing
    PYTHONPATH=src python scripts/demo_rehearsal.py --no-voice # chain only

Exit codes:
    0  every rehearsal invariant held
    1  an invariant failed
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Sequence

# Allow running directly from a source checkout (scripts/ sibling to src/).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ccg.rehearsal import main  # noqa: E402  (import after sys.path shim)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="demo_rehearsal",
        description="Run the offline CCG demo rehearsal over the seeded drift scenarios.",
    )
    parser.add_argument(
        "--no-voice",
        action="store_true",
        help="skip the optional read-only voice briefing step",
    )
    return parser


def _cli(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return main(with_voice=not args.no_voice)


if __name__ == "__main__":
    raise SystemExit(_cli())
