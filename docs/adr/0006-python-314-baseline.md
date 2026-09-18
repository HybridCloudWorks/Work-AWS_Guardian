# ADR 0006 — Python 3.14 runtime baseline

**Status:** Accepted
**Date:** 2026-09-18

## Context
The original handoff specified Python 3.12. The local interpreter and CI environment moved to 3.14, and the owner directed standardizing on 3.14.

## Decision
Baseline Python 3.14 across `pyproject.toml` (`requires-python >=3.14,<3.15`), `ruff.toml` (`target-version = py314`), and CI (`python-version: "3.14"`, `ruff==0.16.6`). All spec/steering/handoff references updated from 3.12.

## Consequences
- **Positive:** single consistent runtime; the 117-test suite passes on 3.14.
- **Caveat:** AWS Lambda's managed runtime for Python 3.14 must be confirmed available before the discovery/tool Lambdas deploy; if not yet GA, use a container image or the latest supported managed runtime and document the divergence.
- One 3.14-specific quirk already encountered: dataclass module resolution under an `importlib`-loaded script required registering the module in `sys.modules` (see `tests/test_gate02_preflight.py`).
