#!/usr/bin/env python3
"""Reproducible build of the CCG Lambda deployment package.

Produces a single deterministic zip containing the `ccg` package (all handlers)
that every Lambda in the Terraform modules shares. Deterministic = stable file
order + fixed timestamps, so the artifact hash only changes when code changes
(which is what Terraform `source_code_hash` keys on).

Usage:
    python scripts/build_lambda_package.py [--out dist/ccg_lambda.zip]

Prints the base64 sha256 (the value Terraform expects for source_code_hash).
No third-party deps; the package is pure-Python (no bundled libraries today).
boto3 is provided by the Lambda runtime, so it is intentionally NOT vendored.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import pathlib
import zipfile

REPO = pathlib.Path(__file__).resolve().parents[1]
PKG = REPO / "src" / "ccg"
# Test-only doubles should not ship in the runtime artifact.
EXCLUDE = {"testing.py", "demo.py", "rehearsal.py"}
FIXED_TS = (1980, 1, 1, 0, 0, 0)  # zip epoch floor → deterministic


def _sources() -> list[pathlib.Path]:
    return sorted(
        p for p in PKG.rglob("*.py")
        if "__pycache__" not in p.parts and p.name not in EXCLUDE
    )


def build(out: pathlib.Path) -> str:
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for src in _sources():
            arc = "ccg/" + str(src.relative_to(PKG)).replace("\\", "/")
            info = zipfile.ZipInfo(arc, date_time=FIXED_TS)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, src.read_bytes())
    digest = hashlib.sha256(out.read_bytes()).digest()
    return base64.b64encode(digest).decode("ascii")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(REPO / "dist" / "ccg_lambda.zip"))
    args = ap.parse_args()
    out = pathlib.Path(args.out)
    b64 = build(out)
    count = len(_sources())
    print(f"built {out} ({out.stat().st_size} bytes, {count} modules)")
    print(f"source_code_hash (base64 sha256): {b64}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
