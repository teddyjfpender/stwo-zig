#!/usr/bin/env python3
"""Deterministic parity gate for constraint-expression vectors.

Default mode:
- Regenerate vectors into a temporary file.
- Compare with committed vectors/constraint_expr.json.
- Fail on mismatch.
- Run `zig build test` unless --skip-zig is passed.

Regenerate mode:
- Overwrite vectors/constraint_expr.json.
- Run `zig build test` unless --skip-zig is passed.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GEN_MANIFEST = ROOT / "tools" / "stwo-cf-vector-gen" / "Cargo.toml"
VECTORS_DIR = ROOT / "vectors"
COMMITTED = VECTORS_DIR / "constraint_expr.json"
TMP = VECTORS_DIR / ".constraint_expr.tmp.json"


def run(cmd: list[str], cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=cwd or ROOT, check=True)


def run_generator(out_path: Path) -> None:
    run(
        [
            "cargo",
            "+nightly-2025-07-14",
            "run",
            "--quiet",
            "--manifest-path",
            str(GEN_MANIFEST),
            "--",
            "--out",
            str(out_path),
        ]
    )


def load_json(path: Path) -> object:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    parser = argparse.ArgumentParser(description="Constraint-expression parity gate")
    parser.add_argument(
        "--regenerate",
        action="store_true",
        help="Regenerate committed vectors/constraint_expr.json in-place",
    )
    parser.add_argument(
        "--skip-zig",
        action="store_true",
        help="Skip `zig build test` after vector verification/regeneration",
    )
    args = parser.parse_args()

    VECTORS_DIR.mkdir(parents=True, exist_ok=True)

    if args.regenerate:
        run_generator(COMMITTED)
    else:
        run_generator(TMP)
        if not COMMITTED.exists():
            print(
                f"missing committed vectors file: {COMMITTED}\n"
                f"run: {Path(__file__).name} --regenerate",
                file=sys.stderr,
            )
            return 1

        committed_json = load_json(COMMITTED)
        generated_json = load_json(TMP)
        TMP.unlink(missing_ok=True)
        if committed_json != generated_json:
            print(
                "constraint expression vectors are out of date.\n"
                f"run: {Path(__file__).name} --regenerate",
                file=sys.stderr,
            )
            return 1

    if not args.skip_zig:
        run(["zig", "build", "test"])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
