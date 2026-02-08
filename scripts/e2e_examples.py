#!/usr/bin/env python3
"""Cross-language examples parity harness.

This harness validates the examples parity milestone by combining:
1. Rust vector generation (`tools/stwo-vector-gen`) for deterministic fixtures.
2. Zig test execution (`zig build test`) for vector consumption and parity checks.
3. A machine-readable report with section coverage counts.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GEN_MANIFEST = ROOT / "tools" / "stwo-vector-gen" / "Cargo.toml"
VECTORS_DIR = ROOT / "vectors"
COMMITTED = VECTORS_DIR / "fields.json"
TMP = VECTORS_DIR / ".fields.examples.tmp.json"
DEFAULT_REPORT = ROOT / "vectors" / "reports" / "examples_parity_report.json"

EXAMPLE_KEYS = (
    "example_state_machine_trace",
    "example_state_machine_transitions",
    "example_state_machine_claimed_sum",
    "example_xor_is_first",
    "example_xor_is_step_with_offset",
    "example_wide_fibonacci_trace",
    "example_plonk_trace",
)


def run(cmd: list[str], cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=cwd or ROOT, check=True)


def run_generator(out_path: Path, count: int) -> None:
    run(
        [
            "cargo",
            "run",
            "--quiet",
            "--manifest-path",
            str(GEN_MANIFEST),
            "--",
            "--out",
            str(out_path),
            "--count",
            str(count),
        ]
    )


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise ValueError(f"expected object at root in {path}")
    return obj


def section_counts(vectors: dict) -> dict[str, int]:
    counts: dict[str, int] = {}
    for key in EXAMPLE_KEYS:
        value = vectors.get(key)
        if not isinstance(value, list):
            raise ValueError(f"missing or non-list vector section: {key}")
        if len(value) == 0:
            raise ValueError(f"empty example vector section: {key}")
        counts[key] = len(value)
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Examples cross-language parity harness")
    parser.add_argument("--count", type=int, default=256)
    parser.add_argument(
        "--regenerate",
        action="store_true",
        help="Regenerate committed vectors/fields.json in-place before running checks",
    )
    parser.add_argument(
        "--skip-zig",
        action="store_true",
        help="Skip `zig build test` execution",
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        default=DEFAULT_REPORT,
        help="Path for JSON report output",
    )
    args = parser.parse_args()

    VECTORS_DIR.mkdir(parents=True, exist_ok=True)

    if args.regenerate:
        run_generator(COMMITTED, args.count)
    else:
        run_generator(TMP, args.count)
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
                "field vectors are out of date.\n"
                f"run: {Path(__file__).name} --regenerate",
                file=sys.stderr,
            )
            return 1

    vectors = load_json(COMMITTED)
    counts = section_counts(vectors)

    zig_ran = not args.skip_zig
    if zig_ran:
        run(["zig", "build", "test"])

    report = {
        "status": "ok",
        "vectors_file": str(COMMITTED.relative_to(ROOT)),
        "meta": {
            "upstream_commit": vectors.get("meta", {}).get("upstream_commit"),
            "schema_version": vectors.get("meta", {}).get("schema_version"),
            "sample_count": vectors.get("meta", {}).get("sample_count"),
        },
        "example_section_counts": counts,
        "gates": {
            "vectors_regenerated": bool(args.regenerate),
            "vectors_match_committed": not args.regenerate,
            "zig_build_test_ran": zig_ran,
        },
    }

    report_out = args.report_out
    report_out.parent.mkdir(parents=True, exist_ok=True)
    with report_out.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")

    # Optional convenience copy for downstream tooling expecting latest report.
    latest = report_out.parent / "latest_examples_parity_report.json"
    if latest != report_out:
        shutil.copyfile(report_out, latest)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
