#!/usr/bin/env python3
"""Profiling smoke harness for parity workloads.

Collects coarse wall-clock and peak RSS data using `/usr/bin/time -l` when available.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REPORT_DEFAULT = ROOT / "vectors" / "reports" / "profile_smoke_report.json"
GEN_MANIFEST = ROOT / "tools" / "stwo-vector-gen" / "Cargo.toml"
TMP_VECTORS = ROOT / "vectors" / ".profile.fields.tmp.json"
RSS_RE = re.compile(r"^\s*(\d+)\s+maximum resident set size\s*$", re.MULTILINE)
TIME_BIN = Path("/usr/bin/time")


def run_profiled(name: str, cmd: list[str]) -> dict:
    start = time.perf_counter()

    if TIME_BIN.exists():
        proc = subprocess.run(
            [str(TIME_BIN), "-l", *cmd],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        stderr = proc.stderr
        match = RSS_RE.search(stderr)
        peak_rss_kb = int(match.group(1)) if match else None
    else:
        subprocess.run(cmd, cwd=ROOT, check=True)
        stderr = ""
        peak_rss_kb = None

    elapsed = time.perf_counter() - start
    return {
        "name": name,
        "command": cmd,
        "seconds": round(elapsed, 6),
        "peak_rss_kb": peak_rss_kb,
        "time_stderr": stderr.splitlines()[-8:] if stderr else [],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Profile smoke harness")
    parser.add_argument("--count", type=int, default=128)
    parser.add_argument(
        "--report-out",
        type=Path,
        default=REPORT_DEFAULT,
        help="Path for JSON report output",
    )
    args = parser.parse_args()

    steps = [
        run_profiled(
            "rust_vector_generation_profile",
            [
                "cargo",
                "run",
                "--quiet",
                "--manifest-path",
                str(GEN_MANIFEST),
                "--",
                "--out",
                str(TMP_VECTORS),
                "--count",
                str(args.count),
            ],
        ),
        run_profiled(
            "zig_state_machine_wrapper_profile",
            [
                "zig",
                "test",
                "src/stwo.zig",
                "--test-filter",
                "examples state_machine: prove/verify wrapper roundtrip",
            ],
        ),
        run_profiled(
            "zig_xor_wrapper_profile",
            [
                "zig",
                "test",
                "src/stwo.zig",
                "--test-filter",
                "examples xor: prove/verify wrapper roundtrip",
            ],
        ),
    ]

    TMP_VECTORS.unlink(missing_ok=True)

    report = {
        "status": "ok",
        "collector": "time -l" if TIME_BIN.exists() else "wall-clock-only",
        "workloads": steps,
    }

    out = args.report_out
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")

    latest = out.parent / "latest_profile_smoke_report.json"
    if latest != out:
        shutil.copyfile(out, latest)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
