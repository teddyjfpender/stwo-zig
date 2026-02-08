#!/usr/bin/env python3
"""Benchmark smoke harness for Rust/Zig parity slices.

Runs deterministic short workloads and emits machine-readable timing data.
This is a smoke gate, not a full performance benchmark protocol.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REPORT_DEFAULT = ROOT / "vectors" / "reports" / "benchmark_smoke_report.json"
GEN_MANIFEST = ROOT / "tools" / "stwo-vector-gen" / "Cargo.toml"
TMP_VECTORS = ROOT / "vectors" / ".bench.fields.tmp.json"


def run(cmd: list[str], cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=cwd or ROOT, check=True)


def timed_run(name: str, cmd: list[str], repeats: int) -> dict:
    samples: list[float] = []
    for _ in range(repeats):
        start = time.perf_counter()
        run(cmd)
        samples.append(time.perf_counter() - start)

    return {
        "name": name,
        "command": cmd,
        "repeats": repeats,
        "samples_seconds": [round(v, 6) for v in samples],
        "min_seconds": round(min(samples), 6),
        "max_seconds": round(max(samples), 6),
        "avg_seconds": round(sum(samples) / len(samples), 6),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark smoke harness")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--count", type=int, default=128)
    parser.add_argument(
        "--report-out",
        type=Path,
        default=REPORT_DEFAULT,
        help="Path for JSON report output",
    )
    args = parser.parse_args()

    if args.repeats <= 0:
        raise ValueError("--repeats must be positive")

    steps = [
        timed_run(
            "rust_vector_generation",
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
            args.repeats,
        ),
        timed_run(
            "zig_state_machine_wrapper_roundtrip",
            [
                "zig",
                "test",
                "src/stwo.zig",
                "--test-filter",
                "examples state_machine: prove/verify wrapper roundtrip",
            ],
            args.repeats,
        ),
        timed_run(
            "zig_xor_wrapper_roundtrip",
            [
                "zig",
                "test",
                "src/stwo.zig",
                "--test-filter",
                "examples xor: prove/verify wrapper roundtrip",
            ],
            args.repeats,
        ),
    ]

    TMP_VECTORS.unlink(missing_ok=True)

    rust_avg = steps[0]["avg_seconds"]
    zig_avg = (steps[1]["avg_seconds"] + steps[2]["avg_seconds"]) / 2.0

    report = {
        "status": "ok",
        "workloads": steps,
        "summary": {
            "rust_avg_seconds": rust_avg,
            "zig_avg_seconds": round(zig_avg, 6),
            "zig_over_rust_ratio": round((zig_avg / rust_avg) if rust_avg > 0 else 0.0, 6),
        },
    }

    out = args.report_out
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")

    latest = out.parent / "latest_benchmark_smoke_report.json"
    if latest != out:
        shutil.copyfile(out, latest)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
