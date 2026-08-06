#!/usr/bin/env python3
"""Collect the experimental, CPU-only H-010 Poseidon layout benchmark."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.typed_air_poseidon_benchmark_lib import (  # noqa: E402
    BenchmarkError,
    Settings,
    run_benchmark,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--executable",
        type=Path,
        default=(
            ROOT
            / "src/frontends/riscv/zig-out/bin/riscv-poseidon-layout-benchmark"
        ),
        help="already-built ReleaseFast child executable",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="new uncommitted JSON path; an existing path is never replaced",
    )
    parser.add_argument(
        "--include-log-18",
        action="store_true",
        help="add the opt-in stress cohort after required logs 10 and 14",
    )
    parser.add_argument(
        "--power-state",
        required=True,
        help="operator declaration, e.g. 'AC power; low-power mode disabled'",
    )
    parser.add_argument("--run-id", help="optional stable identifier for this host run")
    parser.add_argument("--timeout-seconds", type=float, default=7_200.0)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    settings = Settings(
        executable=args.executable,
        output_path=args.output,
        repo_root=ROOT,
        power_state=args.power_state,
        include_log_18=args.include_log_18,
        timeout_seconds=args.timeout_seconds,
        run_id=args.run_id,
    )
    try:
        _, encoded = run_benchmark(settings)
    except (BenchmarkError, OSError, ValueError) as error:
        print(f"H-010 Poseidon layout benchmark failed: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
