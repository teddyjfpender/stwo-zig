#!/usr/bin/env python3
"""Measure Native CUDA lifecycle, steady requests and paired structural classes."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from native_cuda_benchmark_lib import (  # noqa: E402
    COVERAGE_MATRIX,
    PROFILES,
    BenchmarkError,
    Settings,
    run_benchmark,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--candidate-bin",
        type=Path,
        default=ROOT / "zig-out/bin/stwo-zig-native-cuda",
    )
    parser.add_argument("--baseline-bin", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--profile",
        choices=tuple(PROFILES),
        default="screen",
    )
    parser.add_argument("--warmups", type=int)
    parser.add_argument("--samples", type=int)
    parser.add_argument("--rounds", type=int)
    parser.add_argument("--cold-samples", type=int)
    parser.add_argument("--cooldown-seconds", type=float, default=0.25)
    parser.add_argument("--timeout-seconds", type=float, default=3600.0)
    parser.add_argument("--device", default="0")
    parser.add_argument("--bootstrap-resamples", type=int, default=100_000)
    parser.add_argument("--rust-oracle-bin", type=Path)
    parser.add_argument("--rust-oracle-sha256")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    profile = PROFILES[args.profile]
    selected = {
        workload_id
        for workload_id in profile.workload_ids
    }
    settings = Settings(
        candidate_bin=args.candidate_bin.resolve(),
        baseline_bin=(
            args.baseline_bin.resolve()
            if args.baseline_bin is not None
            else None
        ),
        output_path=args.output.resolve(),
        repo_root=ROOT,
        profile_name=args.profile,
        warmups=(
            profile.warmups if args.warmups is None else args.warmups
        ),
        samples=(
            profile.samples if args.samples is None else args.samples
        ),
        rounds=profile.rounds if args.rounds is None else args.rounds,
        cold_samples=(
            profile.cold_samples
            if args.cold_samples is None
            else args.cold_samples
        ),
        cooldown_seconds=args.cooldown_seconds,
        timeout_seconds=args.timeout_seconds,
        device_ordinal=args.device,
        bootstrap_resamples=args.bootstrap_resamples,
        workloads=tuple(
            workload
            for workload in COVERAGE_MATRIX
            if workload.workload_id in selected
        ),
        rust_oracle_bin=(
            args.rust_oracle_bin.resolve()
            if args.rust_oracle_bin is not None
            else None
        ),
        rust_oracle_sha256=args.rust_oracle_sha256,
    )
    try:
        _, encoded = run_benchmark(settings)
    except (BenchmarkError, OSError, ValueError) as error:
        print(f"Native CUDA benchmark failed: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
