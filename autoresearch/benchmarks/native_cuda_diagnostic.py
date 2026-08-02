#!/usr/bin/env python3
"""Run the fixed, fail-closed Native CUDA cold-process diagnostic matrix."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.native_cuda_diagnostic_lib import (  # noqa: E402
    DiagnosticError,
    Settings,
    run_diagnostic,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--product-bin",
        type=Path,
        default=ROOT / "zig-out/bin/stwo-zig-native-cuda",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cold-samples", type=int, default=3)
    parser.add_argument("--cooldown-seconds", type=float, default=1.0)
    parser.add_argument("--timeout-seconds", type=float, default=3600.0)
    parser.add_argument("--device", default="0")
    parser.add_argument(
        "--execution-mode",
        choices=("graphs", "direct"),
        default="graphs",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    settings = Settings(
        product_bin=args.product_bin.resolve(),
        output_path=args.output.resolve(),
        repo_root=ROOT,
        cold_samples=args.cold_samples,
        cooldown_seconds=args.cooldown_seconds,
        timeout_seconds=args.timeout_seconds,
        device_ordinal=args.device,
        execution_mode=args.execution_mode,
    )
    try:
        _, encoded = run_diagnostic(settings)
    except (DiagnosticError, OSError, ValueError) as error:
        print(f"Native CUDA diagnostic failed: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
