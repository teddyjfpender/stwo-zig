#!/usr/bin/env python3
"""Capture the bounded six-example Native CPU/Metal profiler baseline."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from native_profile_capture_lib import (  # noqa: E402
    COUNTER_WORKLOADS,
    METAL_MAX_ENCODERS_PER_COMMAND_BUFFER,
    PROFILE_WORKLOADS,
    CaptureError,
    CaptureSettings,
    run_capture,
)


ROOT = Path(os.environ.get("STWO_ZIG_EXECUTION_ROOT", SCRIPT_DIR.parent)).resolve()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(tempfile.gettempdir()) / "stwo-native-profile-capture",
    )
    parser.add_argument(
        "--cpu-bin",
        type=Path,
        default=ROOT / "zig-out/bin/stwo-zig-native-cpu-bench",
    )
    parser.add_argument(
        "--metal-bin",
        type=Path,
        default=ROOT / "zig-out/bin/native-proof-bench-metal",
    )
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--sample-duration-seconds", type=int, default=1)
    parser.add_argument("--cooldown-seconds", type=float, default=1.0)
    parser.add_argument("--timeout-seconds", type=float, default=900.0)
    parser.add_argument(
        "--encoder-counter-workload",
        choices=COUNTER_WORKLOADS,
        default="blake",
        help="one Metal workload that must provide stage-boundary encoder timestamps",
    )
    parser.add_argument(
        "--metal-max-encoders",
        type=int,
        default=METAL_MAX_ENCODERS_PER_COMMAND_BUFFER,
    )
    parser.add_argument(
        "--blake2-backend",
        choices=("auto", "scalar", "simd"),
        default="auto",
    )
    parser.add_argument(
        "--metal-runtime",
        choices=("source-jit", "authenticated-aot"),
        default="source-jit",
    )
    parser.add_argument("--metal-aot-bundle", type=Path)
    parser.add_argument("--metal-aot-manifest-sha256")
    args = parser.parse_args(argv)
    if not 0 <= args.warmups <= 3:
        parser.error("--warmups must be in [0, 3]")
    if not 1 <= args.sample_duration_seconds <= 10:
        parser.error("--sample-duration-seconds must be in [1, 10]")
    if not 0.0 <= args.cooldown_seconds <= 30.0:
        parser.error("--cooldown-seconds must be in [0, 30]")
    if not 0.0 < args.timeout_seconds <= 3600.0:
        parser.error("--timeout-seconds must be in (0, 3600]")
    if not 1 <= args.metal_max_encoders <= METAL_MAX_ENCODERS_PER_COMMAND_BUFFER:
        parser.error(
            "--metal-max-encoders must be in "
            f"[1, {METAL_MAX_ENCODERS_PER_COMMAND_BUFFER}]"
        )
    if args.metal_runtime == "source-jit":
        if args.metal_aot_bundle is not None or args.metal_aot_manifest_sha256 is not None:
            parser.error("AOT options require --metal-runtime authenticated-aot")
    elif args.metal_aot_bundle is None or args.metal_aot_manifest_sha256 is None:
        parser.error("authenticated AOT requires bundle and manifest SHA-256")
    return args


def settings_from_args(args: argparse.Namespace, argv: list[str]) -> CaptureSettings:
    return CaptureSettings(
        output_dir=args.output_dir,
        cpu_bin=args.cpu_bin,
        metal_bin=args.metal_bin,
        workloads=PROFILE_WORKLOADS,
        warmups=args.warmups,
        sample_duration_seconds=args.sample_duration_seconds,
        cooldown_seconds=args.cooldown_seconds,
        timeout_seconds=args.timeout_seconds,
        encoder_counter_workload=args.encoder_counter_workload,
        metal_max_encoders=args.metal_max_encoders,
        blake2_backend=args.blake2_backend,
        metal_runtime=args.metal_runtime,
        metal_aot_bundle=args.metal_aot_bundle,
        metal_aot_manifest_sha256=args.metal_aot_manifest_sha256,
        controller_command=[sys.executable, str(Path(__file__).resolve()), *argv],
    )


def main(argv: list[str] | None = None) -> int:
    effective_argv = sys.argv[1:] if argv is None else argv
    args = parse_args(effective_argv)
    try:
        result = run_capture(settings_from_args(args, effective_argv))
    except (CaptureError, OSError, ValueError) as error:
        print(f"native profile capture failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
