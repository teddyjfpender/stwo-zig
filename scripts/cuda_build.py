#!/usr/bin/env python3
"""Build the pinned Stwo CUDA archive directly, without a Rust runtime."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from cuda_build_lib.builder import (
    BuildConfig,
    BuildError,
    Toolchain,
    build_plan,
    execute,
    normalize_sms,
    resolve_tool,
)


ROOT = Path(__file__).resolve().parents[1]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument(
        "--source-root",
        type=Path,
        default=ROOT / "src/backends/cuda/vendor/upstream",
    )
    result.add_argument(
        "--source-manifest",
        type=Path,
        default=ROOT / "src/backends/cuda/source_manifest.json",
    )
    result.add_argument(
        "--native-root",
        type=Path,
        default=ROOT / "src/backends/cuda/native",
    )
    result.add_argument("--out-dir", type=Path, required=True)
    result.add_argument("--nvcc", required=True)
    result.add_argument("--host-cxx", required=True)
    result.add_argument("--ar", default="ar")
    result.add_argument("--cuda-home", type=Path, required=True)
    result.add_argument("--cuda-library-dir", type=Path, required=True)
    result.add_argument("--arch", action="append", required=True)
    result.add_argument(
        "--jobs",
        type=int,
        default=max(1, min(8, os.cpu_count() or 1)),
    )
    result.add_argument(
        "--plan-only",
        action="store_true",
        help="validate sources and emit a deterministic plan without probing tools",
    )
    return result


def main() -> int:
    args = parser().parse_args()
    if args.jobs <= 0:
        raise SystemExit("--jobs must be positive")
    try:
        config = BuildConfig(
            source_root=args.source_root,
            source_manifest=args.source_manifest,
            native_root=args.native_root,
            output_dir=args.out_dir,
            toolchain=Toolchain(
                nvcc=resolve_tool(args.nvcc),
                host_cxx=resolve_tool(args.host_cxx),
                archiver=resolve_tool(args.ar),
                cuda_home=args.cuda_home.resolve(),
                cuda_library_dir=args.cuda_library_dir.resolve(),
                sms=normalize_sms(args.arch),
                jobs=args.jobs,
            ),
        )
        if args.plan_only:
            print(json.dumps(build_plan(config, probe_tools=False), indent=2, sort_keys=True))
        else:
            execute(config)
    except BuildError as error:
        raise SystemExit(f"CUDA build rejected: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
