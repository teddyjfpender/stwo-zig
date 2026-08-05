#!/usr/bin/env python3
"""Build or inspect a frontend-specific CuMetal provider archive."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from cuda_build_lib.cumetal_builder import Config, Toolchain, build_plan, execute
from cuda_build_lib.cumetal_toolchain import CuMetalToolchainError
from cuda_build_lib.errors import BuildError


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frontend", choices=("native", "cairo", "riscv"), required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT / "src/backends/cuda/authority/active")
    parser.add_argument("--source-manifest", type=Path, default=ROOT / "src/backends/cuda/active_source_manifest.json")
    parser.add_argument("--product-manifest", type=Path, default=ROOT / "src/backends/cuda/product_manifest.json")
    parser.add_argument("--native-root", type=Path, default=ROOT / "src/backends/cuda/native")
    parser.add_argument("--native-aot-root", type=Path, default=ROOT / "src/backends/cuda/aot/native")
    parser.add_argument("--support-manifest", type=Path, default=ROOT / "src/backends/cuda/cumetal/frontend_support.json")
    parser.add_argument("--compatibility-patch", type=Path, default=ROOT / "src/backends/cuda/cumetal/patches/0001-stwo-aot-ptx.patch")
    parser.add_argument("--cumetal-root", type=Path, required=True)
    parser.add_argument("--clang", type=Path, required=True)
    parser.add_argument("--cumetalc", type=Path, required=True)
    parser.add_argument("--cumetal-library", type=Path, required=True)
    parser.add_argument("--air-inspect", type=Path, required=True)
    parser.add_argument("--air-validate", type=Path, required=True)
    parser.add_argument("--ar", type=Path, default=Path("/usr/bin/ar"))
    parser.add_argument("--jobs", type=int, default=max(1, min(8, os.cpu_count() or 1)))
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--plan-only", action="store_true")
    args = parser.parse_args()
    config = Config(
        source_root=args.source_root.resolve(),
        source_manifest=args.source_manifest.resolve(),
        product_manifest=args.product_manifest.resolve(),
        native_root=args.native_root.resolve(),
        native_aot_root=args.native_aot_root.resolve(),
        support_manifest=args.support_manifest.resolve(),
        output_dir=args.out_dir.resolve(),
        frontend=args.frontend,
        toolchain=Toolchain(
            clang=args.clang.resolve(),
            cumetalc=args.cumetalc.resolve(),
            archiver=args.ar.resolve(),
            cumetal_root=args.cumetal_root.resolve(),
            library=args.cumetal_library.resolve(),
            air_inspect=args.air_inspect.resolve(),
            air_validate=args.air_validate.resolve(),
            compatibility_patch=args.compatibility_patch.resolve(),
            jobs=args.jobs,
        ),
    )
    result = build_plan(config, probe_tools=False) if args.plan_only else execute(config)
    if args.plan_only:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BuildError, CuMetalToolchainError) as error:
        raise SystemExit(f"CuMetal build rejected: {error}") from error
