#!/usr/bin/env python3
"""Verify or explicitly patch the pinned CuMetal source checkout."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cuda_build_lib.cumetal_toolchain import (
    CuMetalToolchainError,
    apply_compatibility_patch,
    verify_checkout,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATCH = (
    ROOT / "src/backends/cuda/cumetal/patches/0001-stwo-aot-ptx.patch"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cumetal-root", type=Path, required=True)
    parser.add_argument("--patch", type=Path, default=DEFAULT_PATCH)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    identity = (
        apply_compatibility_patch(args.cumetal_root, args.patch)
        if args.apply
        else verify_checkout(args.cumetal_root, args.patch)
    )
    print(
        json.dumps(
            {
                "schema": "stwo-zig-cumetal-toolchain-v1",
                "checkout": str(args.cumetal_root.resolve()),
                "patch": str(args.patch.resolve()),
                "identity": identity,
                "verdict": "pass",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CuMetalToolchainError as error:
        raise SystemExit(f"CuMetal toolchain rejected: {error}") from error
