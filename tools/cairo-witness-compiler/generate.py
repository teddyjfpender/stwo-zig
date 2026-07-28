#!/usr/bin/env python3
"""Generate an authenticated Zig Cairo witness-program bundle."""

from __future__ import annotations

import argparse
from pathlib import Path

from orchestrator import generate_bundle


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compile pinned official Stwo-Cairo witness writers into Zig programs."
    )
    parser.add_argument(
        "--source",
        required=True,
        type=Path,
        help="clean checkout of the pinned official starkware-libs/stwo-cairo revision",
    )
    parser.add_argument("--output", required=True, type=Path, help="new bundle path")
    parser.add_argument(
        "--receipt",
        type=Path,
        help="optional new deterministic compiler receipt path",
    )
    args = parser.parse_args()

    receipt = generate_bundle(
        source=args.source.resolve(),
        output=args.output.resolve(),
        receipt_path=args.receipt.resolve() if args.receipt else None,
    )
    print(receipt.to_json(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
