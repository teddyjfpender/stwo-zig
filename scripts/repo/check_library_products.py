#!/usr/bin/env python3
"""Defense-in-depth install and platform-policy checks for library owners."""

from __future__ import annotations

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRODUCTS = {
    "core": {
        "source_owners": ("src/core", "src/products/core"),
        "build_owner": "build_support/products/core.zig",
    },
    "backend-contracts": {
        "source_owners": ("src/backend",),
        "build_owner": None,
    },
    "prover": {
        "source_owners": ("src/prover", "src/products/prover"),
        "build_owner": "build_support/products/prover.zig",
    },
}
PLATFORM_MARKERS = ("linkFramework", "linkSystemLibrary")
BUILD_OWNER_MARKERS = (*PLATFORM_MARKERS, "addInstallArtifact", "getInstallStep")


def source_files(owners: tuple[str, ...]) -> list[Path]:
    files: list[Path] = []
    for owner in owners:
        path = ROOT / owner
        files.extend(path.rglob("*.zig") if path.is_dir() else (path,))
    return sorted(set(files))


def check(product: str) -> list[str]:
    policy = PRODUCTS[product]
    failures: list[str] = []
    for source in source_files(policy["source_owners"]):
        text = source.read_text(encoding="utf-8")
        for marker in PLATFORM_MARKERS:
            if marker in text:
                failures.append(
                    f"{product}: platform marker {marker!r} in {source.relative_to(ROOT)}"
                )
    build_owner = policy["build_owner"]
    if build_owner:
        text = (ROOT / build_owner).read_text(encoding="utf-8")
        for marker in BUILD_OWNER_MARKERS:
            if marker in text:
                failures.append(
                    f"{product}: library owner contains forbidden marker {marker!r}"
                )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--product", choices=(*PRODUCTS, "all"), default="all")
    args = parser.parse_args()
    selected = PRODUCTS if args.product == "all" else (args.product,)
    failures = [failure for product in selected for failure in check(product)]
    if failures:
        print("\n".join(failures))
        return 1
    for product in selected:
        print(f"{product} library markers: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
