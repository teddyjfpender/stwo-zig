#!/usr/bin/env python3
"""Defense-in-depth marker checks for the focused Native Metal product."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OWNED = (
    ROOT / "build_support/products/native_metal.zig",
    ROOT / "src/stwo_native_metal.zig",
    *(ROOT / "src/products/native_metal").glob("*.zig"),
)
FORBIDDEN = (
    "frontends/cairo",
    "frontends/riscv",
    "backends/cuda",
    "src/stwo.zig",
)
REQUIRED_OWNER_MARKERS = (
    '"stwo-native-metal"',
    '"stwo-zig-native-metal"',
    "metal.linkRuntime",
    '"Metal.framework"',
    '"Foundation.framework"',
    '"libobjc"',
)


def main() -> int:
    failures: list[str] = []
    for path in OWNED:
        text = path.read_text(encoding="utf-8")
        for marker in FORBIDDEN:
            if marker in text:
                failures.append(
                    f"{path.relative_to(ROOT)}: forbidden product-owner marker {marker!r}"
                )
    owner = (ROOT / "build_support/products/native_metal.zig").read_text(
        encoding="utf-8"
    )
    for marker in REQUIRED_OWNER_MARKERS:
        if marker not in owner:
            failures.append(f"Native Metal owner is missing required marker {marker}")
    if failures:
        print("\n".join(failures))
        return 1
    print("native Metal product markers: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
