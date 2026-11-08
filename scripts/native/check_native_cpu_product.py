#!/usr/bin/env python3
"""Defense-in-depth marker checks for the focused Native CPU product."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OWNED = (
    ROOT / "build_support/products/native_cpu.zig",
    ROOT / "src/products/native_cpu/main.zig",
    ROOT / "src/stwo_native_cpu.zig",
    *(ROOT / "src/products/native_cpu").glob("*.zig"),
)
FORBIDDEN = (
    "metal_products",
    "linkFramework",
    "linkSystemLibrary",
    "src/stwo.zig",
    "frontends/cairo",
    "frontends/riscv",
    "backends/metal",
    "backends/cuda",
)
REQUIRED_OWNER_MARKERS = (
    '"stwo-native-cpu"',
    '"stwo-zig-native-cpu"',
    '"stwo-zig-native-cpu-bench"',
    '"benchmark-native-cpu"',
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
    owner = (ROOT / "build_support/products/native_cpu.zig").read_text(
        encoding="utf-8"
    )
    for marker in REQUIRED_OWNER_MARKERS:
        if marker not in owner:
            failures.append(f"Native CPU owner is missing required marker {marker}")
    if failures:
        print("\n".join(failures))
        return 1
    print("native CPU product markers: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
