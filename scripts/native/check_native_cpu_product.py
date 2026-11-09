#!/usr/bin/env python3
"""Defense-in-depth marker checks for the focused Native CPU product."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OWNED = (
    ROOT / "build_support/products/native_cpu.zig",
    ROOT / "src/products/native/cpu/main.zig",
    ROOT / "src/products/native/cpu/root.zig",
    *(ROOT / "src/products/native/cpu").glob("*.zig"),
)
FORBIDDEN = (
    "metal_products",
    "linkFramework",
    "linkSystemLibrary",
    "src/products/stwo/root.zig",
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


def check_binary(binary: Path) -> list[str]:
    prefix = b"preserved prior stdout\n"
    try:
        with tempfile.TemporaryFile() as output:
            output.write(prefix)
            output.flush()
            result = subprocess.run(
                [str(binary.resolve()), "applications"], stdout=output,
                stderr=subprocess.PIPE, timeout=10,
            )
            output.seek(0)
            encoded = output.read()
        if result.returncode != 0:
            return [f"Native CPU applications exited {result.returncode}: {result.stderr[:500]!r}"]
        if not encoded.startswith(prefix):
            return ["Native CPU applications overwrote prior redirected output"]
        registry = json.loads(encoded[len(prefix):])
        if (not isinstance(registry, dict)
                or not isinstance(registry.get("product"), dict)
                or registry["product"].get("name") != "stwo-native-cpu"
                or not isinstance(registry.get("applications"), list)
                or not registry["applications"]):
            return ["Native CPU applications did not report its product registry"]
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        return [f"Native CPU applications check failed: {error}"]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, help="also verify real redirected applications output")
    args = parser.parse_args(argv)
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
    if args.binary is not None:
        failures.extend(check_binary(args.binary))
    if failures:
        print("\n".join(failures))
        return 1
    print("native CPU product markers: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
