#!/usr/bin/env python3
"""Defense-in-depth marker checks for the focused RISC-V CPU product."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OWNED = (
    ROOT / "build_support/products/riscv_cpu.zig",
    # The CPU owner's build-graph wiring is shared with the other focused RV32IM
    # owners from here, so it is subject to the same marker checks. Without this
    # entry, moving a line out of riscv_cpu.zig into the shared sibling would
    # silently move it out of marker coverage.
    ROOT / "build_support/products/riscv_shared_shell.zig",
    ROOT / "src/products/riscv_cpu/main.zig",
    ROOT / "src/stwo_riscv_cpu.zig",
    ROOT / "src/riscv_trace_cli.zig",
    *(ROOT / "src/products/riscv_cpu").glob("*.zig"),
    *(ROOT / "src/products/riscv_shared").glob("*.zig"),
)
FORBIDDEN = (
    '@import("stwo.zig")',
    '@import("stwo")',
    'native_dispatch',
    'frontends/cairo',
    'integrations/cairo',
    'backends/metal',
    'backends/cuda',
    'examples/mod.zig',
    'metal_products',
    'linkFramework',
    'linkSystemLibrary',
)


def main() -> int:
    failures: list[str] = []
    for path in OWNED:
        text = path.read_text()
        for marker in FORBIDDEN:
            if marker in text:
                failures.append(f"{path.relative_to(ROOT)}: forbidden focused-product dependency {marker!r}")
    owner = (ROOT / "build_support/products/riscv_cpu.zig").read_text()
    if '.name = "stwo-riscv-cpu"' not in owner:
        failures.append("focused product does not use logical product ID stwo-riscv-cpu")
    if "getInstallStep" in owner:
        failures.append("focused product mutates the global default install step")
    for artifact in ("stwo-zig-riscv-cpu", "riscv-trace-dump"):
        if artifact not in owner:
            failures.append(f"focused product does not construct {artifact}")
    if failures:
        print("\n".join(failures))
        return 1
    print(f"riscv CPU product markers: PASS ({len(OWNED)} owned files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
