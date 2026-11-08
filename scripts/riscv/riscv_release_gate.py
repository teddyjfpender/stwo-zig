#!/usr/bin/env python3
"""Run the phase-aware, fail-closed Sail-backed RISC-V release gate."""

try:
    import riscv_release_gate_lib.controller as controller
except ModuleNotFoundError:  # Imported through the repository package in tests.
    import scripts.riscv_release_gate_lib.controller as controller


def main(argv: list[str] | None = None) -> int:
    return controller.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
