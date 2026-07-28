#!/usr/bin/env python3
"""Tests for the canonical direct Zig protocol-module command graph."""

from __future__ import annotations

import unittest

from scripts.zig_protocol_lib.command import protocol_module_args, test_command


class ZigProtocolCommandTests(unittest.TestCase):
    def test_protocol_modules_are_wired_in_dependency_order(self) -> None:
        arguments = protocol_module_args("src/stwo_deep.zig")

        self.assertEqual("-Mroot=src/stwo_deep.zig", arguments[12])
        self.assertLess(
            arguments.index("-Mstwo_core=src/core/mod.zig"),
            arguments.index("-Mstwo_backend_contracts=src/backend/mod.zig"),
        )
        self.assertLess(
            arguments.index("-Mstwo_backend_contracts=src/backend/mod.zig"),
            arguments.index("-Mstwo_prover_impl=src/prover/mod.zig"),
        )
        self.assertLess(
            arguments.index("-Mstwo_prover_impl=src/prover/mod.zig"),
            arguments.index("-Mstwo_cpu_backend=src/backends/cpu_scalar/mod.zig"),
        )
        self.assertLess(
            arguments.index("-Mstwo_cpu_backend=src/backends/cpu_scalar/mod.zig"),
            arguments.index("-Mstwo_riscv_frontend=src/frontends/riscv/mod.zig"),
        )
        self.assertLess(
            arguments.index("-Mstwo_riscv_frontend=src/frontends/riscv/mod.zig"),
            arguments.index("-Mstwo_cairo_frontend=src/frontends/cairo/mod.zig"),
        )

    def test_test_command_preserves_trailing_zig_arguments(self) -> None:
        command = test_command(
            "src/stwo.zig",
            "-OReleaseFast",
            "--test-filter",
            "proof wire",
        )

        self.assertEqual(["zig", "test"], command[:2])
        self.assertEqual(
            ["-OReleaseFast", "--test-filter", "proof wire"],
            command[-3:],
        )


if __name__ == "__main__":
    unittest.main()
