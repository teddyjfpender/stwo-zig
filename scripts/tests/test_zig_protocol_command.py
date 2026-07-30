#!/usr/bin/env python3
"""Tests for the canonical direct Zig protocol-module command graph."""

from __future__ import annotations

import unittest

from scripts.zig_protocol_lib.command import (
    PROTOCOL_PACKAGES,
    protocol_module_args,
    protocol_package_modules,
    test_command,
)


class ZigProtocolCommandTests(unittest.TestCase):
    def test_protocol_modules_are_wired_in_dependency_order(self) -> None:
        arguments = protocol_module_args("src/stwo_deep.zig")
        modules = protocol_package_modules()
        selected = {module.name for module in modules}
        positions = {
            module.name: arguments.index(f"-M{module.name}={module.source}")
            for module in modules
        }

        self.assertIn("-Mroot=src/stwo_deep.zig", arguments)
        for module in modules:
            for dependency in module.dependencies:
                if dependency in selected:
                    self.assertLess(
                        positions[dependency],
                        positions[module.name],
                        f"{dependency} must precede {module.name}",
                    )

    def test_every_module_scope_uses_its_authoritative_contract_dependencies(self) -> None:
        modules = protocol_package_modules()
        self.assertEqual(PROTOCOL_PACKAGES, tuple(module.name for module in modules))
        arguments = protocol_module_args("src/stwo_deep.zig")

        cursor = arguments.index("-Mroot=src/stwo_deep.zig") + 1
        for module in modules:
            module_flag = f"-M{module.name}={module.source}"
            end = arguments.index(module_flag, cursor)
            scoped = arguments[cursor:end]
            self.assertEqual(
                [item for dependency in module.dependencies for item in ("--dep", dependency)],
                scoped,
                module.name,
            )
            cursor = end + 1

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
