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
                self.assertIn(dependency, selected)
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
            ["--test-filter", "proof wire"],
            command[-2:],
        )


    def test_optimization_is_scoped_before_every_module(self) -> None:
        for flags in (("-OReleaseFast",), ("-O", "ReleaseSafe")):
            command = test_command("src/stwo.zig", *flags, "--test-filter", "proof wire")
            mode = flags[-1].removeprefix("-O")
            module_positions = [i for i, arg in enumerate(command) if arg.startswith("-M")]
            self.assertEqual(len(PROTOCOL_PACKAGES) + 1, len(module_positions))
            for position in module_positions:
                self.assertEqual("-O" + mode, command[position - 1])
            self.assertFalse(any(arg.startswith("-O") for arg in command[module_positions[-1] + 1:]))

    def test_filter_text_is_not_an_optimization_option(self) -> None:
        command = test_command("src/stwo.zig", "--test-filter", "-OReleaseFast")
        self.assertEqual(["--test-filter", "-OReleaseFast"], command[-2:])
        self.assertFalse(any(arg.startswith("-O") for arg in command[:-2]))

    def test_debug_symbol_option_applies_to_every_module_and_last_choice_wins(self) -> None:
        for flags in (("-fstrip",), ("-fstrip", "-fno-strip")):
            command = test_command("src/stwo.zig", "-OReleaseSafe", *flags)
            positions = [i for i, arg in enumerate(command) if arg.startswith("-M")]
            for position in positions:
                self.assertEqual(["-OReleaseSafe", flags[-1]], command[position - 2:position])
            self.assertEqual(len(PROTOCOL_PACKAGES) + 1, command.count(flags[-1]))

    def test_strip_filter_text_and_arguments_after_separator_are_preserved(self) -> None:
        command = test_command("src/stwo.zig", "--test-filter", "-fstrip", "--", "-fno-strip")
        self.assertEqual(["--test-filter", "-fstrip", "--", "-fno-strip"], command[-4:])
        self.assertNotIn("-fstrip", command[:-4])
        self.assertNotIn("-fno-strip", command[:-4])


if __name__ == "__main__":
    unittest.main()
