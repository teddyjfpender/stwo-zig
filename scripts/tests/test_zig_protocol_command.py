#!/usr/bin/env python3
"""Tests for the canonical direct Zig protocol-module command graph."""

from __future__ import annotations

import unittest
from unittest import mock

from scripts.zig_protocol_lib.command import (
    PROTOCOL_PACKAGES,
    CPU_PROTOCOL_PACKAGES,
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
            self.assertEqual(len(PROTOCOL_PACKAGES) + 2, len(module_positions))
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
            self.assertEqual(len(PROTOCOL_PACKAGES) + 2, command.count(flags[-1]))

    def test_strip_filter_text_and_arguments_after_separator_are_preserved(self) -> None:
        command = test_command("src/stwo.zig", "--test-filter", "-fstrip", "--", "-fno-strip")
        self.assertEqual(["--test-filter", "-fstrip", "--", "-fno-strip"], command[-4:])
        self.assertNotIn("-fstrip", command[:-4])
        self.assertNotIn("-fno-strip", command[:-4])

    def test_postcard_bridge_reuses_unique_proof_wire_node(self) -> None:
        arguments = protocol_module_args("focused.zig")
        names = [item.split("=", 1)[0][2:] for item in arguments if item.startswith("-M")]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(1, names.count("interop_postcard"))
        self.assertEqual(1, names.count("stwo_proof_wire"))
        previous = max(i for i, arg in enumerate(arguments[:arguments.index("-Minterop_postcard=src/interop/postcard.zig")]) if arg.startswith("-M"))
        scoped = arguments[previous + 1:arguments.index("-Minterop_postcard=src/interop/postcard.zig")]
        self.assertEqual(["--dep", "stwo_core", "--dep", "stwo_proof_wire"], scoped)

    def test_cpu_graph_is_contract_derived_closed_and_has_no_duplicate_modules(self) -> None:
        arguments = protocol_module_args("focused.zig", cpu_only=True, optimize="ReleaseFast", cpu="native")
        names = [item.split("=", 1)[0][2:] for item in arguments if item.startswith("-M")]
        self.assertEqual(["root", *CPU_PROTOCOL_PACKAGES, "interop_postcard"], names)
        self.assertEqual(len(names), len(set(names)))
        cursor = 0
        for position, arg in enumerate(arguments):
            if not arg.startswith("-M"):
                continue
            scoped = arguments[cursor:position]
            self.assertEqual(["-OReleaseFast", "-mcpu=native"], scoped[-2:])
            name = arg.split("=", 1)[0][2:]
            if name in CPU_PROTOCOL_PACKAGES:
                module = next(m for m in protocol_package_modules() if m.name == name)
                self.assertEqual([x for dep in module.dependencies for x in ("--dep", dep)], scoped[:-2])
            cursor = position + 1

    def test_cpu_flags_debug_and_custom_runner_apply_in_every_module_scope(self) -> None:
        command = test_command("focused.zig", "-OReleaseFast", "-O", "Debug", "-mcpu=baseline", "-mcpu", "native", "--test-runner", "policy.zig", "--test-filter", "-mcpu=wrong", cpu_only=True, zig="chosen-zig", standard_test_runner="compiler/test_runner.zig")
        positions = [i for i, arg in enumerate(command) if arg.startswith("-M")]
        self.assertEqual(["chosen-zig", "test"], command[:2])
        for position in positions:
            self.assertEqual(["-ODebug", "-mcpu=native"], command[position - 2:position])
        self.assertEqual(1, command.count("-Mblock_v5_standard_test_runner=compiler/test_runner.zig"))
        root_scope = command[:command.index("-Mroot=focused.zig")]
        self.assertIn("block_v5_standard_test_runner", root_scope)
        self.assertEqual(["--test-runner", "policy.zig", "--test-filter", "-mcpu=wrong"], command[-4:])

    def test_focused_additional_packages_have_closed_contract_dependencies(self) -> None:
        requested = ("stwo_native_cuda_integration", "stwo_cuda_backend",
                     "stwo_native_cuda_integration")
        arguments = protocol_module_args("focused.zig", cpu_only=True,
                                         extra_packages=requested)
        names = [arg.split("=", 1)[0][2:] for arg in arguments if arg.startswith("-M")]
        self.assertEqual(len(names), len(set(names)))
        modules = {module.name: module for module in protocol_package_modules()}
        expected = set(CPU_PROTOCOL_PACKAGES)
        pending = list(requested)
        while pending:
            name = pending.pop()
            if name not in expected:
                expected.add(name)
                pending.extend(modules[name].dependencies)
        self.assertEqual(expected | {"root", "interop_postcard"}, set(names))
        self.assertNotIn("stwo_riscv_frontend", names)
        for name in expected:
            self.assertTrue(set(modules[name].dependencies) <= set(names))

    def test_unknown_additional_package_rejected_before_compiler_resolution(self) -> None:
        with mock.patch("scripts.zig_protocol_lib.command.standard_runner_source") as resolver:
            with self.assertRaisesRegex(ValueError, "unknown additional protocol packages"):
                test_command("focused.zig", cpu_only=True,
                             extra_packages=("missing_backend",))
        resolver.assert_not_called()

    def test_cpu_flags_after_separator_and_filter_values_are_data(self) -> None:
        command = test_command("focused.zig", "--test-filter", "-mcpu=native", "--", "-mcpu=baseline", "-ODebug", cpu_only=True)
        self.assertEqual(["--test-filter", "-mcpu=native", "--", "-mcpu=baseline", "-ODebug"], command[-5:])
        self.assertFalse(any(arg.startswith("-mcpu") for arg in command[:-5]))

    def test_missing_values_are_explicit_errors_without_compiler_execution(self) -> None:
        for flag in ("-O", "-mcpu", "--test-filter", "--test-runner"):
            with self.assertRaisesRegex(ValueError, "requires a value"):
                test_command("focused.zig", flag)
        with self.assertRaisesRegex(ValueError, "requires a value"):
            test_command("focused.zig", "-mcpu=")
        with self.assertRaisesRegex(ValueError, "optimization mode"):
            test_command("focused.zig", "-Owrong")

    def test_standard_runner_is_from_selected_compiler_without_invoking_it(self) -> None:
        with mock.patch("scripts.zig_protocol_lib.command.standard_runner_source", return_value="selected/compiler/test_runner.zig") as resolver:
            command = test_command("focused.zig", "--test-runner", "policy.zig", zig="selected-zig", cpu_only=True)
        resolver.assert_called_once_with("selected-zig")
        self.assertIn("-Mblock_v5_standard_test_runner=selected/compiler/test_runner.zig", command)


if __name__ == "__main__":
    unittest.main()
