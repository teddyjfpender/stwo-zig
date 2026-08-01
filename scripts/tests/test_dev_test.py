from __future__ import annotations

import unittest
from pathlib import Path

from scripts import dev_test


ROOT = Path(__file__).resolve().parents[2]


class DevTestPlanTests(unittest.TestCase):
    def test_leaf_changes_select_focused_roots(self) -> None:
        self.assertEqual(
            dev_test.commands_for_paths(
                ROOT,
                [
                    "src/core/fields/m31.zig",
                    "src/frontends/riscv/isa/decode.zig",
                    "src/frontends/sm83/runner/cpu.zig",
                ],
            ),
            [
                [
                    "zig",
                    "build",
                    "test-fields",
                    "--build-file",
                    "src/core/build.zig",
                    "-Doptimize=Debug",
                    "-j1",
                ],
                [
                    "zig",
                    "build",
                    "test-isa",
                    "--build-file",
                    "src/frontends/riscv/build.zig",
                    "-Doptimize=Debug",
                    "-j1",
                ],
                [
                    "zig",
                    "build",
                    "test-runner",
                    "--build-file",
                    "src/frontends/sm83/build.zig",
                    "-Doptimize=Debug",
                    "-j1",
                ],
            ],
        )

    def test_multiple_leaves_in_one_slice_deduplicate_the_step(self) -> None:
        commands = dev_test.commands_for_paths(
            ROOT,
            ["src/core/fri/folding.zig", "src/core/pcs/verifier.zig"],
        )
        self.assertEqual(commands[0][2:4], ["test-fri", "test-pcs"])

    def test_prover_pcs_routes_quotients_separately(self) -> None:
        commands = dev_test.commands_for_paths(
            ROOT,
            [
                "src/prover/pcs/quotient_ops.zig",
                "src/prover/pcs/quotients/planning.zig",
                "src/prover/pcs/sampled_values.zig",
            ],
        )
        self.assertEqual(
            commands[0][2:5],
            [
                "test-pcs-commitments",
                "test-pcs-quotient-ops",
                "test-pcs-quotient-planning",
            ],
        )

    def test_unfocused_package_change_uses_its_declared_ci_command(self) -> None:
        (command,) = dev_test.commands_for_paths(ROOT, ["src/core/mod.zig"])
        self.assertEqual(command[:3], ["zig", "build", "test"])
        self.assertIn("src/core/build.zig", command)
        self.assertIn("-Doptimize=ReleaseSafe", command)
        self.assertIn("-j1", command)
        self.assertNotIn("-Doptimize=ReleaseFast", command)
        self.assertNotIn("-j2", command)

    def test_new_quotient_file_falls_back_to_the_complete_package(self) -> None:
        (command,) = dev_test.commands_for_paths(
            ROOT,
            ["src/prover/pcs/quotient_future.zig"],
        )
        self.assertEqual(command[2], "test")

    def test_unfocused_change_supersedes_a_narrow_step_in_the_same_package(self) -> None:
        commands = dev_test.commands_for_paths(
            ROOT,
            ["src/prover/mod.zig", "src/prover/poly/twiddles.zig"],
        )
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][2], "test")

    def test_check_only_uses_incremental_no_binary_build(self) -> None:
        (command,) = dev_test.commands_for_paths(
            ROOT,
            ["src/frontends/sm83/isa/decode.zig"],
            check_only=True,
        )
        self.assertIn("-Dcheck-only=true", command)
        self.assertIn("-fincremental", command)

    def test_unowned_path_fails_closed(self) -> None:
        with self.assertRaisesRegex(dev_test.DevTestError, "no Zig package owns"):
            dev_test.commands_for_paths(ROOT, ["CONTRIBUTING.md"])


if __name__ == "__main__":
    unittest.main()
