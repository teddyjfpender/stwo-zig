from __future__ import annotations

import unittest
from pathlib import Path

from scripts import dev_test


ROOT = Path(__file__).resolve().parents[2]


class DevTestPlanTests(unittest.TestCase):
    def test_recursion_dag_uses_its_standalone_cpu_owner(self):
        commands = dev_test.commands_for_paths(ROOT, ["src/integrations/riscv_cpu/rv64_recursion/om31_native/ready_dag.zig"], optimize="ReleaseFast")
        self.assertEqual(1, len(commands))
        self.assertIn("test-recursion-dag", commands[0])
        self.assertIn("src/integrations/riscv_cpu/build.zig", commands[0])

    def test_optimized_ci_reproduction_covers_focused_and_broad_routes(self) -> None:
        for path, step in (
            ("src/waist/core/fri/folding_family.zig", "test-fri"),
            ("src/waist/core/future_module.zig", "test"),
            ("src/integrations/riscv_cuda/rv64/projection_codegen.zig", "test-native-gkr-codegen"),
        ):
            with self.subTest(path=path):
                (command,) = dev_test.commands_for_paths(ROOT, [path], optimize="ReleaseFast")
                self.assertEqual(command[2], step)
                self.assertIn("-Doptimize=ReleaseFast", command)
                self.assertNotIn("-Doptimize=ReleaseSafe", command)
                self.assertNotIn("-Doptimize=Debug", command)

    def test_python_owner_uses_its_surviving_contract_tests(self) -> None:
        (command,) = dev_test.commands_for_paths(ROOT, ["scripts/dev_test.py"])
        self.assertEqual(command[1:], ["-m", "unittest", "scripts.tests.test_dev_test"])

    def test_deleted_python_owner_uses_complete_surviving_contract_suite(self) -> None:
        (command,) = dev_test.commands_for_paths(ROOT, ["scripts/retired_owner.py"])
        self.assertEqual(command[1:], ["-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_*.py"])

    def test_python_check_is_explicitly_compile_only(self) -> None:
        (command,) = dev_test.commands_for_paths(ROOT, ["scripts/dev_test.py"], check_only=True)
        self.assertEqual(command[1:], ["-m", "compileall", "-q", "scripts"])

    def test_recursion_publication_has_a_gpu_free_focused_check(self) -> None:
        (command,) = dev_test.commands_for_paths(ROOT, [
            "src/integrations/riscv_cpu/rv64_recursion/om31_native/publication.zig",
        ], check_only=True)
        self.assertEqual(command[2], "test-recursion-publication")
        self.assertIn("src/integrations/riscv_cpu/build.zig", command)
        self.assertIn("-Dcheck-only=true", command)

    def test_gpu_resource_and_runtime_edits_use_gpu_free_roots(self) -> None:
        (command,) = dev_test.commands_for_paths(ROOT, [
            "src/integrations/riscv_cuda/rv64/jobs/resources.zig",
            "src/integrations/riscv_cuda/rv64/jobs/arena_test.zig",
            "src/integrations/riscv_cuda/rv64/jobs/worker.zig",
        ])
        self.assertEqual(command[2:4], ["test-rv64-jobs-runtime", "test-rv64-resources"])
        self.assertIn("src/integrations/riscv_cuda/build.zig", command)
        self.assertIn("-Doptimize=Debug", command)

    def test_gpu_resource_check_uses_the_incremental_contract(self) -> None:
        (command,) = dev_test.commands_for_paths(ROOT, [
            "src/integrations/riscv_cuda/rv64/jobs/resources.zig",
        ], check_only=True)
        self.assertEqual(command[2], "test-rv64-resources")
        self.assertIn("-Dcheck-only=true", command)
        self.assertIn("-fincremental", command)

    def test_resource_routing_follows_owned_modules_and_their_tests(self) -> None:
        for filename in ("job_timing.zig", "job_timing_test.zig", "memory_plan.zig", "driver_memory.zig"):
            with self.subTest(filename=filename):
                (command,) = dev_test.commands_for_paths(ROOT, [
                    "src/integrations/riscv_cuda/rv64/jobs/" + filename,
                ])
                self.assertEqual(command[2], "test-rv64-resources")

    def test_node_results_select_the_node_contract_root(self) -> None:
        (command,) = dev_test.commands_for_paths(ROOT, [
            "src/integrations/riscv_cuda/rv64/jobs/outer_result.zig",
            "src/integrations/riscv_cuda/rv64/jobs/outer_job.zig",
        ])
        self.assertEqual(command[2], "test-rv64-jobs-node")

    def test_gpu_component_routes_follow_the_owned_test_roots(self) -> None:
        for filename, target in (
            ("outer_device.zig", "test-rv64-jobs-recursion"),
            ("outer_node_job.zig", "test-rv64-jobs-recursion"),
            ("native_device_stage1.zig", "test-rv64-jobs-native"),
            ("truth_factory.zig", "test-rv64-jobs-truth"),
            ("outer_heap.zig", "test-rv64-jobs-outer"),
        ):
            with self.subTest(filename=filename):
                (command,) = dev_test.commands_for_paths(ROOT, [
                    "src/integrations/riscv_cuda/rv64/jobs/" + filename,
                ])
                self.assertEqual(command[2], target)

    def test_recursion_custody_root_supports_incremental_checking(self) -> None:
        (command,) = dev_test.commands_for_paths(ROOT, [
            "src/integrations/riscv_cuda/rv64_jobs_recursion_test_root.zig",
        ], check_only=True)
        self.assertEqual(command[2], "test-rv64-jobs-recursion")
        self.assertIn("-Dcheck-only=true", command)
        self.assertIn("-fincremental", command)

    def test_unreviewed_gpu_job_falls_back_to_the_complete_package(self) -> None:
        for filename in ("future_job.zig", "resources_test.zig"):
            with self.subTest(filename=filename):
                (command,) = dev_test.commands_for_paths(ROOT, [
                    "src/integrations/riscv_cuda/rv64/jobs/" + filename,
                ])
                self.assertEqual(command[2], "test")

    def test_leaf_changes_select_focused_roots(self) -> None:
        self.assertEqual(
            dev_test.commands_for_paths(
                ROOT,
                [
                    "src/waist/core/fields/m31.zig",
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
                    "src/waist/core/build.zig",
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
            ["src/waist/core/fri/folding.zig", "src/waist/core/pcs/verifier.zig"],
        )
        self.assertEqual(commands[0][2:4], ["test-fri", "test-pcs"])

    def test_prover_pcs_routes_quotients_separately(self) -> None:
        commands = dev_test.commands_for_paths(
            ROOT,
            [
                "src/engine/prover/pcs/quotient_ops.zig",
                "src/engine/prover/pcs/quotients/planning.zig",
                "src/engine/prover/pcs/sampled_values.zig",
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
        (command,) = dev_test.commands_for_paths(ROOT, ["src/waist/core/mod.zig"])
        self.assertEqual(command[:3], ["zig", "build", "test"])
        self.assertIn("src/waist/core/build.zig", command)
        self.assertIn("-Doptimize=ReleaseSafe", command)
        self.assertIn("-j1", command)
        self.assertNotIn("-Doptimize=ReleaseFast", command)
        self.assertNotIn("-j2", command)

    def test_new_quotient_file_falls_back_to_the_complete_package(self) -> None:
        (command,) = dev_test.commands_for_paths(
            ROOT,
            ["src/engine/prover/pcs/quotient_future.zig"],
        )
        self.assertEqual(command[2], "test")

    def test_unfocused_change_supersedes_a_narrow_step_in_the_same_package(self) -> None:
        commands = dev_test.commands_for_paths(
            ROOT,
            ["src/engine/prover/mod.zig", "src/engine/prover/poly/twiddles.zig"],
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
