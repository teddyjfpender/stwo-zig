from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from scripts import dev_test
from scripts.tests.focused_ci_fixtures import git_repository


ROOT = Path(__file__).resolve().parents[2]


class DevTestPlanTests(unittest.TestCase):
    def test_shared_resource_contracts_have_focused_and_mandatory_package_owners(self):
        cases = (
            ("src/prover/shared_resources_test_root.zig", "test-shared-resources", "shared_resources_step", 13),
            ("src/core/borrowed_proof_capture_test_root.zig", "test-borrowed-capture", "capture_tests", 0),
            ("src/integrations/riscv_cpu/rv64_recursion_budget_test_root.zig", "test-recursion-budget", "budget_step", 3),
        )
        for path, step, dependency, named_tests in cases:
            with self.subTest(path=path):
                (command,) = dev_test.commands_for_paths(ROOT, [path], check_only=True)
                self.assertEqual(command[2], step)
                self.assertIn("-Dcheck-only=true", command)
                build = (ROOT / Path(path).parent / "build.zig").read_text()
                self.assertIn(f'"{Path(path).name}"', build)
                self.assertIn(f'test_step.dependOn({dependency});', build)
                body = (ROOT / path).read_text()
                self.assertEqual(sum(line.startswith('test "') for line in body.splitlines()), named_tests)
        capture = (ROOT / cases[1][0]).read_text()
        for name in ("borrowed_proof_capture_test.zig", "borrowed_pcs_capture_success_test.zig"):
            self.assertIn(f'@import("tests/{name}")', capture)

    def test_recursion_dag_uses_its_standalone_cpu_owner(self):
        commands = dev_test.commands_for_paths(ROOT, ["src/integrations/riscv_cpu/rv64_recursion/om31_native/ready_dag.zig"], optimize="ReleaseFast")
        self.assertEqual(1, len(commands))
        self.assertIn("test-recursion-dag", commands[0])
        self.assertIn("src/integrations/riscv_cpu/build.zig", commands[0])

    def test_optimized_ci_reproduction_covers_focused_and_broad_routes(self) -> None:
        for path, step in (
            ("src/core/fri/folding_family.zig", "test-fri"),
            ("src/core/future_module.zig", "test"),
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
        with git_repository({"scripts/retired_owner.py": "pass\n", "scripts/alive_owner.py": "pass\n"}) as root:
            (root / "scripts/retired_owner.py").unlink()
            for path in ("scripts/retired_owner.py", "scripts/alive_owner.py"):
                (command,) = dev_test.commands_for_paths(root, [path])
                self.assertEqual(command[1:], ["-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_*.py"])

    def test_nonexistent_python_typo_never_selects_the_contract_suite(self):
        with self.assertRaisesRegex(dev_test.DevTestError, "does not exist"):
            dev_test.commands_for_paths(ROOT, ["scripts/tests/test_ci_scope_plan.py"])

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
            dev_test.commands_for_paths(ROOT, ["src/unowned_new_source.zig"])

    def test_documentation_uses_ci_policy_without_runtime_builds(self):
        self.assertEqual([], dev_test.commands_for_paths(ROOT, [
            "CONTRIBUTING.md", "src/prover/README.md", "design/riscv-proving-stack/rv64-gpu-hygiene.md",
        ]))

    def test_live_fixtures_select_actual_package_and_script_validators(self):
        for path in ("vectors/fixtures/rv64-m3-basket-v1.json", "vectors/fixtures/README.md"):
            with self.subTest(path=path):
                commands = dev_test.commands_for_paths(ROOT, [path])
                self.assertTrue(any(command[1:4] == ["-m", "unittest", "discover"] for command in commands))
                for owner in ("src/frontends/riscv", "src/integrations/riscv_cuda"):
                    self.assertTrue(any(f"{owner}/build.zig" in command for command in commands))
        commands = dev_test.commands_for_paths(ROOT, ["conformance/rv64-flags.json"])
        self.assertTrue(any("scripts/ci.py" in command and "--fast" in command for command in commands))
        combined = dev_test.commands_for_paths(ROOT, ["scripts/tests/test_dev_test.py", "vectors/fixtures/README.md"])
        self.assertEqual(1, sum(command[1:3] == ["-m", "unittest"] for command in combined))

    def test_only_git_confirmed_unowned_deletions_select_static_checks(self):
        path = "src/retired_unowned_root.zig"
        with mock.patch("scripts.dev_test.subprocess.check_output", return_value=path + "\n"):
            commands = dev_test.commands_for_paths(ROOT, [path])
        self.assertTrue(any("scripts/ci.py" in command and "--fast" in command for command in commands))
        with mock.patch("scripts.dev_test.subprocess.check_output", return_value=""):
            with self.assertRaises(dev_test.DevTestError):
                dev_test.commands_for_paths(ROOT, [path])


if __name__ == "__main__":
    unittest.main()
