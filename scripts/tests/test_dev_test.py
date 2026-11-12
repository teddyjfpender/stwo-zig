from __future__ import annotations

import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from scripts.tests.focused_ci_fixtures import git_repository

from scripts import dev_test
ROOT = Path(__file__).resolve().parents[2]


class DevTestPlanTests(unittest.TestCase):
    def test_cli_preserves_canonical_parent_lock_and_wraps_other_builds(self):
        planned = ["zig", "build", "test-isa", "-j1"]
        for held in ("", dev_test.zig_serial_build.DEFAULT_LOCK, "/tmp/foreign-build.lock"):
            borrowed = held == dev_test.zig_serial_build.DEFAULT_LOCK
            with mock.patch.object(dev_test, "commands_for_paths", return_value=[planned]), mock.patch.dict(
                os.environ, {dev_test.zig_serial_build.HELD_LOCK_ENV: held},
            ), mock.patch("scripts.dev_test.subprocess.run", return_value=mock.Mock(returncode=0)) as run, mock.patch(
                "sys.stdout", new=io.StringIO(),
            ):
                self.assertEqual(0, dev_test.main(["src/frontends/riscv/isa/focused_test_isa_0.zig"]))
            argv = run.call_args.args[0]
            self.assertEqual(borrowed, argv[:2] == ["zig", "build"])
            if not borrowed:
                self.assertIn("scripts/repo/zig_serial_build.py", argv)

    def test_catalog_roots_select_bounded_commands_without_tool_probes(self):
        for filename, step in (
            ("testing/focused_transcript_test_root.zig", "test-recursion-transcript-v2"),
            ("testing/focused_main_trace_plan_execution_test_root.zig", "test-main-trace-plan-execution"),
            ("testing/focused_air_static_profile_registry_test_root.zig", "test-air-static-profile-registry"),
            ("rv32/focused_test_air_semantics_0.zig", "test-air-semantics"),
            ("rv32/focused_test_air_semantics_0.zig", "test-air-semantics"),
            ("rv32/focused_test_air_semantics_0.zig", "test-air-semantics"),
            ("rv32/focused_test_air_semantics_0.zig", "test-air-semantics"),
            ("precompiles/focused_test_guest_precompile_0.zig", "test-guest-precompile"),
            ("precompiles/focused_test_guest_precompile_0.zig", "test-guest-precompile"),
            ("precompiles/focused_test_guest_precompile_0.zig", "test-guest-precompile"),
            ("precompiles/focused_test_guest_precompile_0.zig", "test-guest-precompile"),
        ):
            for check_only in (False, True):
                with self.subTest(filename=filename, check_only=check_only), mock.patch(
                    "scripts.dev_test.subprocess.run", side_effect=AssertionError("tool probe"),
                ), mock.patch("scripts.dev_test.subprocess.check_output", side_effect=AssertionError("tool probe")):
                    (command,) = dev_test.commands_for_paths(
                        ROOT, ["src/frontends/riscv/" + filename],
                        optimize="ReleaseFast", check_only=check_only,
                    )
                self.assertEqual(step, command[2])
                self.assertIn("-Doptimize=ReleaseFast", command)
                self.assertIn("-j1", command)
                self.assertEqual(check_only, "-Dcheck-only=true" in command)

    def test_catalog_routing_keeps_unbounded_ambiguous_and_workload_fallbacks(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = "src/frontends/riscv/qualified.zig"
            self.assertIsNone(dev_test.frontend_root_step(root, path))
            catalog = root / "src/frontends/riscv/build_focused_tests.zig"
            catalog.parent.mkdir(parents=True)
            catalog.write_text("".join(
                f'    .{{\n        .step = "{step}",\n        .root = "{source}.zig",\n'
                + (f'        .minimum = {floor},\n' if floor is not None else "") + '    },\n'
                for step, source, floor in (
                    ("test-qualified", "qualified", 3), ("test-zero", "zero", 0),
                    ("test-default", "default", None), ("benchmark-only", "workload", 3),
                    ("test-shared", "shared", 3), ("test-other", "shared", 4),
                )
            ))
            self.assertEqual("test-qualified", dev_test.frontend_root_step(root, path))
            for source in ("zero", "default", "workload", "shared", "qualified.zig/child"):
                self.assertIsNone(dev_test.frontend_root_step(root, f"src/frontends/riscv/{source}.zig"))
        self.assertEqual("test-runner", dev_test.focus_step(
            "stwo_riscv_frontend", "src/frontends/riscv/rv32/focused_benchmark_minimal_trace_parallel_replay_0.zig", ROOT,
        ))

    def test_child_focused_route_requires_declared_consumer_dependency(self):
        packages = dev_test.ci_package_graph.load_packages(ROOT)
        path = "src/frontends/riscv/rv32/air/extract/runtime_program.zig"
        self.assertEqual("stwo_riscv_frontend", dev_test.focused_test_owner(
            "stwo_riscv_rv32", path, packages, ROOT))
        narrowed = dict(packages)
        parent = packages["stwo_riscv_frontend"]
        narrowed[parent.name] = dev_test.ci_package_graph.Package(
            parent.name, parent.directory, parent.dependencies - {"stwo_riscv_rv32"})
        self.assertEqual("stwo_riscv_rv32", dev_test.focused_test_owner(
            "stwo_riscv_rv32", path, narrowed, ROOT))
        self.assertEqual("stwo_riscv_rv32", dev_test.focused_test_owner(
            "stwo_riscv_rv32", "src/frontends/riscv/rv32/unknown.zig", packages, ROOT))

    def test_native_cpu_product_sources_select_only_their_canonical_ci_lane(self):
        paths = [f"src/products/native/cpu/{name}.zig" for name in (
            "main", "app", "cli", "identity", "registry", "benchmark", "root",
        )]
        for host in ("darwin", "linux"):
            with self.subTest(host=host), mock.patch("scripts.dev_test.sys.platform", host):
                (command,) = dev_test.commands_for_paths(ROOT, paths)
                self.assertIn("scripts/repo/ci_scope_run.py", command)
                self.assertEqual("native_cpu", command[command.index("--lane") + 1])
                self.assertIn("--local-compatible", command)

    def test_shared_native_capabilities_preserve_all_consumer_deferrals(self):
        deferred = []
        commands = dev_test.commands_for_paths(ROOT, ["src/products/native/cpu/capabilities.zig"], check_only=True, deferred=deferred)
        self.assertEqual([], commands)
        self.assertEqual({"native_cpu", "native_metal", "aggregate_cpu", "aggregate_metal"}, set(deferred))

    def test_native_cpu_product_semantic_checks_defer_the_full_execution_lane(self):
        with self.assertRaisesRegex(dev_test.DevTestError, "requires full-lane validation"):
            dev_test.commands_for_paths(ROOT, ["src/products/native/cpu/main.zig"], check_only=True)
        deferred = []
        with mock.patch("scripts.dev_test.subprocess.run") as run:
            commands = dev_test.commands_for_paths(
                ROOT, ["src/products/native/cpu/main.zig"], check_only=True, deferred=deferred,
            )
        self.assertEqual([], commands)
        self.assertEqual(["native_cpu"], deferred)
        run.assert_not_called()

    def test_check_only_never_substitutes_a_full_package_or_ci_build(self):
        with self.assertRaisesRegex(dev_test.DevTestError, "focused owner"):
            dev_test.commands_for_paths(ROOT, ["src/waist/core/mod.zig"], check_only=True)
        deferred = []
        commands = dev_test.commands_for_paths(ROOT, ["build_support/products/riscv_cpu.zig"], check_only=True, deferred=deferred)
        self.assertEqual([], commands)
        self.assertIn("riscv_cpu", deferred)

    def test_owned_and_policy_path_typos_fail_before_planning(self):
        for path in ("src/integrations/riscv_cuda/rv64/jobs/driver_instal_typo.zig", "conformance/missing-review-typo.json", "vectors/riscv/fixtures/missing-review-typo.md"):
            with self.subTest(path=path), self.assertRaisesRegex(dev_test.DevTestError, "does not exist"):
                dev_test.commands_for_paths(ROOT, [path])

    def test_extra_ci_lanes_use_host_policy_and_shared_template_owner(self):
        deferred = []
        policy = dev_test.ci_scope_plan.strict_json(ROOT / "conformance/ci-touchpoints-v1.json")
        # Exercise template delegation with an explicitly local fixture; the
        # real complete RISC-V CPU lane is now hosted and tested separately.
        policy["lanes"]["riscv_cpu"]["local"] = "run"
        with mock.patch("scripts.dev_test.sys.platform", "linux"), mock.patch(
            "scripts.dev_test.ci_scope_plan.strict_json", return_value=policy,
        ):
            commands = dev_test.commands_for_paths(ROOT, ["build_support/products/riscv_cpu.zig"], deferred=deferred)
        self.assertIn("aggregate_metal", deferred)
        self.assertIn("build_graph", deferred)
        self.assertFalse(any("{output_dir}" in argument or "{commit}" in argument for command in commands for argument in command))
        delegated = [command for command in commands if "scripts/repo/ci_scope_run.py" in command]
        self.assertTrue(delegated)
        for command in delegated:
            self.assertIn("--local-compatible", command)
            self.assertIn("--output", command)
        with self.assertRaisesRegex(dev_test.DevTestError, "requires hosted validation"):
            dev_test.commands_for_paths(ROOT, ["build_support/products/riscv_cpu.zig"])

    def test_bounded_observers_defer_the_complete_cpu_lane_without_compilation(self):
        paths = [
            "src/products/riscv/tools/observations/journal.zig",
            "src/products/riscv/tools/observation_contracts.zig",
            "src/products/riscv/tools/analyze_legacy_semantics/main.zig",
            *["src/products/riscv/tools/" + name + "/app.zig" for name in
              ("pc_hotspot", "memcpy_hotspot", "function_value", "memcpy_admission")],
        ]
        for check_only in (False, True):
            for path in paths:
                deferred = []
                with self.subTest(path=path, check_only=check_only), mock.patch(
                    "scripts.dev_test.subprocess.run", side_effect=AssertionError("unexpected local tool"),
                ):
                    commands = dev_test.commands_for_paths(ROOT, [path], check_only=check_only, deferred=deferred)
                self.assertEqual([], commands)
                self.assertEqual(["riscv_cpu"], deferred)

    def test_resource_and_fixture_owners_use_focused_contracts(self):
        for filename, step in (
            ("driver_install.zig", "test-rv64-jobs-runtime"),
            ("driver_fixture_test.zig", "test-rv64-jobs-runtime"),
            ("driver_service_test.zig", "test-rv64-jobs-runtime"),
            ("gpu_native_classes.zig", "test-rv64-class-cache"),
            ("gpu_native_protocol.zig", "test-rv64-class-cache"),
        ):
            (command,) = dev_test.commands_for_paths(ROOT, ["src/integrations/riscv_cuda/rv64/jobs/" + filename], check_only=True)
            self.assertEqual(command[2], step)
            self.assertIn("-Dcheck-only=true", command)

    def test_native_polynomial_aot_has_owned_exporter_and_mandatory_authority_tests(self):
        directory = ROOT / "src/integrations/riscv_metal"
        build = (directory / "build.zig").read_text()
        for name in ("native_polynomial_aot_export.zig", "native_polynomial_aot_test_root.zig"):
            (command,) = dev_test.commands_for_paths(ROOT, [(directory / name).relative_to(ROOT).as_posix()], check_only=True)
            self.assertEqual(command[2], "test-native-polynomial-aot")
            self.assertIn("-Dcheck-only=true", command)
            self.assertLess(build.index(f'b.path("{name}")'), build.index("if (target.result.os.tag != .macos)"))
        for edge in ("native_aot_step.dependOn(&exporter.step);", "test_step.dependOn(native_aot_step);", "else &b.addRunArtifact(aot_tests).step", "linkMetalFrameworks(exporter);", "linkMetalFrameworks(aot_tests);"):
            self.assertIn(edge, build)
        self.assertIn("RISC-V Metal integration requires macOS and the Metal SDK", build)
        self.assertEqual(4, sum(line.startswith('test "') for line in (directory / "native_polynomial_aot_test_root.zig").read_text().splitlines()))

    def test_metal_resource_contracts_preserve_all_cases_and_mandatory_discovery(self):
        build = (ROOT / "src/backends/metal/build.zig").read_text()
        for filename, count in (
            ("composition_pool_test_root.zig", 4), ("external_allocation_admission_test_root.zig", 7),
            ("fri_budget_test_root.zig", 23), ("fri_inverse_lease_test_root.zig", 18),
            ("quotient_allocation_budget_test_root.zig", 10), ("quotient_result_ownership_test_root.zig", 6),
            ("resident_budget_test_root.zig", 3), ("sampled_budget_test_root.zig", 9),
        ):
            path = "src/backends/metal/" + filename
            with self.subTest(path=path):
                (command,) = dev_test.commands_for_paths(ROOT, [path], check_only=True)
                self.assertEqual(command[2], "test-resource-contracts")
                self.assertIn("-Dcheck-only=true", command)
                self.assertLess(build.index(f'b.path("{filename}")'), build.index("if (target.result.os.tag != .macos)"))
                self.assertEqual(count, sum(line.startswith('test "') for line in (ROOT / path).read_text().splitlines()))
        self.assertIn("test_step.dependOn(resource_step);", build)
        self.assertIn("else &b.addRunArtifact(resource_tests).step", build)
        (command,) = dev_test.commands_for_paths(ROOT, ["src/backends/metal/runtime/fri_inverse_cache_budget.zig"])
        self.assertEqual(command[2], "test-resource-contracts")
        (command,) = dev_test.commands_for_paths(ROOT, ["src/backends/metal/runtime.zig"])
        self.assertEqual(command[2], "test")

    def test_only_git_confirmed_unowned_deletions_select_static_checks(self):
        path = "src/retired_unowned_root.zig"
        actual_exists = Path.exists
        with mock.patch.object(Path, "exists", lambda candidate: candidate == ROOT / ".git" or actual_exists(candidate)):
            with mock.patch("scripts.dev_test.subprocess.check_output", return_value=path + "\n"):
                commands = dev_test.commands_for_paths(ROOT, [path])
            self.assertTrue(any("scripts/repo/ci_scope_run.py" in command and command[command.index("--lane") + 1] == "static" for command in commands))
            with mock.patch("scripts.dev_test.subprocess.check_output", return_value=""):
                with self.assertRaises(dev_test.DevTestError):
                    dev_test.commands_for_paths(ROOT, [path])

    def test_live_fixtures_select_actual_package_and_script_validators(self):
        for path in ("vectors/riscv/rv64/m3-basket/summary.json", "vectors/riscv/fixtures/README.md"):
            with self.subTest(path=path):
                commands = dev_test.commands_for_paths(ROOT, [path])
                self.assertTrue(any("scripts/repo/ci_scope_run.py" in command and command[command.index("--lane") + 1] == "script_contracts" for command in commands))
                for owner in ("src/frontends/riscv", "src/integrations/riscv_cuda"):
                    self.assertTrue(any(f"{owner}/build.zig" in command for command in commands))
        commands = dev_test.commands_for_paths(ROOT, ["conformance/rv64-flags.json"])
        self.assertTrue(any("scripts/repo/ci_scope_run.py" in command and command[command.index("--lane") + 1] == "static" for command in commands))
        combined = dev_test.commands_for_paths(ROOT, ["scripts/tests/test_dev_test.py", "vectors/riscv/fixtures/README.md"])
        self.assertEqual(1, sum("scripts/repo/ci_scope_run.py" in command and command[command.index("--lane") + 1] == "script_contracts" for command in combined))
        self.assertFalse(any(command[1:3] == ["-m", "unittest"] for command in combined))

    def test_documentation_uses_ci_policy_without_runtime_builds(self):
        self.assertEqual([], dev_test.commands_for_paths(ROOT, [
            "CONTRIBUTING.md", "src/engine/prover/README.md", "design/riscv/rv64-gpu-hygiene.md",
        ]))

    def test_nonexistent_python_typo_never_selects_the_contract_suite(self):
        with self.assertRaisesRegex(dev_test.DevTestError, "does not exist"):
            dev_test.commands_for_paths(ROOT, ["scripts/tests/test_ci_scope_plan.py"])

    def test_recursion_dag_uses_its_standalone_cpu_owner(self):
        commands = dev_test.commands_for_paths(ROOT, ["src/integrations/riscv_cpu/rv64_recursion/om31_native/ready_dag.zig"], optimize="ReleaseFast")
        self.assertEqual(1, len(commands))
        self.assertIn("test-recursion-dag", commands[0])
        self.assertIn("src/integrations/riscv_cpu/build.zig", commands[0])

    def test_optimized_ci_reproduction_covers_focused_and_broad_routes(self) -> None:
        for path, step in (
            ("src/frontends/riscv/rv32/air/extract/runtime_program.zig", "test-runtime-selector"),
            ("src/frontends/riscv/rv32/focused_test_runtime_selector_0.zig", "test-runtime-selector"),
            ("src/frontends/riscv/recursion/focused_test_retained_fri_frontier_0.zig", "test-retained-fri-frontier"),
            ("src/integrations/riscv_cpu/blake3_proof_tests/blake3_memory_path_proof_test.zig", "test-blake3-proof-contracts"),
            ("src/integrations/riscv_cpu/blake3_proof_contract_test_root.zig", "test-blake3-proof-contracts"),
            ("src/integrations/riscv_cpu/blake3_memory_path_proof_test_root.zig", "test-blake3-proof-contracts"),
            ("src/integrations/riscv_cpu/word16_image_program_contract_test_root.zig", "test-word16-image-program-contracts"),
            ("src/integrations/riscv_cpu/distributed_binary_contract_test_root.zig", "test-distributed-binary-contracts"),
            ("src/frontends/riscv/focused_test_retained_typed_components_0.zig", "test-retained-typed-components"),
            ("src/frontends/riscv/compat/tests/testing/cases/recursion/tests/segment_leaf_local_projection_test.zig", "test-retained-transcript-contracts"),
            ("src/frontends/riscv/compat/tests/testing/cases/recursion/tests/vm_composition_program_test.zig", "test-retained-typed-components"),
            ("src/frontends/riscv/focused_test_retained_transcript_contracts_0.zig", "test-retained-transcript-contracts"),
            ("src/waist/core/air_components_test_root.zig", "test-air-components"),
            ("src/waist/core/tests/borrowed_proof_capture_root.zig", "test-proof-capture"),
            ("src/frontends/riscv/focused_retained_authority_contract_test_root.zig", "test-retained-authority-contracts"),
            ("src/integrations/riscv_cpu/division_contract_test_root.zig", "test-division-contracts"),
            ("src/integrations/riscv_cpu/services_truth_contract_test_root.zig", "test-services-truth-contracts"),
            ("src/frontends/riscv/air_lang/framework/control_row.zig", "test-recursion-framework-interaction"),
            ("src/frontends/riscv/test_inventory_test.zig", "test-inventory"),
            ("src/frontends/riscv/test_inventory.zig", "test-inventory"),
            ("src/frontends/riscv/rv64_test_inventory.zig", "test-inventory"),
            ("src/waist/core/fri/folding_family.zig", "test-fri"),
            ("src/waist/core/mod.zig", "test"),
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
                future = ROOT / "src/integrations/riscv_cuda/rv64/jobs" / filename
                exists = Path.exists
                with mock.patch.object(Path, "exists", lambda path: path == future or exists(path)):
                    (command,) = dev_test.commands_for_paths(ROOT, [future.relative_to(ROOT).as_posix()])
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
        future = ROOT / "src/engine/prover/pcs/quotient_future.zig"
        exists = Path.exists
        with mock.patch.object(Path, "exists", lambda path: path == future or exists(path)):
            (command,) = dev_test.commands_for_paths(ROOT, [future.relative_to(ROOT).as_posix()])
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
        unowned = ROOT / "src/unowned_new_source.zig"
        exists = Path.exists
        with mock.patch.object(Path, "exists", lambda path: path == unowned or exists(path)):
            with self.assertRaisesRegex(dev_test.DevTestError, "no Zig package owns"):
                dev_test.commands_for_paths(ROOT, [unowned.relative_to(ROOT).as_posix()])


if __name__ == "__main__":
    unittest.main()
