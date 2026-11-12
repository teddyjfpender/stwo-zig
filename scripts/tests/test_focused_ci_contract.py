from __future__ import annotations

import io
import contextlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts.repo import ci_scope_plan, ci_scope_push, ci_scope_run, zig_serial_build
from scripts.tests.focused_ci_fixtures import catalog_fixture, product


ROOT = Path(__file__).resolve().parents[2]
COMMIT = "1" * 40
TREE = "2" * 40
class PlannerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = ci_scope_plan.strict_json(
            ROOT / "conformance/ci-touchpoints-v1.json"
        )
        cls.catalog = catalog_fixture()

    def lanes_for(self, *paths: str) -> set[str]:
        lanes, _ = ci_scope_plan.select_lanes(paths, self.catalog, self.policy)
        return set(lanes)

    def test_manual_cpu_selection_is_exact_and_refuses_device_or_foreign_lanes(self):
        for lane in ci_scope_plan.MANUAL_CPU_LANES:
            lanes, reasons = ci_scope_plan.manual_cpu_selection(lane, self.policy)
            self.assertEqual([lane], lanes)
            self.assertIn("not automatic PR scope", reasons[lane][0])
        for lane in ("native_cuda_device", "native_metal", "cairo_metal", "unknown", "core; echo injected"):
            with self.assertRaises(ci_scope_plan.PlanError):
                ci_scope_plan.manual_cpu_selection(lane, self.policy)
        for field, value in (("host", "cuda"), ("hosted", False)):
            policy = json.loads(json.dumps(self.policy))
            policy["lanes"]["core"][field] = value
            with self.assertRaises(ci_scope_plan.PlanError):
                ci_scope_plan.manual_cpu_selection("core", policy)

    def test_manual_cli_emits_pinned_diagnostic_without_diff_or_package_scope(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            catalog = directory / "catalog.json"
            catalog.write_text(json.dumps(self.catalog))
            output = directory / "plan.json"
            arguments = ["--root", str(ROOT), "--catalog", str(catalog),
                         "--manual-cpu-lane", "circuit_frontend", "--output", str(output)]
            with mock.patch.object(ci_scope_plan, "source_identity", return_value=(COMMIT, TREE)), mock.patch.object(
                ci_scope_plan, "git_changed_paths", side_effect=AssertionError("diagnostic is not diff coverage"),
            ), mock.patch.object(ci_scope_plan.ci_package_graph, "load_packages", side_effect=AssertionError("no automatic package scope")), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, ci_scope_plan.main(arguments))
            plan = json.loads(output.read_text())
            self.assertEqual(["circuit_frontend"], plan["lanes"])
            self.assertEqual([], plan["changed_paths"])
            self.assertEqual((COMMIT, TREE), (plan["head"], plan["tree"]))

    def test_documentation_only_change_runs_only_always_lanes(self) -> None:
        self.assertEqual({"static"}, self.lanes_for("docs/focused-ci.md"))

    def test_unknown_non_documentation_path_fails_closed_to_every_lane(self) -> None:
        self.assertEqual(
            set(self.policy["lanes"]),
            self.lanes_for("packaging/new-release-surface.toml"),
        )

    def test_ci_policy_or_planner_change_runs_only_control_contracts(self) -> None:
        expected = {"static", "script_contracts", "build_graph"}
        for path in (
            "conformance/ci-touchpoints-v1.json",
            "scripts/repo/ci_scope_plan.py",
        ):
            with self.subTest(path=path):
                self.assertEqual(expected, self.lanes_for(path))

    def test_shared_core_change_fans_out_to_every_consumer_and_package(self) -> None:
        selected = self.lanes_for("src/waist/core/fields/m31.zig")
        self.assertTrue(
            {
                "static",
                "core",
                "backend_contracts",
                "prover",
                "riscv_frontend",
                "riscv_cpu_integration",
                "riscv_metal_integration",
                "cairo_frontend",
                "cairo_cpu_integration",
                "cpu_backend",
                "metal_backend",
                "package",
                "native_cpu",
                "native_oracle",
                "riscv_cpu",
                "aggregate_cpu",
                "native_cuda_static",
                "native_cuda_device",
                "native_metal",
                "riscv_metal",
                "aggregate_metal",
            }.issubset(selected)
        )
        self.assertNotIn("metal_aot", selected)

    def test_backend_contract_change_runs_its_package_and_dependents(self) -> None:
        selected = self.lanes_for("src/waist/backend/merkle_ops.zig")
        self.assertTrue(
            {
                "static",
                "backend_contracts",
                "prover",
                "riscv_frontend",
                "cairo_frontend",
                "cpu_backend",
                "cuda_backend",
                "metal_backend",
                "package",
            }.issubset(selected)
        )
        self.assertNotIn("core", selected)

    def test_riscv_frontend_has_an_independent_package_lane(self) -> None:
        selected = self.lanes_for("src/frontends/riscv/rv32/air/semantic_eval.zig")
        self.assertTrue(
            {
                "static",
                "riscv_frontend",
                "riscv_cpu_integration",
                "riscv_metal_integration",
                "package",
                "riscv_cpu",
                "riscv_metal",
                "aggregate_cpu",
                "aggregate_metal",
            }.issubset(selected)
        )
        commands = self.policy["lanes"]["riscv_frontend"]["commands"] + self.policy["lanes"]["riscv_frontend_releasefast"]["commands"]
        self.assertEqual(4, len(commands))
        self.assertEqual([["python3", "scripts/repo/zig_serial_build.py", "--cwd", "src/frontends/riscv", "test-retained-transcript-contracts", "test-retained-typed-components", f"-Doptimize={mode}", "-j1", "--summary", "all", "--verbose"] for mode in ("Debug", "ReleaseFast")], self.policy["lanes"]["riscv_retained_contracts"]["commands"] + self.policy["lanes"]["riscv_retained_contracts_releasefast"]["commands"])
        self.assertEqual([["python3", "scripts/repo/zig_serial_build.py", "--cwd", "src/frontends/riscv", "test-air-runtime-profile", f"-Doptimize={mode}", "-j2", "--summary", "all"] for mode in ("Debug", "ReleaseFast")], self.policy["lanes"]["riscv_runtime_profile"]["commands"])
        for command, step, mode in zip(commands, ("test-air-runtime-profile", "test-air-runtime-profile", "test", "test"), ("Debug", "ReleaseFast", "Debug", "ReleaseFast"), strict=True):
            self.assertEqual(["zig", "build", step, "--build-file", "src/frontends/riscv/build.zig", f"-Doptimize={mode}", "-j2"] + (["--verbose", "--summary", "all"] if step == "test" else []), command)

    def test_releasefast_companions_keep_every_parent_trigger(self) -> None:
        for parent in ("riscv_frontend", "riscv_retained_contracts"):
            companion = parent + "_releasefast"
            for rule in self.policy["rules"]:
                self.assertEqual(parent in rule["lanes"], companion in rule["lanes"])
            for lanes in self.policy["product_scope_lanes"].values():
                self.assertEqual(parent in lanes, companion in lanes)
            selected = self.lanes_for("src/frontends/riscv/focused_test_retained_typed_components_0.zig")
            self.assertTrue({parent, companion}.issubset(selected))
            self.assertIn(companion, ci_scope_plan.MANUAL_CPU_LANES)

    def test_releasefast_failure_diagnostic_retains_four_correctness_cases_and_full_gate(self):
        package = ROOT / "src/frontends/riscv"
        catalog = (package / "build_focused_tests.zig").read_text()
        spec = catalog.split('.step = "test-releasefast-acceptance",', 1)[1].split('\n    },', 1)[0]
        filters = re.findall(r'"([^"\n]+)"', re.search(r'\.filters = &\.\{(.*?)\}', spec, re.S)[1])
        parts = re.search(r'\.partition_roots = &\.\{(.*?)\}', spec, re.S)
        roots = re.findall(r'"([^"\n]+)"', parts[1]) if parts else re.findall(r'\.root = "([^"\n]+)"', spec)
        imports = [str((package / source).parent / name) for source in roots
                   for name in re.findall(r'@import\("([^"\n]+\.zig)"\)', (package / source).read_text())]
        self.assertEqual(4, len(set(filters)))
        self.assertEqual(4, len(set(imports)))
        declared = [name for path in imports for name in re.findall(r'test "([^"]+)"', Path(path).read_text())]
        self.assertTrue(all(sum(name == selected for name in declared) == 1 for selected in filters))
        self.assertIn('.error_tracing = true,', spec)
        self.assertIn('.strip = false,', spec)
        lane = "riscv_frontend_acceptance"
        self.assertEqual([["zig", "build", "test-releasefast-acceptance", "--build-file", "src/frontends/riscv/build.zig", "-Doptimize=ReleaseFast", "-j2", "--verbose", "--summary", "all"]], self.policy["lanes"][lane]["commands"])
        self.assertIn(lane, ci_scope_plan.MANUAL_CPU_LANES)
        selected = self.lanes_for("src/frontends/riscv/testing/focused_test_releasefast_acceptance_0.zig")
        self.assertTrue({lane, "riscv_frontend_releasefast"}.issubset(selected))

    def test_package_workspace_has_a_dedicated_failing_pr_gate(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        job = workflow.split("  package-workspace:", 1)[1].split("  focused-plan:", 1)[0]
        self.assertIn("name: Package workspace contracts", job)
        self.assertIn("github.event_name == 'pull_request'", job)
        self.assertIn("run: python3 scripts/repo/check_package_workspace.py", job)
        self.assertNotIn("continue-on-error", job)
        self.assertNotIn("|| true", job)

    def test_main_releasefast_baseline_pins_source_and_identical_command(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        baseline = workflow.split("  frontend-main-baseline:", 1)[1].split("  focused-macos:", 1)[0]
        command, = self.policy["lanes"]["riscv_frontend_releasefast"]["commands"]
        self.assertIn("argv = " + json.dumps(command), baseline)
        self.assertEqual(2, baseline.count("4e260db9605d16fef5d405cc3c280e3042b22e35"))
        self.assertIn("timeout-minutes: 90", baseline)
        self.assertIn("absent tests are not passing evidence", baseline)

    def test_timing_benchmarks_are_separate_and_nonblocking(self):
        package = ROOT / "src/frontends/riscv"
        catalog = (package / "build_focused_tests.zig").read_text()
        spec = catalog.split('.step = "test-typed-witness-benchmarks",', 1)[1].split('\n    },', 1)[0]
        self.assertIn('.minimum = 52,', spec)
        filters = re.findall(r'"([^"\n]+)"', re.search(r'\.filters = &\.\{(.*?)\}', spec, re.S)[1])
        roots = re.findall(r'"([^"\n]+)"', re.search(r'\.partition_roots = &\.\{(.*?)\}', spec, re.S)[1])
        subjects = [(package / source).parent / name for source in roots
                    for name in re.findall(r'@import\("([^"\n]+\.zig)"\)', (package / source).read_text())]
        names = [name for path in subjects for name in re.findall(r'test "([^"\n]+)"', path.read_text())]
        self.assertEqual(52, len(set(filters)))
        self.assertEqual(52, len(names))
        self.assertEqual(set(filters), set(names))
        for path in subjects:
            relative = path.resolve().relative_to(package)
            if relative.parts[0] == "testing":
                inventory = package / "testing/tests/root.zig"
                quoted = "../" + relative.relative_to("testing").as_posix()
            else:
                inventory, quoted = package / "test_inventory.zig", relative.as_posix()
            self.assertNotIn('@import("' + quoted + '")', inventory.read_text())
            self.assertIn('.path = "' + relative.as_posix() + '"', (package / "test_inventory_test.zig").read_text())
        commands = self.policy["lanes"]["riscv_witness_benchmarks"]["commands"]
        self.assertEqual([["zig", "build", "test-typed-witness-benchmarks", "--build-file", "src/frontends/riscv/build.zig", "-Doptimize=" + mode, "-j2", "--verbose", "--summary", "all"] for mode in ("ReleaseFast", "Debug")], commands)
        self.assertIn("continue-on-error: ${{ matrix.lane == 'riscv_witness_benchmarks' }}", (ROOT / ".github/workflows/ci.yml").read_text())

    def test_benchmark_admission_is_exact_and_never_applies_to_correctness_lanes(self):
        arguments = dict(root=ROOT, output=Path("unused"), cache_mode="unreached", cache_root=None, local_compatible=True)
        with self.assertRaisesRegex(ci_scope_plan.PlanError, "invalid cache mode"):
            ci_scope_run.run_lane(policy=self.policy, lane="riscv_witness_benchmarks", **arguments)
        for lane, target in (("riscv_frontend_acceptance", "test-typed-witness-benchmarks"), ("riscv_witness_benchmarks", "benchmark-whole-block")):
            policy = json.loads(json.dumps(self.policy))
            policy["lanes"][lane]["commands"] = [["zig", "build", target]]
            with self.assertRaisesRegex(ci_scope_plan.PlanError, "contains workload targets"):
                ci_scope_run.run_lane(policy=policy, lane=lane, **arguments)

    def test_cairo_frontend_has_an_independent_package_lane(self) -> None:
        selected = self.lanes_for("src/frontends/cairo/air/components/add_ap.zig")
        self.assertTrue(
            {
                "static",
                "cairo_frontend",
                "cairo_cpu_integration",
                "package",
                "cairo_cpu",
                "cairo_metal",
                "native_cuda_static",
                "native_cuda_device",
            }.issubset(selected)
        )
        commands = self.policy["lanes"]["cairo_frontend"]["commands"]
        self.assertEqual(1, len(commands))
        self.assertIn("src/frontends/cairo/build.zig", commands[0])

    def test_cairo_frontend_package_tests_bind_the_repository_vector_root(self) -> None:
        build = (ROOT / "src/frontends/cairo/build.zig").read_text(encoding="utf-8")
        self.assertIn('b.pathFromRoot("../../..")', build)
        self.assertEqual(2, build.count("setCwd(repository_root)"))

    def test_cpu_backend_has_an_independent_package_lane(self) -> None:
        selected = self.lanes_for("src/backends/cpu_scalar/mod.zig")
        self.assertTrue(
            {
                "static",
                "cpu_backend",
                "riscv_cpu_integration",
                "cairo_cpu_integration",
                "package",
                "native_cpu",
                "riscv_cpu",
                "cairo_cpu",
                "native_cuda_static",
                "native_cuda_device",
                "native_metal",
                "riscv_metal",
                "aggregate_cpu",
                "aggregate_metal",
            }.issubset(selected)
        )
        commands = self.policy["lanes"]["cpu_backend"]["commands"]
        self.assertEqual(1, len(commands))
        self.assertIn("src/backends/cpu_scalar/build.zig", commands[0])

    def test_metal_backend_has_an_independent_package_lane(self) -> None:
        selected = self.lanes_for("src/backends/metal/mod.zig")
        self.assertTrue(
            {
                "static",
                "metal_backend",
                "riscv_metal_integration",
                "package",
                "native_metal",
                "riscv_metal",
                "aggregate_metal",
                "metal_compile",
            }.issubset(selected)
        )
        lane = self.policy["lanes"]["metal_backend"]
        self.assertEqual("macos", lane["host"])
        self.assertNotIn("hosted", lane)
        commands = lane["commands"]
        self.assertEqual(1, len(commands))
        self.assertIn("src/backends/metal/build.zig", commands[0])

    def test_cuda_backend_has_an_independent_package_lane(self) -> None:
        selected = self.lanes_for("src/backends/cuda/runtime/session.zig")
        self.assertTrue(
            {
                "static",
                "cuda_backend",
                "native_cuda_integration",
                "cairo_cuda_integration", "riscv_cuda_integration",
                "package",
                "native_cuda_static",
                "native_cuda_device",
            }.issubset(selected)
        )
        lane = self.policy["lanes"]["cuda_backend"]
        self.assertEqual("linux", lane["host"])
        commands = lane["commands"]
        self.assertEqual(1, len(commands))
        self.assertIn("src/backends/cuda/build.zig", commands[0])

    def test_riscv_lane_produces_and_independently_verifies_real_proofs(self) -> None:
        commands = self.policy["lanes"]["riscv_cpu"]["commands"]
        self.assertEqual(["zig", "build", "test-riscv64-parallel", "-Doptimize=Debug", "-j2", "--verbose"], commands[0])
        self.assertIn("stwo-zig-riscv-cpu", commands[1])
        proof_commands = [
            command for command in commands
            if "scripts/riscv/riscv_pr_proof_smoke.py" in command
        ]
        self.assertEqual(1, len(proof_commands))
        self.assertIn("--artifact-dir", proof_commands[0])
        self.assertIn("--report-out", proof_commands[0])
        proof_index = commands.index(proof_commands[0])
        self.assertEqual(2, proof_index)
        self.assertLess(proof_index, next(i for i, command in enumerate(commands) if "test-riscv-observation-contracts" in command and "-Doptimize=Debug" in command))
        self.assertLess(proof_index, next(i for i, command in enumerate(commands) if "test-riscv-profile-partition" in command))

    def test_riscv_parallel_residual_and_drain_contracts_run_in_both_modes(self) -> None:
        commands = self.policy["lanes"]["riscv_cpu"]["commands"]
        for mode in ("Debug", "ReleaseFast"):
            self.assertTrue(any(
                "test-riscv64-parallel" in command and f"-Doptimize={mode}" in command
                for command in commands
            ), mode)

    def test_core_retains_standalone_fri_case_and_ir_in_both_modes(self) -> None:
        commands = self.policy["lanes"]["core"]["commands"]
        for mode in ("Debug", "ReleaseFast"):
            self.assertTrue(any("src/waist/core/fields/tests/cm31_fri_case.zig" in command and "-O" + mode in command and any(arg.startswith("-femit-llvm-ir=") for arg in command) for command in commands), mode)

    def test_riscv_auxiliary_build_owners_select_only_cpu_consumers(self) -> None:
        expected = {"static", "build_graph", "riscv_cpu", "aggregate_cpu", "aggregate_metal"}
        paths = ("build_support/products/riscv_refinement.zig",
                 "build_support/products/riscv_sail_oracle_tests.zig")
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(expected, self.lanes_for(path))

    def test_riscv_product_and_release_gate_consume_formal_certificate_index(self) -> None:
        for relative in ("build_support/products/riscv_cpu.zig",
                         "build_support/gates/riscv.zig"):
            with self.subTest(relative=relative):
                source = (ROOT / relative).read_text(encoding="utf-8")
                self.assertIn("scripts/riscv/riscv_opcode_coverage.py", source)
                self.assertIn('"check"', source)

    def test_leaf_native_cpu_change_does_not_select_unrelated_products(self) -> None:
        self.assertEqual(
            {"static", "native_cpu"},
            self.lanes_for("src/products/native/cpu/cli.zig"),
        )

    def test_cuda_change_requires_static_and_explicit_device_lanes(self) -> None:
        selected = self.lanes_for(
            "src/backends/cuda/native/commitment/progressive.cu"
        )
        self.assertEqual(
            {
                "static",
                "cuda_backend",
                "native_cuda_integration",
                "cairo_cuda_integration",
                "riscv_cuda_integration",
                "package",
                "native_cuda_static",
                "native_cuda_device",
            },
            selected,
        )
        device = self.policy["lanes"]["native_cuda_device"]
        self.assertFalse(device["hosted"])
        self.assertEqual("hosted", device["local"])
        command = "\n".join(device["commands"][0])
        self.assertIn("STWO_CUDA_NVCC", command)
        self.assertIn("zig build stwo-native-cuda", command)
        self.assertIn("scripts/cuda/cuda_device_smoke.py", command)
        self.assertIn("cuda_device_smoke_receipt.json", command)
        self.assertIn('len(receipt["tests"]) == 12', command)
        self.assertIn("zig build stwo-native-cpu", command)
        self.assertIn("scripts/cuda/cuda_proof_parity_gate.py", command)
        self.assertIn("--rust-verifier-sha256", command)
        self.assertIn("--repeat 3", command)
        self.assertIn("--air poseidon", command)
        self.assertIn("--execution-mode graphs", command)
        self.assertIn("--execution-mode direct", command)
        self.assertIn("native-cuda-poseidon-graphs/receipt.json", command)
        self.assertIn("native-cuda-poseidon-direct/receipt.json", command)
        self.assertIn("nvidia-smi", command)

    def test_cairo_cuda_scope_has_a_host_only_contract_lane(self) -> None:
        self.assertEqual(
            {
                "static",
                "cairo_cuda_integration",
                "package",
                "native_cuda_static",
            },
            self.lanes_for("src/integrations/cairo_cuda/executor/mod.zig"),
        )

    def test_cairo_cpu_runs_official_product_and_oracle_gates(self) -> None:
        selected = self.lanes_for("src/integrations/cairo_cpu/prover/transaction.zig")
        self.assertEqual(
            {
                "static", "cairo_cpu_integration", "package",
                "cairo_cpu", "cairo_metal",
                "circuit_metal_integration", "circuit_recursion_cpu",
            },
            selected,
        )
        lane = self.policy["lanes"]["cairo_cpu"]
        self.assertEqual("linux", lane["host"])
        self.assertEqual("hosted", lane["local"])
        commands = [" ".join(command) for command in lane["commands"]]
        self.assertTrue(any("test-cairo-cpu-proof" in command for command in commands))
        self.assertTrue(any("test-cairo-cpu-product" in command for command in commands))
        self.assertTrue(any("test-cairo-cpu-oracle" in command for command in commands))

    def test_cairo_metal_requires_real_device_and_authenticated_aot(self) -> None:
        selected = self.lanes_for(
            "src/integrations/cairo_metal/prover/transaction.zig"
        )
        self.assertEqual(
            {
                "static",
                "cairo_metal_integration",
                "package",
                "cairo_metal", "circuit_metal_integration",
                "metal_compile",
            },
            selected,
        )
        lane = self.policy["lanes"]["cairo_metal"]
        self.assertEqual("macos", lane["host"])
        self.assertFalse(lane["hosted"])
        command = "\n".join(lane["commands"][0])
        self.assertIn("STWO_METAL_CORE_AOT_BUNDLE", command)
        self.assertIn("stwo_zig_core.manifest.sha256", command)
        self.assertIn("test-cairo-metal-product", command)
        self.assertNotIn("test-cairo-metal-oracle", command)

    def test_metal_shader_selects_aot_but_runtime_does_not(self) -> None:
        shader = self.lanes_for(
            "src/backends/metal/shaders/core/circle_transform.metal"
        )
        runtime = self.lanes_for("src/backends/metal/runtime.m")
        self.assertIn("metal_aot", shader)
        self.assertIn("metal_compile", shader)
        self.assertIn("metal_backend", shader)
        self.assertIn("package", shader)
        self.assertIn("native_metal", shader)
        self.assertIn("riscv_metal", shader)
        self.assertNotIn("native_cpu", shader)
        self.assertNotIn("riscv_cpu", shader)
        self.assertNotIn("metal_aot", runtime)
        self.assertNotIn("build_graph", runtime)
        self.assertIn("metal_compile", runtime)
        self.assertIn("metal_backend", runtime)
        self.assertIn("package", runtime)
        self.assertIn("native_metal", runtime)
        self.assertIn("riscv_metal", runtime)

    def test_multiple_paths_take_the_conservative_union(self) -> None:
        selected = self.lanes_for(
            "docs/release.md",
            "src/products/native/cpu/cli.zig",
            "src/backends/metal/runtime.m",
        )
        self.assertTrue(
            {
                "static",
                "native_cpu",
                "metal_backend",
                "native_metal",
                "riscv_metal",
                "metal_compile",
            }.issubset(
                selected
            )
        )

    def test_deferred_catalog_states_are_explicitly_covered(self) -> None:
        catalog = catalog_fixture()
        products = catalog["products"]
        assert isinstance(products, list)
        products.extend(
            [
                product("deferred", state="disabled"),
                product("deferred", state="experimental"),
                product("deferred", state="unavailable"),
            ]
        )
        self.assertEqual(["deferred"], self.policy["product_scope_lanes"]["deferred"])
        ci_scope_plan.validate_catalog(catalog, self.policy)

    def test_new_constructible_scope_without_lane_fails_closed(self) -> None:
        catalog = catalog_fixture()
        products = catalog["products"]
        assert isinstance(products, list)
        products.append(product("new_product", "src/new_product", state="staged"))
        with self.assertRaisesRegex(
            ci_scope_plan.PlanError, "product scopes lack CI lanes"
        ):
            ci_scope_plan.validate_catalog(catalog, self.policy)

    def test_empty_or_unsafe_changed_paths_are_rejected(self) -> None:
        with self.assertRaisesRegex(ci_scope_plan.PlanError, "no changed paths"):
            ci_scope_plan.select_lanes([], self.catalog, self.policy)
        for path in ("../outside", "/absolute/path", "src/waist/core/../../outside"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(ci_scope_plan.PlanError, "unsafe"):
                    ci_scope_plan.select_lanes([path], self.catalog, self.policy)

    def test_path_ownership_is_component_safe(self) -> None:
        self.assertTrue(ci_scope_plan.owns("src/waist/core/field.zig", "src/waist/core"))
        self.assertFalse(ci_scope_plan.owns("src/coreish/field.zig", "src/waist/core"))

    def test_git_rename_and_delete_classify_old_and_new_paths(self) -> None:
        result = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=b"R100\0src/waist/core/old.zig\0src/waist/core/new.zig\0D\0src/engine/prover/gone.zig\0",
            stderr=b"",
        )
        with mock.patch.object(ci_scope_plan.subprocess, "run", return_value=result):
            paths = ci_scope_plan.git_changed_paths(ROOT, "base", "head")
        self.assertEqual(
            ["src/waist/core/old.zig", "src/waist/core/new.zig", "src/engine/prover/gone.zig"],
            paths,
        )

    def test_github_output_has_separate_deterministic_host_matrices(self) -> None:
        # native_metal is hosted=false (needs a real Metal device): selected
        # into the plan, but never emitted into a hosted matrix.
        plan = {"lanes": ["native_cpu", "native_metal", "static"]}
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "github-output"
            ci_scope_plan.emit_github_output(output, plan, self.policy)
            lines = output.read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            [
                'linux_matrix={"lane":["native_cpu","static"]}',
                "linux_count=2",
                'macos_matrix={"lane":[]}',
                "macos_count=0",
                "cuda_required=false",
            ],
            lines,
        )

    def test_cuda_device_lane_is_not_emitted_to_generic_linux(self) -> None:
        plan = {"lanes": ["native_cuda_static", "native_cuda_device"]}
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "github-output"
            ci_scope_plan.emit_github_output(output, plan, self.policy)
            lines = output.read_text(encoding="utf-8").splitlines()
        self.assertIn(
            'linux_matrix={"lane":["native_cuda_static"]}',
            lines,
        )
        self.assertIn("cuda_required=true", lines)

    def test_hosted_capable_macos_lane_still_emitted(self) -> None:
        plan = {"lanes": ["native_metal", "riscv_metal", "aggregate_metal", "metal_backend"]}
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "github-output"
            ci_scope_plan.emit_github_output(output, plan, self.policy)
            lines = output.read_text(encoding="utf-8").splitlines()
        self.assertIn(
            'macos_matrix={"lane":["aggregate_metal","metal_backend"]}',
            lines,
        )
        self.assertIn("macos_count=2", lines)

    def test_hosted_flag_must_be_boolean(self) -> None:
        policy = json.loads(json.dumps(self.policy))
        policy["lanes"]["native_metal"]["hosted"] = "never"
        with self.assertRaises(ci_scope_plan.PlanError):
            ci_scope_plan.validate_policy(policy)


from scripts.tests.focused_ci_runner_contracts import runner_policy


from scripts.tests.focused_ci_runner_contracts import RunnerReceiptTests
RunnerReceiptTests.__module__ = __name__


if __name__ == "__main__":
    unittest.main()
