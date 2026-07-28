from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts import ci_scope_plan, ci_scope_push, ci_scope_run


ROOT = Path(__file__).resolve().parents[2]
COMMIT = "1" * 40
TREE = "2" * 40


def product(scope: str, *prefixes: str, state: str = "released") -> dict[str, object]:
    return {
        "scope": scope,
        "state": state,
        "module_roots": [],
        "allowed_files": [],
        "configure_allowed_files": [],
        "allowed_prefixes": list(prefixes),
        "configure_allowed_prefixes": [],
    }


def catalog_fixture() -> dict[str, object]:
    return {
        "schema": "stwo-product-catalog-v2",
        "products": [
            product(
                "aggregate",
                "src/core",
                "src/backend",
                "src/prover",
                "src/backends/cpu_scalar",
                "src/frontends/riscv",
                "src/integrations/riscv_cpu",
            ),
            product("core", "src/core"),
            product("prover", "src/core", "src/backend", "src/prover"),
            product(
                "native_cpu",
                "src/core",
                "src/backend",
                "src/prover",
                "src/backends/cpu_scalar",
                "src/products/native_cpu",
            ),
            product(
                "riscv_cpu",
                "src/core",
                "src/backend",
                "src/prover",
                "src/backends/cpu_scalar",
                "src/frontends/riscv",
                "src/integrations/riscv_cpu",
            ),
            product(
                "cairo_cpu",
                "src/core",
                "src/backend",
                "src/prover",
                "src/backends/cpu_scalar",
                "src/frontends/cairo",
                "src/integrations/cairo_cpu",
                "src/products/cairo_cpu",
            ),
            product(
                "cairo_metal",
                "src/core",
                "src/backend",
                "src/prover",
                "src/backends/cpu_scalar",
                "src/backends/metal",
                "src/frontends/cairo",
                "src/integrations/cairo_metal",
                "src/products/cairo_metal",
            ),
            product(
                "native_metal",
                "src/core",
                "src/backend",
                "src/prover",
                "src/backends/cpu_scalar",
                "src/backends/metal",
            ),
            product(
                "riscv_metal",
                "src/core",
                "src/backend",
                "src/prover",
                "src/backends/cpu_scalar",
                "src/backends/metal",
                "src/frontends/riscv",
                "src/integrations/riscv_metal",
                "src/products/riscv_metal",
            ),
            product(
                "native_cuda",
                "src/core",
                "src/backend",
                "src/prover",
                "src/backends/cuda",
                "src/backends/cpu_scalar",
                "src/backends/metal",
                "src/frontends/cairo",
                "src/frontends/riscv",
                "src/integrations/native_cuda",
                "src/products/native_cuda",
                state="staged",
            ),
            product(
                "cairo_cuda",
                "src/backends/cuda",
                "src/frontends/cairo",
                "src/integrations/cairo_cuda",
                "src/products/cairo_cuda",
                state="staged",
            ),
        ],
    }


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

    def test_documentation_only_change_runs_only_always_lanes(self) -> None:
        self.assertEqual({"static"}, self.lanes_for("docs/focused-ci.md"))

    def test_unknown_non_documentation_path_fails_closed_to_every_lane(self) -> None:
        self.assertEqual(
            set(self.policy["lanes"]),
            self.lanes_for("packaging/new-release-surface.toml"),
        )

    def test_ci_policy_or_planner_change_selects_every_lane(self) -> None:
        for path in (
            "conformance/ci-touchpoints-v1.json",
            "scripts/ci_scope_plan.py",
            ".github/workflows/ci.yml",
        ):
            with self.subTest(path=path):
                self.assertEqual(set(self.policy["lanes"]), self.lanes_for(path))

    def test_shared_core_change_fans_out_to_every_consumer_and_package(self) -> None:
        selected = self.lanes_for("src/core/fields/m31.zig")
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
        selected = self.lanes_for("src/backend/merkle_ops.zig")
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
        selected = self.lanes_for("src/frontends/riscv/air/semantic_eval.zig")
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
        commands = self.policy["lanes"]["riscv_frontend"]["commands"]
        self.assertEqual(1, len(commands))
        self.assertIn("src/frontends/riscv/build.zig", commands[0])

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
                "metal_backend",
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
                "cairo_cuda_integration",
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
        self.assertIn("stwo-zig-riscv-cpu", commands[0])
        proof_commands = [
            command for command in commands
            if "scripts/riscv_pr_proof_smoke.py" in command
        ]
        self.assertEqual(1, len(proof_commands))
        self.assertIn("--artifact-dir", proof_commands[0])
        self.assertIn("--report-out", proof_commands[0])

    def test_leaf_native_cpu_change_does_not_select_unrelated_products(self) -> None:
        self.assertEqual(
            {"static", "native_cpu"},
            self.lanes_for("src/products/native_cpu/cli.zig"),
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
        self.assertIn("scripts/cuda_device_smoke.py", command)
        self.assertIn("cuda_device_smoke_receipt.json", command)
        self.assertIn('len(receipt["tests"]) == 12', command)
        self.assertIn("zig build stwo-native-cpu", command)
        self.assertIn("scripts/cuda_proof_parity_gate.py", command)
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
                "cairo_metal",
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
            "src/products/native_cpu/cli.zig",
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
        for path in ("../outside", "/absolute/path", "src/core/../../outside"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(ci_scope_plan.PlanError, "unsafe"):
                    ci_scope_plan.select_lanes([path], self.catalog, self.policy)

    def test_path_ownership_is_component_safe(self) -> None:
        self.assertTrue(ci_scope_plan.owns("src/core/field.zig", "src/core"))
        self.assertFalse(ci_scope_plan.owns("src/coreish/field.zig", "src/core"))

    def test_git_rename_and_delete_classify_old_and_new_paths(self) -> None:
        result = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=b"R100\0src/core/old.zig\0src/core/new.zig\0D\0src/prover/gone.zig\0",
            stderr=b"",
        )
        with mock.patch.object(ci_scope_plan.subprocess, "run", return_value=result):
            paths = ci_scope_plan.git_changed_paths(ROOT, "base", "head")
        self.assertEqual(
            ["src/core/old.zig", "src/core/new.zig", "src/prover/gone.zig"],
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

    def test_submission_only_diff_selects_always_lanes_only(self) -> None:
        changed = [
            "autoresearch/submissions/2026-07-20-x/note.md",
            "autoresearch/notes/tile-sweep.md",
        ]
        lanes, _ = ci_scope_plan.select_lanes(changed, self.catalog, self.policy)
        self.assertEqual(sorted(lanes), ["static"])

    def test_hosted_flag_must_be_boolean(self) -> None:
        policy = json.loads(json.dumps(self.policy))
        policy["lanes"]["native_metal"]["hosted"] = "never"
        with self.assertRaises(ci_scope_plan.PlanError):
            ci_scope_plan.validate_policy(policy)


def runner_policy(commands: list[list[str]], host: str | None = None) -> dict[str, object]:
    current_host = "macos" if sys.platform == "darwin" else "linux"
    return {
        "schema": "ci-touchpoints-v1",
        "always_lanes": ["focused"],
        "lanes": {
            "focused": {
                "host": host or current_host,
                "description": "test lane",
                "commands": commands,
            }
        },
        "product_scope_lanes": {},
        "rules": [],
        "documentation_prefixes": ["docs"],
    }


class RunnerReceiptTests(unittest.TestCase):
    def fake_run(
        self,
        command_results: list[tuple[int, bytes, bytes]],
        captured: list[tuple[list[str], dict[str, object]]],
    ):
        remaining = list(command_results)

        def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            if argv == ["git", "rev-parse", "HEAD"]:
                return subprocess.CompletedProcess(argv, 0, COMMIT + "\n", "")
            if argv == ["git", "rev-parse", "HEAD^{tree}"]:
                return subprocess.CompletedProcess(argv, 0, TREE + "\n", "")
            if argv == ["git", "diff", "--quiet", "HEAD", "--"]:
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            if argv == ["git", "ls-files", "--others", "--exclude-standard"]:
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            captured.append((list(argv), kwargs))
            returncode, stdout, stderr = remaining.pop(0)
            return subprocess.CompletedProcess(argv, returncode, stdout, stderr)

        return run

    def test_pre_push_clears_git_environment_before_nested_git_commands(self) -> None:
        result = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="GIT_DIR\nGIT_WORK_TREE\nGIT_INDEX_FILE\n", stderr="",
        )
        inherited = {
            "GIT_DIR": "/repository/.git",
            "GIT_WORK_TREE": "/repository",
            "GIT_INDEX_FILE": "/repository/.git/index",
        }
        with (
            mock.patch.dict(os.environ, inherited, clear=False),
            mock.patch.object(ci_scope_push.subprocess, "run", return_value=result),
        ):
            ci_scope_push.clear_git_local_environment(ROOT)
            for name in inherited:
                self.assertNotIn(name, os.environ)

    def test_pass_receipt_binds_identity_output_digests_and_durations(self) -> None:
        policy = runner_policy(
            [["tool", "--output", "{output_dir}", "--commit", "{commit}"]]
        )
        captured: list[tuple[list[str], dict[str, object]]] = []
        stdout = SimpleNamespace(buffer=io.BytesIO())
        stderr = SimpleNamespace(buffer=io.BytesIO())
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "receipts" / "focused.json"
            with (
                mock.patch.object(
                    ci_scope_run.subprocess,
                    "run",
                    side_effect=self.fake_run([(0, b"ok\n", b"")], captured),
                ),
                mock.patch.object(
                    ci_scope_run.time,
                    "monotonic_ns",
                    side_effect=[100, 200, 500, 900],
                ),
                mock.patch.object(ci_scope_run.platform, "machine", return_value="test64"),
                mock.patch.object(ci_scope_run.sys, "stdout", stdout),
                mock.patch.object(ci_scope_run.sys, "stderr", stderr),
            ):
                receipt = ci_scope_run.run_lane(
                    root=ROOT,
                    policy=policy,
                    lane="focused",
                    output=output,
                    cache_mode="inherit",
                    cache_root=None,
                )
            persisted = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(receipt, persisted)
        self.assertEqual("stwo-focused-ci-timing-v1", receipt["schema"])
        self.assertEqual("PASS", receipt["status"])
        self.assertEqual(COMMIT, receipt["commit"])
        self.assertEqual(TREE, receipt["tree"])
        self.assertTrue(receipt["clean"])
        self.assertEqual("test64", receipt["host_machine"])
        self.assertEqual(800, receipt["duration_ns"])
        self.assertEqual(300, receipt["commands"][0]["duration_ns"])
        self.assertEqual(ci_scope_run.digest(b"ok\n"), receipt["commands"][0]["stdout_sha256"])
        self.assertEqual(ci_scope_run.digest(b""), receipt["commands"][0]["stderr_sha256"])
        self.assertEqual(b"ok\n", stdout.buffer.getvalue())
        self.assertEqual([], [entry for entry in captured if entry[0][:2] == ["git", "rev-parse"]])
        self.assertEqual(
            [
                "tool",
                "--output",
                str(output.parent.resolve()),
                "--commit",
                COMMIT,
            ],
            captured[0][0],
        )

    def test_failed_command_stops_lane_and_persists_failure_receipt(self) -> None:
        policy = runner_policy([["first"], ["second"], ["must-not-run"]])
        captured: list[tuple[list[str], dict[str, object]]] = []
        streams = SimpleNamespace(buffer=io.BytesIO())
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "failed.json"
            with (
                mock.patch.object(
                    ci_scope_run.subprocess,
                    "run",
                    side_effect=self.fake_run(
                        [(0, b"", b""), (7, b"", b"failed\n")], captured
                    ),
                ),
                mock.patch.object(
                    ci_scope_run.time,
                    "monotonic_ns",
                    side_effect=[100, 200, 300, 400, 650, 1000],
                ),
                mock.patch.object(ci_scope_run.sys, "stdout", streams),
                mock.patch.object(
                    ci_scope_run.sys, "stderr", SimpleNamespace(buffer=io.BytesIO())
                ),
            ):
                receipt = ci_scope_run.run_lane(
                    root=ROOT,
                    policy=policy,
                    lane="focused",
                    output=output,
                    cache_mode="inherit",
                    cache_root=None,
                )

            persisted = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual("FAIL", receipt["status"])
        self.assertEqual(receipt, persisted)
        self.assertEqual(["first", "second"], [item[0][0] for item in captured])
        self.assertEqual([0, 7], [record["exit_code"] for record in receipt["commands"]])
        self.assertEqual([100, 250], [record["duration_ns"] for record in receipt["commands"]])
        self.assertEqual(900, receipt["duration_ns"])

    def test_warm_cache_exports_isolated_cache_roots(self) -> None:
        policy = runner_policy([["tool"]])
        captured: list[tuple[list[str], dict[str, object]]] = []
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            output = root / "receipt.json"
            cache = root / "cache"
            with (
                mock.patch.object(
                    ci_scope_run.subprocess,
                    "run",
                    side_effect=self.fake_run([(0, b"", b"")], captured),
                ),
                mock.patch.object(
                    ci_scope_run.time,
                    "monotonic_ns",
                    side_effect=[100, 200, 300, 400],
                ),
                mock.patch.object(
                    ci_scope_run.sys,
                    "stdout",
                    SimpleNamespace(buffer=io.BytesIO()),
                ),
                mock.patch.object(
                    ci_scope_run.sys,
                    "stderr",
                    SimpleNamespace(buffer=io.BytesIO()),
                ),
            ):
                receipt = ci_scope_run.run_lane(
                    root=ROOT,
                    policy=policy,
                    lane="focused",
                    output=output,
                    cache_mode="warm",
                    cache_root=cache,
                )
        environment = captured[0][1]["env"]
        assert isinstance(environment, dict)
        self.assertEqual(str(cache.resolve() / "local"), environment["STWO_CI_CACHE_DIR"])
        self.assertEqual(
            str(cache.resolve() / "zig-local"), environment["ZIG_LOCAL_CACHE_DIR"]
        )
        self.assertEqual(str(cache.resolve() / "global"), environment["ZIG_GLOBAL_CACHE_DIR"])
        self.assertEqual(str(cache.resolve() / "cargo-target"), environment["CARGO_TARGET_DIR"])
        self.assertEqual("warm", receipt["cache_mode"])

    def test_warm_cache_requires_an_explicit_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaisesRegex(
                ci_scope_run.PlanError, "warm cache mode requires --cache-root"
            ):
                ci_scope_run.run_lane(
                    root=ROOT,
                    policy=runner_policy([["tool"]]),
                    lane="focused",
                    output=Path(raw) / "receipt.json",
                    cache_mode="warm",
                    cache_root=None,
                )

    def test_wrong_host_and_unknown_lane_fail_before_execution(self) -> None:
        current_host = "macos" if sys.platform == "darwin" else "linux"
        other_host = "linux" if current_host == "macos" else "macos"
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "receipt.json"
            with self.assertRaisesRegex(ci_scope_run.PlanError, "requires"):
                ci_scope_run.run_lane(
                    root=ROOT,
                    policy=runner_policy([["tool"]], host=other_host),
                    lane="focused",
                    output=output,
                    cache_mode="inherit",
                    cache_root=None,
                )
            with self.assertRaisesRegex(ci_scope_run.PlanError, "unknown CI lane"):
                ci_scope_run.run_lane(
                    root=ROOT,
                    policy=runner_policy([["tool"]]),
                    lane="missing",
                    output=output,
                    cache_mode="inherit",
                    cache_root=None,
                )

    def test_macos_can_run_linux_compatible_lane_only_when_explicit(self) -> None:
        policy = runner_policy([["tool"]], host="linux")
        captured: list[tuple[list[str], dict[str, object]]] = []
        with tempfile.TemporaryDirectory() as raw:
            with (
                mock.patch.object(ci_scope_run.sys, "platform", "darwin"),
                mock.patch.object(
                    ci_scope_run.subprocess,
                    "run",
                    side_effect=self.fake_run([(0, b"", b"")], captured),
                ),
                mock.patch.object(
                    ci_scope_run.time,
                    "monotonic_ns",
                    side_effect=[100, 200, 300, 400],
                ),
                mock.patch.object(
                    ci_scope_run.sys, "stdout", SimpleNamespace(buffer=io.BytesIO())
                ),
                mock.patch.object(
                    ci_scope_run.sys, "stderr", SimpleNamespace(buffer=io.BytesIO())
                ),
            ):
                receipt = ci_scope_run.run_lane(
                    root=ROOT,
                    policy=policy,
                    lane="focused",
                    output=Path(raw) / "receipt.json",
                    cache_mode="inherit",
                    cache_root=None,
                    local_compatible=True,
                )
        self.assertEqual("macos", receipt["host"])
        self.assertEqual("linux", receipt["required_host"])


if __name__ == "__main__":
    unittest.main()
