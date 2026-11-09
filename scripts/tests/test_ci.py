import os
import re
import json
import signal
import subprocess
import sys
import tempfile
import textwrap
import unittest
from types import SimpleNamespace
from unittest import mock
from pathlib import Path

from scripts.ci import FAST_PLAN, TOOLCHAIN_PLAN, command_plan, main
from scripts.repo.check_build_configure_closure import validate_actual_construction
from scripts.release.release_evidence import gate_steps
from scripts.tests.test_focused_ci_contract import COMMIT, TREE, runner_policy

ROOT = Path(__file__).resolve().parents[2]
PINNED_ACTION_RE = re.compile(r"^\s*uses:\s*[^@\s]+@[0-9a-f]{40}(?:\s+#.*)?$")


class CiTests(unittest.TestCase):
    def test_circuit_decoder_process_matrix_checks_exact_outputs_and_keeps_failures(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        start = workflow.index("      - name: Check circuit decoder process boundary")
        end = workflow.index("      - name:", start + 10)
        step = workflow[start:end]
        self.assertLess(workflow.index("      - name: Run focused lane"), start)
        self.assertIn("if: matrix.lane == 'circuit_recursion_cpu'", step)
        self.assertIn("timeout-minutes: 12", step)
        self.assertNotIn("zig build", step)
        code = "\n".join(line[10:] for line in step.split("<<'PYD2'\n", 1)[1].split("          PYD2", 1)[0].splitlines())
        fixture = json.loads((ROOT / "vectors/circuit/r7/verify/multiverifier.json").read_text())["body"]
        usage_source = (ROOT / "src/products/cairo/recursion/cpu/cli.zig").read_text()
        usage = "\n".join(line.lstrip()[2:] for line in usage_source.split("pub const usage =\n", 1)[1].split("\n;", 1)[0].splitlines()).encode()
        outputs = {
            "success": (0, b"accepted: output digest c196ecb3c253ca01b483b6ac9c725aa83555423ea253ec7af8a5a05bb43cb836\n", b""),
            "empty": (3, b"rejected at deserialize: NotEnoughData\n", b'{"schema":"circuit_decode_rejection_v1","provider":"stwo_circuit_recursion_wire","origin":"circuit_serialize.deserializeProof","code":20481,"class":"invalid_input"}\n'),
            "noncanonical": (3, b"rejected at deserialize: ValueOutOfRange\n", b'{"schema":"circuit_decode_rejection_v1","provider":"stwo_circuit_recursion_wire","origin":"circuit_serialize.deserializeProof","code":20482,"class":"invalid_input"}\n'),
            "usage": (2, b"", b"error: UnknownCommand\n" + usage),
            "missing-input": (1, b"", b"error: FileNotFound\n"),
        }
        binary = ROOT / "zig-out/bin/stwo-circuit-recursion-cpu"
        read_bytes = Path.read_bytes
        for fault in (None, "wrong-code", "wrong-exit", "leaked-receipt", "timeout", "claimed-digest", "missing-read-diagnostic"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                calls = []
                def run(command, **kwargs):
                    self.assertEqual(str(binary), command[0])
                    self.assertEqual({"capture_output": True, "timeout": 120, "check": False, "cwd": ROOT}, kwargs)
                    name = list(outputs)[len(calls)]
                    calls.append(command)
                    exit_code, stdout, stderr = outputs[name]
                    if name == "success" and fault == "claimed-digest":
                        stdout = ("accepted: output digest " + "".join(f"{word:08x}" for word in fixture["request"]["output_digest"]) + "\n").encode()
                    if name == "missing-input" and fault != "missing-read-diagnostic":
                        stderr = (f"error: cannot read {command[-1]}: FileNotFound\n").encode() + stderr
                    if name == "empty" and fault == "wrong-code":
                        stderr = outputs["noncanonical"][2]
                    if name == "empty" and fault == "wrong-exit":
                        exit_code = 0
                    if name == "missing-input" and fault == "leaked-receipt":
                        stderr += outputs["empty"][2]
                    if name == "empty" and fault == "timeout":
                        raise subprocess.TimeoutExpired(command, 120, output=b"partial", stderr=b"timeout")
                    return SimpleNamespace(returncode=exit_code, stdout=stdout, stderr=stderr)
                def check_output(command, **kwargs):
                    self.assertEqual({"text": True, "timeout": 10}, kwargs)
                    return {("git", "rev-parse", "HEAD"): COMMIT, ("git", "rev-parse", "HEAD^{tree}"): TREE, ("git", "status", "--porcelain", "--untracked-files=no"): "", ("zig", "version"): "0.15.2"}[tuple(command)]
                with mock.patch.dict(os.environ, {"RUNNER_TEMP": temp, "GITHUB_SHA": COMMIT}), mock.patch.object(subprocess, "run", side_effect=run), mock.patch.object(subprocess, "check_output", side_effect=check_output), mock.patch.object(Path, "read_bytes", lambda path: b"test-binary" if path == binary else read_bytes(path)):
                    if fault:
                        with self.assertRaisesRegex(AssertionError, "process boundary mismatch"):
                            exec(compile(code, "ci-circuit-process", "exec"), {})
                    else:
                        exec(compile(code, "ci-circuit-process", "exec"), {})
                directory = Path(temp) / "focused-ci/circuit-decode-process"
                receipt = json.loads((directory / "matrix.json").read_text())
                self.assertEqual("FAIL" if fault else "PASS", receipt["status"])
                self.assertEqual(5, len(calls))
                self.assertEqual(list(outputs), [row["name"] for row in receipt["cases"]])
                for name in outputs:
                    self.assertTrue((directory / (name + ".stdout")).is_file())
                    self.assertTrue((directory / (name + ".stderr")).is_file())
                    self.assertTrue((directory / (name + ".json")).is_file())

    def test_cpu_golden_check_rejects_changed_proof_without_verifying_or_passing(self):
        from scripts.cuda.cuda_proof_parity_gate import UPSTREAM_COMMIT, EXCHANGE_MODE, EXPECTED_CONFIG
        source = (ROOT / ".github/workflows/ci.yml").read_text().split("- name: Compare fresh Native CPU proof with the frozen golden", 1)[1]
        code = textwrap.dedent(source.split("python3 - <<'PYCPU'\n", 1)[1].split("          PYCPU", 1)[0])
        relative = Path("conformance/evidence/cuda/native-bringup-sm89/product-parity-receipt.json")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference = root / relative
            reference.parent.mkdir(parents=True)
            reference.write_bytes((ROOT / relative).read_bytes())
            calls = []
            def prove(argv, **kwargs):
                calls.append(argv)
                self.assertEqual(60, kwargs["timeout"])
                self.assertTrue(kwargs["check"])
                self.assertEqual("prove", argv[1])
                Path(argv[-1]).write_text(json.dumps({
                    "schema_version": 1, "upstream_commit": UPSTREAM_COMMIT,
                    "exchange_mode": EXCHANGE_MODE, "example": "wide_fibonacci",
                    "pcs_config": EXPECTED_CONFIG, "wide_fibonacci_statement": {"log_n_rows": 5, "sequence_len": 8},
                    "proof_bytes_hex": "00" * 8390,
                }))
            with mock.patch.object(Path, "cwd", return_value=root), mock.patch.dict(os.environ, {"RUNNER_TEMP": str(root / "out")}), mock.patch("subprocess.run", side_effect=prove):
                with self.assertRaisesRegex(AssertionError, "differs from the frozen golden"):
                    exec(code, {})
            self.assertEqual(1, len(calls))
            self.assertFalse(list(root.rglob("native-cpu-frozen-parity.json")))

    def test_killed_runner_preserves_unfinished_output_without_acceptance(self):
        command = [sys.executable, "-c", "import os,signal; os.write(1,b'compiler-progress\\n'); os.write(2,b'before-cancel\\n'); os.kill(os.getppid(),signal.SIGTERM)"]
        policy = runner_policy([command])
        policy["lanes"]["focused"]["host"] = "macos" if sys.platform == "darwin" else "linux"
        launcher = "from pathlib import Path; import json,sys; from scripts.repo.ci_scope_run import run_lane; run_lane(root=Path.cwd(),policy=json.loads(sys.argv[2]),lane='focused',output=Path(sys.argv[1]),cache_mode='inherit',cache_root=None)"
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "receipt.json"
            result = subprocess.run([sys.executable, "-c", launcher, str(output), json.dumps(policy)], cwd=ROOT, capture_output=True, timeout=10)
            self.assertEqual(-signal.SIGTERM, result.returncode, result.stderr)
            self.assertFalse(output.exists())
            self.assertEqual(b"compiler-progress\n", (output.parent / "focused-0.stdout").read_bytes())
            self.assertEqual(b"before-cancel\n", (output.parent / "focused-0.stderr").read_bytes())
            started = json.loads((output.parent / "focused-0.started.json").read_text())
            self.assertEqual("STARTED", started["state"])
            self.assertEqual(command, started["argv"])
            self.assertEqual([], started["completed_commands"])
            self.assertNotIn("exit_code", started)

    def test_circuit_regeneration_is_manual_cpu_only_and_preserves_failed_results(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        job = workflow.split("\n  circuit-oracle-regeneration:\n", 1)[1]
        self.assertIn("if: github.event_name == 'workflow_dispatch' && (inputs.gate == 'regenerate-circuit-vectors' || inputs.gate == 'regenerate-recursion-shapes')", job)
        self.assertIn("if: inputs.gate == 'regenerate-circuit-vectors'", job)
        self.assertIn("if: inputs.gate == 'regenerate-recursion-shapes'", job)
        self.assertIn("python3 scripts/repo/zig_serial_build.py -j2 riscv-recursion-shape-inspector -Doptimize=ReleaseFast", job)
        self.assertIn("scripts/riscv/riscv_recursion_csp_benchmark.py audit-shapes", job)
        self.assertIn("scripts/riscv/riscv_recursion_csp_benchmark.py validate-shapes", job)
        self.assertIn('test ! -s "$OUT/worktree-status.txt"', job)
        self.assertLess(job.index('cp zig-out/bin/stwo-zig-riscv-recursion-shape-inspector'), job.index('scripts/riscv/riscv_recursion_csp_benchmark.py audit-shapes'))
        self.assertIn('for ordinal, case in enumerate(cases):', job)
        self.assertIn('raise SystemExit("canonical shape probes rejected: "', job)
        self.assertIn("runs-on: ubuntu-latest", job)
        self.assertIn('CARGO_BUILD_JOBS: "1"', job)
        self.assertLess(job.index("size < 32 * (1 << 30)"), job.index("/usr/bin/time -v python3"))
        self.assertIn("nightly-2026-01-15", job)
        self.assertIn("python3 scripts/interop/generate_circuit_oracle_vectors.py", job)
        self.assertIn("git diff --exit-code -- src tools scripts .github conformance", job)
        self.assertIn('exit "$STATUS"', job)
        self.assertIn("if: always()", job)
        self.assertIn("if-no-files-found: error", job)
        self.assertNotIn("git push", job)

    def test_repository_scripts_package_wins_over_foreign_installed_package(self):
        with tempfile.TemporaryDirectory() as raw:
            foreign = Path(raw) / "scripts"
            foreign.mkdir()
            (foreign / "__init__.py").write_text('raise RuntimeError("foreign scripts package selected")\n')
            result = subprocess.run(
                [sys.executable, "-c", "import pathlib, scripts; print(pathlib.Path(scripts.__file__).resolve())"],
                cwd=ROOT, env=dict(os.environ, PYTHONPATH=raw),
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(str(ROOT / "scripts/__init__.py"), result.stdout.strip())

    def construction_fixture(self) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
        manifest: dict[str, object] = {
            "scope_role": "product",
            "product_ids": ["focused"],
            "constructors": ["products/matrix.construct.focused"],
            "constructed_products": [
                {
                    "product_id": "focused",
                    "frontend": "native",
                    "backend": "cpu",
                    "role": "cli",
                    "protocol_manifest": "focused-v1",
                }
            ],
            "module_roots": ["src/product/main.zig"],
            "allowed_module_files": ["src/product/main.zig"],
            "allowed_module_prefixes": ["src/product"],
            "generated_module_roots": ["generated:options:"],
            "dependency_module_roots": [],
            "external_tools": ["python3"],
            "runtime_probes": ["Metal.framework"],
            "actual": {
                "products": [
                    {
                        "product_id": "focused",
                        "frontend": "native",
                        "backend": "cpu",
                        "role": "cli",
                        "protocol_manifest": "focused-v1",
                    }
                ],
                "constructors": ["products/matrix.construct.focused"],
                "module_roots": ["src/product/main.zig"],
                "generated_module_roots": ["generated:options:"],
                "dependency_module_roots": [],
                "external_tools": ["python3"],
                "runtime_probes": ["Metal.framework"],
            },
        }
        matrix = {
            "focused": {
                "module_roots": ["src/product/main.zig"],
                "allowed_files": [],
                "allowed_prefixes": ["src/product"],
                "configure_allowed_files": [],
                "configure_allowed_prefixes": [],
            }
        }
        return manifest, matrix

    def test_actual_construction_rejects_undeclared_module_mutation(self) -> None:
        manifest, matrix = self.construction_fixture()
        manifest["actual"]["module_roots"].append("src/zother/hidden.zig")  # type: ignore[index]
        with self.assertRaisesRegex(SystemExit, "undeclared module roots"):
            validate_actual_construction(manifest, matrix, "focused")

    def test_actual_construction_rejects_undeclared_tool_mutation(self) -> None:
        manifest, matrix = self.construction_fixture()
        manifest["actual"]["external_tools"].append("ztool")  # type: ignore[index]
        with self.assertRaisesRegex(SystemExit, "external_tools.*diverges"):
            validate_actual_construction(manifest, matrix, "focused")

    def test_actual_construction_rejects_runtime_probe_mutation(self) -> None:
        manifest, matrix = self.construction_fixture()
        manifest["actual"]["runtime_probes"].append("ZZ.framework")  # type: ignore[index]
        with self.assertRaisesRegex(SystemExit, "runtime_probes.*diverges"):
            validate_actual_construction(manifest, matrix, "focused")

    def test_actual_construction_allows_fully_stubbed_scope(self) -> None:
        # An unavailable-on-this-host scope registers only fail-closed step
        # stubs: no modules, so generated/dependency roots and external tools
        # are unobservable. Constructors must still match.
        manifest, matrix = self.construction_fixture()
        manifest["actual"]["module_roots"] = []  # type: ignore[index]
        manifest["actual"]["generated_module_roots"] = []  # type: ignore[index]
        manifest["actual"]["external_tools"] = []  # type: ignore[index]
        manifest["actual"]["runtime_probes"] = []  # type: ignore[index]
        manifest["actual"]["products"] = []  # type: ignore[index]
        manifest["constructed_products"] = []
        validate_actual_construction(manifest, matrix, "focused")  # must not raise

    def test_actual_construction_rejects_missing_generated_root_when_constructed(self) -> None:
        manifest, matrix = self.construction_fixture()
        manifest["actual"]["generated_module_roots"] = []  # type: ignore[index]
        with self.assertRaisesRegex(SystemExit, "generated_module_roots.*diverges"):
            validate_actual_construction(manifest, matrix, "focused")

    def test_actual_construction_allows_fully_stubbed_probe_host(self) -> None:
        # Capability partition: a host whose probing graphs are fail-closed
        # stubs (e.g. Apple frameworks on Linux) observes zero probes.
        manifest, matrix = self.construction_fixture()
        manifest["actual"]["runtime_probes"] = []  # type: ignore[index]
        validate_actual_construction(manifest, matrix, "focused")  # must not raise

    def test_actual_construction_rejects_partial_probe_construction(self) -> None:
        manifest, matrix = self.construction_fixture()
        manifest["runtime_probes"] = ["Foundation.framework", "Metal.framework"]
        manifest["actual"]["runtime_probes"] = ["Metal.framework"]  # type: ignore[index]
        with self.assertRaisesRegex(SystemExit, "runtime_probes.*partial"):
            validate_actual_construction(manifest, matrix, "focused")

    def test_actual_construction_rejects_constructor_mutation(self) -> None:
        manifest, matrix = self.construction_fixture()
        manifest["actual"]["constructors"] = ["products/matrix.construct.hidden"]  # type: ignore[index]
        with self.assertRaisesRegex(SystemExit, "constructors.*diverges"):
            validate_actual_construction(manifest, matrix, "focused")

    def test_actual_construction_rejects_product_identity_mutation(self) -> None:
        manifest, matrix = self.construction_fixture()
        manifest["actual"]["products"][0]["backend"] = "metal"  # type: ignore[index]
        with self.assertRaisesRegex(SystemExit, "product identities diverge"):
            validate_actual_construction(manifest, matrix, "focused")

    def test_actual_construction_rejects_generated_root_mutation(self) -> None:
        manifest, matrix = self.construction_fixture()
        manifest["actual"]["generated_module_roots"] = ["generated:hidden:"]  # type: ignore[index]
        with self.assertRaisesRegex(SystemExit, "generated_module_roots.*diverges"):
            validate_actual_construction(manifest, matrix, "focused")

    def test_actual_construction_rejects_dependency_root_mutation(self) -> None:
        manifest, matrix = self.construction_fixture()
        manifest["actual"]["dependency_module_roots"] = ["dependency:hidden:root.zig"]  # type: ignore[index]
        with self.assertRaisesRegex(SystemExit, "dependency_module_roots.*diverges"):
            validate_actual_construction(manifest, matrix, "focused")

    def test_backend_tools_allow_declared_dependency_subset_without_host_probes(self) -> None:
        manifest, matrix = self.construction_fixture()
        manifest["scope_role"] = "backend_tools"
        manifest["constructed_products"] = []
        manifest["actual"]["products"] = []  # type: ignore[index]
        manifest["dependency_module_roots"] = [
            "dependency:portable:root.zig",
            "dependency:host_only:root.zig",
        ]
        manifest["actual"]["dependency_module_roots"] = [  # type: ignore[index]
            "dependency:portable:root.zig"
        ]
        manifest["actual"]["runtime_probes"] = []  # type: ignore[index]
        validate_actual_construction(manifest, matrix, "focused")  # must not raise

    def test_backend_tools_reject_undeclared_partitioned_dependency(self) -> None:
        manifest, matrix = self.construction_fixture()
        manifest["scope_role"] = "backend_tools"
        manifest["constructed_products"] = []
        manifest["actual"]["products"] = []  # type: ignore[index]
        manifest["dependency_module_roots"] = ["dependency:portable:root.zig"]
        manifest["actual"]["dependency_module_roots"] = [  # type: ignore[index]
            "dependency:hidden:root.zig"
        ]
        manifest["actual"]["runtime_probes"] = []  # type: ignore[index]
        with self.assertRaisesRegex(SystemExit, "dependency_module_roots.*undeclared"):
            validate_actual_construction(manifest, matrix, "focused")

    def test_backend_tools_reject_empty_partitioned_dependencies(self) -> None:
        manifest, matrix = self.construction_fixture()
        manifest["scope_role"] = "backend_tools"
        manifest["constructed_products"] = []
        manifest["actual"]["products"] = []  # type: ignore[index]
        manifest["dependency_module_roots"] = ["dependency:portable:root.zig"]
        manifest["actual"]["dependency_module_roots"] = []  # type: ignore[index]
        manifest["actual"]["runtime_probes"] = []  # type: ignore[index]
        with self.assertRaisesRegex(SystemExit, "observed no dependencies"):
            validate_actual_construction(manifest, matrix, "focused")

    def test_backend_tools_require_exact_dependencies_with_host_probes(self) -> None:
        manifest, matrix = self.construction_fixture()
        manifest["scope_role"] = "backend_tools"
        manifest["constructed_products"] = []
        manifest["actual"]["products"] = []  # type: ignore[index]
        manifest["dependency_module_roots"] = [
            "dependency:portable:root.zig",
            "dependency:host_only:root.zig",
        ]
        manifest["actual"]["dependency_module_roots"] = [  # type: ignore[index]
            "dependency:portable:root.zig"
        ]
        with self.assertRaisesRegex(SystemExit, "dependency_module_roots.*diverges"):
            validate_actual_construction(manifest, matrix, "focused")

    def test_standard_plan_runs_tooling_then_release_gate(self) -> None:
        plan = command_plan(False, "ReleaseFast")
        self.assertEqual(sys.executable, plan[0][0])
        self.assertIn("scripts/tests", plan[0])
        self.assertEqual(
            ["zig", "build", "release-gate", "-Doptimize=ReleaseFast"],
            plan[1],
        )

    def test_explicit_toolchain_gate_uses_only_the_shared_static_owner(self) -> None:
        self.assertIn(TOOLCHAIN_PLAN[0], FAST_PLAN)
        self.assertEqual([sys.executable, "-m", "unittest", "scripts.tests.test_toolchain_pins"], TOOLCHAIN_PLAN[0])
        with mock.patch("scripts.ci.run_plan", return_value=19) as run:
            self.assertEqual(19, main(["--check-toolchains"]))
        run.assert_called_once_with(TOOLCHAIN_PLAN)

    def test_strict_plan_selects_strict_gate(self) -> None:
        self.assertEqual("release-gate-strict", command_plan(True, "ReleaseSafe")[1][2])

    def test_fast_plan_is_structurally_compilation_free(self) -> None:
        # The fast tier's speed guarantee is enforced here, not by a clock:
        # no command may enter the compilation class. `zig build` compiles;
        # `zig fmt --check` only parses and stays permitted.
        for command in FAST_PLAN:
            self.assertNotEqual(("zig", "build"), tuple(command[:2]), command)
            self.assertFalse(
                any(argument.startswith("-Doptimize") for argument in command),
                command,
            )

    def test_fast_plan_covers_only_static_gates(self) -> None:
        flattened = [" ".join(command) for command in FAST_PLAN]
        self.assertTrue(any("zig fmt --check" in line for line in flattened))
        self.assertTrue(any("check_upstream_pins" in line for line in flattened))
        self.assertTrue(any("check_source_conformance" in line for line in flattened))
        self.assertTrue(any("check_package_workspace" in line for line in flattened))
        self.assertFalse(any("unittest discover" in line for line in flattened))
        self.assertIn("unittest", command_plan(False, "ReleaseFast")[0])

    def test_hosted_ci_exposes_standard_and_strict_shared_entrypoints(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("name: Metal AOT reproducible build", workflow)
        self.assertIn("run: python3 scripts/ci.py\n", workflow)
        self.assertIn("run: python3 scripts/ci.py --strict\n", workflow)
        self.assertIn("inputs.gate == 'strict'", workflow)

    def test_frontend_releasefast_has_only_the_approved_timeout_exception(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        focused_linux = workflow.split("  focused-linux:", 1)[1].split("  focused-macos:", 1)[0]
        self.assertIn("timeout-minutes: ${{ matrix.lane == 'riscv_frontend_releasefast' && 90 || 30 }}", focused_linux)

    def test_focused_cairo_cpu_primes_its_offline_cargo_build(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        focused_linux = workflow.split("  focused-linux:", 1)[1].split(
            "  focused-macos:", 1
        )[0]
        fetch = focused_linux.index("name: Fetch pinned Cairo adapter dependencies")
        run = focused_linux.index("name: Run focused lane")
        self.assertLess(fetch, run)
        self.assertIn("if: matrix.lane == 'cairo_cpu'", focused_linux)
        self.assertIn(
            "cargo fetch --locked\n"
            "          --manifest-path tools/stwo-cairo-vm-adapter-rs/Cargo.toml",
            focused_linux,
        )

    def test_hosted_ci_has_no_archived_stark_v_release_lane(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        dispatch = workflow.split("permissions:", 1)[0]
        for retired in (
            "riscv-release-evidence:",
            "riscv-fast-release-gate:",
            "riscv_release_evidence.py",
            "riscv_release_oracle.py",
            "riscv_release_bundle.py",
            "riscv_release_challenge.py",
            "riscv_release_policy.py",
            "riscv_sandbox_adversary.py",
            "ClementWalter/stark-v",
        ):
            self.assertNotIn(retired, workflow)
        self.assertNotIn("- riscv-candidate", dispatch)
        self.assertNotIn("- riscv-promoted", dispatch)
        self.assertIn("focused-plan:", workflow)
        self.assertIn("focused-linux:", workflow)
        self.assertIn("focused-macos:", workflow)
        self.assertIn("focused-cuda:", workflow)
        self.assertIn("focused-verdict:", workflow)
        self.assertIn("python3 scripts/repo/ci_scope_plan.py", workflow)
        self.assertIn("python3 scripts/repo/ci_scope_run.py", workflow)
        self.assertIn("architecture-diagnostic:", workflow)

    def test_manual_cpu_diagnostics_cannot_dispatch_device_or_production_gates(self):
        source = (ROOT / ".github/workflows/ci.yml").read_text()
        for owner, end in (("focused-plan", "focused-linux"), ("focused-linux", "focused-macos")):
            job = source.split("  " + owner + ":", 1)[1].split("  " + end + ":", 1)[0]
            self.assertIn("inputs.gate == 'focused-cpu'", job)
        for owner, end in (("focused-macos", "focused-cuda"), ("focused-cuda", "focused-verdict"), ("focused-verdict", "release-gate")):
            job = source.split("  " + owner + ":", 1)[1].split("  " + end + ":", 1)[0]
            self.assertNotIn("focused-cpu", job)
        self.assertIn('SCOPE_ARGS+=(--manual-cpu-lane "$MANUAL_CPU_LANE")', source)
        self.assertIn('MANUAL_CPU_LANE: ${{ inputs.cpu_lane }}', source)
        self.assertIn("${{ github.event.pull_request.number || github.ref }}-${{ inputs.gate }}-${{ inputs.cpu_lane }}", source)

    def test_hosted_ci_requires_fail_closed_cuda_device_evidence(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        cuda = workflow.split("  focused-cuda:", 1)[1].split(
            "  focused-verdict:", 1
        )[0]
        self.assertIn("runs-on: [self-hosted, linux, x64, cuda]", cuda)
        self.assertIn(
            "needs.focused-plan.outputs.cuda_required == 'true'",
            cuda,
        )
        self.assertIn("github.event_name == 'schedule'", cuda)
        self.assertNotIn("github.event_name == 'pull_request'", cuda)
        self.assertIn("Require the CUDA-labelled runner contract", cuda)
        self.assertIn("test -n \"$STWO_CUDA_NVCC\"", cuda)
        self.assertIn("nvidia-smi --query-gpu=", cuda)
        self.assertIn("--lane native_cuda_device", cuda)
        self.assertIn("if-no-files-found: error", cuda)
        self.assertIn(
            "repository Rust source + Cargo.lock + nightly-2025-07-14",
            workflow,
        )

        focused = workflow.split("  focused-plan:", 1)[1].split(
            "  release-gate:", 1
        )[0]
        self.assertIn(
            "needs: [focused-plan, focused-linux, focused-macos, focused-cuda]",
            focused,
        )
        self.assertIn("name: Production PR gate", focused)
        self.assertIn("CUDA_ENFORCED", focused)
        self.assertIn('test "$CUDA_RESULT" = success', focused)
        self.assertIn('test "$CUDA_RESULT" = skipped', focused)


    def test_architecture_dispatch_is_a_protected_multi_host_receipt_protocol(self) -> None:
        candidate = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        workflow = (ROOT / ".github/workflows/architecture-authority.yml").read_text(
            encoding="utf-8",
        )
        self.assertIn("- architecture", candidate)
        self.assertIn("architecture-diagnostic:", candidate)
        self.assertNotIn("architecture-authority-linux:", candidate)
        jobs = {
            job: workflow.split(f"  {job}:", 1)[1].split("\n  architecture-authority-", 1)[0]
            for job in (
                "architecture-authority-session",
                "architecture-authority-linux",
                "architecture-authority-macos",
                "architecture-authority-verify",
            )
        }
        for job, body in jobs.items():
            self.assertIn("environment: build-architecture-authority", body)
            self.assertIn("ARCHITECTURE_AUTHORITY_SHA: ${{ vars.ARCHITECTURE_AUTHORITY_SHA }}", body)
        self.assertNotIn("pull_request", "".join(jobs.values()))

        linux = jobs["architecture-authority-linux"]
        macos = jobs["architecture-authority-macos"]
        verifier = jobs["architecture-authority-verify"]
        architecture_plan = (
            ROOT / "conformance/build-architecture-ci-plan-v1.json"
        ).read_text(encoding="utf-8")
        self.assertNotIn("riscv_release_bundle.py", architecture_plan)
        self.assertNotIn("riscv_release_challenge.py", architecture_plan)
        self.assertNotIn("build-and-compare", linux)
        self.assertIn(
            "artifact_name=build-architecture-linux-$CANDIDATE_SHA-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT",
            linux,
        )
        self.assertIn(
            "artifact_name=build-architecture-macos-$CANDIDATE_SHA-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT",
            macos,
        )
        self.assertIn("path: ${{ runner.temp }}/host-artifact/", linux)
        self.assertIn("path: ${{ runner.temp }}/host-artifact/", macos)
        self.assertIn("actions/artifacts/$artifact_id/zip", verifier)
        self.assertNotIn("actions/download-artifact@", verifier)
        self.assertIn("architecture_ci_artifact.py extract-host", verifier)
        self.assertIn("architecture_external_authority.py verify", verifier)
        self.assertIn("- architecture-authority-linux", verifier)
        self.assertIn("- architecture-authority-macos", verifier)

    def test_hosted_ci_accepts_exact_commit_aot_evidence_tags(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn('tags: ["aot-evidence-*"]', workflow)

    def test_release_gates_run_the_complete_test_graph_in_requested_mode(self) -> None:
        build = (ROOT / "build.zig").read_text(encoding="utf-8")
        verification_products = "\n".join(
            (ROOT / path).read_text(encoding="utf-8")
            for path in (
                "build_support/gates/native.zig",
                "build_support/gates/riscv.zig",
                "build_support/benchmarks/native.zig",
                "build_support/gates/release_evidence.zig",
                "build_support/gates/release.zig",
            )
        )
        build_graph = build + verification_products
        full_test_command = '&.{ "zig", "build", "test", build_optimize }'
        self.assertEqual(2, build_graph.count(full_test_command))
        self.assertEqual(3, build_graph.count('"scripts/repo/zig_protocol_test.py"'))
        gate_archive = "zig-out/release-evidence/native/interop-history"
        self.assertEqual(2, build_graph.count(gate_archive))
        self.assertEqual(2, build_graph.count('"--archive-dir"'))
        transitive_commands = {
            '&.{ "zig", "build", "test-riscv", build_optimize }': 2,
            '&.{ "zig", "build", "test-riscv-prover", build_optimize }': 2,
            '&.{ "python3", "scripts/riscv/riscv_trace_vectors.py" }': 3,
            # One additional standalone public API-parity build target is expected.
            '&.{ "python3", "scripts/repo/check_api_parity.py" }': 2,
        }
        for command, expected_count in transitive_commands.items():
            self.assertEqual(expected_count, build_graph.count(command))
        # Test this checkout's ignore rules without depending on its Git
        # metadata or a developer's global excludes/template configuration.
        with tempfile.TemporaryDirectory() as raw:
            fixture = Path(raw)
            git_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
            git_env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
            subprocess.run(["git", "init", "-q", "--template=", raw], check=True, env=git_env)
            (fixture / ".gitignore").write_bytes((ROOT / ".gitignore").read_bytes())
            self.assertEqual(0, subprocess.run(
                ["git", "-c", "core.excludesFile=/dev/null", "check-ignore", "-q", gate_archive],
                cwd=fixture, check=False, env=git_env,
            ).returncode)
        interop_steps = [step for step in gate_steps("strict") if step["name"] == "interop"]
        self.assertEqual(1, len(interop_steps))
        self.assertIn(f"--archive-dir {gate_archive}", interop_steps[0]["command"])

    def test_pre_push_and_hosted_main_are_focused(self) -> None:
        pre_push = (ROOT / ".githooks/pre-push").read_text(encoding="utf-8")
        self.assertIn("exec python3 scripts/repo/ci_scope_push.py", pre_push)
        self.assertNotIn("zig build", pre_push)

        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        focused = workflow.split("  focused-plan:", 1)[1].split("  release-gate:", 1)[0]
        self.assertIn("github.event.before", focused)
        self.assertIn("github.ref == 'refs/heads/main'", focused)
        self.assertEqual(1, focused.count("SCOPE_ARGS+=(--full-matrix)"))
        self.assertIn('elif [ "${{ github.event_name }}" = "schedule" ]', focused)
        self.assertNotIn("PR6 fail-closed correctness smoke", focused)
        self.assertIn("run: python3 scripts/ci.py\n", workflow)

    def test_hosted_ci_cancels_stale_runs_and_avoids_duplicate_caches(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        header = workflow.split("jobs:", 1)[0]
        self.assertIn("group: ci-${{ github.event_name }}-", header)
        self.assertIn("github.event_name == 'pull_request'", header)
        focused = workflow.split("  focused-plan:", 1)[1].split(
            "  release-gate:", 1
        )[0]
        self.assertEqual(4, focused.count("use-cache: false"))
        self.assertEqual(2, focused.count("fetch-depth: 1"))
        self.assertEqual(3, focused.count("fetch-depth: 0"))
        self.assertIn("if: matrix.lane != 'static'", focused)
        self.assertNotIn(
            "hashFiles('build.zig.zon', 'conformance/ci-touchpoints-v1.json')",
            focused,
        )

    def test_hosted_metal_gate_builds_reproducible_aot_and_compiles_broader_graph(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        metal_job = workflow.split("  metal-acceptance:", 1)[1].split(
            "  architecture-diagnostic:", 1
        )[0]
        self.assertIn(
            "xcode-select --print-path | grep -q '^/Applications/Xcode'",
            metal_job,
        )
        self.assertIn("xcrun --sdk macosx --find metal", metal_job)
        self.assertIn("xcrun --sdk macosx --find metallib", metal_job)
        self.assertIn("name: Setup Python", metal_job)
        self.assertIn('python-version: "3.13"', metal_job)
        self.assertIn(
            "zig build metal-eval-prepare -Doptimize=ReleaseFast", metal_job
        )
        self.assertIn(
            "zig build metal-eval-source -Doptimize=ReleaseFast", metal_job
        )
        self.assertIn("zig-out/bin/metal-eval-source", metal_job)
        self.assertIn("-mmacosx-version-min=14.0", metal_job)
        self.assertIn("-std=metal3.1", metal_job)
        self.assertIn("-fno-fast-math", metal_job)
        self.assertIn("-Werror", metal_job)
        self.assertIn("STWO_ZIG_COMPOSITION_METALLIB", metal_job)
        self.assertIn("STWO_ZIG_ALLOW_EXPLICIT_NO_METAL_DEVICE=1", metal_job)
        self.assertIn(
            "SnPieCompositionBundleTest.test_sn1_retarget_loads_in_zig_with_existing_metallib",
            metal_job,
        )
        self.assertIn(
            "zig build metal-core-aot -Doptimize=ReleaseSafe",
            workflow,
        )
        self.assertIn("run: zig build metal-check -Doptimize=ReleaseSafe", workflow)
        self.assertNotIn("run: zig build metal-test", workflow)
        self.assertIn("python3 scripts/metal/metal_core_aot_receipt.py build", workflow)
        self.assertIn("--builder zig-out/bin/metal-core-aot", workflow)
        self.assertIn("--output-dir \"$RUNNER_TEMP/native-metal-core-aot-acceptance\"", workflow)
        self.assertIn(
            '--receipt-out "$RUNNER_TEMP/native-metal-core-aot-acceptance/receipt.json"',
            workflow,
        )
        self.assertIn('--commit "$GITHUB_SHA"', workflow)
        self.assertNotIn("--probe", metal_job)
        self.assertNotIn("metal-core-aot-probe", metal_job)
        self.assertNotIn("metal-core-aot-acceptance -Doptimize", metal_job)
        self.assertIn(
            "uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02  # v4",
            workflow,
        )
        for artifact in (
            "receipt.json",
            "receipt.json.sha256",
            "build-a",
            "build-b",
        ):
            self.assertIn(
                f"${{{{ runner.temp }}}}/native-metal-core-aot-acceptance/{artifact}",
                workflow,
            )
        self.assertIn("if-no-files-found: error", workflow)

        metal_products = (ROOT / "build_support/benchmarks/metal.zig").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "const install_metal_eval_prepare = b.addInstallArtifact(",
            metal_products,
        )
        self.assertIn(
            "metal_eval_prepare_step.dependOn(&install_metal_eval_prepare.step);",
            metal_products,
        )
        self.assertNotIn(
            "b.getInstallStep().dependOn(&install_metal_eval_prepare.step);",
            metal_products,
        )
        self.assertIn(
            "const install_metal_eval_source = b.addInstallArtifact(",
            metal_products,
        )
        self.assertIn(
            "metal_eval_source_step.dependOn(&install_metal_eval_source.step);",
            metal_products,
        )
        self.assertIn(
            "metal_check_step.dependOn(&metal_tests.step);", metal_products
        )
        self.assertNotIn(
            "metal_check_step.dependOn(&run_metal_tests.step);", metal_products
        )

    def test_safe_metal_math_compiles_with_macos_14_and_15_sdks(self) -> None:
        policy = (
            ROOT / "src/backends/metal/runtime/compile_options.h"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && "
            "__MAC_OS_X_VERSION_MAX_ALLOWED >= 150000",
            policy,
        )
        self.assertIn("options.mathMode = MTLMathModeSafe;", policy)
        self.assertEqual(2, policy.count("options.fastMathEnabled = NO;"))
        self.assertIn("options.languageVersion = MTLLanguageVersion3_1;", policy)

        sources = (
            ROOT / "src/backends/metal/tools/core_aot/probe.m",
            ROOT / "src/backends/metal/runtime/initialization.m",
            ROOT / "src/backends/metal/runtime/dynamic_evaluation.m",
        )
        for source in sources:
            text = source.read_text(encoding="utf-8")
            self.assertIn("stwo_zig_configure_safe_metal_compile_options(options);", text)
            self.assertNotIn("configure_eval_compile_options", text)
            self.assertNotIn("options.mathMode", text)
            self.assertNotIn("options.fastMathEnabled", text)

    def test_all_hosted_actions_are_commit_pinned(self) -> None:
        workflows = sorted((ROOT / ".github/workflows").glob("*.yml"))
        self.assertTrue(workflows)
        for workflow in workflows:
            for line_number, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), 1):
                if "uses:" not in line:
                    continue
                self.assertRegex(
                    line,
                    PINNED_ACTION_RE,
                    f"{workflow.relative_to(ROOT)}:{line_number} must pin an action commit",
                )


if __name__ == "__main__":
    unittest.main()
