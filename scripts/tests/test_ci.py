import re
import subprocess
import sys
import unittest
from pathlib import Path

from scripts.ci import FAST_PLAN, command_plan
from scripts.check_build_configure_closure import validate_actual_construction
from scripts.release_evidence import gate_steps

ROOT = Path(__file__).resolve().parents[2]
PINNED_ACTION_RE = re.compile(r"^\s*uses:\s*[^@\s]+@[0-9a-f]{40}(?:\s+#.*)?$")


class CiTests(unittest.TestCase):
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

    def test_fast_plan_covers_static_gates_and_script_tests(self) -> None:
        flattened = [" ".join(command) for command in FAST_PLAN]
        self.assertTrue(any("zig fmt --check" in line for line in flattened))
        self.assertTrue(any("check_upstream_pins" in line for line in flattened))
        self.assertTrue(any("check_source_conformance" in line for line in flattened))
        self.assertTrue(any("unittest discover" in line for line in flattened))

    def test_hosted_ci_exposes_standard_and_strict_shared_entrypoints(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("name: Metal AOT reproducible build", workflow)
        self.assertIn("run: python3 scripts/ci.py\n", workflow)
        self.assertIn("run: python3 scripts/ci.py --strict\n", workflow)
        self.assertIn("inputs.gate == 'strict'", workflow)

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

    def test_hosted_ci_quarantines_the_pre_sail_riscv_evidence_lane(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        dispatch = workflow.split("permissions:", 1)[0]
        self.assertNotIn("- riscv-candidate", dispatch)
        self.assertNotIn("- riscv-promoted", dispatch)
        self.assertNotIn("- riscv-produce-candidate", dispatch)
        self.assertNotIn("- riscv-produce-promoted", dispatch)
        self.assertNotIn("candidate_sha:", dispatch)
        self.assertNotIn("candidate_ref:", dispatch)
        self.assertNotIn("producer_run_id:", dispatch)
        self.assertIn(
            "name: Archived RISC-V Stark-V layout evidence (disabled)", workflow
        )
        self.assertIn(
            "name: Archived RISC-V Stark-V replay gate (disabled)", workflow
        )
        producer = workflow.split("  riscv-release-evidence:", 1)[1].split(
            "  riscv-fast-release-gate:", 1
        )[0]
        fast = workflow.split("  riscv-fast-release-gate:", 1)[1].split(
            "  architecture-diagnostic:", 1
        )[0]
        self.assertIn("if: ${{ false }}", producer)
        self.assertIn("if: ${{ false }}", fast)
        self.assertIn("inputs.gate == 'architecture'", workflow)
        tag_or_dispatch_only = (
            "(github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')) ||\n"
            "      (github.event_name == 'workflow_dispatch' &&\n"
            "      (inputs.gate == 'standard' || inputs.gate == 'strict'))"
        )
        self.assertEqual(2, workflow.count(tag_or_dispatch_only))
        self.assertNotIn("github.event_name == 'push' ||", workflow)
        self.assertIn("focused-plan:", workflow)
        self.assertIn("focused-linux:", workflow)
        self.assertIn("focused-macos:", workflow)
        self.assertIn("focused-cuda:", workflow)
        self.assertIn("focused-verdict:", workflow)
        self.assertIn("python3 scripts/ci_scope_plan.py", workflow)
        self.assertIn("python3 scripts/ci_scope_run.py", workflow)
        self.assertIn("github.event.before", workflow)
        focused = workflow.split("  focused-plan:", 1)[1].split("  release-gate:", 1)[0]
        self.assertEqual(5, focused.count("github.ref == 'refs/heads/main'"))
        self.assertIn("inputs.gate == 'riscv-candidate' && 'candidate' || 'promoted'", workflow)
        self.assertIn("id: riscv-release-state", workflow)
        self.assertEqual(2, workflow.count("src/products/riscv_cpu/capabilities.zig"))
        self.assertEqual(2, workflow.count("pub const adapter_release_gated = (true|false);"))
        self.assertNotIn("RISCV_ADAPTER_RELEASE_GATED = true", workflow)
        self.assertIn("RISC-V capability release state is missing or ambiguous", workflow)
        self.assertIn("https://github.com/ClementWalter/stark-v", workflow)
        self.assertIn("STARK_V_REVISION: d478f783055aa0d73a93768a433a3c6c31c91d1c", workflow)
        self.assertIn("rustup toolchain install nightly-2026-01-29 --profile minimal", workflow)
        self.assertIn("submodule update --init --recursive --depth=1", workflow)
        self.assertIn("STWO_ZIG_RISCV_ORACLE_CACHE_DIR", workflow)
        self.assertIn("actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830", workflow)
        self.assertIn("name: Enforce owner-dispatched cache writer scope", workflow)
        self.assertIn('test "$GITHUB_REPOSITORY" = teddyjfpender/stwo-zig', workflow)
        self.assertIn('test "$GITHUB_EVENT_NAME" = workflow_dispatch', workflow)
        self.assertIn('test "$GITHUB_REF" = refs/heads/main', workflow)
        self.assertIn("id: riscv-oracle-cache", workflow)
        self.assertIn("riscv_release_oracle.py cache-key", workflow)
        self.assertIn(
            "key: riscv-oracle-${{ steps.riscv-oracle-cache.outputs.key_sha256 }}",
            workflow,
        )
        self.assertNotIn("Restore authenticated Stark-V helper cache", workflow)
        self.assertIn(
            "restore-keys: riscv-cpu-static-v1-${{ runner.os }}-zig-0.15.2-",
            workflow,
        )
        self.assertIn("python3 scripts/riscv_release_gate.py", workflow)
        self.assertIn("--strict", workflow)
        self.assertIn('--candidate "$RISCV_CANDIDATE_SHA"', workflow)
        self.assertIn("python3 scripts/riscv_release_bundle.py pack", workflow)
        self.assertIn("python3 scripts/riscv_release_bundle.py verify", workflow)
        self.assertIn("--trust-context", workflow)
        self.assertIn(
            "riscv-exhaustive-bundle-${{ env.RISCV_CANDIDATE_SHA }}-${{ github.run_id }}-${{ github.run_attempt }}",
            workflow,
        )
        self.assertIn("riscv_release_bundle.py verify-anchor", workflow)
        self.assertIn("riscv_release_challenge.py issue", workflow)
        self.assertIn("riscv_release_challenge.py execute", workflow)
        self.assertIn("stwo-zig-riscv-cpu-static", workflow)
        self.assertIn("riscv_sandbox_adversary.py", workflow)
        self.assertIn("riscv_candidate_sandbox_probe.c", workflow)
        self.assertIn('"--protocol", "secure"', (
            ROOT / "scripts/riscv_release_challenge_lib/execution.py"
        ).read_text(encoding="utf-8"))
        self.assertIn("actions/artifacts/${{ steps.riscv-producer.outputs.artifact_id }}/zip", workflow)
        self.assertIn('test "$actual_digest" = "${{ steps.riscv-producer.outputs.artifact_digest }}"', workflow)
        self.assertIn('python3 "$RUNNER_TEMP/riscv_release_policy.py" extract', workflow)
        self.assertNotIn("actions/download-artifact@", workflow)
        fast = workflow.split("  riscv-fast-release-gate:", 1)[1].split(
            "  architecture-diagnostic:", 1
        )[0]
        self.assertNotIn("riscv_staged_smoke.py", fast)
        self.assertNotIn("--profile fast", fast)
        self.assertIn("riscv-release-challenge-result-v1", fast)
        self.assertIn("riscv_release_bundle.py verify-anchor", fast)
        self.assertLess(
            fast.index("riscv_release_challenge.py issue"),
            fast.index("riscv_release_challenge.py execute"),
        )
        self.assertLess(fast.index("actual_digest="), fast.index("riscv_release_policy.py\" extract"))
        self.assertLess(
            fast.index("riscv_release_policy.py\" extract"),
            fast.index("name: Verify reusable exhaustive anchor"),
        )
        self.assertIn("if-no-files-found: error", workflow)

    def test_hosted_ci_requires_fail_closed_cuda_device_and_oracle_evidence(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        cuda = workflow.split("  focused-cuda:", 1)[1].split(
            "  focused-verdict:", 1
        )[0]
        self.assertIn("runs-on: [self-hosted, linux, x64, cuda]", cuda)
        self.assertIn(
            "needs.focused-plan.outputs.cuda_required == 'true'",
            cuda,
        )
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
        self.assertIn('test "$CUDA_RESULT" = success', focused)
        self.assertIn('test "$CUDA_RESULT" = skipped', focused)

    def test_fast_riscv_gate_cannot_cancel_or_confuse_anchor_and_candidate(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("group: riscv-exhaustive-${{", workflow)
        self.assertIn("group: riscv-fast-${{ inputs.candidate_sha }}-${{ inputs.producer_run_id }}", workflow)
        self.assertEqual(2, workflow.count("cancel-in-progress: false"))
        self.assertIn("timeout-minutes: 3", workflow)
        self.assertIn(".timing.wall_duration_ns <= 180000000000", workflow)
        self.assertIn('[[ "$RISCV_CANDIDATE_SHA" =~ ^[0-9a-f]{40}$ ]]', workflow)
        self.assertIn('[[ "$RISCV_CANDIDATE_REF" == refs/heads/* ]]', workflow)
        self.assertIn("branches-where-head", workflow)
        self.assertIn('test "$producer_event" = workflow_dispatch', workflow)
        self.assertIn('test "$(jq -r .repository.id <<<"$producer")" = "$TRUSTED_REPOSITORY_ID"', workflow)
        self.assertIn('test "$(jq -r .actor.id <<<"$producer")" = "$TRUSTED_OWNER_ID"', workflow)
        self.assertIn('test "$(jq -r .triggering_actor.id <<<"$producer")" = "$TRUSTED_OWNER_ID"', workflow)
        self.assertIn('.name == "RISC-V exhaustive release evidence"', workflow)
        self.assertIn('.conclusion == "success"', workflow)
        self.assertIn("artifact_digest=$digest", workflow)
        self.assertIn("anchor_candidate=$anchor_candidate", workflow)
        self.assertIn("riscv-exhaustive-bundle-[0-9a-f]{40}", workflow)
        self.assertIn(".candidate.sha", workflow)
        self.assertIn('test "$(jq -r .head_sha <<<"$run")" = "$GITHUB_SHA"', workflow)
        self.assertNotIn('test "$(jq -r .conclusion <<<"$producer")" = success', workflow)

    def test_riscv_oracle_cache_identity_precedes_exact_restore(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        producer = workflow.split("  riscv-release-evidence:", 1)[1].split(
            "  riscv-fast-release-gate:", 1
        )[0]
        install = producer.index("name: Install pinned Rust toolchains")
        checkout = producer.index("name: Checkout pinned Stark-V oracle")
        recursive = producer.index("submodule update --init --recursive --depth=1")
        trusted_scope = producer.index("name: Enforce owner-dispatched cache writer scope")
        identity = producer.index("name: Compute exact Stark-V helper cache identity")
        restore = producer.index("uses: actions/cache@")
        self.assertLess(install, checkout)
        self.assertLess(checkout, recursive)
        self.assertLess(recursive, trusted_scope)
        self.assertLess(trusted_scope, identity)
        self.assertLess(identity, restore)
        self.assertNotIn("hashFiles(", producer)

    def test_riscv_policy_is_trusted_before_candidate_code_executes(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        producer = workflow.split("  riscv-release-evidence:", 1)[1].split(
            "  riscv-fast-release-gate:", 1
        )[0]
        trusted_checkout = producer.index("name: Checkout trusted main release policy")
        capture = producer.index("name: Capture trusted main release policy")
        candidate_checkout = producer.index("name: Checkout exact candidate")
        compare = producer.index("name: Require candidate release policy matches trusted main")
        candidate_execution = producer.index("name: Detect promoted adapter")
        self.assertLess(trusted_checkout, capture)
        self.assertLess(capture, candidate_checkout)
        self.assertLess(candidate_checkout, compare)
        self.assertLess(compare, candidate_execution)
        candidate_checkout_block = producer[candidate_checkout:compare]
        self.assertIn("fetch-depth: 0", candidate_checkout_block)
        self.assertIn('--policy-context "$RUNNER_TEMP/riscv-policy-match.json"', producer)

        fast = workflow.split("  riscv-fast-release-gate:", 1)[1]
        self.assertLess(
            fast.index("name: Resolve producer workflow trust root"),
            fast.index("name: Checkout current trusted-main release policy"),
        )
        self.assertLess(
            fast.index("name: Require candidate release policy matches current trusted main"),
            fast.index("name: Require requested release phase"),
        )
        self.assertLess(
            fast.index("name: Require candidate release policy matches current trusted main"),
            fast.index("name: Restore exact-candidate Zig build cache"),
        )
        self.assertLess(
            fast.index("name: Restore exact-candidate Zig build cache"),
            fast.index("name: Build focused static candidate prover and diagnostic"),
        )

    def test_riscv_jobs_initialize_runner_paths_at_step_runtime(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        producer = workflow.split("  riscv-release-evidence:", 1)[1].split(
            "  riscv-fast-release-gate:", 1
        )[0]
        fast = workflow.split("  riscv-fast-release-gate:", 1)[1].split(
            "  architecture-diagnostic:", 1
        )[0]
        self.assertNotIn("${{ runner.tool_cache }}", producer)
        self.assertNotIn("${{ runner.temp }}", fast)
        self.assertIn("$RUNNER_TOOL_CACHE/stwo-zig/riscv-oracle", producer)
        self.assertIn("$RUNNER_TEMP/riscv-exhaustive-bundle", fast)

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
        self.assertEqual(3, build_graph.count('"scripts/zig_protocol_test.py"'))
        gate_archive = "zig-out/release-evidence/native/interop-history"
        self.assertEqual(2, build_graph.count(gate_archive))
        self.assertEqual(2, build_graph.count('"--archive-dir"'))
        transitive_commands = {
            '&.{ "zig", "build", "test-riscv", build_optimize }': 2,
            '&.{ "zig", "build", "test-riscv-prover", build_optimize }': 2,
            '&.{ "python3", "scripts/riscv_trace_vectors.py" }': 3,
            # One additional standalone public API-parity build target is expected.
            '&.{ "python3", "scripts/check_api_parity.py" }': 2,
        }
        for command, expected_count in transitive_commands.items():
            self.assertEqual(expected_count, build_graph.count(command))
        self.assertEqual(
            0,
            subprocess.run(
                ["git", "check-ignore", "-q", gate_archive],
                cwd=ROOT,
                check=False,
            ).returncode,
        )
        interop_steps = [step for step in gate_steps("strict") if step["name"] == "interop"]
        self.assertEqual(1, len(interop_steps))
        self.assertIn(f"--archive-dir {gate_archive}", interop_steps[0]["command"])

    def test_pre_push_and_hosted_main_are_focused(self) -> None:
        pre_push = (ROOT / ".githooks/pre-push").read_text(encoding="utf-8")
        self.assertIn("exec python3 scripts/ci_scope_push.py", pre_push)
        self.assertNotIn("zig build", pre_push)

        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        focused = workflow.split("  focused-plan:", 1)[1].split("  release-gate:", 1)[0]
        self.assertIn("github.event.before", focused)
        self.assertIn("github.ref == 'refs/heads/main'", focused)
        self.assertIn("run: python3 scripts/ci.py\n", workflow)

    def test_hosted_metal_gate_builds_reproducible_aot_and_compiles_broader_graph(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        metal_job = workflow.split("  metal-acceptance:", 1)[1].split(
            "  riscv-release-evidence:", 1
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
        self.assertIn("python3 scripts/metal_core_aot_receipt.py build", workflow)
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
            ROOT / "src/tools/metal_core_aot/probe.m",
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
