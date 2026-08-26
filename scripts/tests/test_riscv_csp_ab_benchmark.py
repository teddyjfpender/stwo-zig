from __future__ import annotations

import copy
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.riscv_csp_ab_benchmark_lib import contract, runner


def git(root: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        input=input_bytes,
        capture_output=True,
        check=True,
    )
    return completed.stdout


def methodology() -> dict:
    return {
        "canonical_inputs": True,
        "canonical_sizes": [2, 4, 8, 12, 16, 32, 128, 256, 512, 1024, 2048],
        "target_sizes": {
            "sha256": [128, 256, 512, 1024, 2048],
            "keccak": [128, 256, 512, 1024, 2048],
            "poseidon2_m31": [2, 4, 8, 12, 16],
            "ecdsa_secp256k1": [32],
        },
        "uses_precompile": False,
        "proof_scope": "native RISC-V leaf STARK; recursion and outer proving disabled",
        "proof_duration": "mean execution + witness + proof generation",
        "verify_duration": "mean production verification",
        "proof_size": "Postcard proof bytes, excluding schema-v4 JSON framing",
        "preprocessing_size": "retained RV32IM ELF bytes",
        "peak_memory": "production process lifetime physical-footprint peak",
        "num_constraints": "0 means not exposed; cycles are authoritative",
    }


class CanonicalContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workloads = contract.canonical_workloads()

    def test_profile_registry_is_exactly_sixteen_cases_and_nine_profiles(self) -> None:
        self.assertEqual(16, len(self.workloads))
        self.assertEqual(9, len({case["profile_id"] for case in self.workloads}))
        self.assertEqual(("sha256", 128), (self.workloads[0]["target"], self.workloads[0]["input_size"]))

    def test_schedule_is_balanced_and_alternates_first_arm(self) -> None:
        schedule = contract.canonical_schedule(2)
        self.assertEqual(64, len(schedule))
        for round_index in range(2):
            for case_index in range(16):
                pair = [
                    row["arm"]
                    for row in schedule
                    if row["round"] == round_index
                    and row["case_ordinal"] == case_index
                ]
                expected = ["baseline", "current"] if (round_index + case_index) % 2 == 0 else ["current", "baseline"]
                self.assertEqual(expected, pair)

    def test_schedule_rejects_non_integer_rounds(self) -> None:
        with self.assertRaisesRegex(contract.ABError, "rounds"):
            contract.canonical_schedule("2")  # type: ignore[arg-type]

    def test_descriptive_statistics_keep_tails_and_robust_spread(self) -> None:
        result = contract.distribution([1, 2, 3, 100])
        self.assertEqual(2.5, result["p50"])
        self.assertEqual(100.0, result["p90"])
        self.assertEqual(1.0, result["mad"])
        self.assertEqual(4, result["count"])

    def test_historical_report_is_context_not_denominator(self) -> None:
        context = contract.historical_context()
        self.assertEqual("context_only_not_ab_denominator", context["classification"])
        self.assertEqual("ed573380db2f7ee1bc364a091cf6c82a00500ec3", context["measurement_commit"])

    def plan(self, *, admissible: bool = True) -> dict:
        digest = "a" * 64
        current_head = "c" * 40
        workload = contract.workload_context()
        preflight = {
            "schema": "stwo_native_ab_quiet_host_preflight_v1",
            "admissible": admissible,
            "reasons": [] if admissible else ["host busy"],
            "power_admissible": admissible,
        }
        arms = {
            "baseline": {
                "label": "baseline",
                "source_kind": "committed_baseline_v1",
                "head": contract.BASELINE_COMMIT,
                "benchmark_tree_dirty": False,
                "source_content_sha256": digest,
                "manifest_sha256": workload["manifest_sha256"],
                "harness_sha256": digest,
                "native_guard": {"kind": "recursive_sources_absent_v1"},
            },
            "current": {
                "label": "current",
                "source_kind": "ephemeral_active_snapshot_v1",
                "head": current_head,
                "benchmark_tree_dirty": False,
                "source_content_sha256": digest,
                "manifest_sha256": workload["manifest_sha256"],
                "harness_sha256": digest,
                "native_guard": {"kind": "runtime_native_attestation_v1"},
                "active_snapshot": {
                    "active_worktree_dirty": True,
                    "base_head": contract.BASELINE_COMMIT,
                    "temporary_commit": current_head,
                    "source_content_sha256": digest,
                    "tracked_patch_sha256": digest,
                    "tracked_patch_bytes": 1,
                    "untracked_payload_sha256": digest,
                    "untracked_file_count": 1,
                    "untracked_payload_bytes": 1,
                    "status_sha256": digest,
                    "temporary_tree_listing_sha256": digest,
                    "temporary_tree_git_oid": "e" * 40,
                    "ignored_source_input_count": 0,
                },
            },
        }
        return contract.attach_seal(
            {
                "schema": contract.PLAN_SCHEMA,
                "schema_version": contract.PLAN_VERSION,
                "status": (
                    "ready_ephemeral_current"
                    if admissible
                    else "diagnostic_smoke_only_host_interference"
                ),
                "host": {"host": "test"},
                "power": {
                    "admissible": admissible,
                    "reasons": [] if admissible else ["host busy"],
                },
                "publishable_preflight": preflight,
                "environment": {
                    "policy": "native_ab_sanitized_v1",
                    "fixed": {
                        "STWO_ZIG_WORKERS": "4",
                        "STWO_ZIG_MERKLE_WORKERS": "4",
                    },
                    "removed_stwo_names": [],
                },
                "settings": {
                    "backend": "cpu",
                    "recursion_enabled": False,
                    "rounds": 2,
                    "warmups": 1,
                    "samples": 5,
                    "workers": 4,
                    "timeout_seconds": 3600,
                },
                "arms": arms,
                "workload": workload,
                "schedule": contract.canonical_schedule(2),
                "historical_context": contract.historical_context(),
            }
        )

    def test_sealed_plan_supports_publishable_and_diagnostic_only_host_states(self) -> None:
        contract.validate_plan(self.plan())
        contract.validate_plan(self.plan(admissible=False))

    def test_plan_rejects_schedule_or_worker_ambiguity(self) -> None:
        changed = self.plan()
        changed["schedule"] = changed["schedule"][:-1]
        changed = contract.attach_seal(changed)
        with self.assertRaisesRegex(contract.ABError, "schedule"):
            contract.validate_plan(changed)
        changed = self.plan()
        changed["settings"]["workers"] = None
        changed = contract.attach_seal(changed)
        with self.assertRaisesRegex(contract.ABError, "workers"):
            contract.validate_plan(changed)


class SourceSnapshotTests(unittest.TestCase):
    def make_repository(self, parent: Path) -> Path:
        root = parent / "active"
        root.mkdir()
        git(root, "init", "--quiet")
        git(root, "config", "user.name", "Snapshot Test")
        git(root, "config", "user.email", "snapshot@example.invalid")
        (root / ".gitignore").write_text(".zig-cache/\n__pycache__/\n", encoding="utf-8")
        (root / "src").mkdir()
        (root / "src" / "tracked.bin").write_bytes(b"tracked-v1\x00")
        (root / "src" / "delete.zig").write_text("delete me\n", encoding="utf-8")
        (root / "build.zig").write_text("pub fn build() void {}\n", encoding="utf-8")
        git(root, "add", "-A")
        git(root, "commit", "--quiet", "-m", "base")
        return root

    def test_ephemeral_commit_exactly_reproduces_dirty_content_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            active = self.make_repository(parent)
            (active / "src" / "tracked.bin").write_bytes(b"staged-v2\x00\xff")
            git(active, "add", "src/tracked.bin")
            (active / "src" / "tracked.bin").write_bytes(b"working-v3\x00\xfe")
            (active / "src" / "delete.zig").unlink()
            (active / "src" / "new.zig").write_text("const answer = 42;\n", encoding="utf-8")

            head_before = git(active, "rev-parse", "HEAD")
            status_before = git(active, "status", "--porcelain=v2", "-z", "--untracked-files=all")
            index_before = git(active, "diff", "--cached", "--binary", "HEAD", "--")
            refs_before = git(active, "show-ref")
            digest_before = runner.source_content(active)

            first_root = parent / "snapshot-one"
            first = runner.materialize_ephemeral_current(active, first_root)
            second_root = parent / "snapshot-two"
            second = runner.materialize_ephemeral_current(active, second_root)

            self.assertEqual(head_before, git(active, "rev-parse", "HEAD"))
            self.assertEqual(status_before, git(active, "status", "--porcelain=v2", "-z", "--untracked-files=all"))
            self.assertEqual(index_before, git(active, "diff", "--cached", "--binary", "HEAD", "--"))
            self.assertEqual(refs_before, git(active, "show-ref"))
            self.assertEqual(digest_before, runner.source_content(first_root))
            self.assertEqual(digest_before, runner.source_content(second_root))
            self.assertFalse(runner.worktree_status(first_root)["dirty"])
            self.assertTrue(first["active_worktree_dirty"])
            self.assertEqual(1, first["untracked_file_count"])
            self.assertGreater(first["tracked_patch_bytes"], 0)
            self.assertEqual(first["temporary_commit"], second["temporary_commit"])
            self.assertEqual(first["source_content_sha256"], second["source_content_sha256"])
            artifact = parent / "artifacts"
            artifact.mkdir()
            bundle = runner._bundle_current(first_root, artifact, first["base_head"])
            self.assertEqual(first["temporary_commit"], bundle["temporary_commit"])
            self.assertEqual(bundle["sha256"], contract.sha256_file(artifact / bundle["path"]))
            git(first_root, "bundle", "verify", str(artifact / bundle["path"]))

    def test_ignored_source_file_is_rejected_but_cache_output_is_not(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            active = self.make_repository(parent)
            (active / ".gitignore").write_text(".zig-cache/\nsrc/hidden.zig\n", encoding="utf-8")
            git(active, "add", ".gitignore")
            git(active, "commit", "--quiet", "-m", "ignore policy")
            (active / ".zig-cache").mkdir()
            (active / ".zig-cache" / "cache.bin").write_bytes(b"cache")
            (active / "src" / "hidden.zig").write_text("hidden source\n", encoding="utf-8")
            with self.assertRaisesRegex(contract.ABError, "ignored files may influence"):
                runner.assert_no_ignored_source_inputs(active)

    def test_full_plan_creation_materializes_both_isolated_arms(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            active = self.make_repository(parent)
            (active / "vectors" / "riscv_csp").mkdir(parents=True)
            shutil.copy2(
                contract.ROOT / "vectors" / "riscv_csp" / "manifest-v2.json",
                active / "vectors" / "riscv_csp" / "manifest-v2.json",
            )
            (active / "scripts").mkdir()
            shutil.copy2(
                contract.ROOT / "scripts" / "riscv_csp_benchmark.py",
                active / "scripts" / "riscv_csp_benchmark.py",
            )
            git(active, "add", "-A")
            git(active, "commit", "--quiet", "-m", "benchmark baseline")
            baseline = git(active, "rev-parse", "HEAD").decode().strip()
            recursion = active / "src" / "frontends" / "riscv" / "recursion"
            recursion.mkdir(parents=True)
            (recursion / "mod.zig").write_text("pub const enabled = true;\n", encoding="utf-8")
            host = {
                "os": "Darwin",
                "cpu": "Test CPU",
                "logical_cpu_count": 4,
                "memory_bytes": 1,
                "gpu": {},
                "power_source": "AC Power",
                "low_power_mode": False,
            }
            preflight = {
                "schema": "stwo_native_ab_quiet_host_preflight_v1",
                "admissible": True,
                "reasons": [],
                "power_admissible": True,
            }
            with (
                mock.patch.object(contract, "BASELINE_COMMIT", baseline),
                mock.patch.object(runner, "collect_host", return_value=host),
                mock.patch.object(runner, "quiet_host_preflight", return_value=preflight),
            ):
                plan = runner.create_plan(
                    active,
                    rounds=1,
                    warmups=0,
                    samples=1,
                    workers=4,
                    timeout_seconds=60,
                )
                contract.validate_plan(plan)
            self.assertEqual("ready_ephemeral_current", plan["status"])
            self.assertEqual(32, len(plan["schedule"]))
            self.assertEqual("recursive_sources_absent_v1", plan["arms"]["baseline"]["native_guard"]["kind"])
            self.assertEqual("runtime_native_attestation_v1", plan["arms"]["current"]["native_guard"]["kind"])
            self.assertTrue(plan["arms"]["current"]["active_snapshot"]["active_worktree_dirty"])


class HostAndEnvironmentTests(unittest.TestCase):
    def test_quiet_host_contract_accepts_only_idle_unthrottled_samples(self) -> None:
        clear = runner.classify_quiet_host(
            idle_percent=[96.0, 97.0, 98.0],
            load_1m=[1.0, 1.1, 1.2],
            logical_cpu_count=8,
            thermal={"thermal_clear": True},
            power_admissible=True,
            power_reasons=[],
        )
        self.assertTrue(clear["admissible"])
        busy = runner.classify_quiet_host(
            idle_percent=[89.0, 97.0, 98.0],
            load_1m=[1.0, 1.1, 1.2],
            logical_cpu_count=8,
            thermal={"thermal_clear": True},
            power_admissible=True,
            power_reasons=[],
        )
        self.assertFalse(busy["admissible"])
        self.assertTrue(any("minimum CPU idle" in reason for reason in busy["reasons"]))

    def test_environment_removes_all_stwo_tuning_and_pins_workers(self) -> None:
        environment, evidence = runner.benchmark_environment(
            {
                "PATH": "/bin",
                "STWO_RECURSION_ENABLED": "1",
                "STWO_ZIG_WORKERS": "99",
                "ZIG_GLOBAL_CACHE_DIR": "/shared",
            },
            7,
        )
        self.assertNotIn("STWO_RECURSION_ENABLED", environment)
        self.assertEqual("7", environment["STWO_ZIG_WORKERS"])
        self.assertEqual("7", environment["STWO_ZIG_MERKLE_WORKERS"])
        self.assertNotIn("ZIG_GLOBAL_CACHE_DIR", environment)
        self.assertEqual(
            ["STWO_RECURSION_ENABLED", "STWO_ZIG_WORKERS"],
            evidence["removed_stwo_names"],
        )


class PartialReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.case = contract.canonical_workloads()[0]
        cls.host = {"machine": "test-host", "power_source": "AC Power", "low_power_mode": False}
        cls.settings = {"warmups": 0, "samples": 2, "workers": 4}

    def arm(self, label: str, guard: str) -> dict:
        return {
            "label": label,
            "head": ("b" if label == "baseline" else "c") * 40,
            "native_guard": {"kind": guard},
        }

    def report(
        self,
        arm: dict,
        schema: str = "stwo_riscv_csp_benchmark_v4",
        case: dict | None = None,
    ) -> dict:
        case = self.case if case is None else case
        row = {
            "backend": "cpu",
            "recursion_enabled": False,
            "target": case["target"],
            "input_size": case["input_size"],
            "cycles": case["expected_cycles"],
            "uses_precompile": False,
            "proof_duration": 1_000,
            "verify_duration": 200,
            "peak_memory": 4096,
            "proof_size": 123,
            "evidence": {
                "status": "verified",
                "input_sha256": case["input_sha256"],
                "guest_sha256": case["guest_sha256"],
                "output_digest": case["expected_output_digest"],
                "expected_output_digest": case["expected_output_digest"],
                "retained_verify_receipt": {
                    "status": "verified",
                    "implementation_commit": arm["head"],
                    "implementation_dirty": False,
                    "proof_bytes": 123,
                    "proof_sha256": "d" * 64,
                },
            },
            "timing": {"verified_end_to_end_sample_seconds": [1.0, 1.1]},
        }
        return {
            "schema": schema,
            "measurement_commit": arm["head"],
            "repository_head": arm["head"],
            "suite_manifest_sha256": contract.workload_context()["manifest_sha256"],
            "host": self.host,
            "power_conditions_admissible": True,
            "methodology": methodology(),
            "run": {
                "backend": "cpu",
                "targets": [case["target"]],
                "sizes": [case["input_size"]],
                "warmups": 0,
                "samples": 2,
                "workers": 4,
                "recursion_enabled": False,
                "complete_matrix": False,
            },
            "summary": {
                "row_count": 1,
                "all_outputs_match": True,
                "all_proofs_verified": True,
                "all_recursion_disabled": True,
                "all_peak_memory_available": True,
            },
            "identities": {
                "prover_build_identity": {"optimize": "ReleaseFast"},
                "prover_executable_sha256": "e" * 64,
                "trace_executable_sha256": "f" * 64,
                "trace_provenance": {
                    "implementation_commit": arm["head"],
                    "implementation_dirty": False,
                },
            },
            "measurements": [row],
        }

    def validate(self, report: dict, arm: dict, **kwargs: object) -> dict:
        return contract.validate_partial_report(
            report,
            arm=arm,
            case=self.case,
            settings=self.settings,
            expected_host=self.host,
            **kwargs,
        )

    def test_v4_native_report_is_admitted(self) -> None:
        arm = self.arm("current", "runtime_native_attestation_v1")
        normalized = self.validate(self.report(arm), arm)
        self.assertEqual([1.0, 1.1], normalized["end_to_end_sample_seconds"])

    def test_v3_is_only_admitted_when_recursive_sources_are_absent(self) -> None:
        baseline = self.arm("baseline", "recursive_sources_absent_v1")
        self.validate(self.report(baseline, "stwo_riscv_csp_benchmark_v3"), baseline)
        current = self.arm("current", "runtime_native_attestation_v1")
        with self.assertRaisesRegex(contract.ABError, "predates runtime recursion"):
            self.validate(self.report(current, "stwo_riscv_csp_benchmark_v3"), current)

    def test_recursion_or_receipt_shape_mutation_is_rejected(self) -> None:
        arm = self.arm("current", "runtime_native_attestation_v1")
        recursive = self.report(arm)
        recursive["measurements"][0]["recursion_enabled"] = True
        with self.assertRaisesRegex(contract.ABError, "recursion attestation"):
            self.validate(recursive, arm)
        wrong_size = self.report(arm)
        wrong_size["measurements"][0]["evidence"]["retained_verify_receipt"]["proof_bytes"] += 1
        with self.assertRaisesRegex(contract.ABError, "proof size"):
            self.validate(wrong_size, arm)

    def test_smoke_may_validate_proof_evidence_under_nonpublishable_power(self) -> None:
        arm = self.arm("current", "runtime_native_attestation_v1")
        report = self.report(arm)
        report["power_conditions_admissible"] = False
        self.validate(report, arm, require_publishable_power=False)
        with self.assertRaisesRegex(contract.ABError, "power conditions"):
            self.validate(report, arm)

    def test_full_assembler_requires_and_retains_every_pair_and_launch_receipt(self) -> None:
        plan = CanonicalContractTests("test_profile_registry_is_exactly_sixteen_cases_and_nine_profiles").plan()
        plan["host"] = self.host
        plan["settings"].update({"warmups": 0, "samples": 2, "workers": 4})
        plan = contract.attach_seal(plan)
        contract.validate_plan(plan)
        with tempfile.TemporaryDirectory() as raw:
            artifact = Path(raw)
            pair_evidence: dict[tuple[int, int], dict] = {}
            for entry in plan["schedule"]:
                key = (entry["round"], entry["case_ordinal"])
                if key not in pair_evidence:
                    gate = contract.attach_seal(
                        {
                            "schema": "stwo_native_ab_bounded_quiet_gate_v1",
                            "label": f"pair {key}",
                            "admissible": True,
                            "reasons": [],
                            "enforce_load_threshold": False,
                            "elapsed_seconds": 1.0,
                            "attempts": [{"ordinal": 0}],
                        }
                    )
                    gate_path = runner._pair_gate_relative(entry)
                    contract.write_new_json(artifact / gate_path, gate)
                    pair_evidence[key] = runner._gate_evidence(
                        artifact, gate_path, require_admissible=True
                    )
                arm = plan["arms"][entry["arm"]]
                report = self.report(
                    arm, case=plan["workload"]["cases"][entry["case_ordinal"]]
                )
                report_path = artifact / runner._partial_relative(entry)
                contract.write_new_json(report_path, report)
                raw_report = report_path.read_bytes()
                receipt = contract.attach_seal(
                    {
                        "schema": "stwo_riscv_csp_native_ab_launch_receipt_v1",
                        "entry": entry,
                        "report_path": str(runner._partial_relative(entry)),
                        "report_sha256": contract.sha256_bytes(raw_report),
                        "report_bytes": len(raw_report),
                        "quiet_gate": pair_evidence[key],
                    }
                )
                contract.write_new_json(
                    artifact / runner._receipt_relative(entry), receipt
                )
            post_gate = contract.attach_seal(
                {
                    "schema": "stwo_native_ab_bounded_quiet_gate_v1",
                    "label": "post-build",
                    "admissible": True,
                    "reasons": [],
                    "enforce_load_threshold": True,
                    "elapsed_seconds": 1.0,
                    "attempts": [{"ordinal": 0}],
                }
            )
            post_path = Path("gates/post-build.json")
            contract.write_new_json(artifact / post_path, post_gate)
            result = runner.assemble_report(
                plan,
                artifact,
                plan_evidence={"seal_sha256": plan["seal_sha256"]},
                snapshot_bundle={"sha256": "a" * 64},
                execution_preflight=plan["publishable_preflight"],
                post_build_gate=runner._gate_evidence(
                    artifact, post_path, require_admissible=True
                ),
                pair_gates=[pair_evidence[key] for key in sorted(pair_evidence)],
            )
            self.assertEqual(16, len(result["cases"]))
            self.assertEqual(64, len(result["captures"]))
            self.assertEqual(32, len(result["paired_case_quiet_gates"]))
            self.assertFalse(result["interpretation"]["aggregate_speedup_claim"])


class CommandContractTests(unittest.TestCase):
    def test_commands_pin_releasefast_cpu_and_separate_products(self) -> None:
        root = Path("/tmp/arm")
        build = runner.build_command(root)
        self.assertIn("-Doptimize=ReleaseFast", build)
        self.assertIn("stwo-zig-riscv-cpu", build)
        self.assertIn("riscv-trace-dump", build)
        settings = {"warmups": 0, "samples": 1, "workers": 7, "timeout_seconds": 60}
        command = runner.benchmark_command(
            root,
            Path("/tmp/report.json"),
            {"target": "sha256", "input_size": 128},
            settings,
        )
        self.assertEqual("cpu", command[command.index("--backend") + 1])
        workers_index = command.index("--workers")
        self.assertEqual("7", command[workers_index + 1])
        self.assertEqual("--timeout", command[workers_index + 2])
        self.assertEqual(1, command.count("--workers"))
        self.assertNotIn("recursion", " ".join(command).lower())

    def test_generated_argv_is_accepted_by_the_production_harness_parser(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            command = runner.benchmark_command(
                contract.ROOT,
                temporary / "report.json",
                {"target": "sha256", "input_size": 128},
                {"warmups": 0, "samples": 1, "workers": 7, "timeout_seconds": 60},
            )
            command[command.index("--cli") + 1] = str(temporary / "missing-prover")
            command[command.index("--trace-cli") + 1] = str(temporary / "missing-trace")
            completed = subprocess.run(
                command,
                cwd=contract.ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(1, completed.returncode)
            self.assertNotIn("unrecognized arguments", completed.stderr)
            self.assertIn("executable is missing", completed.stderr)

    def test_logged_timeout_terminates_its_owned_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with self.assertRaisesRegex(contract.ABError, "timed out"):
                runner._run_logged(
                    [
                        os.fspath(Path(sys.executable)),
                        "-c",
                        "import time; time.sleep(30)",
                    ],
                    cwd=root,
                    env={},
                    log_path=root / "timeout.log",
                    timeout=1,
                )

    def test_seal_rejects_mutation(self) -> None:
        document = contract.attach_seal({"schema": "test", "value": 1})
        contract.validate_seal(document, "test")
        changed = copy.deepcopy(document)
        changed["value"] = 2
        with self.assertRaisesRegex(contract.ABError, "seal mismatch"):
            contract.validate_seal(changed, "test")


if __name__ == "__main__":
    unittest.main()
