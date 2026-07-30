"""Group-aware runner behavior: loud skips and honest missing-binary failures."""

import contextlib
import hashlib
import io
import json
import os
import shlex
import sys
import tempfile
import textwrap
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli"))
from stwo_perf import manifest as manifest_mod, runner
from stwo_perf.manifest import Manifest
from scripts.tests.test_native_cuda_diagnostic import FAKE_PRODUCT

REPO_ROOT = Path(__file__).resolve().parents[2]

FAKE_REPORT = (
    '{"schema_version":7,"timing":{"prove_seconds":{"median":0.001}},'
    '"workload":{"committed_trace_cells":8192},'
    '"resource_admission":{"profile":"standard",'
    '"accounted_bytes_per_committed_cell":16,"committed_cells":8192,'
    '"accounted_bytes":131072,"max_committed_cells":33554432,'
    '"max_accounted_bytes":536870912},'
    '"proof":{"verified_samples":1,"all_samples_byte_identical":true,'
    '"samples":[{"bytes":1024,"sha256":"' + "a" * 64 + '"}]},'
    '"resources":{"measurement_scope":"verified_process_request_batch",'
    '"source":"darwin_proc_pid_rusage_v6","measured_warmups":1,'
    '"measured_samples":1,"lifetime_peak_physical_footprint_bytes":1048576,'
    '"energy_nj":1000000000,"instructions":1000,"cycles":500,'
    '"canonical_proof_bytes":1024,"complete":true,'
    '"unavailable_reason":null}}'
)

GATES_POLICY = {
    "ci_level": 0.95,
    "theta_floor": 0.01,
    "dispersion_multiplier": 2.0,
    "targeted_class_budget": 1.02,
    "matrix_row_budget": 1.05,
    "warmups": 0,
    "samples_per_round": 1,
    "min_rounds": 3,
    "max_rounds": 3,
    "search_health": {
        "trailing_window": 4,
        "gradient_snr_threshold": 2.0,
        "auto_boost_rounds": 2,
        "maximum_rounds": 8,
    },
    "wall_clock_cap_seconds": {"small": 60, "wide": 60, "deep": 60},
}


def make_raw(riscv_enabled: bool, native_binary: str = "bin/fakebench") -> dict:
    riscv = {
        "enabled": riscv_enabled,
        "promotion_eligible": riscv_enabled,
        "board": "riscv",
        "build_step": "true",
        "binary": "bin/missing-riscv-bench",
        "report_schema": "riscv_proof_v2",
        "correctness_oracle": {
            "authority": "sail-riscv",
            "repository": "https://github.com/riscv/sail-riscv",
            "commit": "8c7f2da58de0ba5e4457e4de07e0046f0439f35f",
            "final_validator": True,
        },
        "mechanism_telemetry": {
            "fail_closed": True,
            "required_fields": [
                "total_steps", "n_components", "mean_execution_seconds",
                "mean_witness_seconds", "mean_proving_seconds",
                "mean_verification_seconds", "statement_sha256",
                "transcript_state_blake2s",
            ],
        },
        "resource_telemetry": json.loads(json.dumps(
            manifest_mod.RISCV_RESOURCE_TELEMETRY
        )),
        "workloads": {
            "riscv_alu": {
                "class": "wide",
                "args": "--elf vectors/riscv_elfs/alu_test.elf "
                        "{admission} --warmups {warmups} --samples {samples}",
                "native_unit": "executed instructions",
            },
        },
    }
    if not riscv_enabled:
        riscv["disabled_reason"] = "stark-v adapter pending release gate"
    return {
        "manifest_version": 2,
        "harness": {"anchor_commit": None},
        "editable_paths": [],
        "locked_paths": [],
        "gates_policy": GATES_POLICY,
        "qualification_policy": {
            "required_checks": ["allowed_diff"],
            "max_active_per_user": 1,
        },
        "workload_registry": {
            "classes": {
                name: {
                    "scored": True,
                    "resource": {
                        "profile": "standard",
                        "command_timeout_seconds": 60,
                        "wall_clock_cap_seconds": 60,
                    },
                    "sampling": {
                        "warmups": 1,
                        "samples_per_round": 1,
                        "min_rounds": 3,
                        "max_rounds": 3,
                    },
                }
                for name in ("small", "wide", "deep")
            },
            "groups": {
                "native": {
                    "enabled": True,
                    "promotion_eligible": True,
                    "board": "core_cpu",
                    "build_step": "true",
                    "binary": native_binary,
                    "report_schema": "native_proof_v7",
                    "workloads": {
                        "wf_small": {
                            "class": "small",
                            "args": "--warmups {warmups} --samples {samples}",
                            "native_unit": "trace rows",
                        },
                    },
                },
                "riscv": riscv,
            },
        },
    }


class RunnerGroupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        bench = self.root / "bin" / "fakebench"
        bench.parent.mkdir(parents=True)
        bench.write_text(f"#!/bin/sh\necho '{FAKE_REPORT}'\n")
        os.chmod(bench, 0o755)
        self.out_dir = self.root / "runs"

    def tearDown(self):
        self.tmp.cleanup()

    def _manifest(self, **kwargs) -> Manifest:
        raw = make_raw(**kwargs)
        manifest_mod._validate(raw)  # fixture must be a valid v2 manifest
        return Manifest(root=self.root, raw=raw)

    def _cuda_manifest(self) -> Manifest:
        raw = make_raw(riscv_enabled=False)
        raw["workload_registry"]["groups"]["native_cuda"] = {
            "enabled": True,
            "promotion_eligible": False,
            "board": "core_cuda",
            "build_step": "true",
            "binary": "bin/cudabench",
            "report_schema": "native_cuda_product_v6",
            "correctness_oracle": {
                "authority": "pinned-rust-stwo",
                "repository": "https://github.com/starkware-libs/stwo",
                "commit": "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2",
                "final_validator": True,
            },
            "workloads": {
                "cuda_wf": {
                    "class": "wide",
                    "args": (
                        "prove --air wide_fibonacci --backend cuda "
                        "--protocol raw-stwo-wide-v1 --log-n-rows 5 "
                        "--sequence-len 8 --repeat {samples}"
                    ),
                    "native_unit": "committed cells",
                },
            },
        }
        manifest_mod._validate(raw)
        return Manifest(self.root, raw)

    def _set_riscv_phase(self, promoted: bool) -> None:
        capability = self.root / "src/products/riscv_cpu/capabilities.zig"
        artifact = self.root / "src/interop/riscv_artifact.zig"
        capability.parent.mkdir(parents=True, exist_ok=True)
        artifact.parent.mkdir(parents=True, exist_ok=True)
        capability.write_text(
            f"pub const adapter_release_gated = {str(promoted).lower()};\n",
            encoding="utf-8",
        )
        artifact.write_text(
            'pub const RELEASE_STATUS = "'
            + ("release_gated" if promoted else "not_release_gated")
            + '";\n',
            encoding="utf-8",
        )

    def _riscv_manifest(self) -> Manifest:
        raw = make_raw(riscv_enabled=True)
        raw["workload_registry"]["groups"]["riscv"]["binary"] = "bin/fakebench"
        manifest_mod._validate(raw)
        return Manifest(root=self.root, raw=raw)

    @staticmethod
    def _riscv_artifact(status: str, proof_hex: str = "0102",
                        implementation_commit: str = "b" * 40) -> dict:
        return {
            "artifact_kind": "stwo_riscv_proof",
            "schema_version": 4,
            "exchange_mode": "riscv_proof_json_wire_v4",
            "release_status": status,
            "generator": "zig",
            "air": "sail_rv32im_zkvm_v1",
            "backend": "cpu",
            "protocol": "functional",
            "source": {"elf_sha256": "1" * 64, "input_sha256": "2" * 64},
            "provenance": {
                "oracle_repository": "https://github.com/riscv/sail-riscv",
                "oracle_commit": "8c7f2da58de0ba5e4457e4de07e0046f0439f35f",
                "implementation_repository": "https://github.com/teddyjfpender/stwo-zig",
                "implementation_commit": implementation_commit,
                "implementation_dirty": False,
                "witness_layout_sha256": "3" * 64,
            },
            "pcs_config": {},
            "statement": {},
            "interaction_claim": {},
            "proof_bytes_hex": proof_hex,
        }

    def _riscv_run(self, status: str, experimental: bool,
                    proof_hex: str = "0102", mutate_report=None,
                    implementation_commit: str = "b" * 40,
                    mutate_artifact=None):
        commands = []

        def fake_run(command, _root, timeout):
            del timeout
            commands.append(command)
            parts = shlex.split(command)
            proof_path = Path(parts[parts.index("--proof-out") + 1])
            artifact = self._riscv_artifact(
                status, proof_hex, implementation_commit,
            )
            if mutate_artifact:
                mutate_artifact(artifact)
            encoded = json.dumps(artifact, separators=(",", ":")).encode()
            proof_path.write_bytes(encoded)
            report = {
                "schema": "riscv_proof_v2",
                "release_status": status,
                "mode": "bench",
                "experimental": experimental,
                "profiled": False,
                "warmups": 0,
                "samples": 1,
                "verified_samples": 1,
                "total_steps": 32,
                "n_components": 2,
                "throughput_numerator": "vm_steps",
                "median_seconds": 0.004,
                "throughput_mhz": 0.008,
                "mean_execution_seconds": 0.0005,
                "mean_witness_seconds": 0.0005,
                "mean_proving_seconds": 0.003,
                "mean_verification_seconds": 0.0002,
                "sample_seconds": [0.004],
                "statement_sha256": "4" * 64,
                "transcript_state_blake2s": "5" * 64,
                "implementation_commit": implementation_commit,
                "implementation_dirty": False,
                "executable_sha256": "6" * 64,
                "artifact_sha256": hashlib.sha256(encoded).hexdigest(),
                "proof_path": str(proof_path),
                "resources": {
                    "availability": "available",
                    "source": "darwin.proc_pid_rusage.RUSAGE_INFO_V6",
                    "scope": "self_process_lifetime",
                    "unavailable_reason": None,
                    "before_warmups": {
                        "lifetime_max_phys_footprint_bytes": 16 * 1024 * 1024,
                        "energy_nj": 100,
                        "instructions": 200,
                        "cycles": 300,
                    },
                    "after_verified_samples": {
                        "lifetime_max_phys_footprint_bytes": 32 * 1024 * 1024,
                        "energy_nj": 110,
                        "instructions": 220,
                        "cycles": 330,
                    },
                    "interval_delta": {
                        "energy_nj": 10,
                        "instructions": 20,
                        "cycles": 30,
                    },
                },
            }
            if mutate_report:
                mutate_report(report)
            return json.dumps(report)

        return commands, fake_run

    @staticmethod
    def _riscv_verify_receipt(report: dict, artifact: dict) -> dict:
        proof = bytes.fromhex(artifact["proof_bytes_hex"])
        return {
            "schema": "riscv_verify_v1",
            "status": "verified",
            "artifact_kind": artifact["artifact_kind"],
            "artifact_schema_version": artifact["schema_version"],
            "release_status": artifact["release_status"],
            "security_policy": artifact["protocol"],
            "statement_sha256": report["statement_sha256"],
            "proof_bytes": len(proof),
            "proof_sha256": hashlib.sha256(proof).hexdigest(),
            "transcript_state_blake2s": report["transcript_state_blake2s"],
            "implementation_commit": report["implementation_commit"],
            "implementation_dirty": report["implementation_dirty"],
            "executable_sha256": report["executable_sha256"],
        }

    def test_disabled_group_is_skipped_loudly_with_reason(self):
        m = self._manifest(riscv_enabled=False)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            result = runner.evaluate_aa(self.root, m, "small", self.out_dir)
        self.assertIn(
            "skipped group riscv: stark-v adapter pending release gate",
            buf.getvalue(),
        )
        self.assertEqual(
            result["skipped_groups"],
            [{"group": "riscv", "reason": "stark-v adapter pending release gate"}],
        )
        self.assertEqual(result["workload"], "wf_small")

    def test_announce_helper_reports_every_disabled_group(self):
        m = self._manifest(riscv_enabled=False)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            skipped = runner.announce_skipped_groups(m)
        self.assertEqual([s["group"] for s in skipped], ["riscv"])
        self.assertIn("skipped group riscv:", buf.getvalue())

    def test_disabled_group_workloads_never_run(self):
        m = self._manifest(riscv_enabled=False)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(runner.RunError) as ctx:
            runner.evaluate_aa(self.root, m, "wide", self.out_dir, board="riscv")
        self.assertIn("no enabled workloads registered for board riscv", str(ctx.exception))
        self.assertIn("skipped group riscv", buf.getvalue())

    def test_enabled_group_with_missing_binary_fails_clearly(self):
        m = self._manifest(riscv_enabled=True)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(runner.RunError) as ctx:
            runner.evaluate_aa(self.root, m, "wide", self.out_dir, board="riscv")
        message = str(ctx.exception)
        self.assertIn("riscv", message)
        self.assertIn("bin/missing-riscv-bench", message)
        self.assertIn("refusing to fabricate", message)
        # no fabricated report may exist for the missing binary
        self.assertFalse(list(self.out_dir.glob("riscv_alu.*.json")))

    def test_bench_once_checks_binary_before_running(self):
        m = self._manifest(riscv_enabled=True)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        workload = m.workloads("wide", board="riscv")[0]
        with self.assertRaises(runner.RunError) as ctx:
            runner.bench_once(self.root, m, workload, 0, 1, self.out_dir, "a1")
        self.assertIn("not found", str(ctx.exception))

    def test_bench_once_rejects_wrong_report_schema(self):
        bench = self.root / "bin" / "fakebench"
        bench.write_text(
            "#!/bin/sh\n"
            "echo '{\"schema_version\":6,\"timing\":{\"prove_seconds\":"
            "{\"median\":0.001}},\"proof\":{\"verified_samples\":1,"
            "\"all_samples_byte_identical\":true}}'\n"
        )
        m = self._manifest(riscv_enabled=False)
        workload = m.workloads("small", board="core_cpu")[0]
        with self.assertRaises(runner.RunError) as ctx:
            runner.bench_once(self.root, m, workload, 0, 1, self.out_dir, "a1")
        self.assertIn("expected native_proof_v7", str(ctx.exception))
        self.assertFalse((self.out_dir / "wf_small.a1.json").exists())

    def test_bench_once_rejects_duplicate_report_fields(self):
        bench = self.root / "bin" / "fakebench"
        bench.write_text(
            "#!/bin/sh\n"
            "echo '{\"schema_version\":7,\"schema_version\":7}'\n"
        )
        manifest = self._manifest(riscv_enabled=False)
        workload = manifest.workloads("small", board="core_cpu")[0]
        with self.assertRaisesRegex(runner.RunError, "non-JSON output"):
            runner.bench_once(
                self.root, manifest, workload, 0, 1, self.out_dir, "a1",
            )

    def test_cuda_bench_parses_retained_product_v6_fail_closed(self):
        binary = self.root / "bin" / "cudabench"
        binary.write_text(textwrap.dedent(FAKE_PRODUCT).lstrip())
        binary.chmod(0o755)
        manifest = self._cuda_manifest()
        workload = manifest.workloads("wide", board="core_cuda")[0]

        result = runner.bench_once(
            self.root,
            manifest,
            workload,
            1,
            2,
            self.out_dir,
            "a1",
        )

        self.assertEqual(2, result.proof_verified)
        self.assertTrue(result.byte_identical)
        self.assertGreater(result.prove_ms, 0)
        self.assertGreater(result.request_ms, result.prove_ms)
        self.assertIsNotNone(result.mechanism["residency"])
        self.assertTrue(
            (self.out_dir / "cuda_wf.a1.proof.json").is_file()
        )
        report = json.loads(
            (self.out_dir / "cuda_wf.a1.product.json").read_text()
        )
        self.assertEqual(4, report["process_repetition"]["count"])

    def test_cuda_bench_rejects_fallback_report(self):
        binary = self.root / "bin" / "cudabench"
        binary.write_text(textwrap.dedent(FAKE_PRODUCT).lstrip())
        binary.chmod(0o755)
        manifest = self._cuda_manifest()
        workload = manifest.workloads("wide", board="core_cuda")[0]
        with mock.patch.dict(os.environ, {"FAKE_CUDA_MODE": "fallback"}), \
                self.assertRaisesRegex(runner.RunError, "fallback"):
            runner.bench_once(
                self.root,
                manifest,
                workload,
                0,
                1,
                self.out_dir,
                "a1",
            )

    def test_native_report_resource_admission_fails_closed(self):
        manifest = self._manifest(riscv_enabled=False)
        group = manifest.group("native")
        workload = manifest.workloads("small", board="core_cpu")[0]
        base = json.loads(FAKE_REPORT)
        runner._parse_native_report(base, group, workload, 1, 1, Path("report.json"))

        mutations = {
            "missing field": lambda report: report["resource_admission"].pop(
                "max_accounted_bytes"
            ),
            "profile": lambda report: report["resource_admission"].__setitem__(
                "profile", "large"
            ),
            "cells": lambda report: report["resource_admission"].__setitem__(
                "committed_cells", 8191
            ),
            "accounted": lambda report: report["resource_admission"].__setitem__(
                "accounted_bytes", 131071
            ),
            "factor": lambda report: report["resource_admission"].__setitem__(
                "accounted_bytes_per_committed_cell", 4
            ),
            "budget": lambda report: report["resource_admission"].__setitem__(
                "max_committed_cells", 1 << 63
            ),
        }
        for name, mutate in mutations.items():
            report = json.loads(FAKE_REPORT)
            mutate(report)
            with self.subTest(name=name), self.assertRaises(ValueError):
                runner._parse_native_report(
                    report, group, workload, 1, 1, Path("report.json")
                )

        large_workload = runner.Workload(
            workload_id="wf_huge",
            workload_class="huge",
            args="--resource-profile large --warmups {warmups} --samples {samples}",
            native_unit="trace rows",
        )
        large = json.loads(FAKE_REPORT)
        large["resource_admission"].update({
            "profile": "large",
            "max_committed_cells": 134217728,
            "max_accounted_bytes": 2147483648,
        })
        runner._parse_native_report(
            large, group, large_workload, 1, 1, Path("large-report.json")
        )

    def test_enabled_native_group_still_scores(self):
        m = self._manifest(riscv_enabled=False)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            result = runner.evaluate_aa(self.root, m, "small", self.out_dir)
        self.assertEqual(result["rounds"], 3)
        self.assertEqual(result["aa_r"], 1.0)

    def test_riscv_bench_uses_staged_admission_and_canonical_proof_digest(self):
        self._set_riscv_phase(promoted=False)
        manifest = self._riscv_manifest()
        workload = manifest.workloads("wide", board="riscv")[0]
        commands, fake_run = self._riscv_run("not_release_gated", True)
        with mock.patch.object(runner, "_run", side_effect=fake_run):
            result = runner.bench_once(
                self.root, manifest, workload, 0, 1, self.out_dir, "a1",
            )
        self.assertIn("--experimental", shlex.split(commands[0]))
        self.assertEqual(hashlib.sha256(bytes.fromhex("0102")).hexdigest(),
                         result.proof_digest)
        self.assertEqual(result.mechanism["total_steps"], 32)
        self.assertEqual(result.mechanism["statement_sha256"], "4" * 64)
        self.assertEqual(result.peak_rss_mib, 32.0)
        self.assertEqual(result.energy_j, 10 / 1_000_000_000.0)
        self.assertEqual(result.instructions, 20)
        self.assertEqual(result.cycles, 30)
        self.assertTrue(result.resources_complete)

    def test_riscv_bench_rejects_unavailable_resource_counters(self):
        self._set_riscv_phase(promoted=True)
        manifest = self._riscv_manifest()
        workload = manifest.workloads("wide", board="riscv")[0]

        def unavailable(report):
            report["resources"].update({
                "availability": "unavailable",
                "unavailable_reason": "unsupported_platform",
                "before_warmups": None,
                "after_verified_samples": None,
                "interval_delta": None,
            })

        _commands, fake_run = self._riscv_run(
            "release_gated", False, mutate_report=unavailable,
        )
        with mock.patch.object(runner, "_run", side_effect=fake_run):
            result = runner.bench_once(
                self.root, manifest, workload, 0, 1, self.out_dir, "a1",
            )
        self.assertFalse(result.resources_complete)
        self.assertIsNone(result.peak_rss_mib)
        self.assertIsNone(result.energy_j)

    def test_riscv_bench_rejects_inconsistent_resource_delta(self):
        self._set_riscv_phase(promoted=True)
        manifest = self._riscv_manifest()
        workload = manifest.workloads("wide", board="riscv")[0]
        _commands, fake_run = self._riscv_run(
            "release_gated", False,
            mutate_report=lambda report: report["resources"]["interval_delta"].update(
                energy_nj=9
            ),
        )
        with mock.patch.object(runner, "_run", side_effect=fake_run), \
                self.assertRaisesRegex(runner.RunError, "energy_nj is inconsistent"):
            runner.bench_once(
                self.root, manifest, workload, 0, 1, self.out_dir, "a1",
            )

    def test_riscv_bench_uses_promoted_admission_without_experimental(self):
        self._set_riscv_phase(promoted=True)
        manifest = self._riscv_manifest()
        workload = manifest.workloads("wide", board="riscv")[0]
        commands, fake_run = self._riscv_run("release_gated", False)
        with mock.patch.object(runner, "_run", side_effect=fake_run):
            runner.bench_once(
                self.root, manifest, workload, 0, 1, self.out_dir, "a1",
            )
        self.assertNotIn("--experimental", shlex.split(commands[0]))

    def test_riscv_runner_artifact_contract_matches_source_schema(self):
        schema = (
            REPO_ROOT / "src/interop/riscv_artifact/schema.zig"
        ).read_text(encoding="utf-8")
        self.assertIn(
            f"pub const SCHEMA_VERSION: u32 = {runner.RISCV_ARTIFACT_SCHEMA_VERSION};",
            schema,
        )
        self.assertIn(
            f'pub const EXCHANGE_MODE = "{runner.RISCV_ARTIFACT_EXCHANGE_MODE}";',
            schema,
        )
        self.assertIn(
            f'pub const AIR = "{runner.RISCV_ARTIFACT_AIR}";',
            schema,
        )

    def test_riscv_bench_rejects_legacy_v3_artifact(self):
        self._set_riscv_phase(promoted=True)
        manifest = self._riscv_manifest()
        workload = manifest.workloads("wide", board="riscv")[0]

        def legacy_v3(artifact):
            artifact.update({
                "schema_version": 3,
                "exchange_mode": "riscv_proof_json_wire_v3",
                "air": "stark_v_rv32im",
            })
            artifact["provenance"].update({
                "oracle_repository": "https://github.com/ClementWalter/stark-v",
                "oracle_commit": "d478f783055aa0d73a93768a433a3c6c31c91d1c",
            })

        _commands, fake_run = self._riscv_run(
            "release_gated", False, mutate_artifact=legacy_v3,
        )
        with mock.patch.object(runner, "_run", side_effect=fake_run), \
                self.assertRaisesRegex(runner.RunError, "schema_version.*equal 4"):
            runner.bench_once(
                self.root, manifest, workload, 0, 1, self.out_dir, "legacy-v3",
            )

    def test_riscv_bench_rejects_non_sail_artifact_authority(self):
        self._set_riscv_phase(promoted=True)
        manifest = self._riscv_manifest()
        workload = manifest.workloads("wide", board="riscv")[0]
        mutations = {
            "repository": lambda artifact: artifact["provenance"].update(
                oracle_repository="https://github.com/ClementWalter/stark-v"
            ),
            "commit": lambda artifact: artifact["provenance"].update(
                oracle_commit="d478f783055aa0d73a93768a433a3c6c31c91d1c"
            ),
        }
        for name, mutate in mutations.items():
            _commands, fake_run = self._riscv_run(
                "release_gated", False, mutate_artifact=mutate,
            )
            with self.subTest(name=name), \
                    mock.patch.object(runner, "_run", side_effect=fake_run), \
                    self.assertRaisesRegex(
                        runner.RunError, "provenance does not bind the report",
                    ):
                runner.bench_once(
                    self.root, manifest, workload, 0, 1, self.out_dir,
                    f"non-sail-{name}",
                )

    def test_riscv_bench_rejects_malformed_artifact_provenance(self):
        self._set_riscv_phase(promoted=True)
        manifest = self._riscv_manifest()
        workload = manifest.workloads("wide", board="riscv")[0]
        _commands, fake_run = self._riscv_run(
            "release_gated",
            False,
            mutate_artifact=lambda artifact: artifact["provenance"].pop(
                "witness_layout_sha256"
            ),
        )
        with mock.patch.object(runner, "_run", side_effect=fake_run), \
                self.assertRaisesRegex(
                    runner.RunError, "provenance is not canonical",
                ):
            runner.bench_once(
                self.root, manifest, workload, 0, 1, self.out_dir,
                "malformed-provenance",
            )

    def test_riscv_proof_digest_ignores_commit_bearing_artifact_fields(self):
        self._set_riscv_phase(promoted=True)
        manifest = self._riscv_manifest()
        workload = manifest.workloads("wide", board="riscv")[0]
        _commands, first = self._riscv_run("release_gated", False)
        with mock.patch.object(runner, "_run", side_effect=first):
            a = runner.bench_once(
                self.root, manifest, workload, 0, 1, self.out_dir, "a1",
            )
        _commands, second = self._riscv_run(
            "release_gated", False, implementation_commit="c" * 40,
        )
        with mock.patch.object(runner, "_run", side_effect=second):
            b = runner.bench_once(
                self.root, manifest, workload, 0, 1, self.out_dir, "b1",
            )
        self.assertEqual(a.proof_digest, b.proof_digest)
        self.assertNotEqual(
            hashlib.sha256((self.out_dir / "riscv_alu.a1.proof.json").read_bytes()).hexdigest(),
            hashlib.sha256((self.out_dir / "riscv_alu.b1.proof.json").read_bytes()).hexdigest(),
        )

    def test_riscv_bench_rejects_mixed_release_state(self):
        self._set_riscv_phase(promoted=False)
        artifact = self.root / "src/interop/riscv_artifact.zig"
        artifact.write_text('pub const RELEASE_STATUS = "release_gated";\n')
        manifest = self._riscv_manifest()
        workload = manifest.workloads("wide", board="riscv")[0]
        with self.assertRaisesRegex(runner.RunError, "release states disagree"):
            runner.bench_once(
                self.root, manifest, workload, 0, 1, self.out_dir, "a1",
            )

    def test_riscv_bench_rejects_forged_artifact_digest(self):
        self._set_riscv_phase(promoted=True)
        manifest = self._riscv_manifest()
        workload = manifest.workloads("wide", board="riscv")[0]
        _commands, fake_run = self._riscv_run(
            "release_gated", False,
            mutate_report=lambda report: report.update(artifact_sha256="0" * 64),
        )
        with mock.patch.object(runner, "_run", side_effect=fake_run), \
                self.assertRaisesRegex(runner.RunError, "artifact_sha256"):
            runner.bench_once(
                self.root, manifest, workload, 0, 1, self.out_dir, "a1",
            )

    def test_riscv_bench_rejects_noncanonical_proof_hex(self):
        self._set_riscv_phase(promoted=True)
        manifest = self._riscv_manifest()
        workload = manifest.workloads("wide", board="riscv")[0]
        _commands, fake_run = self._riscv_run("release_gated", False, "ABCD")
        with mock.patch.object(runner, "_run", side_effect=fake_run), \
                self.assertRaisesRegex(runner.RunError, "canonical lowercase"):
            runner.bench_once(
                self.root, manifest, workload, 0, 1, self.out_dir, "a1",
            )

    def test_riscv_bench_rejects_missing_required_mechanism_field(self):
        self._set_riscv_phase(promoted=True)
        manifest = self._riscv_manifest()
        workload = manifest.workloads("wide", board="riscv")[0]
        _commands, fake_run = self._riscv_run(
            "release_gated", False,
            mutate_report=lambda report: report.pop("statement_sha256"),
        )
        with mock.patch.object(runner, "_run", side_effect=fake_run), \
                self.assertRaisesRegex(runner.RunError, "statement_sha256"):
            runner.bench_once(
                self.root, manifest, workload, 0, 1, self.out_dir, "a1",
            )

    def test_riscv_workload_requires_explicit_admission_token(self):
        self._set_riscv_phase(promoted=True)
        raw = make_raw(riscv_enabled=True)
        riscv = raw["workload_registry"]["groups"]["riscv"]
        riscv["binary"] = "bin/fakebench"
        riscv["workloads"]["riscv_alu"]["args"] = "--elf alu.elf"
        manifest_mod._validate(raw)
        manifest = Manifest(self.root, raw)
        workload = manifest.workloads("wide", board="riscv")[0]
        with self.assertRaisesRegex(runner.RunError, "lacks.*admission"):
            runner.bench_once(
                self.root, manifest, workload, 0, 1, self.out_dir, "a1",
            )

    def test_seeded_riscv_holdout_is_deterministic_and_changes_elf(self):
        raw = make_raw(riscv_enabled=True)
        riscv = raw["workload_registry"]["groups"]["riscv"]
        riscv["workloads"].update({
            "riscv_sort": {
                "class": "wide",
                "args": "--elf vectors/riscv_elfs/bubble_sort.elf {admission} "
                        "--warmups {warmups} --samples {samples}",
                "native_unit": "executed instructions",
            },
            "riscv_collatz": {
                "class": "wide",
                "args": "--elf vectors/riscv_elfs/collatz.elf {admission} "
                        "--warmups {warmups} --samples {samples}",
                "native_unit": "executed instructions",
            },
        })
        riscv["holdout_generator"] = {
            "strategy": "seeded_workload_pool_v1",
            "pools": {"wide": ["riscv_sort", "riscv_collatz"]},
        }
        manifest_mod._validate(raw)
        manifest = Manifest(self.root, raw)
        first = runner.draw_holdout(manifest, "wide", 12345, board="riscv")
        second = runner.draw_holdout(manifest, "wide", 12345, board="riscv")
        self.assertIsNotNone(first)
        self.assertEqual(first, second)
        primary = manifest.workloads("wide", board="riscv")[0]
        self.assertNotEqual(first.args, primary.args)
        self.assertRegex(first.args, r"riscv_elfs/(bubble_sort|collatz)\.elf")

    def test_large_generated_holdouts_retain_explicit_resource_profile(self):
        manifest = manifest_mod.load(REPO_ROOT)
        for workload_class in ("xlarge", "huge"):
            with self.subTest(workload_class=workload_class):
                holdout = runner.draw_holdout(
                    manifest, workload_class, 12345, board="core_cpu",
                )
                self.assertIsNotNone(holdout)
                self.assertIn("--resource-profile large", holdout.args)

    def test_correctness_oracle_dispatches_by_group(self):
        native = self._manifest(riscv_enabled=False)
        native_workload = native.workloads("small", board="core_cpu")[0]
        with mock.patch.object(
            runner, "_native_rust_oracle_check", return_value={"oracle": "native"},
        ) as native_check, mock.patch.object(
            runner, "_riscv_sail_oracle_check", return_value={"oracle": "riscv"},
        ) as riscv_check:
            self.assertEqual(
                "native",
                runner.rust_oracle_check(
                    self.root, native, native_workload, self.out_dir,
                )["oracle"],
            )
            native_check.assert_called_once()
            riscv_check.assert_not_called()

        riscv = self._riscv_manifest()
        riscv_workload = riscv.workloads("wide", board="riscv")[0]
        with mock.patch.object(
            runner, "_native_rust_oracle_check", return_value={"oracle": "native"},
        ) as native_check, mock.patch.object(
            runner, "_riscv_sail_oracle_check", return_value={"oracle": "riscv"},
        ) as riscv_check:
            self.assertEqual(
                "riscv",
                runner.rust_oracle_check(
                    self.root, riscv, riscv_workload, self.out_dir,
                )["oracle"],
            )
            riscv_check.assert_called_once()
            native_check.assert_not_called()

        cuda = self._cuda_manifest()
        cuda_workload = cuda.workloads("wide", board="core_cuda")[0]
        with mock.patch.object(
            runner, "_cuda_rust_oracle_check", return_value={"oracle": "cuda"},
        ) as cuda_check:
            self.assertEqual(
                "cuda",
                runner.rust_oracle_check(
                    self.root, cuda, cuda_workload, self.out_dir,
                )["oracle"],
            )
            cuda_check.assert_called_once()

    def test_cuda_oracle_emits_artifact_bound_rust_receipt(self):
        binary = self.root / "bin" / "cudabench"
        binary.write_text(textwrap.dedent(FAKE_PRODUCT).lstrip())
        binary.chmod(0o755)
        oracle = (
            self.root
            / "tools/stwo-interop-rs/target/release/stwo-interop-rs"
        )
        oracle.parent.mkdir(parents=True)
        oracle.write_text("#!/bin/sh\nexit 0\n")
        oracle.chmod(0o755)
        manifest = self._cuda_manifest()
        group = manifest.group("native_cuda")
        workload = manifest.workloads("wide", board="core_cuda")[0]

        receipt = runner._cuda_rust_oracle_check(
            self.root,
            group,
            workload,
            self.out_dir,
        )

        self.assertTrue(receipt["verified"])
        self.assertEqual("pinned-rust-stwo", receipt["oracle"])
        self.assertEqual(
            hashlib.sha256(oracle.read_bytes()).hexdigest(),
            receipt["oracle_binary_sha256"],
        )
        self.assertRegex(receipt["canonical_proof_sha256"], r"^[0-9a-f]{64}$")

    def test_riscv_oracle_validates_sail_evidence_and_retained_artifact(self):
        self._set_riscv_phase(promoted=True)
        script = self.root / "scripts/riscv_sail_gate.py"
        script.parent.mkdir(parents=True)
        script.write_text("# fixture\n")
        elf = self.root / "vectors/riscv_elfs/alu_test.elf"
        elf.parent.mkdir(parents=True)
        elf.write_bytes(b"ELF fixture")
        manifest = self._riscv_manifest()
        group = manifest.group("riscv")
        object.__setattr__(group, "correctness_oracle", {
            "authority": "sail-riscv",
            "repository": "https://github.com/riscv/sail-riscv",
            "commit": "8c7f2da58de0ba5e4457e4de07e0046f0439f35f",
            "final_validator": True,
        })
        workload = manifest.workloads("wide", board="riscv")[0]
        _bench_commands, bench_run = self._riscv_run("release_gated", False)
        with mock.patch.object(runner, "_run", side_effect=bench_run):
            runner.bench_once(
                self.root, manifest, workload, 0, 1, self.out_dir, "b1",
            )
        evidence = self.root / "sail-evidence.json"
        evidence.write_text(json.dumps({
            "schema": "stwo-riscv-formal-corpus-evidence-v1",
            "result": "equivalent",
            "semantic_authority": "Sail",
            "independent_cross_check": "Spike",
            "programs": 17,
            "retirements": 472827,
            "sail": {
                "repository_revision": "8c7f2da58de0ba5e4457e4de07e0046f0439f35f",
            },
        }))
        object.__setattr__(group, "correctness_oracle", {
            **group.correctness_oracle,
            "evidence": {
                "path": "sail-evidence.json",
                "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
            },
        })
        report = json.loads((self.out_dir / "riscv_alu.b1.json").read_text())
        artifact = json.loads(
            (self.out_dir / "riscv_alu.b1.proof.json").read_text()
        )
        commands = []

        def fake_run(command, _root, timeout):
            del timeout
            commands.append(command)
            if " verify " in f" {command} ":
                return json.dumps(self._riscv_verify_receipt(report, artifact))
            return "anchor valid"

        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(runner, "_run", side_effect=fake_run):
            result = runner._riscv_sail_oracle_check(
                self.root, group, workload, self.out_dir,
            )
        self.assertEqual(result["oracle"], "pinned-sail-corpus-evidence")
        self.assertTrue(any(
            "riscv_sail_gate.py" in command and command.endswith(" bind")
            for command in commands
        ))
        verify_commands = [
            shlex.split(command)
            for command in commands
            if " verify " in f" {command} "
        ]
        self.assertEqual(1, len(verify_commands))
        self.assertEqual(
            str(elf.resolve()),
            verify_commands[0][verify_commands[0].index("--elf") + 1],
        )
        self.assertFalse(any("build-and-compare" in command for command in commands))
        self.assertFalse(any("stwo-interop-rs" in command for command in commands))

    def test_riscv_oracle_requires_precomputed_sail_evidence(self):
        manifest = self._riscv_manifest()
        group = manifest.group("riscv")
        object.__setattr__(group, "correctness_oracle", {
            "authority": "sail-riscv",
            "repository": "https://github.com/riscv/sail-riscv",
            "commit": "8c7f2da58de0ba5e4457e4de07e0046f0439f35f",
            "final_validator": True,
        })
        workload = manifest.workloads("wide", board="riscv")[0]
        with mock.patch.dict(os.environ, {}, clear=True), \
                self.assertRaisesRegex(runner.RunError, "RISCV_SAIL_EVIDENCE"):
            runner._riscv_sail_oracle_check(
                self.root, group, workload, self.out_dir,
            )

    def test_riscv_oracle_rejects_forged_verification_receipt(self):
        report = {
            "statement_sha256": "4" * 64,
            "transcript_state_blake2s": "5" * 64,
            "implementation_commit": "b" * 40,
            "implementation_dirty": False,
            "executable_sha256": "6" * 64,
        }
        artifact = self._riscv_artifact("release_gated")
        receipt = self._riscv_verify_receipt(report, artifact)
        receipt["proof_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "proof_sha256 differs"):
            runner._validate_riscv_verify_receipt(
                json.dumps(receipt), report, artifact, artifact["proof_bytes_hex"],
            )

    def test_riscv_oracle_rejects_unpinned_group_authority(self):
        manifest = self._riscv_manifest()
        group = manifest.group("riscv")
        object.__setattr__(group, "correctness_oracle", {
            **group.correctness_oracle,
            "commit": "0" * 40,
        })
        workload = manifest.workloads("wide", board="riscv")[0]
        with self.assertRaisesRegex(runner.RunError, "not bound to the pinned"):
            runner._riscv_sail_oracle_check(
                self.root, group, workload, self.out_dir,
            )

    def test_board_selection_does_not_pool_enabled_groups(self):
        m = self._manifest(riscv_enabled=True)
        with mock.patch.object(runner, "build_arm") as build, \
                mock.patch.object(runner, "paired_rounds") as paired:
            paired.return_value = runner.WorkloadScore(
                workload=m.workloads("small", board="core_cpu")[0],
                ratios=[1.0, 1.0, 1.0],
                r=1.0,
                ci=(1.0, 1.0),
                a_median_ms=1.0,
                b_median_ms=1.0,
                rss_ratio=None,
                proof_bytes=4096,
                measurement_seconds=1.0,
            )
            result = runner.evaluate_aa(
                self.root, m, "small", self.out_dir, board="core_cpu",
            )
        self.assertEqual(result["workload"], "wf_small")
        self.assertEqual(result["board"], "core_cpu")
        self.assertEqual(paired.call_args.args[3].group_id, "native")
        self.assertEqual(build.call_args.kwargs["groups"][0].group_id, "native")

    def test_group_sampling_policy_reaches_paired_runner(self):
        raw = make_raw(riscv_enabled=False)
        native = raw["workload_registry"]["groups"]["native"]
        native["gates_policy"] = {
            "warmups": 1,
            "samples_per_round": 2,
            "min_rounds": 4,
            "max_rounds": 5,
            "wall_clock_cap_seconds": {"small": 17},
        }
        manifest_mod._validate(raw)
        manifest = Manifest(self.root, raw)
        score = runner.WorkloadScore(
            workload=manifest.workloads("small", board="core_cpu")[0],
            ratios=[1.0] * 4,
            r=1.0,
            ci=(1.0, 1.0),
            a_median_ms=1.0,
            b_median_ms=1.0,
            rss_ratio=None,
            proof_bytes=4096,
            measurement_seconds=1.0,
        )
        with mock.patch.object(runner, "build_arm"), \
                mock.patch.object(runner, "paired_rounds", return_value=score) as paired:
            runner.evaluate_aa(
                self.root, manifest, "small", self.out_dir, board="core_cpu",
            )
        policy = paired.call_args.args[4]
        self.assertEqual(
            (policy["warmups"], policy["samples_per_round"],
             policy["min_rounds"], policy["max_rounds"]),
            (1, 2, 4, 5),
        )
        self.assertEqual(policy["wall_clock_cap_seconds"]["small"], 17)

    def test_pair_arms_receive_smaller_of_command_and_remaining_class_budget(self):
        manifest = self._manifest(riscv_enabled=False)
        workload = manifest.workloads("small", board="core_cpu")[0]
        report_path = self.root / "report.json"
        report_path.write_text("{}")
        arm = runner.ArmResult(
            1.0, 1, True, None, str(report_path), proof_digest="7" * 64,
            proof_bytes=4096,
        )
        policy = {
            **GATES_POLICY,
            "min_rounds": 3,
            "max_rounds": 3,
            "command_timeout_seconds": 4,
            "wall_clock_cap_seconds": {"small": 10},
        }
        with mock.patch.object(
            runner.time, "monotonic", side_effect=[float(value) for value in range(10)],
        ), mock.patch.object(runner, "bench_once", return_value=arm) as bench:
            runner.paired_rounds(
                self.root, self.root, manifest, workload, policy, self.out_dir,
            )
        self.assertEqual(
            [call.kwargs["timeout_seconds"] for call in bench.call_args_list],
            [4, 4, 4, 4, 3, 2],
        )

    def test_pair_fails_before_launch_when_class_wall_budget_is_exhausted(self):
        manifest = self._manifest(riscv_enabled=False)
        workload = manifest.workloads("small", board="core_cpu")[0]
        policy = {
            **GATES_POLICY,
            "command_timeout_seconds": 100,
            "wall_clock_cap_seconds": {"small": 10},
        }
        with mock.patch.object(
            runner.time, "monotonic", side_effect=[0.0, 11.0],
        ), mock.patch.object(runner, "bench_once") as bench, \
                self.assertRaisesRegex(runner.RunError, "wall-clock budget exhausted"):
            runner.paired_rounds(
                self.root, self.root, manifest, workload, policy, self.out_dir,
            )
        bench.assert_not_called()

    def test_out_of_scope_stray_fails_g2(self):
        m = self._manifest(riscv_enabled=False)
        with mock.patch.object(
            runner, "changed_paths", return_value=["docs/out-of-scope.md"],
        ):
            gates = runner._gates(
                self.root, m, [], GATES_POLICY, False, None, "small", "core_cpu",
            )
        self.assertFalse(gates["G2"]["pass"])
        self.assertIn("outside editable set", gates["G2"]["detail"])

    def test_judged_g5_requires_exact_class_anchor_and_dispersion(self):
        raw = make_raw(riscv_enabled=False)
        raw["harness"] = {
            "anchor_commit": "a" * 40,
            "anchor_prove_ms": {"core_cpu": {"small": None}},
        }
        manifest = Manifest(self.root, raw)
        with mock.patch.object(runner, "changed_paths", return_value=[]):
            missing_anchor = runner._gates(
                self.root, manifest, [], GATES_POLICY, True, 0.01,
                "small", "core_cpu",
            )
        self.assertFalse(missing_anchor["G5"]["pass"])

        raw["harness"]["anchor_prove_ms"]["core_cpu"]["small"] = 1.0
        manifest = Manifest(self.root, raw)
        with mock.patch.object(runner, "changed_paths", return_value=[]):
            missing_dispersion = runner._gates(
                self.root, manifest, [], GATES_POLICY, True, None,
                "small", "core_cpu",
            )
            complete = runner._gates(
                self.root, manifest, [], GATES_POLICY, True, 0.01,
                "small", "core_cpu",
            )
        self.assertFalse(missing_dispersion["G5"]["pass"])
        self.assertTrue(complete["G5"]["pass"])

    def test_riscv_score_without_verified_mechanism_fails_g3(self):
        manifest = self._riscv_manifest()
        score = runner.WorkloadScore(
            workload=manifest.workloads("wide", board="riscv")[0],
            ratios=[1.0],
            r=1.0,
            ci=(1.0, 1.0),
            a_median_ms=1.0,
            b_median_ms=1.0,
            rss_ratio=None,
            mechanism_verified=False,
            proof_bytes=4096,
            measurement_seconds=1.0,
        )
        with mock.patch.object(runner, "changed_paths", return_value=[]):
            gates = runner._gates(
                self.root, manifest, [score], GATES_POLICY, False, None,
                "wide", "riscv",
            )
        self.assertFalse(gates["G3"]["pass"])
        self.assertIn("0/1 workloads", gates["G3"]["detail"])

    def test_faster_candidate_over_resource_budget_fails_g4_by_dimension(self):
        manifest = self._manifest(riscv_enabled=False)
        workload = manifest.workloads("small", board="core_cpu")[0]
        for failed_dimension in runner.dimensions.RESOURCE_DIMENSIONS:
            estimates = {
                dimension: runner.dimensions.RatioEstimate(
                    1.0,
                    (1.0, 1.0) if dimension == "proof_bytes" else (0.99, 1.01),
                    7,
                )
                for dimension in runner.dimensions.RESOURCE_DIMENSIONS
            }
            estimates[failed_dimension] = runner.dimensions.RatioEstimate(
                1.08, (1.06, 1.10), 7,
            )
            score = runner.WorkloadScore(
                workload=workload,
                ratios=[0.8] * 7,
                r=0.8,
                ci=(0.79, 0.81),
                a_median_ms=10.0,
                b_median_ms=8.0,
                rss_ratio=estimates["peak_rss_mib"].ratio,
                resource_estimates=estimates,
            )
            policy = {
                **GATES_POLICY,
                "resource_budgets": {
                    "peak_rss_mib": 1.05,
                    "energy_j": 1.05,
                    "proof_bytes": 1.0,
                },
            }
            with self.subTest(dimension=failed_dimension), mock.patch.object(
                runner, "changed_paths", return_value=[],
            ):
                gates = runner._gates(
                    self.root, manifest, [score], policy, False, None,
                    "small", "core_cpu",
                )
                self.assertFalse(gates["G4"]["pass"])
                self.assertIn(failed_dimension, gates["G4"]["detail"])
                self.assertIn("budget_exceeded", gates["G4"]["detail"])

    def test_judged_riscv_score_without_resources_fails_g5(self):
        raw = make_raw(riscv_enabled=True)
        raw["workload_registry"]["groups"]["riscv"]["binary"] = "bin/fakebench"
        raw["harness"]["anchor_commit"] = "a" * 40
        raw["harness"]["anchor_prove_ms"] = {"riscv": {"wide": 1.0}}
        manifest_mod._validate(raw)
        manifest = Manifest(self.root, raw)
        score = runner.WorkloadScore(
            workload=manifest.workloads("wide", board="riscv")[0],
            ratios=[1.0],
            r=1.0,
            ci=(1.0, 1.0),
            a_median_ms=1.0,
            b_median_ms=1.0,
            rss_ratio=None,
            mechanism_verified=True,
            proof_bytes=4096,
            measurement_seconds=1.0,
            resources_complete=False,
        )
        with mock.patch.object(runner, "changed_paths", return_value=[]):
            gates = runner._gates(
                self.root, manifest, [score], GATES_POLICY, True, 0.01,
                "wide", "riscv",
            )
        self.assertFalse(gates["G5"]["pass"])
        self.assertIn("complete resource vectors", gates["G5"]["detail"])

    def test_paired_round_rejects_riscv_semantic_telemetry_drift(self):
        manifest = self._riscv_manifest()
        workload = manifest.workloads("wide", board="riscv")[0]
        stable = {
            "total_steps": 32,
            "n_components": 2,
            "statement_sha256": "4" * 64,
            "transcript_state_blake2s": "5" * 64,
        }
        a = runner.ArmResult(
            1.0, 1, True, None, "a.json", proof_digest="7" * 64,
            proof_bytes=4096,
            mechanism=stable,
        )
        b = runner.ArmResult(
            1.0, 1, True, None, "b.json", proof_digest="7" * 64,
            proof_bytes=4096,
            mechanism={**stable, "statement_sha256": "8" * 64},
        )
        with mock.patch.object(runner, "bench_once", side_effect=[a, b]), \
                self.assertRaisesRegex(runner.RunError, "semantic mechanism telemetry"):
            runner.paired_rounds(
                self.root, self.root, manifest, workload, GATES_POLICY, self.out_dir,
            )

    def test_paired_round_rejects_non_identical_proof_bytes(self):
        m = self._manifest(riscv_enabled=False)
        workload = m.workloads("small", board="core_cpu")[0]
        non_identical = runner.ArmResult(1.0, 1, False, None, "a.json")
        identical = runner.ArmResult(1.0, 1, True, None, "b.json")
        with mock.patch.object(
            runner, "bench_once", side_effect=[non_identical, identical],
        ), self.assertRaises(runner.RunError) as ctx:
            runner.paired_rounds(
                self.root, self.root, m, workload, GATES_POLICY, self.out_dir,
            )
        self.assertIn("proof bytes changed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
