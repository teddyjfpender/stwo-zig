from __future__ import annotations

import argparse
import contextlib
import json
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.tests.native_proof_matrix_support import (
    MODULE,
    PROOF_WIRE_BYTES,
    PROOF_WIRE_SHA256,
    args,
    backend_counters,
    lane_args,
    make_report,
    pipeline_cache,
    resource_usage_stderr,
    set_prove_times,
    summary,
    write_proof_artifact,
)
from native_proof_matrix_lib.contract import pipeline_preparation_occurred


class NativeProofMatrixTests(unittest.TestCase):
    def test_real_wide_fibonacci_oracle_identity_is_pinned(self) -> None:
        from native_proof_matrix_lib import RUST_ORACLE_SHA256

        self.assertEqual(
            RUST_ORACLE_SHA256,
            "a2304005ff1bb45151dfbb6491bc5eb53468fe9cdd6c6aefc7168b75ab0684ca",
        )

    def test_library_miss_is_cold_but_hit_timing_alone_is_warm(self) -> None:
        cache = pipeline_cache()
        cache["library_cache_misses"] = 1
        self.assertTrue(pipeline_preparation_occurred(cache))

        cache = pipeline_cache()
        cache["library_cache_hits"] = 1
        cache["pipeline_preparation_seconds"] = 0.125
        cache["library_preparation_seconds"] = 0.25
        self.assertFalse(pipeline_preparation_occurred(cache))

    def test_atomic_output_and_lock_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "nested" / "result.json"
            destination.parent.mkdir()
            destination.write_bytes(b"old")
            MODULE.atomic_write_bytes(destination, b"complete-new-document")
            self.assertEqual(destination.read_bytes(), b"complete-new-document")
            self.assertEqual(
                [path for path in destination.parent.iterdir() if path != destination],
                [],
            )

            output_dir = root / "matrix"
            with MODULE.output_dir_lock(output_dir):
                with self.assertRaisesRegex(MODULE.MatrixError, "locked"):
                    with MODULE.output_dir_lock(output_dir):
                        self.fail("second lock unexpectedly succeeded")

    def test_tagged_workloads_have_exact_geometry_and_fixed_descriptors(self) -> None:
        vectors = (
            (
                MODULE.parse_workload("wide_fibonacci:sequence_len=8,log_n_rows=10"),
                8,
                8192,
                "8586bce9ae8c0673453803b3b65ca8d4fc677638d53e5933e7692af4dd38586f",
            ),
            (
                MODULE.parse_workload("xor:offset=3,log_step=2,log_size=10"),
                15,
                15360,
                "7cc6f69d95db54edac2908b65701c3c3674215f0c83c29db474680bf5a1405db",
            ),
            (
                MODULE.parse_workload("plonk:log_n_rows=10"),
                8,
                8192,
                "8e22d72f97cfe01bdb3fdf94e362160418ca16022db7cdaccacf073e2ef67cee",
            ),
            (
                MODULE.parse_workload(
                    "state_machine:initial_y=3,log_n_rows=10,initial_x=9"
                ),
                12,
                9216,
                "90501fb81745fd984bd8186e5750f9b7ff6bf2017b0df4df869f313299b771e9",
            ),
            (
                MODULE.parse_workload("blake:n_rounds=2,log_n_rows=8"),
                192,
                49152,
                "bee0efa41b40d2f61fbecccb2096af92ff2bcf6fbbc253a852077d4c95a1830e",
            ),
            (
                MODULE.parse_workload("poseidon:log_n_instances=13"),
                1296,
                1_327_104,
                "bb508f796006fc2b8482e04b0fc941be001c86d05be029600bc3ca8af123c7e3",
            ),
        )
        for workload, columns, cells, descriptor in vectors:
            with self.subTest(workload=workload.name):
                self.assertEqual(
                    workload.trace_rows,
                    256 if workload.name == "blake" else 1024,
                )
                self.assertEqual(workload.committed_columns, columns)
                self.assertEqual(workload.committed_trace_cells, cells)
                if workload.name == "blake":
                    self.assertEqual(workload.native_unit, "blake_round_instances")
                    self.assertEqual(workload.native_units, 512)
                elif workload.name == "poseidon":
                    self.assertEqual(workload.native_unit, "poseidon_instances")
                    self.assertEqual(workload.native_units, 8192)
                    self.assertEqual(workload.report_dict()["committed_trees"], 3)
                self.assertEqual(
                    MODULE.workload_descriptor_sha256(workload, "functional"),
                    descriptor,
                )
        self.assertEqual(
            MODULE.parse_workload("10:8"), MODULE.Workload.wide_fibonacci(10, 8)
        )

    def test_holistic_suite_has_stable_rows_and_fits_the_global_cell_budget(self) -> None:
        suite = MODULE.HOLISTIC_SUITE
        self.assertIs(MODULE.WORKLOAD_SUITES["holistic"], suite)
        self.assertEqual(
            [row.id for row in suite.rows],
            [
                "wf_log10x8",
                "wf_log14x32",
                "wf_log16x64",
                "xor_log14",
                "xor_log16",
                "plonk_log14",
                "plonk_log16",
                "sm_v2_log14",
                "sm_v2_log16",
                "blake_log10x10",
                "blake_log12x16",
                "poseidon_log10",
                "poseidon_log13",
            ],
        )
        self.assertEqual(len(suite.rows), MODULE.MAX_MATRIX_ROWS)
        self.assertEqual(suite.committed_trace_cells_per_lane, 16_115_712)
        maximum_request_cells = suite.request_cells(
            MODULE.MAX_WARMUPS, MODULE.MAX_SAMPLES
        )
        self.assertEqual(maximum_request_cells, 1_643_802_624)
        self.assertLessEqual(maximum_request_cells, MODULE.MAX_TOTAL_REQUEST_CELLS)
        MODULE.validate_suite(suite)

    def test_holistic_suite_parser_is_opt_in_and_exclusive(self) -> None:
        parsed = MODULE.parse_args(
            [
                "--suite",
                "holistic",
                "--allow-non-headline",
                "--warmups",
                "0",
                "--samples",
                "1",
                "--cooldown-seconds",
                "0",
            ]
        )
        self.assertEqual(parsed.suite, "holistic")
        self.assertEqual(tuple(parsed.workloads), MODULE.HOLISTIC_SUITE.workloads)

        conflicts = (
            ["--workload", "plonk:log_n_rows=10"],
            ["--log-rows", "10", "--sequence-lens", "8"],
        )
        for selector in conflicts:
            with self.subTest(selector=selector), contextlib.redirect_stderr(
                io.StringIO()
            ), self.assertRaises(SystemExit):
                MODULE.parse_args(
                    ["--suite", "holistic", "--allow-non-headline", *selector]
                )

    def test_workload_parser_rejects_noncanonical_or_unbounded_rows(self) -> None:
        invalid = (
            "unknown:x=1",
            "xor:log_size=10,log_step=2",
            "xor:log_size=10,log_step=11,offset=3",
            "xor:log_size=10,log_step=2,offset=-1",
            "xor:log_size=10,log_step=2,offset=4",
            "wide_fibonacci:log_n_rows=10,log_n_rows=11,sequence_len=8",
            "wide_fibonacci:log_n_rows=22,sequence_len=512",
            "plonk:log_n_rows=0",
            "plonk:log_n_rows=23",
            "plonk:log_size=10",
            "state_machine:log_n_rows=0,initial_x=9,initial_y=3",
            "state_machine:log_n_rows=10,initial_x=-1,initial_y=3",
            "state_machine:log_n_rows=10,initial_x=2147483647,initial_y=3",
            "state_machine:log_n_rows=10,initial_x=9",
            "blake:log_n_rows=8",
            "blake:log_n_rows=8,n_rounds=0",
            "blake:log_n_rows=8,n_rounds=33",
            "poseidon:log_n_instances=3",
            "poseidon:log_n_instances=13,log_n_rows=10",
        )
        for encoded in invalid:
            with self.subTest(encoded=encoded):
                with self.assertRaises(argparse.ArgumentTypeError):
                    MODULE.parse_workload(encoded)

    def test_resource_profiles_are_bound_to_the_zig_source_authority(self) -> None:
        MODULE.validate_source_contract()
        source = MODULE.ZIG_RESOURCE_AUTHORITY.read_text(encoding="utf-8")
        self.assertIn("STANDARD_MAX_COMMITTED_CELLS", source)
        self.assertEqual(
            MODULE.MAX_COMMITTED_TRACE_CELLS,
            MODULE.ZIG_RESOURCE_CONSTANTS["STANDARD_MAX_COMMITTED_CELLS"],
        )
        self.assertEqual(
            MODULE.RESOURCE_PROFILES["large"].max_committed_cells,
            MODULE.ZIG_RESOURCE_CONSTANTS["LARGE_MAX_COMMITTED_CELLS"],
        )

        workload = MODULE.parse_workload(
            "wide_fibonacci:log_n_rows=20,sequence_len=100"
        )
        with self.assertRaisesRegex(ValueError, "standard profile"):
            MODULE.validate_workload(workload)
        MODULE.validate_workload(workload, resource_profile="large")
        too_large = MODULE.Workload.wide_fibonacci(22, 100)
        with self.assertRaisesRegex(ValueError, "large profile"):
            MODULE.validate_workload(too_large, resource_profile="large")

    def test_large_profile_is_explicit_in_commands_and_report_evidence(self) -> None:
        from native_proof_matrix_lib.artifacts import lane_command

        workload = MODULE.Workload.wide_fibonacci(20, 100)
        command = lane_command(
            Path("cpu"),
            workload,
            0,
            1,
            "functional",
            Path("/tmp/proof.json"),
            resource_profile="large",
        )
        self.assertEqual(
            command[command.index("--resource-profile") + 1],
            "large",
        )
        report = make_report(
            "cpu",
            workload,
            samples=1,
            warmups=0,
            resource_profile="large",
        )
        MODULE.validate_report(
            report,
            "cpu",
            workload,
            args(samples=1, warmups=0, resource_profile="large"),
        )
        report["resource_admission"]["max_accounted_bytes"] -= 1
        with self.assertRaisesRegex(MODULE.MatrixError, "reviewed profile"):
            MODULE.validate_report(
                report,
                "cpu",
                workload,
                args(samples=1, warmups=0, resource_profile="large"),
            )

    def test_controller_bounds_and_formal_oracle_are_checked_during_parse(self) -> None:
        diagnostic = MODULE.parse_args(["--allow-non-headline"])
        self.assertFalse(diagnostic.formal)
        self.assertEqual(
            [row.name for row in diagnostic.workloads],
            ["wide_fibonacci", "xor", "plonk", "state_machine", "blake", "poseidon"],
        )
        self.assertEqual(diagnostic.warmups, MODULE.MIN_HEADLINE_WARMUPS)
        self.assertEqual(diagnostic.blake2_backend, "auto")
        self.assertEqual(diagnostic.metal_runtime, "source-jit")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            MODULE.parse_args([])
        formal = MODULE.parse_args(["--rust-oracle-bin", "/tmp/oracle"])
        self.assertTrue(formal.formal)
        aot = MODULE.parse_args([
            "--allow-non-headline",
            "--metal-runtime",
            "authenticated-aot",
            "--metal-aot-bundle",
            "/tmp/native-core",
            "--metal-aot-manifest-sha256",
            "ab" * 32,
        ])
        self.assertEqual(aot.metal_aot_manifest_sha256, "ab" * 32)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            MODULE.parse_args([
                "--allow-non-headline",
                "--metal-runtime",
                "authenticated-aot",
                "--metal-aot-bundle",
                "/tmp/native-core",
            ])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            MODULE.parse_args(
                [
                    "--allow-non-headline",
                    "--workload",
                    "wide_fibonacci:log_n_rows=16,sequence_len=512",
                    "--warmups",
                    str(MODULE.MAX_WARMUPS),
                    "--samples",
                    str(MODULE.MAX_SAMPLES),
                ]
            )
        large_row = "wide_fibonacci:log_n_rows=20,sequence_len=100"
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            MODULE.parse_args([
                "--allow-non-headline",
                "--workload",
                large_row,
                "--warmups",
                "0",
                "--samples",
                "1",
            ])
        admitted = MODULE.parse_args([
            "--allow-non-headline",
            "--resource-profile",
            "large",
            "--workload",
            large_row,
            "--warmups",
            "0",
            "--samples",
            "1",
        ])
        self.assertEqual(admitted.resource_profile, "large")

    def test_lane_commands_use_only_canonical_tagged_flags(self) -> None:
        from native_proof_matrix_lib.artifacts import lane_command

        artifact = Path("/tmp/proof.json")
        self.assertEqual(
            lane_command(Path("cpu"), MODULE.Workload.wide_fibonacci(10, 8), 1, 2, "functional", artifact),
            ["cpu", "--example", "wide_fibonacci", "--log-n-rows", "10", "--sequence-len", "8", "--warmups", "1", "--samples", "2", "--protocol", "functional", "--resource-profile", "standard", "--proof-artifact-out", "/tmp/proof.json"],
        )
        self.assertIn("--log-step", lane_command(Path("metal"), MODULE.Workload.xor(10, 2, 3), 1, 2, "functional", artifact))
        self.assertEqual(
            lane_command(Path("cpu"), MODULE.Workload.plonk(10), 10, 2, "functional", artifact),
            ["cpu", "--example", "plonk", "--log-n-rows", "10", "--warmups", "10", "--samples", "2", "--protocol", "functional", "--resource-profile", "standard", "--proof-artifact-out", "/tmp/proof.json"],
        )
        self.assertEqual(
            lane_command(
                Path("metal"),
                MODULE.Workload.state_machine(10, 9, 3),
                10,
                2,
                "functional",
                artifact,
            ),
            ["metal", "--example", "state_machine", "--log-n-rows", "10", "--initial-x", "9", "--initial-y", "3", "--warmups", "10", "--samples", "2", "--protocol", "functional", "--resource-profile", "standard", "--proof-artifact-out", "/tmp/proof.json"],
        )
        self.assertEqual(
            lane_command(
                Path("cpu"),
                MODULE.Workload.blake(8, 2),
                10,
                2,
                "functional",
                artifact,
            ),
            ["cpu", "--example", "blake", "--log-n-rows", "8", "--n-rounds", "2", "--warmups", "10", "--samples", "2", "--protocol", "functional", "--resource-profile", "standard", "--proof-artifact-out", "/tmp/proof.json"],
        )
        self.assertEqual(
            lane_command(
                Path("metal"),
                MODULE.Workload.poseidon(13),
                10,
                2,
                "functional",
                artifact,
            ),
            ["metal", "--example", "poseidon", "--log-n-instances", "13", "--warmups", "10", "--samples", "2", "--protocol", "functional", "--resource-profile", "standard", "--proof-artifact-out", "/tmp/proof.json"],
        )

    def test_reports_and_artifacts_validate_for_both_examples_and_lanes(self) -> None:
        workloads = (
            MODULE.Workload.wide_fibonacci(10, 8),
            MODULE.Workload.xor(10, 2, 3),
            MODULE.Workload.plonk(10),
            MODULE.Workload.state_machine(10, 9, 3),
            MODULE.Workload.blake(8, 2),
            MODULE.Workload.poseidon(13),
        )
        with tempfile.TemporaryDirectory() as directory:
            for workload in workloads:
                for lane in ("cpu", "metal"):
                    with self.subTest(workload=workload.name, lane=lane):
                        path = Path(directory) / f"{workload.name}-{lane}.json"
                        write_proof_artifact(path, workload)
                        artifact = MODULE.load_proof_artifact(path, lane)
                        report = make_report(lane, workload, artifact_path=path)
                        fingerprint, blockers = MODULE.validate_report(report, lane, workload, args())
                        self.assertEqual(fingerprint, (PROOF_WIRE_SHA256, len(PROOF_WIRE_BYTES)))
                        self.assertEqual(blockers, [])
                        MODULE.validate_proof_artifact(report, lane, workload, args(), artifact, fingerprint)

    def test_report_schema_and_derived_metrics_fail_closed(self) -> None:
        workload = MODULE.Workload.wide_fibonacci(10, 8)
        for mutation in ("missing", "extra"):
            report = make_report("cpu", workload)
            if mutation == "missing":
                del report["timing"]["request_seconds"]
            else:
                report["timing"]["surprise"] = 1
            with self.subTest(mutation=mutation), self.assertRaises(MODULE.MatrixError):
                MODULE.validate_report(report, "cpu", workload, args())
        for field in (
            "native_mhz",
            "request_native_mhz",
            "trace_row_mhz",
            "request_trace_row_mhz",
            "committed_mcells_per_second",
        ):
            report = make_report("cpu", workload)
            report["timing"]["samples"][0][field] *= 2
            with self.subTest(field=field), self.assertRaises(MODULE.MatrixError):
                MODULE.validate_report(report, "cpu", workload, args())
        report = make_report("cpu", workload)
        report["throughput"]["headline_native_mhz"]["median"] *= 2
        with self.assertRaises(MODULE.MatrixError):
            MODULE.validate_report(report, "cpu", workload, args())
        report = make_report("cpu", workload)
        report["timing"]["samples"][0]["request_seconds"] = 2.01
        report["timing"]["request_seconds"] = summary(2.402)
        with self.assertRaisesRegex(MODULE.MatrixError, "shorter than its phases"):
            MODULE.validate_report(report, "cpu", workload, args())

    def test_sampling_evidence_and_headline_requirements_are_recomputed(self) -> None:
        workload = MODULE.Workload.wide_fibonacci(10, 8)
        for samples, warmups in ((2, 10), (5, 1)):
            report = make_report("cpu", workload, samples=samples, warmups=warmups)
            report["evidence_class"] = "verified_unprofiled"
            requirements = report["throughput"]["headline_requirements"]
            requirements["verified_unprofiled"] = True
            requirements["sampling_contract"] = True
            report["throughput"]["headline_eligible"] = True
            for field in (
                "headline_native_mhz",
                "headline_request_native_mhz",
                "headline_trace_row_mhz",
                "headline_request_trace_row_mhz",
                "headline_committed_mcells_per_second",
            ):
                report["throughput"][field] = summary(
                    report["timing"]["samples"][0][
                        {
                            "headline_native_mhz": "native_mhz",
                            "headline_request_native_mhz": "request_native_mhz",
                            "headline_trace_row_mhz": "trace_row_mhz",
                            "headline_request_trace_row_mhz": "request_trace_row_mhz",
                            "headline_committed_mcells_per_second": "committed_mcells_per_second",
                        }[field]
                    ]
                )
            with self.subTest(samples=samples, warmups=warmups), self.assertRaisesRegex(
                MODULE.MatrixError,
                "measured sampling",
            ):
                MODULE.validate_report(
                    report,
                    "cpu",
                    workload,
                    args(samples=samples, warmups=warmups),
                )

    def test_ordered_prove_time_drift_blocks_unstable_headline_data(self) -> None:
        workload = MODULE.Workload.wide_fibonacci(10, 8)
        stable = make_report("cpu", workload)
        _, stable_blockers = MODULE.validate_report(
            stable, "cpu", workload, args()
        )
        self.assertNotIn("cpu_ordered_prove_time_drift", stable_blockers)

        drifting = make_report("cpu", workload)
        set_prove_times(drifting, workload, [2.2, 2.2, 2.0, 2.0, 2.0])
        _, drifting_blockers = MODULE.validate_report(
            drifting, "cpu", workload, args()
        )
        self.assertIn("cpu_ordered_prove_time_drift", drifting_blockers)

    def test_descriptor_session_protocol_and_telemetry_fail_closed(self) -> None:
        workload = MODULE.Workload.xor(10, 2, 3)
        mutations = (
            ("descriptor", lambda report: report["workload"].__setitem__("descriptor_sha256", "0" * 64)),
            ("geometry", lambda report: report["workload"].__setitem__("committed_columns", 4)),
            ("protocol", lambda report: report["protocol"].__setitem__("pow_bits", 9)),
            ("session", lambda report: report["session"].__setitem__("tower_build_count", 2)),
            ("telemetry", lambda report: report["backend_telemetry"].__setitem__("total_metal_dispatches", 0)),
            (
                "cache_entries",
                lambda report: report["backend_telemetry"]["post_warmup_pipeline_cache"].__setitem__("library_cache_entries", 9),
            ),
            (
                "cache_peak_bytes",
                lambda report: report["backend_telemetry"]["post_warmup_pipeline_cache"].__setitem__("pipeline_cache_peak_bytes", 16 * 1024 * 1024 + 1),
            ),
            (
                "archive_entries",
                lambda report: report["backend_telemetry"]["post_warmup_archive_store"].__setitem__("archive_disk_entries", 129),
            ),
        )
        for name, mutate in mutations:
            report = make_report("metal", workload)
            mutate(report)
            with self.subTest(name=name), self.assertRaises(MODULE.MatrixError):
                MODULE.validate_report(report, "metal", workload, args())

        report = make_report("metal", workload, cold_pipeline=True)
        _, blockers = MODULE.validate_report(report, "metal", workload, args())
        self.assertIn("metal_requirement_backend_telemetry_valid", blockers)
        self.assertFalse(report["throughput"]["headline_eligible"])
        report["backend_telemetry"]["valid"] = True
        with self.assertRaisesRegex(MODULE.MatrixError, "pipeline warmth"):
            MODULE.validate_report(report, "metal", workload, args())

        report = make_report("metal", workload, metal_fallbacks=1)
        _, blockers = MODULE.validate_report(report, "metal", workload, args())
        self.assertIn("metal_requirement_backend_telemetry_valid", blockers)
        self.assertFalse(report["throughput"]["headline_eligible"])
        report["backend_telemetry"]["valid"] = True
        with self.assertRaisesRegex(MODULE.MatrixError, "CPU fallback counters"):
            MODULE.validate_report(report, "metal", workload, args())

        report = make_report("metal", workload, cold_pipeline=True)
        report["backend_telemetry"]["samples"][0]["pipeline_cache"]["direct_compiles"] = 0
        report["backend_telemetry"]["samples"][0]["pipeline_cache"]["pipeline_preparation_seconds"] = 0.0
        report["backend_telemetry"]["samples"][0]["archive_store"]["archive_disk_hits"] = 1
        _, blockers = MODULE.validate_report(report, "metal", workload, args())
        self.assertIn("metal_requirement_backend_telemetry_valid", blockers)

        report = make_report("metal", workload)
        report["backend_telemetry"]["samples"] = report["backend_telemetry"][
            "samples"
        ][:-1]
        with self.assertRaisesRegex(MODULE.MatrixError, "cover every request"):
            MODULE.validate_report(report, "metal", workload, args())

        report = make_report("metal", workload)
        delta = report["backend_telemetry"]["warmups"][0]
        delta["counters"] = backend_counters(0, 1)
        delta["metal_dispatches"] = 0
        delta["cpu_fallbacks"] = 1
        delta["classification"] = "host_only"
        report["backend_telemetry"]["total_metal_dispatches"] -= 4
        report["backend_telemetry"]["total_cpu_fallbacks"] += 1
        with self.assertRaisesRegex(MODULE.MatrixError, "no accelerated work"):
            MODULE.validate_report(report, "metal", workload, args())

    def test_blake2s_dispatch_provenance_fails_closed(self) -> None:
        workload = MODULE.Workload.wide_fibonacci(10, 8)
        report = make_report("cpu", workload)
        MODULE.validate_report(report, "cpu", workload, args())

        inconsistent = make_report("cpu", workload)
        inconsistent["provenance"]["blake2s_simd_supported"] = False
        with self.assertRaisesRegex(MODULE.MatrixError, "requested/effective"):
            MODULE.validate_report(inconsistent, "cpu", workload, args())

        unsupported = make_report("cpu", workload)
        unsupported["provenance"]["blake2s_requested_backend"] = "gpu"
        with self.assertRaisesRegex(MODULE.MatrixError, "is unsupported"):
            MODULE.validate_report(unsupported, "cpu", workload, args())

        overridden = make_report("cpu", workload)
        overridden["provenance"]["environment_overrides"] = [
            {"name": "STWO_ZIG_METAL_CACHE_DIR", "value": "/tmp/cache"}
        ]
        with self.assertRaisesRegex(MODULE.MatrixError, "disagrees with overrides"):
            MODULE.validate_report(overridden, "cpu", workload, args())

    def test_runtime_admission_is_bound_to_controller_request(self) -> None:
        workload = MODULE.Workload.wide_fibonacci(10, 8)
        source = make_report("metal", workload)
        MODULE.validate_report(source, "metal", workload, args())

        substituted_origin = make_report("metal", workload)
        substituted_origin["runtime_admission"]["origin"] = "authenticated_core_aot"
        with self.assertRaisesRegex(MODULE.MatrixError, "controller request"):
            MODULE.validate_report(substituted_origin, "metal", workload, args())

        aot_args = args()
        aot_args.metal_runtime = "authenticated-aot"
        aot_args.metal_aot_manifest_sha256 = "ab" * 32
        aot = make_report("metal", workload)
        aot["runtime_admission"].update({
            "origin": "authenticated_core_aot",
            "manifest_sha256": "ab" * 32,
            "metallib_sha256": "cd" * 32,
            "metallib_bytes": 4096,
        })
        MODULE.validate_report(aot, "metal", workload, aot_args)
        aot["runtime_admission"]["manifest_sha256"] = "ef" * 32
        with self.assertRaisesRegex(MODULE.MatrixError, "manifest"):
            MODULE.validate_report(aot, "metal", workload, aot_args)

    def test_artifact_statement_and_cross_backend_proofs_must_match(self) -> None:
        workload = MODULE.Workload.xor(10, 2, 3)
        cpu = make_report("cpu", workload)
        metal = make_report("metal", workload)
        cpu_fingerprint, _ = MODULE.validate_report(cpu, "cpu", workload, args())
        metal_fingerprint, _ = MODULE.validate_report(metal, "metal", workload, args())
        MODULE.validate_pair(cpu, metal, cpu_fingerprint, metal_fingerprint)
        metal["proof"]["samples"][0]["sha256"] = "0" * 64
        with self.assertRaises(MODULE.MatrixError):
            MODULE.validate_report(metal, "metal", workload, args())

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            write_proof_artifact(path, workload)
            artifact = MODULE.load_proof_artifact(path, "cpu")
            report = make_report("cpu", workload, artifact_path=path)
            fingerprint, _ = MODULE.validate_report(report, "cpu", workload, args())
            artifact["document"]["xor_statement"]["offset"] += 1
            with self.assertRaises(MODULE.MatrixError):
                MODULE.validate_proof_artifact(report, "cpu", workload, args(), artifact, fingerprint)

            report["proof"]["artifact"]["sample_index"] = 1
            with self.assertRaisesRegex(MODULE.MatrixError, "binding does not match"):
                MODULE.validate_proof_artifact(
                    report, "cpu", workload, args(), artifact, fingerprint
                )
            report = make_report("cpu", workload, artifact_path=path)
            document = json.loads(path.read_text())
            document["upstream_commit"] = "0" * 40
            path.write_text(json.dumps(document) + "\n")
            mutated = MODULE.load_proof_artifact(path, "cpu")
            with self.assertRaisesRegex(MODULE.MatrixError, "upstream_commit"):
                MODULE.validate_proof_artifact(
                    report, "cpu", workload, args(), mutated, fingerprint
                )

    def test_fri_fold_commit_epochs_are_counted_as_metal_dispatches(self) -> None:
        workload = MODULE.Workload.wide_fibonacci(10, 8)
        report = make_report("metal", workload)
        for delta in (
            report["backend_telemetry"]["warmups"]
            + report["backend_telemetry"]["samples"]
        ):
            delta["counters"]["metal_circle_lde_dispatches"] = 0
            delta["counters"]["metal_fri_fold_commit_epochs"] = 4
        MODULE.validate_report(report, "metal", workload, args())

    def test_state_machine_artifact_binds_the_derived_statement(self) -> None:
        workload = MODULE.Workload.state_machine(10, 9, 3)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state-machine.json"
            write_proof_artifact(path, workload)
            report = make_report("cpu", workload, artifact_path=path)
            fingerprint, _ = MODULE.validate_report(report, "cpu", workload, args())

            artifact = MODULE.load_proof_artifact(path, "cpu")
            MODULE.validate_proof_artifact(
                report, "cpu", workload, args(), artifact, fingerprint
            )
            for mutation in (
                "initial",
                "final",
                "stmt0",
                "claim_negative",
                "claim_noncanonical",
            ):
                artifact = MODULE.load_proof_artifact(path, "cpu")
                statement = artifact["document"]["state_machine_statement"]
                if mutation == "initial":
                    statement["public_input"][0][0] += 1
                elif mutation == "final":
                    statement["public_input"][1][1] += 1
                elif mutation == "stmt0":
                    statement["stmt0"]["m"] += 1
                elif mutation == "claim_negative":
                    statement["stmt1"]["x_axis_claimed_sum"][0] = -1
                else:
                    statement["stmt1"]["x_axis_claimed_sum"][0] = (1 << 31) - 1
                with self.subTest(mutation=mutation), self.assertRaises(
                    MODULE.MatrixError
                ):
                    MODULE.validate_proof_artifact(
                        report, "cpu", workload, args(), artifact, fingerprint
                    )
            write_proof_artifact(path, workload, PROOF_WIRE_BYTES + b" ")
            mutated = MODULE.load_proof_artifact(path, "cpu")
            with self.assertRaisesRegex(MODULE.MatrixError, "bytes disagree"):
                MODULE.validate_proof_artifact(
                    report, "cpu", workload, args(), mutated, fingerprint
                )

    def test_blake_artifact_binds_log_rows_and_round_count(self) -> None:
        workload = MODULE.Workload.blake(8, 2)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "blake.json"
            write_proof_artifact(path, workload)
            report = make_report("cpu", workload, artifact_path=path)
            fingerprint, _ = MODULE.validate_report(report, "cpu", workload, args())

            artifact = MODULE.load_proof_artifact(path, "cpu")
            MODULE.validate_proof_artifact(
                report, "cpu", workload, args(), artifact, fingerprint
            )
            for field in ("log_n_rows", "n_rounds"):
                artifact = MODULE.load_proof_artifact(path, "cpu")
                artifact["document"]["blake_statement"][field] += 1
                with self.subTest(field=field), self.assertRaisesRegex(
                    MODULE.MatrixError,
                    "statement does not match request",
                ):
                    MODULE.validate_proof_artifact(
                        report, "cpu", workload, args(), artifact, fingerprint
                    )

    def test_poseidon_artifact_binds_instance_count(self) -> None:
        workload = MODULE.Workload.poseidon(13)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "poseidon.json"
            write_proof_artifact(path, workload)
            report = make_report("cpu", workload, artifact_path=path)
            fingerprint, _ = MODULE.validate_report(report, "cpu", workload, args())
            artifact = MODULE.load_proof_artifact(path, "cpu")
            artifact["document"]["poseidon_statement"]["log_n_instances"] += 1
            with self.assertRaisesRegex(
                MODULE.MatrixError,
                "statement does not match request",
            ):
                MODULE.validate_proof_artifact(
                    report, "cpu", workload, args(), artifact, fingerprint
                )

    def test_lane_failures_publish_bounded_streams_and_require_artifact(self) -> None:
        workload = MODULE.Workload.wide_fibonacci(10, 8)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "bench"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)

            def nonzero_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                kwargs["stdout"].write(b"partial stdout")
                kwargs["stderr"].write(b"specific failure")
                return subprocess.CompletedProcess(command, 7)

            artifact_dir = root / "nonzero"
            with mock.patch(
                "native_proof_matrix_lib.artifacts.subprocess.run",
                side_effect=nonzero_run,
            ), self.assertRaisesRegex(MODULE.MatrixError, "exited 7"):
                MODULE.run_lane(
                    "cpu", binary, workload, lane_args(), artifact_dir
                )
            self.assertEqual(
                (artifact_dir / "cpu.stdout.json").read_bytes(), b"partial stdout"
            )
            self.assertEqual(
                (artifact_dir / "cpu.stderr.txt").read_bytes(), b"specific failure"
            )

            def timeout_run(command: list[str], **kwargs: object) -> None:
                kwargs["stdout"].write(b"timeout stdout")
                kwargs["stderr"].write(b"timeout stderr")
                raise subprocess.TimeoutExpired(command, 0.01)

            artifact_dir = root / "timeout"
            with mock.patch(
                "native_proof_matrix_lib.artifacts.subprocess.run",
                side_effect=timeout_run,
            ), self.assertRaisesRegex(MODULE.MatrixError, "timed out"):
                MODULE.run_lane(
                    "cpu", binary, workload, lane_args(0.01), artifact_dir
                )
            self.assertEqual(
                (artifact_dir / "cpu.stderr.txt").read_bytes(), b"timeout stderr"
            )

            def missing_artifact_run(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                kwargs["stdout"].write(
                    json.dumps(make_report("cpu", workload)).encode()
                )
                kwargs["stderr"].write(resource_usage_stderr())
                return subprocess.CompletedProcess(command, 0)

            artifact_dir = root / "missing"
            with mock.patch(
                "native_proof_matrix_lib.artifacts.subprocess.run",
                side_effect=missing_artifact_run,
            ), self.assertRaisesRegex(MODULE.MatrixError, "was not produced"):
                MODULE.run_lane(
                    "cpu", binary, workload, lane_args(), artifact_dir
                )

    def test_oversized_stdout_still_publishes_stderr(self) -> None:
        workload = MODULE.Workload.wide_fibonacci(10, 8)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "bench"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)

            def oversized_run(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                kwargs["stdout"].write(b"oversized stdout")
                kwargs["stderr"].write(b"preserved stderr")
                return subprocess.CompletedProcess(command, 0)

            artifact_dir = root / "oversized"
            with mock.patch(
                "native_proof_matrix_lib.artifacts.subprocess.run",
                side_effect=oversized_run,
            ), mock.patch(
                "native_proof_matrix_lib.artifacts.MAX_STDOUT_BYTES", 4
            ), self.assertRaisesRegex(MODULE.MatrixError, "stream limit exceeded"):
                MODULE.run_lane(
                    "cpu", binary, workload, lane_args(), artifact_dir
                )
            self.assertEqual(
                (artifact_dir / "cpu.stdout.json").read_bytes(), b"oversized stdout"
            )
            self.assertEqual(
                (artifact_dir / "cpu.stderr.txt").read_bytes(), b"preserved stderr"
            )

if __name__ == "__main__":
    unittest.main()
