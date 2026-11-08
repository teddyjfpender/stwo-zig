from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts.bench import benchmark_delta
from scripts.native import native_proof_matrix
from scripts.bench.benchmark_delta_lib.common import IncompatibleReports
from scripts.bench.benchmark_delta_lib.native_oracle import classify_transition
from scripts.native.native_proof_matrix_lib.artifacts import parse_process_resources
from scripts.native.native_proof_matrix_lib.evidence import validate_rust_oracle_receipt
from scripts.native.native_proof_matrix_lib.model import (
    INTEROP_UPSTREAM_COMMIT,
    RUST_ORACLE_SHA256,
    RUST_ORACLE_TOOLCHAIN,
    MatrixError,
)
from scripts.tests.test_benchmark_delta import native_report, summary, write_json


EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def native_v4_report(commit: str, binary_suffix: str, peak_rss_kib: int) -> dict:
    report = native_report(commit, binary_suffix)
    report["schema_version"] = 4
    report["protocol"] = benchmark_delta.NATIVE_PROTOCOL_V4
    configuration = report["configuration"]
    configuration["samples_per_lane"] = 10
    configuration["stability_contract"] = {
        "minimum_measured_verified_proofs_per_lane": 10,
    }
    row = report["rows"][0]
    row["proof_parity"] = True
    row["stability"] = {
        "required_verified_proofs_per_lane": 10,
        "cpu_verified_proofs": 10,
        "metal_verified_proofs": 10,
        "cpu_byte_identical": True,
        "metal_byte_identical": True,
        "satisfied": True,
    }
    artifact_sha256 = "6" * 64
    row["rust_oracle"]["artifact_sha256"] = artifact_sha256
    for lane_name, lane in row["lanes"].items():
        lane["resources"] = {
            "measurement": "darwin_usr_bin_time_l_v1",
            "measurement_locale": "C",
            "normalized_unit": "KiB",
            "peak_rss_kib": peak_rss_kib,
        }
        lane["metrics"]["peak_rss_kib"] = summary(float(peak_rss_kib))
        lane["proof_artifact"] = {"sha256": artifact_sha256}
        lane["backend_telemetry"] = (
            {"total_cpu_fallbacks": 3} if lane_name == "metal" else None
        )
    report["summary"] = {
        "rows": 1,
        "headline_rows": 1,
        "all_rows_headline_eligible": True,
        "all_proofs_verified_and_byte_identical": True,
        "all_cross_backend_proofs_identical": True,
        "all_rust_oracles_verified": True,
        "all_rows_meet_stability_contract": True,
    }
    return report


class NativeMatrixPhase1EvidenceTests(unittest.TestCase):
    def test_rss_measurements_are_normalized_to_kib(self) -> None:
        self.assertEqual(
            parse_process_resources(
                b"1048576  maximum resident set size\n",
                "darwin_usr_bin_time_l_v1",
            )["peak_rss_kib"],
            1024,
        )
        self.assertEqual(
            parse_process_resources(
                b"Maximum resident set size (kbytes): 2048\n",
                "gnu_usr_bin_time_v_v1",
            )["peak_rss_kib"],
            2048,
        )
        with self.assertRaisesRegex(MatrixError, "one positive"):
            parse_process_resources(b"", "darwin_usr_bin_time_l_v1")

    def test_formal_mode_requires_ten_measured_proofs(self) -> None:
        parsed = native_proof_matrix.parse_args(
            ["--rust-oracle-bin", "/tmp/oracle", "--samples", "10"]
        )
        self.assertTrue(parsed.formal)
        self.assertEqual(parsed.samples, 10)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            native_proof_matrix.parse_args(
                ["--rust-oracle-bin", "/tmp/oracle", "--samples", "9"]
            )
        diagnostic = native_proof_matrix.parse_args(
            ["--allow-non-headline", "--samples", "5"]
        )
        self.assertFalse(diagnostic.formal)

    def test_rust_receipt_must_bind_the_exact_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oracle = root / "oracle"
            artifact_path = root / "proof.json"
            artifact_path.write_text("{}\n")
            artifact_sha256 = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
            receipt = {
                "status": "passed",
                "verified": True,
                "upstream_commit": INTEROP_UPSTREAM_COMMIT,
                "toolchain": RUST_ORACLE_TOOLCHAIN,
                "binary_path": str(oracle),
                "binary_sha256": RUST_ORACLE_SHA256,
                "artifact_path": str(artifact_path),
                "artifact_sha256": artifact_sha256,
                "command": [
                    str(oracle),
                    "--mode",
                    "verify",
                    "--artifact",
                    str(artifact_path),
                ],
                "elapsed_seconds": 0.01,
                "stdout_sha256": EMPTY_SHA256,
                "stderr_sha256": EMPTY_SHA256,
            }
            artifact = {
                "path": artifact_path,
                "sha256": artifact_sha256,
            }
            validate_rust_oracle_receipt(receipt, oracle, artifact)
            mutated = copy.deepcopy(receipt)
            mutated["artifact_sha256"] = "0" * 64
            with self.assertRaisesRegex(MatrixError, "accepted artifact"):
                validate_rust_oracle_receipt(mutated, oracle, artifact)

    def test_v4_delta_compares_rss_and_preserves_v3_incompatibility(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = native_v4_report("a" * 40, "3", 2048)
            current = native_v4_report("b" * 40, "4", 1024)
            baseline_path = root / "baseline.json"
            current_path = root / "current.json"
            write_json(baseline_path, baseline)
            write_json(current_path, current)
            delta, _, _ = benchmark_delta.compare_reports(
                baseline_path, current_path, "2026-07-17T12:00:00Z"
            )
            self.assertEqual(delta["status"], "comparable")
            rss = next(
                metric
                for metric in delta["comparisons"][0]["metrics"]
                if metric["metric"] == "peak_rss_kib"
            )
            self.assertEqual(rss["unit"], "kibibytes")
            self.assertEqual(rss["improvement_percent"], 50.0)

            write_json(baseline_path, native_report("a" * 40, "3"))
            mixed, _, _ = benchmark_delta.compare_reports(
                baseline_path, current_path, "2026-07-17T12:00:00Z"
            )
            self.assertEqual(mixed["status"], "incomparable")
            self.assertIn("protocols differ", mixed["incompatibilities"][0])

    def test_v4_delta_rejects_resource_or_summary_drift(self) -> None:
        for mutation, expected in (
            (
                lambda report: report["rows"][0]["lanes"]["metal"]["resources"].__setitem__(
                    "peak_rss_kib", 0
                ),
                "RSS evidence",
            ),
            (
                lambda report: report["summary"].__setitem__(
                    "all_rust_oracles_verified", False
                ),
                "summary is inconsistent",
            ),
        ):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                baseline = native_v4_report("a" * 40, "3", 2048)
                current = native_v4_report("b" * 40, "4", 1024)
                mutation(current)
                baseline_path = root / "baseline.json"
                current_path = root / "current.json"
                write_json(baseline_path, baseline)
                write_json(current_path, current)
                with self.assertRaisesRegex(benchmark_delta.DeltaError, expected):
                    benchmark_delta.compare_reports(
                        baseline_path, current_path, "2026-07-17T12:00:00Z"
                    )

    def test_v4_to_v5_delta_uses_the_shared_formal_evidence_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = native_v4_report("a" * 40, "3", 2048)
            current = native_v4_report("b" * 40, "4", 1024)
            current["schema_version"] = 5
            current["protocol"] = benchmark_delta.NATIVE_PROTOCOL_V5
            current["configuration"]["host_environment"] = {
                "schema": "native_matrix_host_environment_v1"
            }
            current["configuration"]["host_load"] = {
                "start": {"schema": "native_matrix_host_load_v1"},
                "end": {"schema": "native_matrix_host_load_v1"},
            }
            baseline_path = root / "baseline.json"
            current_path = root / "current.json"
            write_json(baseline_path, baseline)
            write_json(current_path, current)

            delta, _, _ = benchmark_delta.compare_reports(
                baseline_path, current_path, "2026-07-18T12:00:00Z"
            )

        self.assertEqual(delta["status"], "comparable")
        self.assertEqual(
            delta["report_kind"],
            f"{benchmark_delta.NATIVE_PROTOCOL_V4}->{benchmark_delta.NATIVE_PROTOCOL_V5}",
        )
        self.assertEqual(
            delta["comparison_identity"]["report_protocol"],
            delta["report_kind"],
        )

    def test_v4_to_v5_allows_only_the_pinned_verifier_boundary_transition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = native_v4_report("a" * 40, "3", 2048)
            current = native_v4_report("b" * 40, "4", 1024)
            current["schema_version"] = 5
            current["protocol"] = benchmark_delta.NATIVE_PROTOCOL_V5
            baseline["rows"][0]["rust_oracle"]["binary_sha256"] = (
                "4d223c37e85b96f61dccc684f2897c82d2d55f6c50b59616a69cc5cc70d2ccf8"
            )
            current["rows"][0]["rust_oracle"]["binary_sha256"] = (
                "b8b8d824fa54db7091d77918f2f72c470b5fa372d65e9d5a9c91638536b57697"
            )
            baseline_path = root / "baseline.json"
            current_path = root / "current.json"
            write_json(baseline_path, baseline)
            write_json(current_path, current)

            delta, _, _ = benchmark_delta.compare_reports(
                baseline_path, current_path, "2026-07-18T12:00:00Z"
            )
            transition = delta["comparison_identity"]["oracle_binary_transition"]
            self.assertEqual("none", transition["timed_lane_impact"])
            self.assertTrue(transition["proof_identity_required"])
            self.assertEqual(
                "fail_closed_pcs_schema_and_verifier_safety_checks_outside_timed_lanes",
                transition["reason"],
            )

            current["rows"][0]["rust_oracle"]["binary_sha256"] = "9" * 64
            write_json(current_path, current)
            rejected, _, _ = benchmark_delta.compare_reports(
                baseline_path, current_path, "2026-07-18T12:00:00Z"
            )
            self.assertEqual("incomparable", rejected["status"])
            self.assertIn("binary_sha256", rejected["incompatibilities"][0])

    def test_v5_to_v6_allows_only_the_parallel_oracle_transition(self) -> None:
        old = "b8b8d824fa54db7091d77918f2f72c470b5fa372d65e9d5a9c91638536b57697"
        new = "bca74321517d41e6c2128ab20567756ab498ef18cee3fba422a51eea74b92b2b"
        transition = classify_transition(
            {(old, new)},
            (benchmark_delta.NATIVE_PROTOCOL_V5, benchmark_delta.NATIVE_PROTOCOL_V6),
            benchmark_delta.NATIVE_PROTOCOL_V4,
            benchmark_delta.NATIVE_PROTOCOL_V5,
            benchmark_delta.NATIVE_PROTOCOL_V6,
        )
        self.assertEqual("none", transition["timed_lane_impact"])
        self.assertEqual(
            "enable_parallel_feature_in_pinned_rust_oracle_outside_timed_lanes",
            transition["reason"],
        )
        with self.assertRaises(IncompatibleReports):
            classify_transition(
                {(old, "9" * 64)},
                (benchmark_delta.NATIVE_PROTOCOL_V5, benchmark_delta.NATIVE_PROTOCOL_V6),
                benchmark_delta.NATIVE_PROTOCOL_V4,
                benchmark_delta.NATIVE_PROTOCOL_V5,
                benchmark_delta.NATIVE_PROTOCOL_V6,
            )


if __name__ == "__main__":
    unittest.main()
