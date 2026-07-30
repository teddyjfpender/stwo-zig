from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from native_proof_matrix_lib.model import RUST_ORACLE_SHA256
from scripts.tests.native_proof_matrix_support import (
    MODULE,
    PROOF_WIRE_BYTES,
    PROOF_WIRE_SHA256,
    UPSTREAM_COMMIT,
    args,
    make_report,
    write_proof_artifact,
)


class NativeProofMatrixFormalTests(unittest.TestCase):
    def test_pinned_rust_oracle_records_binary_and_artifact_evidence(self) -> None:
        from native_proof_matrix_lib.artifacts import run_rust_oracle

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "proof.json"
            artifact.write_text("{}\n")
            oracle = root / "oracle"
            oracle.write_text("#!/bin/sh\nexit 0\n")
            oracle.chmod(0o755)
            oracle_digest = hashlib.sha256(oracle.read_bytes()).hexdigest()
            with self.assertRaisesRegex(MODULE.MatrixError, "pinned verifier"):
                run_rust_oracle(oracle, artifact, 2.0)
            with mock.patch(
                "native_proof_matrix_lib.artifacts.RUST_ORACLE_SHA256",
                oracle_digest,
            ):
                evidence = run_rust_oracle(oracle, artifact, 2.0)
            self.assertTrue(evidence["verified"])
            self.assertEqual(evidence["upstream_commit"], UPSTREAM_COMMIT)
            self.assertEqual(evidence["toolchain"], "nightly-2025-07-14")
            self.assertEqual(
                evidence["binary_sha256"],
                hashlib.sha256(oracle.read_bytes()).hexdigest(),
            )
            oracle.write_text("#!/bin/sh\nprintf unexpected\n")
            oracle.chmod(0o755)
            oracle_digest = hashlib.sha256(oracle.read_bytes()).hexdigest()
            with mock.patch(
                "native_proof_matrix_lib.artifacts.RUST_ORACLE_SHA256",
                oracle_digest,
            ), self.assertRaisesRegex(MODULE.MatrixError, "unexpected output"):
                run_rust_oracle(oracle, artifact, 2.0)
            oracle.write_text("#!/bin/sh\nexit 1\n")
            oracle.chmod(0o755)
            oracle_digest = hashlib.sha256(oracle.read_bytes()).hexdigest()
            with mock.patch(
                "native_proof_matrix_lib.artifacts.RUST_ORACLE_SHA256",
                oracle_digest,
            ), self.assertRaisesRegex(MODULE.MatrixError, "rejected"):
                run_rust_oracle(oracle, artifact, 2.0)

            oracle.write_text('#!/bin/sh\nprintf x >> "$4"\n')
            oracle.chmod(0o755)
            oracle_digest = hashlib.sha256(oracle.read_bytes()).hexdigest()
            artifact.write_text("{}\n")
            with mock.patch(
                "native_proof_matrix_lib.artifacts.RUST_ORACLE_SHA256",
                oracle_digest,
            ), self.assertRaisesRegex(MODULE.MatrixError, "artifact changed"):
                run_rust_oracle(oracle, artifact, 2.0)

    def test_formal_matrix_invokes_pinned_oracle_once_per_parity_row(self) -> None:
        workloads = [
            MODULE.Workload.wide_fibonacci(10, 8),
            MODULE.Workload.xor(10, 2, 3),
            MODULE.Workload.plonk(10),
            MODULE.Workload.state_machine(10, 9, 3),
            MODULE.Workload.blake(8, 2),
            MODULE.Workload.poseidon(13),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binaries = {}
            for name in ("cpu", "metal", "oracle"):
                binary = root / name
                binary.write_text("#!/bin/sh\nexit 0\n")
                binary.chmod(0o755)
                binaries[name] = binary

            matrix_args = argparse.Namespace(
                workloads=workloads,
                cpu_bin=binaries["cpu"],
                metal_bin=binaries["metal"],
                rust_oracle_bin=binaries["oracle"],
                output_dir=root / "out",
                protocol="functional",
                warmups=10,
                samples=10,
                cooldown_seconds=0.0,
                timeout_seconds=2.0,
                formal=True,
            )

            def fake_lane(
                lane: str,
                _binary: Path,
                workload: MODULE.Workload,
                _args: argparse.Namespace,
                artifact_dir: Path,
            ) -> dict[str, object]:
                artifact_path = artifact_dir / f"{lane}.proof-artifact.json"
                write_proof_artifact(artifact_path, workload)
                report = make_report(
                    lane,
                    workload,
                    samples=_args.samples,
                    warmups=_args.warmups,
                    artifact_path=artifact_path,
                )
                stdout_path = artifact_dir / f"{lane}.stdout.json"
                stderr_path = artifact_dir / f"{lane}.stderr.txt"
                stdout_path.write_text(json.dumps(report))
                stderr_path.write_bytes(b"")
                return {
                    "lane": lane,
                    "command": [lane],
                    "process_wall_seconds": 1.0,
                    "resources": {
                        "measurement": "darwin_usr_bin_time_l_v1",
                        "measurement_locale": "C",
                        "normalized_unit": "KiB",
                        "peak_rss_kib": 1024,
                    },
                    "stdout_path": stdout_path,
                    "stderr_path": stderr_path,
                    "report": report,
                    "proof_artifact": MODULE.load_proof_artifact(
                        artifact_path, lane
                    ),
                }

            def oracle_evidence(
                binary: Path, artifact_path: Path, _timeout: float
            ) -> dict[str, object]:
                artifact_sha256 = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
                command = [
                    str(binary),
                    "--mode",
                    "verify",
                    "--artifact",
                    str(artifact_path),
                ]
                return {
                    "status": "passed",
                    "verified": True,
                    "upstream_commit": UPSTREAM_COMMIT,
                    "toolchain": "nightly-2025-07-14",
                    "binary_path": str(binary),
                    "binary_sha256": RUST_ORACLE_SHA256,
                    "artifact_path": str(artifact_path),
                    "artifact_sha256": artifact_sha256,
                    "command": command,
                    "elapsed_seconds": 0.01,
                    "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                }
            with mock.patch(
                "native_proof_matrix_lib.controller.run_lane",
                side_effect=fake_lane,
            ), mock.patch(
                "native_proof_matrix_lib.controller.preflight_rust_oracle_adapter",
                return_value={
                    "schema_version": 1,
                    "protocol": "stwo_interop_capabilities_v1",
                    "upstream_commit": UPSTREAM_COMMIT,
                    "exact_air_protocols": {
                        "poseidon": "raw-stwo-poseidon-logup-split2-v1",
                        "state_machine": "raw-stwo-state-machine-v2",
                        "xor": "raw-stwo-xor-lookup-v2",
                    },
                },
            ) as oracle_preflight, mock.patch(
                "native_proof_matrix_lib.controller.run_rust_oracle",
                side_effect=oracle_evidence,
            ) as oracle, mock.patch(
                "native_proof_matrix_lib.controller.collect_static",
                return_value={
                    "schema": "native_matrix_host_environment_v1",
                    "toolchain": {},
                    "complete": True,
                    "blockers": [],
                },
            ), mock.patch(
                "native_proof_matrix_lib.controller.collect_load",
                return_value={
                    "schema": "native_matrix_host_load_v1",
                    "load_average": {
                        "one_minute": 0.0,
                        "five_minutes": 0.0,
                        "fifteen_minutes": 0.0,
                    },
                    "complete": True,
                    "blockers": [],
                },
            ):
                document = MODULE.run_matrix(matrix_args)
            oracle_preflight.assert_called_once_with(binaries["oracle"].resolve(), 2.0)
            self.assertEqual(oracle.call_count, 6)
            self.assertTrue(document["summary"]["all_rust_oracles_verified"])
            self.assertEqual(
                "native_matrix_host_environment_v1",
                document["configuration"]["host_environment"]["schema"],
            )
            self.assertEqual(
                {"start", "end"},
                set(document["configuration"]["host_load"]),
            )
            self.assertEqual(
                [row["lane_order"] for row in document["rows"]],
                [
                    ["cpu", "metal"],
                    ["metal", "cpu"],
                    ["cpu", "metal"],
                    ["metal", "cpu"],
                    ["cpu", "metal"],
                    ["metal", "cpu"],
                ],
            )
            self.assertTrue(all(row["rust_oracle"] for row in document["rows"]))
            self.assertEqual(document["schema_version"], 6)
            self.assertEqual(
                document["protocol"], "native_proof_cross_backend_matrix_v6"
            )
            self.assertEqual(set(document["product_receipts"]), {"cpu", "metal"})
            self.assertTrue(
                all(
                    receipt["promotion_eligible"]
                    for receipt in document["product_receipts"].values()
                )
            )
            self.assertEqual(
                document["product_receipts"]["cpu"]["product_identity"]["name"],
                "stwo-native-cpu",
            )
            cpu_lane = document["rows"][0]["lanes"]["cpu"]
            self.assertEqual(cpu_lane["resources"]["normalized_unit"], "KiB")
            self.assertEqual(
                cpu_lane["request_resources"]["measurement_scope"],
                "verified_process_request_batch",
            )

    def test_dirty_provenance_blocks_headline_without_weakening_parity(self) -> None:
        workload = MODULE.Workload.wide_fibonacci(10, 8)
        report = make_report("cpu", workload, dirty=True)
        fingerprint, blockers = MODULE.validate_report(
            report, "cpu", workload, args()
        )
        self.assertEqual(fingerprint, (PROOF_WIRE_SHA256, len(PROOF_WIRE_BYTES)))
        self.assertIn("cpu_git_dirty", blockers)
        self.assertIn("cpu_requirement_clean_complete_provenance", blockers)
        self.assertFalse(report["throughput"]["headline_eligible"])

    def test_formal_mode_returns_nonzero_for_non_headline_matrix(self) -> None:
        parsed = argparse.Namespace(allow_non_headline=False)
        document = {"summary": {"all_rows_headline_eligible": False}}
        with mock.patch.object(
            MODULE, "parse_args", return_value=parsed
        ), mock.patch.object(
            MODULE, "run_matrix", return_value=document
        ), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ):
            self.assertEqual(MODULE.main([]), 2)
        parsed.allow_non_headline = True
        with mock.patch.object(
            MODULE, "parse_args", return_value=parsed
        ), mock.patch.object(
            MODULE, "run_matrix", return_value=document
        ), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(MODULE.main([]), 0)

    def test_unprofiled_environment_gate_is_fail_closed(self) -> None:
        MODULE.require_unprofiled_environment({})
        with self.assertRaises(MODULE.MatrixError):
            MODULE.require_unprofiled_environment({"STWO_ZIG_METAL_PROFILE_OUT": "x"})


if __name__ == "__main__":
    unittest.main()
