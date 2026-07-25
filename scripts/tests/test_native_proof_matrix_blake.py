from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.tests.native_proof_matrix_support import (
    MODULE,
    args,
    make_report,
    write_proof_artifact,
)


class NativeProofMatrixBlakeTests(unittest.TestCase):
    def test_oracle_identity_is_pinned(self) -> None:
        from native_proof_matrix_lib import RUST_ORACLE_SHA256

        self.assertEqual(
            RUST_ORACLE_SHA256,
            "075a01f4cc23f455985cd396f5870159d2856271c5fe1e9ab7c86b41c4f1e36d",
        )

    def test_artifact_binds_exact_public_statement(self) -> None:
        workload = MODULE.Workload.blake(8, 10)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "blake.json"
            write_proof_artifact(path, workload)
            report = make_report(
                "cpu",
                workload,
                artifact_path=path,
                resource_profile="large",
            )
            matrix_args = args(resource_profile="large")
            fingerprint, _ = MODULE.validate_report(
                report,
                "cpu",
                workload,
                matrix_args,
            )

            artifact = MODULE.load_proof_artifact(path, "cpu")
            MODULE.validate_proof_artifact(
                report, "cpu", workload, matrix_args, artifact, fingerprint
            )
            artifact["document"]["blake_statement"]["stmt0"]["log_size"] += 1
            with self.assertRaisesRegex(
                MODULE.MatrixError,
                "does not match the request",
            ):
                MODULE.validate_proof_artifact(
                    report, "cpu", workload, matrix_args, artifact, fingerprint
                )

            artifact = MODULE.load_proof_artifact(path, "cpu")
            artifact["document"]["blake_statement"]["stmt1"][
                "scheduler_claimed_sum"
            ][0] = (1 << 31) - 1
            with self.assertRaisesRegex(MODULE.MatrixError, "not canonical M31"):
                MODULE.validate_proof_artifact(
                    report, "cpu", workload, matrix_args, artifact, fingerprint
                )

            artifact = MODULE.load_proof_artifact(path, "cpu")
            artifact["document"]["blake_statement"]["stmt1"][
                "round_claimed_sums"
            ].pop()
            with self.assertRaisesRegex(MODULE.MatrixError, "2 claimed sums"):
                MODULE.validate_proof_artifact(
                    report, "cpu", workload, matrix_args, artifact, fingerprint
                )


if __name__ == "__main__":
    unittest.main()
