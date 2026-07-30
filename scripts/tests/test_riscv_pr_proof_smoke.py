from __future__ import annotations

import unittest

from scripts import riscv_pr_proof_smoke as smoke


COMMIT = "1" * 40
STATEMENT = "2" * 64
TRANSCRIPT = "3" * 64
EXECUTABLE = "4" * 64
PROOF = "5" * 64
ADMISSION = smoke.riscv_cli_admission.Admission(
    "candidate", "not_release_gated", True,
)


def prove_report(workload: smoke.Workload) -> dict[str, object]:
    return {
        "schema": "riscv_prove_v1",
        "release_status": "not_release_gated",
        "experimental": True,
        "verified_in_process": True,
        "total_steps": workload.expected_steps,
        "n_components": 4,
        "proving_seconds": 1.0,
        "verification_seconds": 0.1,
        "total_seconds": 1.2,
        "statement_sha256": STATEMENT,
        "transcript_state_blake2s": TRANSCRIPT,
        "implementation_commit": COMMIT,
        "implementation_dirty": False,
        "executable_sha256": EXECUTABLE,
    }


def verify_receipt() -> dict[str, object]:
    return {
        "schema": "riscv_verify_v1",
        "status": "verified",
        "artifact_kind": "stwo_riscv_proof",
        "artifact_schema_version": 4,
        "release_status": "not_release_gated",
        "security_policy": "functional",
        "statement_sha256": STATEMENT,
        "transcript_state_blake2s": TRANSCRIPT,
        "implementation_commit": COMMIT,
        "implementation_dirty": False,
        "executable_sha256": EXECUTABLE,
        "proof_bytes": 1024,
        "proof_sha256": PROOF,
    }


class RiscVPrProofSmokeTests(unittest.TestCase):
    def test_corpus_covers_distinct_structural_roles(self) -> None:
        self.assertEqual(4, len(smoke.WORKLOADS))
        self.assertEqual(4, len({item.structural_role for item in smoke.WORKLOADS}))
        self.assertEqual(
            {"branch_fib", "memcpy_loop", "multi_shard_addi", "sha2_input_128B"},
            {item.name for item in smoke.WORKLOADS},
        )

    def test_prove_and_verify_contract_accepts_bound_receipts(self) -> None:
        workload = smoke.WORKLOADS[0]
        report = prove_report(workload)
        statement, transcript = smoke.validate_prove_report(
            report, workload, COMMIT, False, ADMISSION,
        )
        smoke.validate_verify_receipt(
            verify_receipt(), report, statement, transcript, workload, COMMIT, False,
            ADMISSION,
        )

    def test_step_drift_is_rejected(self) -> None:
        workload = smoke.WORKLOADS[0]
        report = prove_report(workload)
        report["total_steps"] = workload.expected_steps + 1
        with self.assertRaisesRegex(smoke.SmokeError, "step count drifted"):
            smoke.validate_prove_report(report, workload, COMMIT, False, ADMISSION)

    def test_independent_receipt_must_bind_the_same_transcript(self) -> None:
        workload = smoke.WORKLOADS[0]
        report = prove_report(workload)
        receipt = verify_receipt()
        receipt["transcript_state_blake2s"] = "6" * 64
        with self.assertRaisesRegex(smoke.SmokeError, "transcript_state_blake2s"):
            smoke.validate_verify_receipt(
                receipt, report, STATEMENT, TRANSCRIPT, workload, COMMIT, False,
                ADMISSION,
            )

    def test_promoted_reports_are_validated_against_the_registry_phase(self) -> None:
        workload = smoke.WORKLOADS[0]
        admission = smoke.riscv_cli_admission.Admission(
            "promoted", "release_gated", False,
        )
        report = prove_report(workload)
        report.update(release_status="release_gated", experimental=False)
        receipt = verify_receipt()
        receipt["release_status"] = "release_gated"
        statement, transcript = smoke.validate_prove_report(
            report, workload, COMMIT, False, admission,
        )
        smoke.validate_verify_receipt(
            receipt, report, statement, transcript, workload, COMMIT, False,
            admission,
        )

    def test_duplicate_json_fields_are_rejected(self) -> None:
        with self.assertRaisesRegex(smoke.SmokeError, "repeats JSON field"):
            smoke.strict_json_bytes(b'{"status":"PASS","status":"FAIL"}', "receipt")


if __name__ == "__main__":
    unittest.main()
