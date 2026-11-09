from __future__ import annotations

import copy
import json
import subprocess
import tempfile
from pathlib import Path
from unittest import mock
import unittest

from scripts.riscv import riscv_pr_proof_smoke as smoke
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

    def check_pair(self, modern: bool, report_change=None, receipt_change=None) -> None:
        workload = smoke.WORKLOADS[0]
        report, receipt = prove_report(workload), verify_receipt()
        if modern:
            for value in (report, receipt):
                value.pop("transcript_state_blake2s")
                value["transcript_receipt"] = {"suite": "blake3", "version": 2, "digest": TRANSCRIPT}
            report["schema"], receipt["schema"] = "riscv_prove_v2", "riscv_verify_v2"
            receipt["artifact_schema_version"] = 5
        if report_change:
            report.update(copy.deepcopy(report_change))
        if receipt_change:
            receipt.update(copy.deepcopy(receipt_change))
        statement, transcript = smoke.validate_prove_report(report, workload, COMMIT, False, ADMISSION)
        self.assertEqual((STATEMENT, TRANSCRIPT), (statement, transcript))
        smoke.validate_verify_receipt(receipt, report, statement, transcript, workload, COMMIT, False, ADMISSION)

    def test_existing_suite_pairs_and_inactive_null_fields(self) -> None:
        for modern in (False, True):
            inactive = "transcript_state_blake2s" if modern else "transcript_receipt"
            self.check_pair(modern)
            self.check_pair(modern, {inactive: None}, {inactive: None})

    def test_suite_schema_and_identity_mutations_are_rejected(self) -> None:
        modern_transcript = {"suite": "blake3", "version": 2, "digest": TRANSCRIPT}
        for modern in (False, True):
            mutations = [
                {"schema": "unknown"}, {"schema": "riscv_prove_v1" if modern else "riscv_prove_v2"},
                {"transcript_receipt": modern_transcript, "transcript_state_blake2s": TRANSCRIPT},
                {"implementation_commit": "6" * 40}, {"implementation_dirty": True},
                {"implementation_dirty": None}, {"verified_in_process": False}, {"transcript_digest_blake3": TRANSCRIPT},
                {"statement_sha256": "G" * 64}, {"executable_sha256": "bad"},
            ]
            transcript_mutations = [{"digest": value} for value in (None, "bad", "AB" * 32)]
            transcript_mutations += [{"suite": "blake2s"}, {"suite": "unknown"}, {"version": 1}, {"version": 3}, {"version": True}, {"version": 2.0}]
            if modern:
                mutations += [{"transcript_receipt": value} for value in (None, [], "bad")]
                mutations += [{"transcript_receipt": modern_transcript | change} for change in transcript_mutations]
            else:
                mutations += [{"transcript_state_blake2s": value} for value in (None, "bad", "AB" * 32)]
            for change in mutations:
                with self.subTest(modern=modern, prove=change), self.assertRaises(smoke.SmokeError):
                    self.check_pair(modern, change)
            receipt_mutations = [
                {"schema": "unknown"}, {"schema": "riscv_verify_v1" if modern else "riscv_verify_v2"},
                {"artifact_schema_version": 4 if modern else 5}, {"artifact_schema_version": 5.0 if modern else 4.0},
                {"transcript_receipt": modern_transcript, "transcript_state_blake2s": TRANSCRIPT},
                {"statement_sha256": "6" * 64}, {"executable_sha256": "6" * 64},
                {"implementation_commit": "6" * 40}, {"implementation_dirty": True},
                {"implementation_dirty": None}, {"status": "unverified"}, {"proof_sha256": "bad"},
            ]
            if modern:
                receipt_mutations += [{"transcript_receipt": modern_transcript | change} for change in transcript_mutations + [{"digest": "6" * 64}]]
            else:
                receipt_mutations += [{"transcript_state_blake2s": value} for value in ("6" * 64, None, "AB" * 32)]
            for change in receipt_mutations:
                with self.subTest(modern=modern, receipt=change), self.assertRaises(smoke.SmokeError):
                    self.check_pair(modern, receipt_change=change)

    def full_width_pair(self):
        # Exact main99f serializer output, run42677996124/artifact13701593572.
        fixtures = smoke.ROOT / "vectors/riscv/fixtures/pr-proof-smoke-main99f"
        raw = [(fixtures / (name + ".json")).read_bytes() for name in ("prove", "verify")]
        self.assertEqual(["9b21ef101862611fa70b8ec7870d90aea3f7c3d20a267cdc3e0e7c0d31120873",
                          "1023ac409d77d420a071d3b4d4f89f7c58cf15fdf4c8075d05d4428bf2739cc5"],
                         [smoke.sha256_bytes(value) for value in raw])
        return [smoke.strict_json_bytes(value, "main99f fixture") for value in raw]

    def check_full_width(self, report_change=None, receipt_change=None):
        report, receipt = self.full_width_pair()
        report.update(copy.deepcopy(report_change or {}))
        receipt.update(copy.deepcopy(receipt_change or {}))
        commit = "99f2e13f713be28951c7faff4b6286a9524f1c96"
        admission = smoke.riscv_cli_admission.Admission("promoted", "release_gated", False)
        statement, transcript = smoke.validate_prove_report(report, smoke.WORKLOADS[0], commit, False, admission)
        smoke.validate_verify_receipt(receipt, report, statement, transcript, smoke.WORKLOADS[0], commit, False, admission)

    def test_full_width_actual_serializers_and_optional_null_policy(self):
        self.check_full_width()
        report, _ = self.full_width_pair()
        self.check_full_width({"pcs_config": report["pcs_config"] | {"lifting_log_size": None}})

    def test_full_width_identity_policy_and_phase_mutations_rejected(self):
        report, receipt = self.full_width_pair()
        changes = [{key: value} for key, value in (
            ("schema", "riscv_prove_v2"), ("artifact_magic", "B3PVART1"), ("execution_profile", "unknown"),
            ("proof_suite", "blake2s"), ("security_policy", "smoke"), ("release_status", "release_gated"),
            ("implementation_commit", COMMIT), ("implementation_dirty", True), ("verified_in_process", False),
            ("statement_blake3", "AB" * 32), ("transcript_digest_blake3", "bad"), ("executable_sha256", "bad"),
            ("elf_sha256", STATEMENT), ("input_sha256", STATEMENT), ("total_steps", 145),
            ("transcript_state_blake2s", TRANSCRIPT), ("transcript_receipt", {}), ("samples", True),
            ("timings", []), ("timings", [report["timings"][0] | {"total_ns": 1}]),
            ("proof_device_counts", [{"dispatches": False, "cpu_fallbacks": 0}]),
            ("timings", [report["timings"][0] | {"execution_ns": True}]), ("median_seconds", float("nan")),
            ("pcs_config", report["pcs_config"] | {"pow_bits": 0}),
        )]
        for change in changes:
            with self.subTest(prove=change), self.assertRaises(smoke.SmokeError): self.check_full_width(change)
        for key in ("schema", "status", "artifact_magic", "proof_suite", "statement_blake3", "transcript_digest_blake3",
                    "elf_sha256", "input_sha256", "output_sha256", "implementation_commit", "executable_sha256",
                    "proof_sha256", "release_status", "security_policy", "execution_profile"):
            with self.subTest(verify=key), self.assertRaises(smoke.SmokeError): self.check_full_width(receipt_change={key: "6" * 64 if key.endswith(("sha256", "blake3")) or key == "implementation_commit" else "bad"})
        for change in ({"implementation_dirty": True}, {"implementation_dirty": None}, {"proof_bytes": 1}, {"total_steps": True},
                       {"pcs_config": {}}, {"transcript_state_blake2s": TRANSCRIPT}, {"transcript_receipt": {}}):
            with self.subTest(verify=change), self.assertRaises(smoke.SmokeError): self.check_full_width(receipt_change=change)

    def test_full_width_independent_verify_retains_workload_input(self):
        report, receipt = self.full_width_pair()
        workload = smoke.WORKLOADS[-1]
        report.update(total_steps=workload.expected_steps, elf_sha256=smoke.sha256_file(smoke.ROOT / workload.elf),
                      input_sha256=smoke.sha256_file(smoke.ROOT / workload.input_path))
        receipt.update({key: report[key] for key in ("total_steps", "elf_sha256", "input_sha256")})
        calls = []
        original_sha = smoke.sha256_file
        def run(argv):
            calls.append(argv)
            if "prove" in argv:
                Path(argv[argv.index("--output") + 1]).write_bytes(b"proof")
                report.update(proof_bytes=5, proof_sha256=smoke.sha256_bytes(b"proof"))
                receipt.update(proof_bytes=5, proof_sha256=report["proof_sha256"])
                Path(argv[argv.index("--report-out") + 1]).write_text(json.dumps(report))
            return subprocess.CompletedProcess(argv, 0, json.dumps(receipt).encode(), b""), 1
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(smoke, "run_command", side_effect=run):
            admission = smoke.riscv_cli_admission.Admission("promoted", "release_gated", False)
            row = smoke.run_workload(Path("/fake-cli"), workload, Path(tmp), report["implementation_commit"], False, admission)
            self.assertEqual("experimental_full_width", row["proof_release_status"])
            self.assertEqual(report["statement_blake3"], row["statement_digest"])
            self.assertNotIn("statement_sha256", row)
            self.assertEqual((report["schema"], receipt["schema"]), (row["prove_schema"], row["verify_schema"]))
            calls.clear()
            with mock.patch.object(smoke, "sha256_file", side_effect=lambda p: "0" * 64 if p.name.endswith(".proof.json") else original_sha(p)):
                with self.assertRaisesRegex(smoke.SmokeError, "retained artifact differs"):
                    smoke.run_workload(Path("/fake-cli"), workload, Path(tmp), report["implementation_commit"], False, admission)
            self.assertEqual(1, len(calls))
            calls.clear()
            smoke.run_workload(Path("/fake-cli"), workload, Path(tmp), report["implementation_commit"], False, admission)
        self.assertEqual(2, len(calls))
        self.assertIn("verify", calls[1])
        self.assertEqual(str(smoke.ROOT / workload.input_path), calls[1][calls[1].index("--input") + 1])

    def test_functional_pass_does_not_relabel_experimental_proof_as_release_gated(self):
        row = {"proof_release_status": "experimental_full_width"}
        admission = smoke.riscv_cli_admission.Admission("promoted", "release_gated", False)
        with tempfile.TemporaryDirectory() as tmp:
            cli, out = Path(tmp) / "cli", Path(tmp) / "report.json"
            cli.touch()
            with mock.patch.object(smoke.riscv_cli_admission, "resolve", return_value=admission), \
                 mock.patch.object(smoke, "run_command", return_value=(subprocess.CompletedProcess([], 0, COMMIT.encode(), b""), 1)), \
                 mock.patch.object(smoke, "run_workload", return_value=row):
                self.assertEqual(0, smoke.main(["--cli", str(cli), "--artifact-dir", str(Path(tmp) / "proofs"),
                    "--report-out", str(out), "--workload", "branch_fib"]))
            report = json.loads(out.read_text())
        self.assertEqual({"release_status": "release_gated", "experimental": False}, report["cli_admission"])
        self.assertEqual("functional_cpu_proof_verification", report["acceptance_scope"])
        self.assertNotIn("release_status", report)
        self.assertNotIn("experimental", report)
        self.assertEqual("experimental_full_width", report["workloads"][0]["proof_release_status"])

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
