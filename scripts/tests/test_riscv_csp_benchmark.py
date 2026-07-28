from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import riscv_csp_benchmark as csp
from scripts.riscv_csp_benchmark_lib import contract as csp_contract


class ManifestContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest, cls.cases, cls.negative_cases = csp.validate_manifest()

    def test_checked_manifest_is_the_complete_pinned_workload_matrix(self) -> None:
        self.assertEqual(
            "269c43cc32d3127e3d9ce74d20652887d894cca3",
            self.manifest["upstream"]["commit"],
        )
        self.assertEqual(
            [
                (target, size)
                for target in csp.TARGET_ORDER
                for size in csp.TARGET_SIZES[target]
            ],
            [(case.target, case.input_size) for case in self.cases],
        )
        self.assertTrue(all(not case.uses_precompile for case in self.cases))
        self.assertEqual(
            [("ecdsa_secp256k1_bad_signature", "ecdsa_secp256k1")],
            [(case.name, case.target) for case in self.negative_cases],
        )

    def test_every_committed_fixture_is_authenticated(self) -> None:
        for case in self.cases:
            self.assertEqual(case.input_sha256, csp.sha256_file(case.input_path))
            self.assertEqual(case.guest_sha256, csp.sha256_file(case.guest_path))
        for case in self.negative_cases:
            self.assertEqual(case.input_sha256, csp.sha256_file(case.input_path))

    def test_manifest_rejects_duplicate_json_fields(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "duplicate.json"
            path.write_text(
                '{"schema":"stwo_riscv_csp_suite_v2","schema":"substitution"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(csp.BenchmarkError, "repeats field"):
                csp.load_json(path)

    def test_manifest_target_substitution_fails_closed(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["targets"]["sha256"]["uses_precompile"] = True
        with mock.patch.object(csp_contract, "load_json", return_value=changed):
            with self.assertRaisesRegex(csp.BenchmarkError, "explicit RV32IM"):
                csp.validate_manifest()

    def test_unsupported_target_ledger_cannot_silently_shrink(self) -> None:
        changed = copy.deepcopy(self.manifest)
        del changed["unsupported_targets"]["ecdsa_p256"]
        with mock.patch.object(csp_contract, "load_json", return_value=changed):
            with self.assertRaisesRegex(csp.BenchmarkError, "ledger drifted"):
                csp.validate_manifest()

    def test_poseidon_extension_cannot_be_relabelled_canonical(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["targets"]["poseidon2_m31"]["comparison_class"] = "csp_canonical"
        with mock.patch.object(csp_contract, "load_json", return_value=changed):
            with self.assertRaisesRegex(csp.BenchmarkError, "workload contract"):
                csp.validate_manifest()

    def test_repository_guest_source_mutation_fails_closed(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["targets"]["ecdsa_secp256k1"]["guest"]["source_files"][0][
            "sha256"
        ] = "0" * 64
        with mock.patch.object(csp_contract, "load_json", return_value=changed):
            with self.assertRaisesRegex(
                csp.BenchmarkError,
                "repository source binding drifted",
            ):
                csp.validate_manifest()

    def test_input_fixture_bit_flip_is_rejected(self) -> None:
        target = csp.ROOT / "vectors" / "riscv_csp" / "inputs" / "msg_128.bin"
        original_read_bytes = Path.read_bytes

        def read_with_mutation(path: Path) -> bytes:
            value = original_read_bytes(path)
            if path.resolve() == target.resolve():
                mutated = bytearray(value)
                mutated[-1] ^= 1
                return bytes(mutated)
            return value

        with mock.patch.object(Path, "read_bytes", read_with_mutation):
            with self.assertRaisesRegex(csp.BenchmarkError, "input digest drifted"):
                csp.validate_manifest()

    def test_negative_signature_fixture_bit_flip_is_rejected(self) -> None:
        target = (
            csp.ROOT
            / "vectors"
            / "riscv_csp"
            / "inputs"
            / "ecdsa_secp256k1_bad_signature.bin"
        )
        original_read_bytes = Path.read_bytes

        def read_with_mutation(path: Path) -> bytes:
            value = original_read_bytes(path)
            if path.resolve() == target.resolve():
                mutated = bytearray(value)
                mutated[-2] ^= 1
                return bytes(mutated)
            return value

        with mock.patch.object(Path, "read_bytes", read_with_mutation):
            with self.assertRaisesRegex(
                csp.BenchmarkError,
                "negative fixture 0 binding drifted",
            ):
                csp.validate_manifest()

    def test_noncanonical_m31_fixture_is_rejected_before_hash_check(self) -> None:
        target = (
            csp.ROOT
            / "vectors"
            / "riscv_csp"
            / "inputs"
            / "field_m31_2.bin"
        )
        original_read_bytes = Path.read_bytes

        def read_with_mutation(path: Path) -> bytes:
            value = original_read_bytes(path)
            if path.resolve() == target.resolve():
                mutated = bytearray(value)
                mutated[4:8] = ((1 << 31) - 1).to_bytes(4, "little")
                return bytes(mutated)
            return value

        with mock.patch.object(Path, "read_bytes", read_with_mutation):
            with self.assertRaisesRegex(csp.BenchmarkError, "noncanonical M31"):
                csp.validate_manifest()


class PublicOutputContractTests(unittest.TestCase):
    @staticmethod
    def diagnostic(last_word: int = 0x00000065) -> dict:
        return {
            "schema": "riscv-public-values-diagnostic-v1",
            "public_data": {
                "io_entries": {
                    "output_len": 5,
                    "output_len_addr": 0x2000,
                    "output_data_addr": 0x2004,
                    "output_words": [
                        {"addr": 0x2000, "value": 5},
                        {"addr": 0x2004, "value": 0x64636261},
                        {"addr": 0x2008, "value": last_word},
                    ],
                }
            },
        }

    def test_output_words_reconstruct_exact_little_endian_bytes(self) -> None:
        self.assertEqual(b"abcde", csp.reconstruct_public_output(self.diagnostic()))

    def test_nonzero_output_padding_is_rejected(self) -> None:
        with self.assertRaisesRegex(csp.BenchmarkError, "padding is nonzero"):
            csp.reconstruct_public_output(self.diagnostic(last_word=0x00000165))


class VerificationReceiptContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.case = csp.validate_manifest()[1][0]

    @staticmethod
    def receipt() -> dict:
        return {
            "schema": "riscv_verify_v1",
            "status": "verified",
            "statement_sha256": "a" * 64,
            "proof_bytes": 3,
            "proof_sha256": csp.sha256_bytes(b"air"),
            "implementation_commit": "b" * 40,
            "implementation_dirty": False,
        }

    def validate(self, receipt: dict) -> None:
        csp._validate_verify_receipt(
            receipt,
            self.case,
            statement_digest="a" * 64,
            proof_bytes=b"air",
            proof_sha256=csp.sha256_bytes(b"air"),
            implementation_commit="b" * 40,
        )

    def test_production_receipt_contract_is_accepted(self) -> None:
        self.validate(self.receipt())

    def test_boolean_verified_substitution_is_rejected(self) -> None:
        changed = self.receipt()
        changed.pop("status")
        changed["verified"] = True
        with self.assertRaisesRegex(csp.BenchmarkError, "receipt drifted"):
            self.validate(changed)

    def test_wrong_proof_binding_is_rejected(self) -> None:
        changed = self.receipt()
        changed["proof_sha256"] = "0" * 64
        with self.assertRaisesRegex(csp.BenchmarkError, "receipt drifted"):
            self.validate(changed)


class HostEvidenceTests(unittest.TestCase):
    def test_report_host_metadata_excludes_network_identity(self) -> None:
        host = csp.collect_host()
        self.assertNotIn("hostname", host)
        self.assertEqual(
            {
                "architecture",
                "cpu",
                "kernel",
                "logical_cpu_count",
                "memory_bytes",
                "os",
                "os_version",
                "python",
            },
            set(host),
        )


class RetainedReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = csp.load_json(csp.DEFAULT_REPORT)
        cls.manifest_path = csp.ROOT / cls.report["suite_manifest"]
        cls.manifest = csp.load_json(cls.manifest_path)
        cls.raw_cases = [
            (target, case, spec["guest"])
            for target, spec in cls.manifest["targets"].items()
            for case in spec["cases"]
        ]

    def test_report_is_the_complete_verified_standard_matrix(self) -> None:
        report = self.report
        expected_schema = (
            "stwo_riscv_csp_benchmark_v2"
            if self.manifest["schema"] == "stwo_riscv_csp_suite_v2"
            else "stwo_riscv_csp_benchmark_v1"
        )
        self.assertEqual(expected_schema, report["schema"])
        self.assertEqual(report["measurement_commit"], report["repository_head"])
        self.assertRegex(report["measurement_commit"], csp.HEX_40)
        self.assertEqual(
            csp.sha256_file(self.manifest_path),
            report["suite_manifest_sha256"],
        )
        summary = report["summary"]
        self.assertTrue(summary["all_outputs_match"])
        self.assertTrue(summary["all_peak_memory_available"])
        self.assertTrue(summary["all_proofs_verified"])
        self.assertEqual(len(self.raw_cases), summary["row_count"])
        self.assertEqual(len(self.manifest["targets"]), summary["target_count"])
        self.assertEqual(
            list(self.manifest["targets"]),
            report["run"]["targets"],
        )
        self.assertEqual(
            sorted({case["input_size"] for _, case, _ in self.raw_cases}),
            report["run"]["sizes"],
        )
        self.assertEqual(1, report["run"]["warmups"])
        self.assertEqual(10, report["run"]["samples"])
        self.assertTrue(report["run"]["complete_matrix"])

        measurements = report["measurements"]
        self.assertEqual(
            [
                (target, case["input_size"])
                for target, case, _ in self.raw_cases
            ],
            [(row["target"], row["input_size"]) for row in measurements],
        )
        for (target, case, guest), row in zip(
            self.raw_cases,
            measurements,
            strict=True,
        ):
            with self.subTest(target=target, size=case["input_size"]):
                self.assertEqual(case["expected_cycles"], row["cycles"])
                self.assertEqual(guest["bytes"], row["preprocessing_size"])
                self.assertFalse(row["uses_precompile"])
                self.assertGreater(row["proof_duration"], 0)
                self.assertGreater(row["verify_duration"], 0)
                self.assertGreater(row["proof_size"], 0)
                self.assertGreater(row["peak_memory"], 0)

                evidence = row["evidence"]
                self.assertEqual("verified", evidence["status"])
                self.assertEqual(case["input_sha256"], evidence["input_sha256"])
                self.assertEqual(guest["sha256"], evidence["guest_sha256"])
                self.assertEqual(case["expected_digest"], evidence["output_digest"])
                self.assertEqual(
                    case["expected_digest"],
                    evidence["expected_output_digest"],
                )
                self.assertRegex(evidence["proof_sha256"], csp.HEX_32)
                self.assertRegex(evidence["statement_sha256"], csp.HEX_32)
                receipt = evidence["retained_verify_receipt"]
                self.assertEqual("verified", receipt["status"])
                self.assertEqual(
                    evidence["statement_sha256"],
                    receipt["statement_sha256"],
                )
                self.assertEqual(evidence["proof_sha256"], receipt["proof_sha256"])
                self.assertEqual(
                    report["measurement_commit"],
                    receipt["implementation_commit"],
                )
                self.assertFalse(receipt["implementation_dirty"])

        if self.manifest["schema"] == "stwo_riscv_csp_suite_v2":
            self.assertTrue(summary["all_negative_fixtures_rejected"])
            self.assertEqual(
                [
                    (
                        fixture["name"],
                        fixture["target"],
                        "rejected_as_expected",
                    )
                    for fixture in self.manifest["negative_fixtures"]
                ],
                [
                    (item["name"], item["target"], item["status"])
                    for item in report["negative_validation"]
                ],
            )

    def test_report_preserves_security_and_host_qualification(self) -> None:
        report = self.report
        self.assertEqual("secure", report["security"]["profile"])
        self.assertEqual(csp.SECURE_PCS_CONFIG, report["security"]["pcs_config"])
        self.assertEqual("not_requested", report["source_audit"]["status"])
        self.assertNotIn("hostname", report["host"])
        self.assertEqual(
            report["host_matches_official_csp"],
            report["result_class"] == "official-host-comparable",
        )
        self.assertRegex(
            report["identities"]["prover_executable_sha256"],
            csp.HEX_32,
        )
        self.assertRegex(
            report["identities"]["trace_executable_sha256"],
            csp.HEX_32,
        )


class BuildRegistrationTests(unittest.TestCase):
    def test_standard_build_step_is_registered_once(self) -> None:
        product = (
            csp.ROOT / "build_support" / "products" / "riscv_cpu.zig"
        ).read_text(encoding="utf-8")
        catalog = (
            csp.ROOT / "build_support" / "products" / "catalog.zig"
        ).read_text(encoding="utf-8")
        self.assertEqual(1, product.count('"riscv-csp-bench"'))
        self.assertEqual(1, catalog.count('.name = "riscv-csp-bench"'))


if __name__ == "__main__":
    unittest.main()
