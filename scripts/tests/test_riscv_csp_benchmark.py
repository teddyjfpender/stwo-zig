from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import riscv_csp_benchmark as csp


class ManifestContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest, cls.cases = csp.validate_manifest()

    def test_checked_manifest_is_the_complete_pinned_hash_matrix(self) -> None:
        self.assertEqual(
            "269c43cc32d3127e3d9ce74d20652887d894cca3",
            self.manifest["upstream"]["commit"],
        )
        self.assertEqual(
            [
                (target, size)
                for target in csp.TARGET_ORDER
                for size in csp.CANONICAL_SIZES
            ],
            [(case.target, case.input_size) for case in self.cases],
        )
        self.assertTrue(all(not case.uses_precompile for case in self.cases))

    def test_every_committed_fixture_is_authenticated(self) -> None:
        for case in self.cases:
            self.assertEqual(case.input_sha256, csp.sha256_file(case.input_path))
            self.assertEqual(case.guest_sha256, csp.sha256_file(case.guest_path))

    def test_manifest_rejects_duplicate_json_fields(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "duplicate.json"
            path.write_text(
                '{"schema":"stwo_riscv_csp_suite_v1","schema":"substitution"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(csp.BenchmarkError, "repeats field"):
                csp.load_json(path)

    def test_manifest_target_substitution_fails_closed(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["targets"]["sha256"]["uses_precompile"] = True
        with mock.patch.object(csp, "load_json", return_value=changed):
            with self.assertRaisesRegex(csp.BenchmarkError, "explicit RV32IM"):
                csp.validate_manifest()

    def test_unsupported_target_ledger_cannot_silently_shrink(self) -> None:
        changed = copy.deepcopy(self.manifest)
        del changed["unsupported_targets"]["ecdsa"]
        with mock.patch.object(csp, "load_json", return_value=changed):
            with self.assertRaisesRegex(csp.BenchmarkError, "ledger drifted"):
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
