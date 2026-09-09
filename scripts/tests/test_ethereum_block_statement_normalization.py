import copy
import unittest

from autoresearch.benchmarks import ethereum_block_comparison as comparison
from autoresearch.benchmarks import ethereum_block_statement_normalization as subject


class NormalizationTest(unittest.TestCase):
    def setUp(self):
        self.manifest = comparison.load_manifest()
        host = self.manifest["stwo"]["semantic_projection"]["host_validation"]
        self.output = bytes.fromhex(host["new_payload_request_root"]) + b"\x01" + (1).to_bytes(8, "little") + (5121).to_bytes(2, "little")
        self.decoded = {"projection": {
            "schema": "stwo.ethereum.fixture-normalization-projection.v1",
            "block": {key: self.manifest["block"][key] for key in subject.BLOCK_FIELDS},
            "parent_state_root": "0x" + "12" * 32,
            "schema_id": 5121, "guest_execution_reproduced": False},
            "new_payload_request_root": "0x" + host["new_payload_request_root"]}

    def test_different_outputs_normalize_to_one_header_without_hash_equality(self):
        result = subject.validate_decoded_projection(self.decoded, self.manifest, self.output)
        self.assertNotEqual(result["new_payload_request_root"], result["block"]["hash"])
        self.assertEqual(result["block"]["number"], 24628607)
        self.assertEqual(result["schema_id"], 5121)
        self.assertFalse(self.decoded["projection"]["guest_execution_reproduced"])

    def test_every_header_field_is_bound(self):
        for field in subject.BLOCK_FIELDS:
            changed = copy.deepcopy(self.decoded)
            original = changed["projection"]["block"][field]
            changed["projection"]["block"][field] = original + 1 if type(original) is int else "0x" + "00" * 32
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "header differs"):
                subject.validate_decoded_projection(changed, self.manifest, self.output)

    def test_result_root_success_chain_and_fork_are_bound(self):
        for offset in (0, 32, 33, 41):
            changed = bytearray(self.output)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                subject.validate_decoded_projection(self.decoded, self.manifest, bytes(changed))
        with self.assertRaises(ValueError):
            subject.validate_decoded_projection(self.decoded, self.manifest, self.output + b"\0")

    def test_wrong_fork_and_execution_claim_are_rejected(self):
        for field, value in (("schema_id", 5122), ("guest_execution_reproduced", True)):
            changed = copy.deepcopy(self.decoded)
            changed["projection"][field] = value
            with self.assertRaises(ValueError):
                subject.validate_decoded_projection(changed, self.manifest, self.output)

    def test_zisk_output_pin_is_not_replaced_by_stwo_hash(self):
        changed = copy.deepcopy(self.manifest)
        changed["zisk"]["execution"]["output"]["sha256"] = changed["stwo"]["semantic_projection"]["host_validation"]["output_sha256"]
        with self.assertRaisesRegex(ValueError, "ZisK output statement"):
            subject.validate_decoded_projection(self.decoded, changed, self.output)

    def test_job_join_requires_same_elf_input_output_and_terminal_request(self):
        identities = {name: {"bytes": index + 1, "sha256": str(index) * 64}
                      for index, name in enumerate(("elf", "input", "expected_output"), 1)}
        admitted = {"source_request": {**copy.deepcopy(identities), "strict_completion": True},
                    "manifest": {"job": {"job_sha256": "a" * 64}, "segment_count": 121, "total_cycles": 253646998},
                    "source_request_identity": {"sha256": "b" * 64}}
        args = {"expected_elf": identities["elf"], "runner": identities["input"], "output": identities["expected_output"]}
        self.assertEqual(subject.validate_materialization_join(admitted, **args)["segment_count"], 121)
        for field in identities:
            for part in ("bytes", "sha256"):
                changed = copy.deepcopy(admitted)
                changed["source_request"][field][part] = 99 if part == "bytes" else "f" * 64
                with self.subTest(field=field, part=part), self.assertRaises(ValueError):
                    subject.validate_materialization_join(changed, **args)
        admitted["source_request"]["strict_completion"] = False
        with self.assertRaisesRegex(ValueError, "terminal"):
            subject.validate_materialization_join(admitted, **args)


if __name__ == "__main__":
    unittest.main()
