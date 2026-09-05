from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch/benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_bulk_memcpy_admission_evidence as subject  # noqa: E402
import ethereum_block_keccak_words_execution_evidence as execution  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402


def identity(path: Path) -> dict:
    return subject._identity(path, "fixture")


class BulkMemcpyAdmissionEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.elf = self.root / "candidate.elf"
        self.input = self.root / "input.bin"
        self.journal = self.root / "candidate.ndjson"
        self.elf.write_bytes(b"candidate ELF")
        self.input.write_bytes(b"ethereum input")
        self.journal.write_bytes(b"journal")
        self.elf_identity = identity(self.elf)
        self.input_identity = identity(self.input)
        self.journal_identity = identity(self.journal)
        self.execution_path = self.root / "execution-evidence.json"
        self.execution_path.write_bytes(b"execution evidence")
        self.execution_identity = identity(self.execution_path)
        self.execution = {
            "schema": execution.SCHEMA,
            "inputs": {
                "candidate_elf": self.elf_identity,
                "candidate_journal": self.journal_identity,
                "common_input": self.input_identity,
            },
            "executions": {
                "keccak_words_candidate": {
                    "elf_sha256": self.elf_identity["sha256"],
                    "input_sha256": self.input_identity["sha256"],
                    "journal": self.journal_identity,
                    "segment_count": 2,
                    "total_cycles": 100,
                    "total_core_trace_rows": 90,
                },
            },
            "claim_boundary": {
                "production_active": False,
                "candidate_air_complete": None,
                "proof_correctness": None,
                "fresh_proof_verification": None,
                "measured_proving_end_to_end_wall_ns": None,
                "production_promotion_eligible": False,
            },
        }
        self.observation = self.root / "observation.json"
        self.write_observation()
        self.executable = self.root / "observer"
        self.source = self.root / "observer.zig"
        self.timing = self.root / "observer.time"
        self.executable.write_bytes(b"observer executable")
        self.source.write_bytes(b"observer source")
        self.timing.write_text(
            "real 0.50\nuser 0.40\nsys 0.10\n"
            " 100 maximum resident set size\n 0 swaps\n"
            " 120 peak memory footprint\n",
            encoding="ascii",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def observation_value(self) -> dict:
        empty = {
            "calls": 0, "requested_bytes": 0,
            "software_rows": 0, "word_rows": 0,
        }
        return protocol.seal({
            "admission_predicate": subject.PREDICATE,
            "admitted": {
                "calls": 2, "requested_bytes": 128,
                "software_rows": 12, "word_rows": 32,
            },
            "aligned_word_overlap": copy.deepcopy(empty),
            "alignment_mismatch": {
                "calls": 1, "requested_bytes": 33,
                "software_rows": 3, "word_rows": 0,
            },
            "byte_overlap": copy.deepcopy(empty),
            "clock_frame": "leaf_local",
            "completed_call_count": 3,
            "elf_sha256": self.elf_identity["sha256"],
            "endpoint_invalid": copy.deepcopy(empty),
            "execution_profile": "rv32im-zkvm-ethereum-v1",
            "first_global_cycle": 1,
            "first_segment_index": 0,
            "input_sha256": self.input_identity["sha256"],
            "journal_sha256": self.journal_identity["sha256"],
            "memcpy_entry_pc": 0x880,
            "production": False,
            "removable_core_rows": 10,
            "retired_instructions": 90,
            "sampled_cycles": 100,
            "schema": subject.OBSERVATION_SCHEMA,
            "segment_count": 2,
            "status": subject.OBSERVATION_STATUS,
            "too_short": copy.deepcopy(empty),
            "total_software_rows_in_memcpy": 15,
            "validated_register_reads": 120,
        })

    def write_observation(self) -> None:
        self.observation.write_bytes(
            protocol.canonical_bytes(self.observation_value()),
        )

    def build(self) -> dict:
        return subject._build_loaded(
            self.execution, self.execution_identity, self.observation,
            self.executable, self.source, self.timing,
        )

    def test_complete_sample_projection_stays_unmeasured_and_nonpromotable(self) -> None:
        value = self.build()
        self.assertTrue(value["sample"]["sample_is_complete_execution"])
        self.assertTrue(value["sample"]["no_extrapolation"])
        self.assertEqual(value["execution_projection"][
            "predicted_core_trace_rows"
        ], 80)
        self.assertFalse(value["execution_projection"][
            "measured_candidate_execution"
        ])
        self.assertIsNone(value["claim_boundary"]["proof_correctness"])
        self.assertIsNone(value["claim_boundary"]["measured_end_to_end_wall_ns"])
        self.assertFalse(value["claim_boundary"]["performance_claim_eligible"])

    def test_bool_bucket_and_resealed_promotion_mutations_reject(self) -> None:
        changed = self.observation_value()
        changed["production"] = 0
        changed["content_sha256"] = protocol.content_sha256(changed)
        self.observation.write_bytes(protocol.canonical_bytes(changed))
        with self.assertRaises(subject.BulkMemcpyAdmissionEvidenceError):
            self.build()

        changed = self.observation_value()
        changed["completed_call_count"] += 1
        changed["content_sha256"] = protocol.content_sha256(changed)
        self.observation.write_bytes(protocol.canonical_bytes(changed))
        with self.assertRaises(subject.BulkMemcpyAdmissionEvidenceError):
            self.build()

        self.write_observation()
        value = self.build()
        with (
            mock.patch.object(subject, "_validate_identity"),
            mock.patch.object(subject, "_build_loaded", return_value=value),
            mock.patch.object(execution, "load", return_value=self.execution),
        ):
            changed = copy.deepcopy(value)
            changed["claim_boundary"]["production_promotion_eligible"] = 0
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(subject.BulkMemcpyAdmissionEvidenceError):
                subject.validate(changed)


if __name__ == "__main__":
    unittest.main()
