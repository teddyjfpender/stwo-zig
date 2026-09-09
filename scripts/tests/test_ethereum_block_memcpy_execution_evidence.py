from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch/benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_allocator_execution_evidence as allocator  # noqa: E402
import ethereum_block_memcpy_execution_evidence as subject  # noqa: E402
import ethereum_block_post_allocator_opportunity_ledger as post  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402
from scripts.tests.test_ethereum_block_allocator_execution_evidence import (  # noqa: E402
    write_journal,
)


class MemcpyExecutionEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.baseline_elf = self.root / "baseline.elf"
        self.candidate_elf = self.root / "candidate.elf"
        self.input = self.root / "input.bin"
        self.baseline_elf.write_bytes(b"allocator baseline")
        self.candidate_elf.write_bytes(b"memcpy candidate")
        self.input.write_bytes(b"ethereum input")
        self.baseline_journal = self.root / "baseline-v3.ndjson"
        self.candidate_journal = self.root / "candidate-v3.ndjson"
        write_journal(
            self.baseline_journal, self.baseline_elf.read_bytes(),
            self.input.read_bytes(), (5, 4), legacy_v2=False,
        )
        write_journal(
            self.candidate_journal, self.candidate_elf.read_bytes(),
            self.input.read_bytes(), (5,), legacy_v2=False,
        )
        self.timing = self.root / "candidate.time"
        self.timing.write_text(
            "real 0.75\nuser 0.50\nsys 0.25\n"
            " 100 maximum resident set size\n 0 swaps\n"
            " 120 peak memory footprint\n",
            encoding="ascii",
        )
        self.source = self.root / "fast_word_memcpy_v3.rs"
        self.source.write_bytes(b"candidate source")
        self.allocator_path = self.root / "allocator-evidence.json"
        self.allocator_path.write_bytes(b"allocator evidence")
        self.post_path = self.root / "post-ledger.json"
        self.post_path.write_bytes(b"post ledger")
        self.allocator_identity = subject._identity(
            self.allocator_path, "allocator fixture",
        )
        self.post_identity = subject._identity(self.post_path, "post fixture")
        self.baseline_elf_identity = subject._identity(
            self.baseline_elf, "baseline ELF",
        )
        self.input_identity = subject._identity(self.input, "input")
        self.baseline_journal_identity = subject._identity(
            self.baseline_journal, "baseline journal",
        )
        self.allocator = {
            "schema": allocator.SCHEMA,
            "inputs": {
                "candidate_elf": self.baseline_elf_identity,
                "common_input": self.input_identity,
            },
            "measurements": {
                "candidate_process": {
                    "maximum_resident_set_size_bytes": 200,
                    "peak_memory_footprint_bytes": 220,
                    "retained_process_log": True,
                    "scope": "whole-segmented-execution-cli-process",
                    "swaps": 0,
                    "system_ns": 250_000_000,
                    "user_ns": 750_000_000,
                    "wall_ns": 1_000_000_000,
                },
            },
        }
        self.post = {
            "schema": post.SCHEMA,
            "inputs": {
                "allocator_execution_evidence": self.allocator_identity,
                "candidate_v3_journal": self.baseline_journal_identity,
            },
            "corpus": {
                "identity": self.baseline_journal_identity,
                "header": {
                    "elf_sha256": self.baseline_elf_identity["sha256"],
                    "input_sha256": self.input_identity["sha256"],
                },
            },
            "claims": {
                "full_block_proof_complete": None,
                "measured_end_to_end_wall_ns": None,
            },
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self) -> dict:
        return subject._build_loaded(
            self.post, self.post_identity,
            self.allocator, self.allocator_identity,
            self.candidate_journal, self.candidate_elf, self.timing, self.source,
        )

    def test_output_external_and_measured_execution_reductions_only(self) -> None:
        value = self.build()
        self.assertEqual(value["reductions"]["cycles"]["saved"], 4)
        self.assertEqual(value["reductions"]["segments"]["saved"], 1)
        self.assertEqual(value["reductions"]["measured_wall_ns"]["saved"],
                         250_000_000)
        self.assertTrue(value["equivalence"]["same_external_family_rows"])
        self.assertFalse(value["equivalence"]["program_and_elf_equal"])
        self.assertFalse(value["equivalence"]["final_cpu_sha256_equal"])
        self.assertIsNone(value["equivalence"]["full_state_equivalence_claim"])
        self.assertIsNone(value["claim_boundary"]["proof_correctness"])
        self.assertIsNone(value["claim_boundary"]["measured_proving_end_to_end_wall_ns"])

    def test_bool_as_int_and_output_mutations_reject(self) -> None:
        self.allocator["measurements"]["candidate_process"][
            "retained_process_log"
        ] = 1
        with self.assertRaises(subject.MemcpyExecutionEvidenceError):
            self.build()

        self.allocator["measurements"]["candidate_process"][
            "retained_process_log"
        ] = True
        self.post["claims"]["full_block_proof_complete"] = False
        with self.assertRaises(subject.MemcpyExecutionEvidenceError):
            self.build()

    def test_resealed_promotion_mutation_fails_replay(self) -> None:
        value = self.build()
        with mock.patch.object(subject, "build", return_value=value):
            self.assertIs(subject.validate(value), value)
            mutated = copy.deepcopy(value)
            mutated["claim_boundary"]["production_promotion_eligible"] = 0
            mutated["content_sha256"] = protocol.content_sha256(mutated)
            with self.assertRaises(subject.MemcpyExecutionEvidenceError):
                subject.validate(mutated)

    def test_candidate_journal_byte_mutation_is_detected(self) -> None:
        value = self.build()
        self.candidate_journal.write_bytes(
            self.candidate_journal.read_bytes() + b"mutation",
        )
        with self.assertRaises((subject.MemcpyExecutionEvidenceError,
                                protocol.ProofProtocolError)):
            subject._validate_identity(
                value["inputs"]["candidate_journal"], "candidate journal",
            )


if __name__ == "__main__":
    unittest.main()
