from __future__ import annotations

import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch/benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_keccak_words_execution_evidence as subject  # noqa: E402
import ethereum_block_memcpy_execution_evidence as memcpy  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts.tests.test_ethereum_block_allocator_execution_evidence import (  # noqa: E402
    write_journal,
)


class KeccakWordsExecutionEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.baseline_elf = self.root / "baseline.elf"
        self.candidate_elf = self.root / "candidate.elf"
        self.input = self.root / "input.bin"
        self.baseline_elf.write_bytes(b"memcpy v6")
        self.candidate_elf.write_bytes(b"word sponge")
        self.input.write_bytes(b"ethereum input")
        self.baseline_journal = self.root / "baseline.ndjson"
        self.candidate_journal = self.root / "candidate.ndjson"
        write_journal(
            self.baseline_journal, self.baseline_elf.read_bytes(),
            self.input.read_bytes(), (5, 4), legacy_v2=False,
        )
        write_journal(
            self.candidate_journal, self.candidate_elf.read_bytes(),
            self.input.read_bytes(), (5,), legacy_v2=False,
        )
        self.baseline_elf_identity = subject._identity(
            self.baseline_elf, "baseline ELF",
        )
        self.input_identity = subject._identity(self.input, "input")
        self.baseline = memcpy._journal(
            self.baseline_journal, self.baseline_elf_identity,
            self.input_identity, "baseline journal",
        )
        self.baseline_identity = subject._identity(
            self.root / "baseline-evidence.json", "baseline evidence",
        ) if (self.root / "baseline-evidence.json").exists() else {
            "path": str((self.root / "baseline-evidence.json").absolute()),
            "bytes": 1,
            "sha256": "0" * 64,
        }
        self.baseline_evidence = {
            "schema": memcpy.SCHEMA,
            "inputs": {
                "common_input": self.input_identity,
                "candidate_elf": self.baseline_elf_identity,
                "candidate_journal": self.baseline["journal"],
            },
            "executions": {"memcpy_candidate": self.baseline},
            "equivalence": {
                "same_output_bytes_and_sha256": True,
                "same_external_family_rows": True,
            },
            "measurements": {
                "memcpy_candidate_process": {
                    "retained_process_log": True,
                    "scope": "whole-segmented-execution-cli-process",
                    "wall_ns": 2_000_000_000,
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
        self.candidate_timing = self.root / "candidate.time"
        self.build_timing = self.root / "build.time"
        self.write_timing(self.candidate_timing, "1.00")
        self.write_timing(self.build_timing, "3.00")
        self.trace = self.root / "trace"
        self.trace.write_bytes(b"trace executable")
        self.sources = []
        for index, role in enumerate(subject.SOURCE_ROLES):
            path = self.root / f"source-{index}"
            path.write_bytes(role.encode("ascii"))
            self.sources.append((role, path))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_timing(path: Path, real: str) -> None:
        path.write_text(
            f"real {real}\nuser 1.00\nsys 0.25\n"
            " 100 maximum resident set size\n 0 swaps\n"
            " 120 peak memory footprint\n",
            encoding="ascii",
        )

    def build(self) -> dict:
        return subject._build_loaded(
            self.baseline_evidence, self.baseline_identity,
            self.candidate_journal, self.candidate_elf,
            self.candidate_timing, self.build_timing, self.trace, self.sources,
        )

    def test_execution_equivalence_and_only_measured_execution_reduction(self) -> None:
        value = self.build()
        self.assertEqual(value["reductions"]["cycles"]["saved"], 4)
        self.assertEqual(value["reductions"]["segments"]["saved"], 1)
        self.assertTrue(value["equivalence"]["same_external_family_rows"])
        self.assertIsNone(value["equivalence"]["full_state_equivalence_claim"])
        self.assertIsNone(value["claim_boundary"]["proof_correctness"])
        self.assertIsNone(value["claim_boundary"][
            "measured_proving_end_to_end_wall_ns"
        ])

    def test_bool_as_int_and_resealed_promotion_reject(self) -> None:
        self.baseline_evidence["claim_boundary"]["production_active"] = 0
        with self.assertRaises(subject.KeccakWordsExecutionEvidenceError):
            self.build()

        self.baseline_evidence["claim_boundary"]["production_active"] = False
        value = self.build()
        with (
            mock.patch.object(subject, "_validate_identity"),
            mock.patch.object(subject, "_build_loaded", return_value=value),
            mock.patch.object(memcpy, "load", return_value=self.baseline_evidence),
        ):
            changed = copy.deepcopy(value)
            changed["claim_boundary"]["production_promotion_eligible"] = 0
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(subject.KeccakWordsExecutionEvidenceError):
                subject.validate(changed)


if __name__ == "__main__":
    unittest.main()
