from __future__ import annotations

import copy
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch/benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_memcpy_execution_evidence as execution  # noqa: E402
import ethereum_block_pc_hotspot_retained_evidence as subject  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts.tests.test_ethereum_block_pc_hotspot_evidence import (  # noqa: E402
    observation,
    write_journal,
)


class RetainedPcHotspotEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.elf = self.root / "candidate.elf"
        self.input = self.root / "input.bin"
        self.journal = self.root / "execution-v3.ndjson"
        self.elf.write_bytes(b"candidate ELF")
        self.input.write_bytes(b"ethereum input")
        write_journal(self.journal, self.elf.read_bytes(), self.input.read_bytes())
        observed = observation(self.elf, self.input, self.journal)
        mapping = {0x1000: 0x870, 0x1004: 0x874, 0x1008: 0x878}
        for row in observed["per_pc"]:
            row["pc"] = mapping[row["pc"]]
        for row in observed["basic_edges"]:
            row["from_pc"] = mapping[row["from_pc"]]
            row["to_pc"] = mapping[row["to_pc"]]
        observed["content_sha256"] = protocol.content_sha256(observed)
        self.observation = self.root / "observation.json"
        self.observation.write_bytes(protocol.canonical_bytes(observed))
        self.executable = self.root / "observer"
        self.executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.executable.chmod(self.executable.stat().st_mode | stat.S_IXUSR)
        self.source = self.root / "observer.zig"
        self.source.write_bytes(b"// observer source\n")
        self.timing = self.root / "observer.time"
        self.timing.write_text(
            "real 0.50\nuser 0.40\nsys 0.10\n"
            " 100 maximum resident set size\n 0 swaps\n"
            " 120 peak memory footprint\n",
            encoding="ascii",
        )
        self.execution_path = self.root / "execution-evidence.json"
        self.execution_path.write_bytes(b"execution evidence")
        self.execution_identity = subject._identity(
            self.execution_path, "execution evidence",
        )
        elf_identity = subject._identity(self.elf, "candidate ELF")
        input_identity = subject._identity(self.input, "input")
        journal_identity = subject._identity(self.journal, "journal")
        self.execution = {
            "schema": execution.SCHEMA,
            "inputs": {
                "candidate_elf": elf_identity,
                "candidate_journal": journal_identity,
                "common_input": input_identity,
            },
            "executions": {
                "memcpy_candidate": {
                    "journal": journal_identity,
                    "elf_sha256": elf_identity["sha256"],
                    "input_sha256": input_identity["sha256"],
                    "segment_count": 2,
                },
            },
            "equivalence": {"same_output_bytes_and_sha256": True},
            "claim_boundary": {"proof_correctness": None},
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self) -> dict:
        return subject._normalized(
            observation_path=self.observation,
            executable_path=self.executable,
            observer_source_path=self.source,
            timing_log_path=self.timing,
            execution=self.execution,
            execution_identity=self.execution_identity,
            first_segment_index=0,
            segment_count=2,
        )

    def test_replays_full_observation_and_projects_only_exact_range(self) -> None:
        value = self.build()
        self.assertEqual(value["canonical_totals"]["retired_instructions"], 9)
        self.assertEqual(value["candidate_pc_range_projection"]["observed_rows"], 9)
        self.assertEqual(value["candidate_pc_range_projection"]["entry_count"], 3)
        self.assertFalse(value["process_measurement"]["performance_claim_eligible"])
        self.assertIsNone(value["candidate_pc_range_projection"]["symbol_map_receipt"])
        self.assertIsNone(value["claim_boundary"]["proof_correctness"])
        self.assertIsNone(value["claim_boundary"]["measured_end_to_end_wall_ns"])

    def test_bool_as_int_and_observation_mutations_reject(self) -> None:
        self.execution["equivalence"]["same_output_bytes_and_sha256"] = 1
        with self.assertRaises(subject.RetainedPcHotspotEvidenceError):
            self.build()

        self.execution["equivalence"]["same_output_bytes_and_sha256"] = True
        value = json.loads(self.observation.read_bytes())
        value["basic_edges"][0]["count"] += 1
        value["content_sha256"] = protocol.content_sha256(value)
        self.observation.write_bytes(protocol.canonical_bytes(value))
        with self.assertRaises(subject.RetainedPcHotspotEvidenceError):
            self.build()

    def test_resealed_promotion_mutation_fails_replay(self) -> None:
        value = self.build()
        with mock.patch.object(subject, "build", return_value=value):
            self.assertIs(subject.validate(value), value)
            changed = copy.deepcopy(value)
            changed["claim_boundary"]["production_promotion_eligible"] = 0
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(subject.RetainedPcHotspotEvidenceError):
                subject.validate(changed)


if __name__ == "__main__":
    unittest.main()
