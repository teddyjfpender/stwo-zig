from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch/benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_allocator_execution_evidence as allocator  # noqa: E402
import ethereum_block_memcpy_hotspot_evidence as memcpy  # noqa: E402
import ethereum_block_opportunity_ledger_v2 as ledger_v2  # noqa: E402
import ethereum_block_opportunity_ledger_v3 as subject  # noqa: E402
import ethereum_block_provider_retention_evidence as retention  # noqa: E402


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def ratio(saved: int, baseline: int) -> dict:
    return {"saved": saved, "baseline": baseline,
            "millionths": saved * 1_000_000 // baseline}


class OpportunityLedgerV3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

        def identity(name: str) -> dict:
            path = self.root / name
            path.write_bytes(name.encode("ascii"))
            return {
                "path": str(path), "bytes": len(name),
                "sha256": hashlib.sha256(name.encode("ascii")).hexdigest(),
            }

        self.base_identity = identity("base.json")
        self.allocator_identity = identity("allocator.json")
        self.retention_identity = identity("retention.json")
        self.memcpy_identity = identity("memcpy.json")
        self.journal = identity("journal.ndjson")
        self.baseline_elf = identity("baseline.elf")
        self.candidate_elf = identity("candidate.elf")
        self.input = identity("input.bin")
        corpus = {
            "segment_count": 10, "total_cycles": 100,
            "total_core_trace_rows": 95, "total_external_trace_rows": 5,
            "output_bytes": 3, "output_sha256": digest("output"),
        }
        self.base = {
            "schema": ledger_v2.SCHEMA,
            "base_ledger_v1": {
                "inputs": {"journal": self.journal},
                "corpus": corpus,
            },
        }
        baseline = {
            "journal_schema": "stwo.riscv.segmented-execution-header.v3",
            **corpus,
        }
        candidate = {
            "journal_schema": "stwo.riscv.segmented-execution-header.v2",
            "segment_count": 4, "total_cycles": 40,
            "total_core_trace_rows": 35, "total_external_trace_rows": 5,
            "output_bytes": 3, "output_sha256": digest("output"),
        }
        self.allocator = {
            "schema": allocator.SCHEMA,
            "content_sha256": digest("allocator content"),
            "inputs": {
                "baseline_journal": self.journal,
                "baseline_elf": self.baseline_elf,
                "candidate_elf": self.candidate_elf,
                "common_input": self.input,
            },
            "executions": {"baseline": baseline, "candidate": candidate},
            "equivalence": {
                "same_input_bytes_and_sha256": True,
                "same_output_bytes_and_sha256": True,
                "program_and_elf_equal": False,
            },
            "reductions": {
                "cycles": ratio(60, 100),
                "core_trace_rows": ratio(60, 95),
                "segments": ratio(6, 10),
                "reported_wall_ns": ratio(60, 100),
            },
            "promotion": {
                "proof_completion": None,
                "measured_end_to_end_wall_ns": None,
            },
        }
        self.retention = {
            "schema": retention.EVIDENCE_SCHEMA,
            "content_sha256": digest("retention content"),
            "measured_arms": [
                {"policy": "always", "proof_batch_wall_ns": 10},
                {"policy": "never", "proof_batch_wall_ns": 23},
            ],
            "measured_retention_speedup_milli": 2300,
            "ranking": {
                "scope": "standalone-provider-coefficient-retention-stage-only",
                "fresh_verification": True,
                "estimated_end_to_end_wall_ns": None,
                "production_promotion_eligible": False,
            },
        }
        sample = {
            "segment_count": 3,
            "full_journal_segment_count": 4,
            "full_journal_total_cycles": 40,
            "full_journal_total_core_trace_rows": 35,
            "full_journal_total_external_trace_rows": 5,
            "full_journal_output_sha256": digest("output"),
            "call_count": 7,
        }
        self.memcpy = {
            "schema": memcpy.EVIDENCE_SCHEMA,
            "content_sha256": digest("memcpy content"),
            "inputs": {
                "allocator_execution_evidence": self.allocator_identity,
                "candidate_elf": self.candidate_elf,
                "input": self.input,
            },
            "sample": sample,
            "process_measurement": {"wall_ns": 10},
            "claim_boundary": {
                "prefix_only": True,
                "no_extrapolation": True,
                "proof_correctness": None,
                "measured_end_to_end_wall_ns": None,
            },
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self) -> dict:
        return subject._build_loaded(
            self.base, self.base_identity,
            self.allocator, self.allocator_identity,
            self.retention, self.retention_identity,
            self.memcpy, self.memcpy_identity,
        )

    def test_preserves_scopes_and_nulls_all_proof_e2e_claims(self) -> None:
        value = self.build()
        self.assertEqual(
            value["allocator_execution_candidate"]["cycle_reduction"]["saved"], 60,
        )
        self.assertEqual(
            value["provider_retention_stage"]["measured_retention_speedup_milli"],
            2300,
        )
        self.assertIsNone(value["memcpy_candidate_prefix"]["air_component_complete"])
        self.assertIsNone(value["claims"]["full_block_proof_complete"])
        self.assertFalse(value["claims"]["production_promotion_eligible"])

    def test_bool_as_int_and_cross_corpus_mutations_reject(self) -> None:
        self.allocator["equivalence"]["same_input_bytes_and_sha256"] = 1
        with self.assertRaises(subject.OpportunityLedgerV3Error):
            self.build()

        self.allocator["equivalence"]["same_input_bytes_and_sha256"] = True
        self.memcpy["sample"]["full_journal_total_cycles"] = 41
        with self.assertRaises(subject.OpportunityLedgerV3Error):
            self.build()


if __name__ == "__main__":
    unittest.main()
