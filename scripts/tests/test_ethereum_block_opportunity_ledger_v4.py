from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch/benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_memcpy_execution_evidence as execution  # noqa: E402
import ethereum_block_opportunity_ledger_v4 as subject  # noqa: E402
import ethereum_block_pc_hotspot_retained_evidence as pc  # noqa: E402
import ethereum_block_poseidon_d5_telemetry_evidence as d5  # noqa: E402
import ethereum_block_post_allocator_opportunity_ledger as post  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def identity(label: str) -> dict:
    return {"path": f"/private/tmp/{label}", "bytes": 1, "sha256": digest(label)}


class OpportunityLedgerV4Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.post_identity = identity("post")
        self.current_identity = identity("current-v6")
        self.predecessor_identity = identity("predecessor-v5")
        self.pc_identity = identity("predecessor-v5-pc")
        self.d5_identity = identity("d5")
        self.input_identity = identity("input")
        self.baseline_journal = identity("baseline-journal")
        self.baseline = {
            "journal": self.baseline_journal,
            "segment_count": 72,
            "total_cycles": 100,
            "total_core_trace_rows": 90,
            "total_external_trace_rows": 10,
            "output_sha256": digest("output"),
        }
        self.post = {
            "schema": post.SCHEMA,
            "inputs": {"candidate_v3_journal": self.baseline_journal},
            "corpus": {
                "identity": self.baseline_journal,
                "header": {"elf_sha256": digest("baseline ELF")},
                "segment_count": 72,
                "total_cycles": 100,
                "total_core_trace_rows": 90,
                "total_external_trace_rows": 10,
                "output_sha256": digest("output"),
            },
            "alias_opportunities": {"candidate": "alias"},
            "poseidon_opportunity": {"candidate": "poseidon"},
            "keccak_opportunity": {"candidate": "keccak"},
            "memcpy_opportunity": {"candidate": "memcpy"},
        }
        self.current = self.execution_fixture(
            "v6", segment_count=68, core=70, external=10,
        )
        self.predecessor = self.execution_fixture(
            "v5", segment_count=68, core=80, external=10,
        )
        self.pc = {
            "schema": pc.SCHEMA,
            "inputs": {
                "memcpy_execution_evidence": self.predecessor_identity,
                "candidate_elf": self.predecessor["inputs"]["candidate_elf"],
                "candidate_journal": self.predecessor["inputs"][
                    "candidate_journal"
                ],
                "input": self.input_identity,
            },
            "sample": {"segment_count": 64, "retired_instructions": 75},
            "canonical_totals": {"retired_instructions": 75},
            "candidate_pc_range_projection": {"observed_rows": 25},
            "claim_boundary": {
                "prefix_only": True,
                "no_extrapolation": True,
                "production_active": False,
                "proof_correctness": None,
            },
            "process_measurement": {"performance_claim_eligible": False},
        }
        self.d5 = {
            "schema": d5.SCHEMA,
            "source_records": {
                "ab": {"production": False},
                "prepared_telemetry": [{"row_evaluation_ns": 100}],
            },
            "stage_ranking": {
                "best_measured_arm": "legacy_always",
                "degree5_never_faster_than_legacy_never": True,
                "degree5_retained_regresses_vs_legacy_retained": True,
            },
            "process_measurement": {"wall_ns": 1000},
            "claim_boundary": {
                "production_active": False,
                "executable_custody": None,
                "proof_artifacts_retained": False,
                "proof_correctness": None,
                "fresh_proof_verification": None,
                "measured_end_to_end_wall_ns": None,
                "performance_claim_eligible": False,
                "production_promotion_eligible": False,
            },
        }

    def execution_fixture(
        self, label: str, *, segment_count: int, core: int, external: int,
    ) -> dict:
        candidate_elf = identity(f"{label}-elf")
        candidate_journal = identity(f"{label}-journal")
        return {
            "schema": execution.SCHEMA,
            "inputs": {
                "post_allocator_ledger": self.post_identity,
                "baseline_journal": self.baseline_journal,
                "common_input": self.input_identity,
                "candidate_elf": candidate_elf,
                "candidate_journal": candidate_journal,
            },
            "executions": {
                "allocator_baseline": copy.deepcopy(self.baseline),
                "memcpy_candidate": {
                    "segment_count": segment_count,
                    "total_cycles": core + external,
                    "total_core_trace_rows": core,
                    "total_external_trace_rows": external,
                    "output_sha256": digest("output"),
                },
            },
            "equivalence": {
                "same_input_bytes_and_sha256": True,
                "same_output_bytes_and_sha256": True,
                "same_external_family_rows": True,
                "same_external_trace_rows": True,
                "program_and_elf_equal": False,
                "full_state_equivalence_claim": None,
            },
            "claim_boundary": {
                "production_active": False,
                "candidate_air_complete": None,
                "proof_correctness": None,
                "fresh_proof_verification": None,
                "measured_proving_end_to_end_wall_ns": None,
                "production_promotion_eligible": False,
            },
            "measurements": {"wall_comparison_fully_file_backed": True},
            "reductions": {"cycles": {"saved": 100 - core - external}},
        }

    def build(self) -> dict:
        return subject._build_loaded(
            self.post, self.post_identity,
            self.current, self.current_identity,
            self.predecessor, self.predecessor_identity,
            self.pc, self.pc_identity,
            self.d5, self.d5_identity,
        )

    def test_current_predecessor_and_stage_scopes_stay_separate(self) -> None:
        value = self.build()
        self.assertTrue(value["current_memcpy_v6_execution"][
            "current_candidate"
        ])
        self.assertTrue(value["predecessor_memcpy_v5"][
            "superseded_by_current"
        ])
        self.assertFalse(value["predecessor_memcpy_v5"]["pc_prefix"][
            "applies_to_current_memcpy_v6"
        ])
        self.assertFalse(value["poseidon_d5_stage_diagnostic"][
            "applies_to_current_memcpy_v6_block_proof"
        ])
        self.assertIsNone(value["claims"]["full_block_proof_complete"])
        self.assertIsNone(value["claims"]["measured_proving_end_to_end_wall_ns"])
        self.assertFalse(value["claims"]["production_promotion_eligible"])

    def test_wrong_pc_join_and_bool_as_int_reject(self) -> None:
        self.pc["inputs"]["memcpy_execution_evidence"] = self.current_identity
        with self.assertRaises(subject.OpportunityLedgerV4Error):
            self.build()

        self.pc["inputs"][
            "memcpy_execution_evidence"
        ] = self.predecessor_identity
        self.current["claim_boundary"]["production_active"] = 0
        with self.assertRaises(subject.OpportunityLedgerV4Error):
            self.build()

    def test_resealed_promotion_mutation_fails_replay(self) -> None:
        value = self.build()
        with (
            mock.patch.object(subject, "_validate_identity"),
            mock.patch.object(subject, "build", return_value=value),
        ):
            self.assertIs(subject.validate(value), value)
            changed = copy.deepcopy(value)
            changed["claims"]["production_promotion_eligible"] = 0
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(subject.OpportunityLedgerV4Error):
                subject.validate(changed)


if __name__ == "__main__":
    unittest.main()
