from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch/benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_evm_micro_op_candidate_matrix_v8 as subject  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402


class EvmMicroOpCandidateMatrixV8Tests(unittest.TestCase):
    def test_word_alu_boundary_is_recomputed_not_summed(self) -> None:
        symbols = [
            {
                "symbol": "revm_interpreter::instructions::arithmetic::add",
                "category": "arithmetic", "opcode_group": "add",
                "observed_rows": 5,
            },
            {
                "symbol": "revm_interpreter::instructions::bitwise::eq",
                "category": "bitwise", "opcode_group": "eq",
                "observed_rows": 4,
            },
        ]
        edges = [
            ("outside", symbols[0]["symbol"], 2),
            (symbols[0]["symbol"], symbols[0]["symbol"], 2),
            (symbols[0]["symbol"], symbols[1]["symbol"], 1),
            (symbols[1]["symbol"], symbols[1]["symbol"], 3),
            (symbols[1]["symbol"], "outside", 1),
        ]
        candidate = subject._candidate(
            "word-alu-v1", ("arithmetic", "bitwise"), "typed-air",
            symbols, [], [], edges, 9,
        )
        self.assertEqual(candidate["observed_rows"], 9)
        self.assertEqual(candidate["observed_outside_candidate_entries"], 2)
        self.assertEqual(candidate["observed_internal_cross_symbol_edges"], 1)
        self.assertEqual(candidate["observed_self_symbol_edges"], 5)
        self.assertEqual(candidate["rows_without_observed_incoming_edge"], 1)
        self.assertEqual(
            candidate["observed_one_row_dispatch_upper_bound_removable_rows"], 7,
        )

    def candidate(self, candidate_id: str, rank: int) -> dict:
        rows, entries, self_edges = 100 - rank, 2, 90 - rank
        return {
            "candidate_id": candidate_id,
            "priority_rank": rank,
            "selected_for_first_tranche": rank <= subject.SELECTED_COUNT,
            "production_active": False,
            "observed_rows": rows,
            "observed_outside_candidate_entries": entries,
            "observed_self_symbol_edges": self_edges,
            "rows_per_observed_outside_entry": subject._ratio(rows, entries),
            "self_loop_concentration": subject._ratio(self_edges, rows),
            "observed_one_row_dispatch_upper_bound_removable_rows": rows - entries,
            **{
                name: None for name in (
                    "candidate_implementation_identity", "candidate_active_rows",
                    "candidate_padded_rows", "candidate_main_columns",
                    "candidate_main_cells", "candidate_saved_execution_rows",
                    "candidate_saved_main_cells", "candidate_proof_identity",
                    "fresh_candidate_verification", "candidate_end_to_end_wall_ns",
                )
            },
        }

    def fixture(self) -> dict:
        identity = {
            "path": "/private/tmp/source", "bytes": 1, "sha256": "1" * 64,
        }
        ids = [spec[0] for spec in subject.FAMILY_SPECS]
        candidates = [
            self.candidate(candidate_id, rank)
            for rank, candidate_id in enumerate(ids, start=1)
        ]
        return protocol.seal({
            "schema": subject.SCHEMA,
            "status": subject.STATUS,
            "inputs": {
                "prior_census_v7": copy.deepcopy(identity),
                "prior_v7_inputs": {},
                "pc_observation": copy.deepcopy(identity),
                "symbol_map": copy.deepcopy(identity),
            },
            "partition_authority": {},
            "candidate_matrix": candidates,
            "ranking": {
                "selected_count": subject.SELECTED_COUNT,
                "selected_candidate_ids": ids[:subject.SELECTED_COUNT],
                "independent_gain_multiplication_used": False,
                "selected_candidate_saved_execution_rows": None,
                "selected_candidate_saved_main_cells": None,
                "selected_candidate_end_to_end_wall_ns": None,
            },
            "claim_boundary": {
                "candidate_implementations_available": False,
                "candidate_cells_available": False,
                "proof_correctness": None,
                "fresh_proof_verification": None,
                "measured_end_to_end_wall_ns": None,
                "performance_claim_eligible": False,
                "production_active": False,
            },
        })

    def test_resealed_bound_cell_and_boolean_mutations_reject(self) -> None:
        value = self.fixture()
        with (
            mock.patch.object(subject, "_validate_identity"),
            mock.patch.object(subject, "build", return_value=value),
        ):
            self.assertIs(subject.validate(value), value)
            changed = copy.deepcopy(value)
            changed["candidate_matrix"][0][
                "observed_one_row_dispatch_upper_bound_removable_rows"
            ] += 1
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(subject.EvmMicroOpCandidateMatrixV8Error):
                subject.validate(changed)

            changed = copy.deepcopy(value)
            changed["candidate_matrix"][0]["candidate_main_cells"] = 0
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(subject.EvmMicroOpCandidateMatrixV8Error):
                subject.validate(changed)

            changed = copy.deepcopy(value)
            changed["claim_boundary"]["production_active"] = 0
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(subject.EvmMicroOpCandidateMatrixV8Error):
                subject.validate(changed)


if __name__ == "__main__":
    unittest.main()
