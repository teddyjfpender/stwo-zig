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

import ethereum_block_evm_micro_op_census_v7 as subject  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402


class EvmMicroOpCensusV7Tests(unittest.TestCase):
    def test_only_named_nm_stderr_may_be_empty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty"
            path.write_bytes(b"")
            identity = {
                "path": str(path), "bytes": 0,
                "sha256": protocol.sha256_bytes(b""),
            }
            self.assertEqual(
                subject._validate_identity_map(
                    {"nm_stderr": identity}, "PC census input",
                )["nm_stderr"],
                identity,
            )
            with self.assertRaises(subject.EvmMicroOpCensusV7Error):
                subject._validate_identity_map(
                    {"other": identity}, "PC census input",
                )

    def test_exact_symbol_and_group_boundary_census(self) -> None:
        observation = {
            "retired_instructions": 11,
            "transition_count": 9,
            "per_pc": [
                {"pc": 0x400, "count": 2},
                {"pc": 0x500, "count": 5},
                {"pc": 0x600, "count": 4},
            ],
            "basic_edges": [
                {"from_pc": 0x400, "to_pc": 0x500, "count": 2},
                {"from_pc": 0x500, "to_pc": 0x500, "count": 2},
                {"from_pc": 0x500, "to_pc": 0x600, "count": 1},
                {"from_pc": 0x600, "to_pc": 0x600, "count": 3},
                {"from_pc": 0x600, "to_pc": 0x400, "count": 1},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            symbols = Path(directory) / "nm.stdout"
            symbols.write_text(
                "00000400 T outside\n"
                "00000500 T revm_interpreter::instructions::arithmetic::add\n"
                "00000600 T revm_interpreter::instructions::arithmetic::mul\n",
                encoding="utf-8",
            )
            result = subject.derive(observation, symbols, 2)
        totals = result["totals"]
        self.assertEqual(totals["executed_function_count"], 2)
        self.assertEqual(totals["observed_rows"], 9)
        self.assertEqual(totals["observed_cross_symbol_entries"], 3)
        self.assertEqual(totals["observed_outside_module_entries"], 2)
        self.assertEqual(totals["module_rows_without_observed_incoming_edge"], 1)
        self.assertEqual(result["category_groups"][0]["observed_rows"], 9)
        self.assertEqual(
            result["category_groups"][0]["observed_outside_category_entries"], 2,
        )
        symbols_by_name = {row["symbol"]: row for row in result["symbols"]}
        mul = symbols_by_name[
            "revm_interpreter::instructions::arithmetic::mul"
        ]
        self.assertEqual(mul["observed_cross_symbol_entries"], 1)
        self.assertEqual(
            mul["rows_per_observed_cross_symbol_entry"]["numerator_rows"], 4,
        )

    def fixture(self) -> dict:
        identity = {
            "path": "/private/tmp/source", "bytes": 1, "sha256": "1" * 64,
        }
        symbol = {
            "symbol": "revm_interpreter::instructions::arithmetic::add",
            "category": "arithmetic",
            "opcode_group": "add",
            "observed_rows": 5,
            "observed_cross_symbol_entries": 2,
            "observed_outside_module_entries": 2,
            "observed_other_interpreter_symbol_entries": 0,
            "observed_self_symbol_edges": 3,
            "rows_without_observed_incoming_edge": 0,
            "rows_per_observed_cross_symbol_entry": subject._ratio(5, 2),
            "observed_row_rank": 1,
        }
        return protocol.seal({
            "schema": subject.SCHEMA,
            "status": subject.STATUS,
            "inputs": {
                "prior_ledger_v6": copy.deepcopy(identity),
                "prior_v6_inputs": {"source": copy.deepcopy(identity)},
                "pc_census_inputs": {"source": copy.deepcopy(identity)},
            },
            "sample": {
                "complete_execution": True,
                "no_extrapolation": True,
            },
            "census": {
                "symbols": [symbol],
                "totals": {
                    "executed_function_count": 1,
                    "category_count": 1,
                    "opcode_group_count": 1,
                    "observed_rows": 5,
                    "observed_cross_symbol_entries": 2,
                    "observed_outside_module_entries": 2,
                    "observed_other_interpreter_symbol_entries": 0,
                    "observed_self_symbol_edges": 3,
                    "module_rows_without_observed_incoming_edge": 0,
                    "all_execution_transition_omission_count": 1,
                    "segment_boundary_entry_omission_upper_bound": 1,
                },
            },
            "claim_boundary": {
                "candidate_micro_op_air_available": False,
                "candidate_active_rows": None,
                "candidate_padded_rows": None,
                "candidate_main_columns": None,
                "candidate_main_cells": None,
                "candidate_saved_main_cells": None,
                "candidate_execution_wall_ns": None,
                "candidate_proof_identity": None,
                "candidate_proof_wall_ns": None,
                "fresh_candidate_verification": None,
                "candidate_end_to_end_wall_ns": None,
                "performance_claim_eligible": False,
                "production_active": False,
            },
        })

    def test_resealed_ratio_cell_and_boolean_mutations_reject(self) -> None:
        value = self.fixture()
        with (
            mock.patch.object(subject, "_validate_identity"),
            mock.patch.object(subject, "build", return_value=value),
        ):
            self.assertIs(subject.validate(value), value)
            changed = copy.deepcopy(value)
            changed["census"]["symbols"][0][
                "rows_per_observed_cross_symbol_entry"
            ]["numerator_rows"] += 1
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(subject.EvmMicroOpCensusV7Error):
                subject.validate(changed)

            changed = copy.deepcopy(value)
            changed["claim_boundary"]["candidate_main_cells"] = 0
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(subject.EvmMicroOpCensusV7Error):
                subject.validate(changed)

            changed = copy.deepcopy(value)
            changed["claim_boundary"]["production_active"] = 0
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(subject.EvmMicroOpCensusV7Error):
                subject.validate(changed)


if __name__ == "__main__":
    unittest.main()
