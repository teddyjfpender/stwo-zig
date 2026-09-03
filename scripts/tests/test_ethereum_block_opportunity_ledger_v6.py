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

import ethereum_block_opportunity_ledger_v6 as subject  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402


class OpportunityLedgerV6Tests(unittest.TestCase):
    def test_interpreter_residual_uses_edges_without_extrapolation(self) -> None:
        observation = {
            "retired_instructions": 8,
            "per_pc": [
                {"pc": 0x400, "count": 3},
                {"pc": 0x500, "count": 5},
            ],
            "basic_edges": [
                {"from_pc": 0x400, "to_pc": 0x500, "count": 2},
                {"from_pc": 0x500, "to_pc": 0x500, "count": 3},
                {"from_pc": 0x500, "to_pc": 0x400, "count": 1},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            symbols = Path(directory) / "nm.stdout"
            symbols.write_text(
                "00000400 T outside\n"
                "00000500 T revm_interpreter::instructions::add\n"
                "00000600 T <revm_handler::mainnet_handler::MainnetHandler>::execution\n",
                encoding="utf-8",
            )
            # The selector requires one mainnet handler row; make the final
            # outside row use that symbol without changing module totals.
            observation["per_pc"][0] = {"pc": 0x600, "count": 3}
            observation["basic_edges"][0]["from_pc"] = 0x600
            observation["basic_edges"][2]["to_pc"] = 0x600
            result = subject._interpreter_residual(observation, symbols, 2)
        self.assertEqual(result["executed_function_count"], 1)
        self.assertEqual(result["observed_rows"], 5)
        self.assertEqual(result["observed_outside_to_module_entries"], 2)
        self.assertEqual(result["module_rows_without_observed_incoming_edge"], 0)
        self.assertIsNone(result["candidate_main_cells"])
        self.assertIs(result["no_extrapolation"], True)

    def fixture(self) -> dict:
        identity = {
            "path": "/private/tmp/source", "bytes": 1, "sha256": "1" * 64,
        }
        residual = {
            "executed_function_count": 135,
            "observed_rows": 26_625_429,
            "retired_instruction_denominator": 127_850_202,
            "observed_share_basis_points_rounded": 2_083,
            "observed_outside_to_module_entries": 457_142,
            "observed_internal_module_edges": 26_168_282,
            "observed_module_to_outside_exits": 457_142,
            "module_rows_without_observed_incoming_edge": 5,
            "segment_boundary_transition_omission_upper_bound": 31,
            "mainnet_handler_observed_rows": 11_456_335,
            "no_extrapolation": True,
            "no_row_subtraction": True,
            "typed_evm_step_air_available": False,
        }
        for name in (
            "candidate_active_rows", "candidate_padded_rows",
            "candidate_main_columns", "candidate_main_cells", "saved_main_cells",
            "measured_candidate_execution_wall_ns",
            "measured_candidate_proof_wall_ns",
            "measured_candidate_end_to_end_wall_ns",
        ):
            residual[name] = None
        return protocol.seal({
            "schema": subject.SCHEMA,
            "status": subject.STATUS,
            "inputs": {
                name: copy.deepcopy(identity) for name in (
                    "prior_ledger_v5", "ecrecover_pc_census_evidence",
                    "pc_observation", "symbol_map",
                )
            },
            "retained_prior_ledger": {},
            "evm_interpreter_residual": residual,
            "current_cpu_main_geometry": {
                "segment_count": 31,
                "total_padded_main_cells": 7_139_605_168,
                "load_store_padded_main_cells": 3_407_872_000,
                "component_sharding_applied": False,
                "candidate_geometry": None,
                "candidate_main_cells": None,
                "saved_main_cells": None,
            },
            "opcode_column_authorities": {
                "composition_manifest_source": copy.deepcopy(identity),
            },
            "future_evm_micro_op_evidence_contract": {
                "contract_frozen": False,
                "candidate_instance": None,
                "reduction_estimates": None,
                "promotion_requires_all_sections": True,
                "no_reduction_estimates": True,
            },
            "claims": {
                "candidate_air_complete": None,
                "candidate_execution_complete": None,
                "candidate_proof_complete": None,
                "fresh_candidate_verification": None,
                "measured_candidate_end_to_end_wall_ns": None,
                "production_promotion_eligible": False,
            },
        })

    def test_resealed_candidate_and_boolean_mutations_reject(self) -> None:
        value = self.fixture()
        with (
            mock.patch.object(subject, "_validate_identity"),
            mock.patch.object(subject, "build", return_value=value),
        ):
            self.assertIs(subject.validate(value), value)
            changed = copy.deepcopy(value)
            changed["evm_interpreter_residual"]["candidate_main_cells"] = 0
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(subject.OpportunityLedgerV6Error):
                subject.validate(changed)

            changed = copy.deepcopy(value)
            changed["evm_interpreter_residual"]["no_extrapolation"] = 1
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(subject.OpportunityLedgerV6Error):
                subject.validate(changed)

            changed = copy.deepcopy(value)
            changed["claims"]["production_promotion_eligible"] = 0
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(subject.OpportunityLedgerV6Error):
                subject.validate(changed)


if __name__ == "__main__":
    unittest.main()
