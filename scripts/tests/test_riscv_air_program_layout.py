"""Adversarial tests for formal AIR node-layout normalization."""

from __future__ import annotations

import copy
import unittest
from unittest import mock

from scripts.riscv_refinement_lib import air_program_layout
from scripts.riscv_refinement_lib.air_program_contract import OPCODES


REVISION = "1" * 40


def _payload(manifest_id: int, mnemonic: str, family: str) -> dict:
    return {
        "active_row": 3,
        "columns": [
            {"index": 0, "name": "x", "role": "input", "type": "m31", "width": 1},
            {"index": 1, "name": "y", "role": "output", "type": "m31", "width": 1},
        ],
        "events": [
            {"kind": "constraint", "ordinal": 0, "root": 5},
            {
                "access_ordinal": None,
                "domain": "range_check_20",
                "kind": "lookup",
                "liveness": "nonzero_numerator",
                "numerator": 2,
                "ordinal": 1,
                "role": "request",
                "table_id": "range_check_20",
                "tuple": [3],
            },
        ],
        "family": family,
        "field": {"modulus": 2_147_483_647, "name": "M31"},
        "fixed_tables": [],
        "kind": "stwo-riscv-air-constraint-program",
        "nodes": [
            {"column": 0, "op": "col"},
            {"column": 1, "op": "col"},
            {"op": "const", "value": 1},
            {"args": [0, 2], "op": "add"},
            {"args": [1, 2], "op": "sub"},
            {"args": [3, 4], "op": "mul"},
        ],
        "opcode_selector": {
            "expression": 2,
            "manifest_id": manifest_id,
            "mnemonic": mnemonic,
        },
        "projection": {
            "destination_events": [],
            "next_pc": 3,
            "program_event": 1,
            "source_events": [],
            "state_events": [],
        },
        "schema_version": 2,
    }


def _inventory() -> dict[str, dict]:
    return {
        mnemonic: _payload(manifest_id, mnemonic, family)
        for manifest_id, mnemonic, family in OPCODES
    }


def _reordered(payload: dict) -> dict:
    result = copy.deepcopy(payload)
    result["nodes"] = [
        {"column": 0, "op": "col"},
        {"column": 1, "op": "col"},
        {"op": "const", "value": 1},
        {"args": [1, 2], "op": "sub"},
        {"args": [0, 2], "op": "add"},
        {"args": [4, 3], "op": "mul"},
    ]
    result["events"][0]["root"] = 5
    result["events"][1]["tuple"] = [4]
    result["active_row"] = 4
    result["projection"]["next_pc"] = 4
    return result


class NodeLayoutTest(unittest.TestCase):
    def setUp(self):
        self.reviewed = _inventory()
        self.receipt = air_program_layout.build_receipt(self.reviewed, REVISION)

    def test_reordered_structural_dag_normalizes_to_exact_reviewed_bytes(self):
        candidates = {
            mnemonic: _reordered(payload)
            for mnemonic, payload in self.reviewed.items()
        }
        with mock.patch.object(
            air_program_layout,
            "validate_receipt",
            wraps=air_program_layout.validate_receipt,
        ) as validate:
            self.assertEqual(
                air_program_layout.normalize_inventory(candidates, self.receipt),
                self.reviewed,
            )
        self.assertEqual(validate.call_count, 1)

    def test_event_semantics_cannot_hide_behind_same_node_set(self):
        candidate = _reordered(self.reviewed["addi"])
        candidate["events"][0]["root"] = 4
        with self.assertRaisesRegex(
            air_program_layout.LayoutError,
            "differs from reviewed bytes",
        ):
            air_program_layout.normalize(candidate, "addi", self.receipt)

    def test_structural_expression_drift_is_rejected(self):
        candidate = _reordered(self.reviewed["addi"])
        candidate["nodes"][5] = {"args": [4, 4], "op": "mul"}
        with self.assertRaisesRegex(
            air_program_layout.LayoutError,
            "structural expression set drifted",
        ):
            air_program_layout.normalize(candidate, "addi", self.receipt)

    def test_non_topological_and_unknown_nodes_fail_closed(self):
        for node in (
            {"args": [0, 6], "op": "add"},
            {"args": [0], "op": "inverse"},
        ):
            candidate = _reordered(self.reviewed["addi"])
            candidate["nodes"].append(node)
            with self.subTest(node=node):
                with self.assertRaises(air_program_layout.LayoutError):
                    air_program_layout.normalize(candidate, "addi", self.receipt)

    def test_receipt_digest_and_record_shapes_are_authenticated(self):
        tampered = copy.deepcopy(self.receipt)
        tampered["programs"][0]["node_count"] += 1
        with self.assertRaisesRegex(
            air_program_layout.LayoutError,
            "identity or digest drifted",
        ):
            air_program_layout.validate_receipt(tampered)

        malformed = copy.deepcopy(self.receipt)
        malformed["programs"][0] = "not an object"
        malformed["canonical_digest"] = air_program_layout._receipt_digest(malformed)
        with self.assertRaisesRegex(
            air_program_layout.LayoutError,
            "inventory or order drifted",
        ):
            air_program_layout.validate_receipt(malformed)

    def test_signed_candidate_is_not_silently_rewritten(self):
        candidate = _reordered(self.reviewed["addi"])
        candidate["content_digest"] = "0" * 64
        with self.assertRaisesRegex(
            air_program_layout.LayoutError,
            "requires unsigned AIR",
        ):
            air_program_layout.normalize(candidate, "addi", self.receipt)


if __name__ == "__main__":
    unittest.main()
