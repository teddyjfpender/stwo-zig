"""Serialized AIR interchange-representation contracts."""

from __future__ import annotations

import unittest
from pathlib import Path

from scripts.air_uniqueness_lib import analysis, smtlib
from scripts.riscv_air_ir_lib import ir

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "air_uniqueness"
ADDER = FIXTURES / "byte_carry_adder.json"


class IntermediateRepresentationTest(unittest.TestCase):
    def test_flat_and_nested_encodings_agree(self) -> None:
        nested = ir.load(ADDER)
        flat = ir.from_dict(
            {
                "columns": [
                    {"name": c.name, "role": c.role} for c in nested.columns
                ],
                "nodes": [
                    {
                        "op": n.op,
                        **({"value": n.value} if n.op == "const" else {}),
                        **({"name": n.name} if n.op == "col" else {}),
                        **({"args": list(n.args)} if n.args else {}),
                    }
                    for n in nested.nodes
                ],
                "constraints": list(nested.constraints),
                "lookups": [
                    {
                        "domain": lookup.domain,
                        "numerator": lookup.numerator,
                        "tuple": list(lookup.tuple_),
                        "label": lookup.label,
                    }
                    for lookup in nested.lookups
                ],
                "family": nested.family,
            }
        )
        self.assertEqual(flat.nodes, nested.nodes)
        self.assertEqual(flat.constraints, nested.constraints)
        self.assertEqual(flat.lookups, nested.lookups)

    def test_bit_sugar_expands_to_the_common_bit_idiom(self) -> None:
        base = {"columns": [{"name": "x", "role": "output"}], "constraints": ["c"]}
        sugared = ir.from_dict({**base, "exprs": {"c": ["bit", ["col", "x"]]}})
        explicit = ir.from_dict(
            {
                **base,
                "exprs": {
                    "c": ["mul", ["col", "x"], ["sub", ["const", 1], ["col", "x"]]]
                },
            }
        )
        self.assertEqual(sugared.nodes, explicit.nodes)
        self.assertEqual(sugared.constraints, explicit.constraints)

    def test_hash_consing_shares_repeated_subexpressions(self) -> None:
        system = ir.from_dict(
            {
                "columns": [{"name": "x", "role": "output"}],
                "exprs": {
                    "a": ["mul", ["col", "x"], ["col", "x"]],
                    "b": ["mul", ["col", "x"], ["col", "x"]],
                },
                "constraints": ["a", "b"],
            }
        )
        self.assertEqual(system.constraints[0], system.constraints[1])

    def test_degrees_are_reported_per_node(self) -> None:
        system = ir.load(ADDER)
        node_degrees = analysis.degrees(system)
        self.assertEqual(max(node_degrees[c] for c in system.constraints), 2)

    def test_malformed_ir_is_rejected(self) -> None:
        cases = {
            "undeclared column": {
                "columns": [{"name": "x", "role": "output"}],
                "exprs": {"c": ["col", "y"]},
                "constraints": ["c"],
            },
            "unknown operator": {
                "columns": [{"name": "x", "role": "output"}],
                "exprs": {"c": ["xor", ["col", "x"], ["col", "x"]]},
                "constraints": ["c"],
            },
            "wrong modulus": {
                "modulus": 97,
                "columns": [{"name": "x", "role": "output"}],
                "exprs": {"c": ["col", "x"]},
                "constraints": ["c"],
            },
            "both encodings": {
                "columns": [{"name": "x", "role": "output"}],
                "exprs": {"c": ["col", "x"]},
                "nodes": [{"op": "col", "name": "x"}],
                "constraints": [0],
            },
            "forward reference": {
                "columns": [{"name": "x", "role": "output"}],
                "nodes": [{"op": "add", "args": [1, 1]}, {"op": "col", "name": "x"}],
                "constraints": [0],
            },
            "unknown expression name": {
                "columns": [{"name": "x", "role": "output"}],
                "exprs": {"c": ["add", "missing", ["col", "x"]]},
                "constraints": ["c"],
            },
            "domain on a non-input": {
                "columns": [
                    {
                        "name": "x",
                        "role": "output",
                        "domain": {"lo": 0, "hi": 255, "why": "no"},
                    }
                ],
                "exprs": {"c": ["col", "x"]},
                "constraints": ["c"],
            },
            "domain without a justification": {
                "columns": [
                    {"name": "y", "role": "output"},
                    {"name": "x", "role": "input", "domain": {"lo": 0, "hi": 255}},
                ],
                "exprs": {"c": ["col", "x"]},
                "constraints": ["c"],
            },
            "domain outside the field": {
                "columns": [
                    {"name": "y", "role": "output"},
                    {
                        "name": "x",
                        "role": "input",
                        "domain": {"lo": 0, "hi": ir.MODULUS, "why": "too wide"},
                    },
                ],
                "exprs": {"c": ["col", "x"]},
                "constraints": ["c"],
            },
            "stride that does not divide its bounds": {
                "columns": [
                    {"name": "y", "role": "output"},
                    {
                        "name": "x",
                        "role": "input",
                        "domain": {"lo": 0, "hi": 255, "stride": 4, "why": "ragged"},
                    },
                ],
                "exprs": {"c": ["col", "x"]},
                "constraints": ["c"],
            },
        }
        for label, payload in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(ir.IRError):
                    ir.from_dict(payload)

    def test_lookup_arity_is_enforced_against_the_relation_domain(self) -> None:
        system = ir.from_dict(
            {
                "columns": [{"name": "x", "role": "output"}],
                "exprs": {"one": ["const", 1], "x": ["col", "x"]},
                "constraints": [],
                "lookups": [
                    {"domain": "range_check_8_8", "numerator": "one", "tuple": ["x"]}
                ],
            }
        )
        with self.assertRaises(smtlib.tables.DomainError):
            smtlib.emit_uniqueness_query(system)


if __name__ == "__main__":
    unittest.main()
