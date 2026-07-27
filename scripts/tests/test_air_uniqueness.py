"""Contracts for the per-row witness-uniqueness pipeline.

The headline tests are the four hand-written models: the pipeline earns trust
by reproducing a known under-constraint as `sat`, flipping to `unsat` when the
shipped fix is added, and proving a realistic byte-carry adder unique.  The
rest guard the parts of the encoding whose failure mode is a silently missing
counterexample rather than a visible error.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from scripts import air_uniqueness
from scripts.air_uniqueness_lib import analysis, ir, smtlib, solve, tables

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "air_uniqueness"
SCHEMA_ZIG = ROOT / "src/frontends/riscv/air/lookups/tables/schema.zig"
ENTRY_ZIG = ROOT / "src/frontends/riscv/air/lookups/entry.zig"

UNDER_CONSTRAINED = FIXTURES / "sign_load_underconstrained.json"
FIXED = FIXTURES / "sign_load_fixed.json"
ADDER = FIXTURES / "byte_carry_adder.json"
ADDER_UNRANGED = FIXTURES / "byte_carry_adder_unranged.json"
XOR = FIXTURES / "bitwise_xor_byte.json"

# Observed worst case is ~3.5s, on the bitwise model whose int2bv encoding is
# the least predictable. The headroom is deliberate but bounded: a regression
# that loses the exact rewrites in `analysis.py` must fail here rather than
# hang the discovered suite.
TIMEOUT_MS = 20_000

try:  # Hosted CI installs no Python packages; z3 is a local operator tool.
    import z3 as _z3  # noqa: F401

    HAVE_Z3 = True
except ModuleNotFoundError:  # pragma: no cover - depends on the environment
    HAVE_Z3 = False

needs_z3 = unittest.skipUnless(
    HAVE_Z3, "z3 bindings are absent; IR and emitter contracts still run"
)


def _check(path: Path, refine: bool = True) -> solve.Result:
    return solve.check(ir.load(path), timeout_ms=TIMEOUT_MS, refine=refine)


@needs_z3
class ToyModelVerdictTest(unittest.TestCase):
    """The pipeline reproduces a known bug and its known fix."""

    def test_free_sign_witness_is_reported_as_non_unique(self) -> None:
        result = _check(UNDER_CONSTRAINED)
        self.assertEqual(result.status, "sat")
        first, second = smtlib.COPIES
        self.assertEqual(
            result.witnesses[first].inputs, result.witnesses[second].inputs
        )
        # The whole point of the bug: one free bit moves the sign fill.
        self.assertNotEqual(
            result.witnesses[first].witness["src_msb"],
            result.witnesses[second].witness["src_msb"],
        )
        self.assertEqual(
            set(result.differing_outputs), {"result1", "result2", "result3"}
        )
        for copy in (first, second):
            fill = result.witnesses[copy].witness["src_msb"] * 255
            for limb in ("result1", "result2", "result3"):
                self.assertEqual(result.witnesses[copy].outputs[limb], fill)

    def test_sign_range_lookup_restores_uniqueness(self) -> None:
        result = _check(FIXED)
        self.assertEqual(result.status, "unsat")
        self.assertTrue(result.constraints_satisfiable)
        self.assertFalse(result.vacuous)

    def test_fixed_model_differs_from_the_broken_one_only_by_the_fix(self) -> None:
        """The sat -> unsat flip must be attributable to the fix alone."""
        broken = json.loads(UNDER_CONSTRAINED.read_text(encoding="utf-8"))
        fixed = json.loads(FIXED.read_text(encoding="utf-8"))
        self.assertEqual(broken["columns"], fixed["columns"])
        self.assertEqual(broken["constraints"], fixed["constraints"])
        self.assertEqual(
            set(fixed["exprs"]) - set(broken["exprs"]), {"sign_residual"}
        )
        self.assertEqual(
            {k: v for k, v in fixed["exprs"].items() if k in broken["exprs"]},
            broken["exprs"],
        )
        added = [l for l in fixed["lookups"] if l not in broken["lookups"]]
        removed = [l for l in broken["lookups"] if l not in fixed["lookups"]]
        self.assertEqual(removed, [])
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0]["domain"], "range_check_m31")

    def test_byte_carry_adder_is_unique(self) -> None:
        result = _check(ADDER)
        self.assertEqual(result.status, "unsat")
        self.assertTrue(result.constraints_satisfiable)
        self.assertEqual(len(result.modelled_lookups), 6)

    def test_unranged_adder_result_limbs_are_not_unique(self) -> None:
        """Membership must be load-bearing: without it the adder breaks."""
        result = _check(ADDER_UNRANGED)
        self.assertEqual(result.status, "sat")
        self.assertTrue(result.differing_outputs)

    def test_adder_pair_differs_only_by_the_result_range_checks(self) -> None:
        ranged = json.loads(ADDER.read_text(encoding="utf-8"))
        unranged = json.loads(ADDER_UNRANGED.read_text(encoding="utf-8"))
        for key in ("columns", "exprs", "constraints"):
            self.assertEqual(ranged[key], unranged[key], key)
        self.assertEqual(
            [l for l in unranged["lookups"] if l not in ranged["lookups"]], []
        )
        dropped = [l for l in ranged["lookups"] if l not in unranged["lookups"]]
        self.assertEqual(
            [l["label"] for l in dropped], ["sum low half", "sum high half"]
        )

    def test_bitwise_table_defines_its_result(self) -> None:
        result = _check(XOR)
        self.assertEqual(result.status, "unsat")
        self.assertTrue(result.constraints_satisfiable)


class EncodingSoundnessTest(unittest.TestCase):
    """Guards on the parts that could delete a counterexample unnoticed."""

    @needs_z3
    def test_implied_bounds_never_change_a_sat_verdict(self) -> None:
        for path in (UNDER_CONSTRAINED, ADDER_UNRANGED):
            with self.subTest(model=path.name):
                self.assertEqual(_check(path, refine=False).status, "sat")

    def test_implied_bounds_only_follow_from_asserted_obligations(self) -> None:
        system = ir.load(ADDER)
        bounds = analysis.implied_column_bounds(system)
        # Carries: from the `bit` constraints alone.
        self.assertEqual(bounds["c0"], (0, 1))
        self.assertEqual(bounds["c3"], (0, 1))
        # Limbs: from unconditionally live box-table requests.
        self.assertEqual(bounds["a0"], (0, 255))
        self.assertEqual(bounds["s3"], (0, 255))

    def test_conditional_lookups_do_not_bound_columns(self) -> None:
        """`is_signed` gates the sign lookup, so it may not bound anything."""
        system = ir.load(FIXED)
        bounds = analysis.implied_column_bounds(system)
        self.assertEqual(bounds["result0"], (0, ir.MODULUS - 1))
        self.assertEqual(bounds["result3"], (0, ir.MODULUS - 1))

    def test_field_reduction_is_explicit(self) -> None:
        """No `mod`/`div`: wraparound must stay visible to the solver."""
        text = smtlib.emit_uniqueness_query(ir.load(ADDER)).text
        self.assertNotIn("(mod ", text)
        self.assertNotIn("(div ", text)
        self.assertIn(str(ir.MODULUS), text)

    def test_bus_relations_assert_nothing(self) -> None:
        query = smtlib.emit_uniqueness_query(ir.load(UNDER_CONSTRAINED))
        self.assertEqual(len(query.skipped_bus_lookups), 1)
        self.assertIn("bus relation, not a table", query.text)

    @needs_z3
    def test_vacuous_uniqueness_is_reported(self) -> None:
        contradictory = {
            "columns": [
                {"name": "x", "role": "input"},
                {"name": "y", "role": "output"},
            ],
            "exprs": {
                "pin_low": ["col", "y"],
                "pin_high": ["sub", ["col", "y"], ["const", 1]],
            },
            "constraints": ["pin_low", "pin_high"],
        }
        result = solve.check(ir.from_dict(contradictory), timeout_ms=TIMEOUT_MS)
        self.assertTrue(result.unique)
        self.assertTrue(result.vacuous)
        self.assertIn("VACUOUS", solve.format_result(result))

    def test_uniqueness_query_declares_both_copies(self) -> None:
        text = smtlib.emit_uniqueness_query(ir.load(ADDER)).text
        for copy in smtlib.COPIES:
            self.assertIn(f"(declare-const a0@{copy} Int)", text)
        self.assertIn("(assert (= a0@a a0@b))", text)


class IntermediateRepresentationTest(unittest.TestCase):
    def test_flat_and_nested_encodings_agree(self) -> None:
        """A machine emitter writes `nodes`; a human writes `exprs`."""
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
                        "domain": l.domain,
                        "numerator": l.numerator,
                        "tuple": list(l.tuple_),
                        "label": l.label,
                    }
                    for l in nested.lookups
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
            "no output column": {
                "columns": [{"name": "x", "role": "input"}],
                "exprs": {"c": ["col", "x"]},
                "constraints": ["c"],
            },
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
        with self.assertRaises(tables.DomainError):
            smtlib.emit_uniqueness_query(system)


def _zig_switch_arms(text: str, function: str) -> dict[str, int]:
    """Read `.member => literal,` arms out of one Zig switch function."""
    body = re.search(rf"pub fn {function}\(.*?\n\}}", text, re.S)
    assert body is not None, f"{function} not found"
    arms: dict[str, int] = {}
    for members, value in re.findall(
        r"^\s*((?:\.\w+\s*,\s*)*\.\w+)\s*=>\s*(\d+)\s*,", body.group(0), re.M
    ):
        for member in members.split(","):
            arms[member.strip().lstrip(".")] = int(value)
    return arms


class ZigTableTranscriptionTest(unittest.TestCase):
    """`tables.py` restates protocol constants owned by the Zig sources.

    A restatement in a second toolchain is a second source of truth unless
    something ties them together, and a silently stale width would weaken the
    membership encoding without failing anything else.
    """

    def test_box_widths_match_schema_log_sizes_and_arities(self) -> None:
        text = SCHEMA_ZIG.read_text(encoding="utf-8")
        log_sizes = _zig_switch_arms(text, "logSize")
        arities = _zig_switch_arms(text, "arity")
        self.assertEqual(
            set(log_sizes), set(tables.BOX_TABLES) | {tables.BITWISE_DOMAIN}
        )
        for name, widths in tables.BOX_TABLES.items():
            with self.subTest(table=name):
                self.assertEqual(sum(widths), log_sizes[name])
                self.assertEqual(len(widths), arities[name])
        # The bitwise table is indexed by (lhs, rhs, op); `value` is derived,
        # so the row count covers three of the four tuple components.
        lhs, rhs, _value, op = tables.BITWISE_WIDTHS
        self.assertEqual(lhs + rhs + op, log_sizes[tables.BITWISE_DOMAIN])
        self.assertEqual(arities[tables.BITWISE_DOMAIN], 4)

    def test_relation_domains_and_arities_match_entry_zig(self) -> None:
        text = ENTRY_ZIG.read_text(encoding="utf-8")
        enum_body = re.search(r"pub const Domain = enum\(u8\) \{(.*?)\};", text, re.S)
        assert enum_body is not None
        declared = {
            line.strip().rstrip(",")
            for line in enum_body.group(1).splitlines()
            if line.strip() and not line.strip().startswith("//")
        }
        self.assertEqual(declared, set(tables.ARITIES))
        self.assertEqual(
            set(tables.BUS_DOMAINS) | set(tables.BOX_TABLES) | {tables.BITWISE_DOMAIN},
            declared,
        )
        self.assertEqual(_zig_switch_arms(text, "expectedArity"), tables.ARITIES)


@needs_z3
class CommandLineTest(unittest.TestCase):
    def test_explain_names_what_the_query_does_not_cover(self) -> None:
        self.assertIn("What the query does NOT cover", air_uniqueness.ENCODING_SPEC)
        for absent in ("Cross-row", "Multiset", "Completeness", "Degenerate"):
            self.assertIn(absent, air_uniqueness.ENCODING_SPEC)

    def test_check_exit_code_reports_the_verdict(self) -> None:
        self.assertEqual(air_uniqueness.main(["check", str(FIXED)]), 0)
        self.assertEqual(air_uniqueness.main(["check", str(UNDER_CONSTRAINED)]), 1)

    def test_counterexample_export_is_a_witness_pair(self) -> None:
        system = ir.load(UNDER_CONSTRAINED)
        result = solve.check(system, timeout_ms=TIMEOUT_MS)
        payload = solve.counterexample_payload(system, result)
        first, second = smtlib.COPIES
        self.assertEqual(
            payload["witnesses"][first]["witness"]["src_msb"],
            1 - payload["witnesses"][second]["witness"]["src_msb"],
        )
        self.assertTrue(payload["differing_outputs"])
        json.dumps(payload)  # Must be serialisable for the mutation corpus.

    def test_counterexample_export_refuses_an_unsat_result(self) -> None:
        system = ir.load(FIXED)
        result = solve.check(system, timeout_ms=TIMEOUT_MS)
        with self.assertRaises(ValueError):
            solve.counterexample_payload(system, result)


if __name__ == "__main__":
    unittest.main()
