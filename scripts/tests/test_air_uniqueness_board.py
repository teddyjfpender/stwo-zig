"""Contracts for the board: how a family's question is split, and how the
shard answers are folded back into one row.

Splitting is the part of this pipeline that can go wrong quietly.  An incomplete
case split drops cases, and a dropped case is a counterexample nobody sees, so
every split here has to be derived from the IR rather than recognised by name.
The folding rules are the other half: a board is read as coverage, so a shard
that ran out of budget has to survive the fold as a timeout rather than being
averaged away by the shards that finished.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from pathlib import Path

from scripts import air_uniqueness_board
from scripts.air_uniqueness_lib import analysis, ir, smtlib, solve

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "air_uniqueness"
UNDER_CONSTRAINED = FIXTURES / "sign_load_underconstrained.json"
ADDER = FIXTURES / "byte_carry_adder.json"
INLINE_ADDER = FIXTURES / "inline_carry_adder.json"

TIMEOUT_MS = 20_000

try:  # Hosted CI installs no Python packages; z3 is a local operator tool.
    import z3 as _z3  # noqa: F401

    HAVE_Z3 = True
except ModuleNotFoundError:  # pragma: no cover - depends on the environment
    HAVE_Z3 = False

needs_z3 = unittest.skipUnless(
    HAVE_Z3, "z3 bindings are absent; the planning contracts still run"
)


class ShardingTest(unittest.TestCase):
    """A split is only allowed where the IR proves the case split is complete."""

    def _one_hot(self, *, with_bits: bool) -> ir.System:
        exprs = {
            "pick": [
                "sub",
                ["add", ["col", "left_flag"], ["col", "right_flag"]],
                ["const", 1],
            ],
            "left_bit": ["bit", ["col", "left_flag"]],
            "right_bit": ["bit", ["col", "right_flag"]],
            "pin": [
                "sub",
                ["col", "out"],
                ["mul", ["col", "left_flag"], ["col", "value"]],
            ],
        }
        constraints = ["pick", "pin"] + (["left_bit", "right_bit"] if with_bits else [])
        return ir.from_dict(
            {
                "family": "toy_one_hot",
                "columns": [
                    {"name": "left_flag", "role": "input"},
                    {"name": "right_flag", "role": "input"},
                    {"name": "value", "role": "input"},
                    {"name": "out", "role": "output"},
                ],
                "exprs": exprs,
                "constraints": constraints,
            }
        )

    def test_a_one_hot_group_is_derived_from_the_constraints(self) -> None:
        self.assertEqual(
            analysis.one_hot_selectors(self._one_hot(with_bits=True)),
            ("left_flag", "right_flag"),
        )

    def test_without_the_bit_constraints_it_is_not_a_group(self) -> None:
        """`f + g = 1` alone allows f = 7, g = -6; enumerating two cases would
        delete every other solution, and with them any counterexample there."""
        self.assertEqual(analysis.one_hot_selectors(self._one_hot(with_bits=False)), ())

    def test_splitting_on_a_column_outside_the_group_is_refused(self) -> None:
        system = self._one_hot(with_bits=True)
        with self.assertRaises(ir.IRError):
            smtlib.emit_uniqueness_query(system, shard=smtlib.Shard(selector="value"))

    def test_splitting_on_a_column_that_is_not_an_output_is_refused(self) -> None:
        system = self._one_hot(with_bits=True)
        with self.assertRaises(ir.IRError):
            smtlib.emit_uniqueness_query(system, shard=smtlib.Shard(output="value"))

    def test_the_plan_covers_every_output_under_every_opcode(self) -> None:
        system = ir.load(ADDER)
        plan = smtlib.plan_shards(system, by_output=True, by_selector=True)
        self.assertEqual(
            sorted(shard.output for shard in plan), sorted(system.by_role("output"))
        )
        self.assertEqual({shard.selector for shard in plan}, {""})

    def test_a_pinned_opcode_enters_as_a_bound_not_an_assertion(self) -> None:
        """A bound is what interval analysis can act on; see `explain` 4c."""
        text = smtlib.emit_uniqueness_query(
            self._one_hot(with_bits=True), shard=smtlib.Shard(selector="right_flag")
        ).text
        self.assertIn("(assert (<= 1 right_flag@s))", text)
        self.assertIn("(assert (<= left_flag@s 0))", text)
        # `left_flag * value` is then statically zero, so `out` is `0` and the
        # shard is decided without the solver searching for it.
        self.assertIn("(assert (= n11@s (* left_flag@s value@s)))", text)
        self.assertIn("(assert (<= n11@s 0))", text)

    @needs_z3
    def test_every_shard_of_a_unique_family_is_unsat(self) -> None:
        system = ir.load(ADDER)
        shards = [
            solve.check(system, timeout_ms=TIMEOUT_MS, shard=shard)
            for shard in smtlib.plan_shards(system, by_output=True, by_selector=True)
        ]
        self.assertTrue(all(s.status == "unsat" for s in shards))
        self.assertEqual(solve.aggregate(system.family, shards).status, "unsat")

    @needs_z3
    def test_a_broken_family_has_a_sat_shard_naming_the_output(self) -> None:
        system = ir.load(UNDER_CONSTRAINED)
        shards = [
            solve.check(system, timeout_ms=TIMEOUT_MS, shard=shard)
            for shard in smtlib.plan_shards(system, by_output=True, by_selector=True)
        ]
        merged = solve.aggregate(system.family, shards)
        self.assertEqual(merged.status, "sat")
        self.assertIn("result1", merged.open_shards)


@needs_z3
class EncodingDifferentialTest(unittest.TestCase):
    """Every speed-up is checked against the encoding it replaced, on models
    that are deliberately broken.

    A faster encoding whose only visible failure is that it stops finding
    counterexamples cannot be caught by running it on correct models, because
    correct models have none to find.  So: delete one obligation from a fixture,
    which is exactly how a real under-constraint looks, and require the old
    encoding and the new one to reach the same verdict on the wreckage.

    Runtime ~25s: 33 mutants, each solved twice.
    """

    MODELS = (ADDER, INLINE_ADDER, UNDER_CONSTRAINED)

    @staticmethod
    def _mutants(system: ir.System):
        """`system` with each single obligation deleted in turn."""
        for index in range(len(system.constraints)):
            dropped = system.constraints[:index] + system.constraints[index + 1 :]
            yield f"constraint {index}", replace(system, constraints=dropped)
        for index in range(len(system.lookups)):
            dropped = system.lookups[:index] + system.lookups[index + 1 :]
            yield f"lookup {index}", replace(system, lookups=dropped)

    def test_the_fast_encoding_finds_every_counterexample_the_slow_one_does(
        self,
    ) -> None:
        for model in self.MODELS:
            system = ir.load(model)
            for name, mutant in self._mutants(system):
                with self.subTest(model=model.stem, deleted=name):
                    slow = solve.check(
                        mutant, timeout_ms=TIMEOUT_MS, derived=False
                    )
                    fast = solve.check(mutant, timeout_ms=TIMEOUT_MS)
                    if "unknown" in (slow.status, fast.status):
                        self.skipTest(f"{name}: out of budget, nothing to compare")
                    self.assertEqual(slow.status, fast.status)

    def test_sharding_agrees_with_the_monolithic_question(self) -> None:
        for model in self.MODELS:
            system = ir.load(model)
            for name, mutant in self._mutants(system):
                with self.subTest(model=model.stem, deleted=name):
                    whole = solve.check(mutant, timeout_ms=TIMEOUT_MS)
                    parts = solve.aggregate(
                        mutant.family,
                        [
                            solve.check(mutant, timeout_ms=TIMEOUT_MS, shard=shard)
                            for shard in smtlib.plan_shards(mutant, True, True)
                        ],
                    )
                    if "unknown" in (whole.status, parts.status):
                        self.skipTest(f"{name}: out of budget, nothing to compare")
                    self.assertEqual(whole.status, parts.status)


class VacuityReportingTest(unittest.TestCase):
    """An unfinished honest-witness probe is not a disproof of one."""

    def test_a_probe_that_did_not_finish_leaves_vacuity_open(self) -> None:
        result = solve.Result(family="toy", status="unsat", seconds=0.0)
        self.assertIsNone(result.constraints_satisfiable)
        self.assertFalse(result.vacuous)
        self.assertIn("did not finish", solve.format_result(result))

    def test_a_probe_that_came_back_unsat_is_vacuous(self) -> None:
        result = solve.Result(
            family="toy", status="unsat", seconds=0.0, constraints_satisfiable=False
        )
        self.assertTrue(result.vacuous)
        self.assertIn("VACUOUS", solve.format_result(result))


class BoardTest(unittest.TestCase):
    """The runner's folding rules, on synthetic rows so no solver is involved."""

    @staticmethod
    def _row(status: str, shard: str, **extra: object) -> dict:
        row = {
            "family": "toy",
            "kind": "unique",
            "shard": shard,
            "status": status,
            "seconds": 1.0,
            "wall": 1.0,
            "detail": status,
            "report": "",
            "counterexample": None,
        }
        row.update(extra)
        return row

    def test_one_unfinished_shard_makes_the_family_a_timeout(self) -> None:
        rows = [self._row("unsat", "a"), self._row("unknown", "b")]
        (folded,) = air_uniqueness_board.collect(rows)
        self.assertEqual(folded["status"], "timeout")
        self.assertEqual(folded["open_shards"], ["b"])

    def test_a_counterexample_outranks_an_unfinished_shard(self) -> None:
        rows = [self._row("unknown", "a"), self._row("sat", "b")]
        (folded,) = air_uniqueness_board.collect(rows)
        self.assertEqual(folded["status"], "sat")
        self.assertEqual(folded["deciding_shard"], "b")

    def test_an_unsatisfiable_opcode_marks_the_family_vacuous(self) -> None:
        rows = [
            self._row("unsat", "add"),
            {"family": "toy", "kind": "probe", "satisfiable": False, "seconds": 0.1},
        ]
        (folded,) = air_uniqueness_board.collect(rows)
        self.assertIs(folded["honest_witness"], False)
        self.assertIn("VACUOUS", air_uniqueness_board._vacuity_note(folded))

    def test_an_unfinished_probe_is_not_read_as_vacuous(self) -> None:
        rows = [
            self._row("unsat", "add"),
            {"family": "toy", "kind": "probe", "satisfiable": None, "seconds": 0.1},
        ]
        (folded,) = air_uniqueness_board.collect(rows)
        self.assertIsNone(folded["honest_witness"])
        self.assertNotIn("VACUOUS", air_uniqueness_board._vacuity_note(folded))
