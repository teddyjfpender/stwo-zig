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
from dataclasses import replace
from pathlib import Path
from unittest import mock

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
INLINE_ADDER = FIXTURES / "inline_carry_adder.json"
MULTIPLIER = FIXTURES / "window_carry_multiplier.json"
DIV_IR = ROOT / "zig-out" / "uniqueness-ir" / "div.json"

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


def _check(model: Path | ir.System, refine: bool = True) -> solve.Result:
    system = ir.load(model) if isinstance(model, Path) else model
    return solve.check(system, timeout_ms=TIMEOUT_MS, refine=refine)


def _assume(system: ir.System) -> solve.Result:
    return solve.check(system, timeout_ms=TIMEOUT_MS, assume_domains=True)


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

    def test_the_two_copies_are_two_variables_where_they_may_differ(self) -> None:
        """Inputs are one variable; anything the copies may disagree on is two.

        Making the hypothesis structural rather than asserted is what removes
        the possibility of a missing `x@a = x@b`, but it also means a column
        wrongly counted as shared silently strengthens the hypothesis.  So the
        contract is stated from both ends.
        """
        query = smtlib.emit_uniqueness_query(ir.load(ADDER))
        self.assertIn("a0", query.shared_columns)
        self.assertIn("(declare-const a0@s Int)", query.text)
        self.assertNotIn("a0@a", query.text)
        for copy in smtlib.COPIES:
            self.assertIn(f"(declare-const c0@{copy} Int)", query.text)

    def test_a_column_is_shared_only_where_the_constraints_determine_it(self) -> None:
        system = ir.load(ADDER)
        inputs = frozenset(system.by_role("input"))
        determined = analysis.determined_columns(system, inputs)
        # Carries and sums are free until the range checks pin them, and the
        # range checks are memberships rather than equations.
        self.assertEqual(determined, inputs)

    def test_a_chain_of_equations_reaches_the_far_end(self) -> None:
        system = ir.from_dict(
            {
                "columns": [
                    {"name": "given", "role": "input"},
                    {"name": "middle", "role": "witness"},
                    {"name": "far", "role": "output"},
                    {"name": "free", "role": "output"},
                ],
                "exprs": {
                    "first": ["sub", ["col", "middle"], ["col", "given"]],
                    "second": ["sub", ["col", "far"], ["col", "middle"]],
                    "loose": ["bit", ["col", "free"]],
                },
                "constraints": ["first", "second", "loose"],
            }
        )
        determined = analysis.determined_columns(system, frozenset({"given"}))
        self.assertEqual(determined, {"given", "middle", "far"})
        self.assertNotIn("free", determined)


def _escape_model(escape: int, stride: int) -> dict[str, object]:
    """`b` is free exactly when `pc` takes one value, chosen outside the domain.

    The declared domain is the only thing that can decide this model, so the
    verdict is a direct read-out of whether the domain reached the solver.
    """
    return {
        "columns": [
            {
                "name": "pc",
                "role": "input",
                "domain": {
                    "lo": 0,
                    "hi": 1 << 30,
                    "stride": stride,
                    "why": "toy: the escape value is outside this domain",
                },
            },
            {"name": "b", "role": "output"},
        ],
        "exprs": {
            "gate": ["mul", ["sub", ["col", "pc"], ["const", escape]], ["col", "b"]],
            "boolean": ["bit", ["col", "b"]],
        },
        "constraints": ["gate", "boolean"],
    }


@needs_z3
class DeclaredDomainTest(unittest.TestCase):
    """A declared domain is an assumption, so it needs evidence both ways.

    It must actually reach the solver, and dropping it must restore the
    counterexample it was hiding -- otherwise the flag that measures it lies.
    """

    def test_range_half_decides_a_model_the_free_field_cannot(self) -> None:
        system = ir.from_dict(_escape_model(escape=(1 << 30) + 4, stride=1))
        self.assertEqual(_check(system).status, "sat")
        self.assertEqual(_assume(system).status, "unsat")

    def test_stride_half_decides_a_model_the_range_alone_cannot(self) -> None:
        system = ir.from_dict(_escape_model(escape=1, stride=4))
        self.assertEqual(_check(system).status, "sat")
        self.assertEqual(_assume(system).status, "unsat")

    def test_domains_are_off_unless_asked_for(self) -> None:
        """An assumption that arrives by default is an assumption nobody made."""
        system = ir.from_dict(_escape_model(escape=1, stride=4))
        self.assertNotIn("pc!stride", smtlib.emit_uniqueness_query(system).text)
        self.assertIn(
            "pc!stride",
            smtlib.emit_uniqueness_query(system, assume_domains=True).text,
        )

    def test_the_domain_binds_the_variable_both_copies_read(self) -> None:
        """Only an input may declare a domain, and an input is one variable, so
        the domain reaching "both copies" is now a property of the naming."""
        query = smtlib.emit_uniqueness_query(
            ir.from_dict(_escape_model(escape=1, stride=4)), assume_domains=True
        )
        self.assertIn("pc", query.shared_columns)
        self.assertIn(f"(assert (<= pc@s {1 << 30}))", query.text)
        self.assertIn("(assert (= pc@s (* 4 pc!stride@s)))", query.text)
        self.assertNotIn("(mod ", query.text)

    def test_the_two_knobs_are_independent(self) -> None:
        """`--no-refine` drops derived narrowing, never a declared domain."""
        system = ir.from_dict(_escape_model(escape=1, stride=4))
        self.assertEqual(
            solve.check(
                system, timeout_ms=TIMEOUT_MS, refine=False, assume_domains=True
            ).status,
            "unsat",
        )


class LookupLivenessTest(unittest.TestCase):
    """Every shipped request is gated by `-enabler`, never by a literal."""

    ENABLER_GATED = {
        "columns": [
            {"name": "enabler", "role": "input"},
            {"name": "limb", "role": "output"},
        ],
        "exprs": {
            "placement": ["sub", ["col", "enabler"], ["const", 1]],
            "gate": ["neg", ["col", "enabler"]],
            "limb": ["col", "limb"],
            "pad": ["const", 0],
        },
        "constraints": ["placement"],
        "lookups": [
            {"domain": "range_check_8_8", "numerator": "gate", "tuple": ["limb", "pad"]}
        ],
    }

    def test_placement_makes_an_enabler_gated_request_live(self) -> None:
        system = ir.from_dict(self.ENABLER_GATED)
        self.assertEqual(analysis.implied_column_bounds(system)["limb"], (0, 255))

    def test_without_placement_the_request_stays_conditional(self) -> None:
        payload = dict(self.ENABLER_GATED, constraints=[])
        system = ir.from_dict(payload)
        self.assertEqual(
            analysis.implied_column_bounds(system)["limb"], (0, ir.MODULUS - 1)
        )

    def test_elimination_solves_a_chained_system(self) -> None:
        """Back-substitution must reach pivots discovered after the fact."""
        system = ir.from_dict(
            {
                "columns": [
                    {"name": "x", "role": "output"},
                    {"name": "y", "role": "witness"},
                    {"name": "z", "role": "witness"},
                ],
                "exprs": {
                    "sum": ["sub", ["add", ["col", "x"], ["col", "y"]], ["const", 3]],
                    "difference": [
                        "sub",
                        ["sub", ["col", "x"], ["col", "y"]],
                        ["const", 1],
                    ],
                    "chain": [
                        "sub",
                        ["col", "z"],
                        ["add", ["col", "x"], ["col", "y"]],
                    ],
                },
                "constraints": ["sum", "difference", "chain"],
            }
        )
        self.assertEqual(
            analysis.solved_forms(system), {"x": ({}, 2), "y": ({}, 1), "z": ({}, 3)}
        )

    def test_a_product_constraint_yields_no_equation(self) -> None:
        """`bit(x)` is a disjunction; treating it as `x = 0` would be unsound."""
        system = ir.from_dict(
            {
                "columns": [{"name": "x", "role": "output"}],
                "exprs": {"c": ["bit", ["col", "x"]]},
                "constraints": ["c"],
            }
        )
        self.assertEqual(analysis.solved_forms(system), {})
        # The root analysis still bounds it, by the argument it is entitled to.
        self.assertEqual(analysis.implied_column_bounds(system)["x"], (0, 1))


class RenormalisationTest(unittest.TestCase):
    """The rewrite that makes an inline carry chain reachable for the solver."""

    def setUp(self) -> None:
        self.system = ir.load(INLINE_ADDER)
        self.bounds = analysis.implied_column_bounds(self.system)

    def test_the_carry_is_pinned_although_no_column_in_it_is(self) -> None:
        """The fact lives on a line of the column space, not on a column.

        This is the whole reason the column-only analysis could not see it: the
        AIR spells a carry as an expression over four byte columns, none of
        which is a bit.
        """
        values = analysis.constrained_node_values(self.system)
        carries = [
            index
            for index, pinned in values.items()
            if pinned == (0, 1) and self.system.nodes[index].op == "mul"
        ]
        self.assertEqual(len(carries), 4, "one carry per limb")
        self.assertEqual(
            [i for i in values if self.system.nodes[i].op == "col"],
            [],
            "the fact is on a line through four columns, not on any one of them",
        )
        for column in ("a0", "s0", "s3"):
            self.assertEqual(self.bounds[column], (0, 255))

    def test_interval_width_stops_compounding_at_the_pinned_nodes(self) -> None:
        widest = lambda r: max(hi - lo for lo, hi in r.effective)  # noqa: E731
        plain = analysis.renormalise(self.system, self.bounds, values={})
        renormalised = analysis.renormalise(self.system, self.bounds)
        self.assertGreater(widest(plain), 10**60, "2^23 per limb, four limbs")
        self.assertLessEqual(widest(renormalised), 511)

    @needs_z3
    def test_the_verdict_is_the_same_with_and_without_it(self) -> None:
        for derived in (False, True):
            with self.subTest(renormalise=derived):
                result = solve.check(
                    self.system,
                    timeout_ms=TIMEOUT_MS,
                    derived=derived,
                )
                self.assertEqual(result.status, "unsat")
                self.assertTrue(result.constraints_satisfiable)


class LookupWindowTest(unittest.TestCase):
    """Range representatives recovered from live box requests.

    The multiplier families pin their carries with `range_check_8_11`, not with
    `bit()`, so the value-set renormalisation above never fires for them and
    the window is the only thing between the carry chain and a 2^23-per-limb
    interval blowup.  The window points the dangerous way -- it narrows -- so
    the tests here are mostly about when it must NOT apply.
    """

    def setUp(self) -> None:
        self.system = ir.load(MULTIPLIER)
        self.bounds = analysis.implied_column_bounds(self.system)

    def test_a_live_request_windows_the_carry_expression(self) -> None:
        renorm = analysis.renormalise(self.system, self.bounds)
        by_op = {
            self.system.nodes[index].op: window
            for index, window in renorm.windows.items()
        }
        self.assertEqual(len(renorm.windows), 2)
        self.assertEqual(by_op["mul"], (0, 2047), "the 11-bit half of the box")
        self.assertEqual(
            by_op["sub"],
            (0, 256 * 2047),
            "the sum the carry divides, through inv(256)",
        )
        for index, window in renorm.windows.items():
            self.assertEqual(renorm.effective[index], window)

    def test_without_placement_the_window_is_refused(self) -> None:
        """Unpinned enabler leaves the request dodgeable: a witness could set
        it to zero and put anything in the tuple, so narrowing would delete
        exactly that witness."""
        from dataclasses import replace

        mutant = replace(self.system, constraints=self.system.constraints[1:])
        bounds = analysis.implied_column_bounds(mutant)
        self.assertEqual(analysis.renormalise(mutant, bounds).windows, {})

    def test_the_naive_arm_never_windows(self) -> None:
        """`--no-derived-facts` must reproduce the un-rewritten query."""
        naive = analysis.renormalise(self.system, self.bounds, values={})
        self.assertEqual(naive.windows, {})

    @needs_z3
    def test_the_multiplier_toy_is_unique_and_non_vacuous(self) -> None:
        result = solve.check(self.system, timeout_ms=TIMEOUT_MS)
        self.assertEqual(result.status, "unsat")
        self.assertTrue(result.constraints_satisfiable)

    @needs_z3
    def test_dropping_the_request_is_sat_under_both_encodings(self) -> None:
        """The window derives from the lookup, so deleting the lookup must
        delete the window with it -- a window that survived would prove the
        mutant unique with an obligation that no longer exists."""
        from dataclasses import replace

        mutant = replace(self.system, lookups=())
        for derived in (False, True):
            with self.subTest(derived=derived):
                result = solve.check(
                    mutant, timeout_ms=TIMEOUT_MS, derived=derived, probe=False
                )
                self.assertEqual(result.status, "sat")


class ProofOnlyLookupSliceTest(unittest.TestCase):
    """A prefix lemma may weaken the AIR only in the proof direction."""

    def setUp(self) -> None:
        self.system = ir.load(MULTIPLIER)

    def test_every_analysis_sees_the_dropped_lookup_set(self) -> None:
        """No range window from a dropped request may survive into the query."""
        for prefix in range(len(self.system.lookups) + 1):
            with self.subTest(prefix=prefix):
                sliced = smtlib.emit_uniqueness_query(
                    self.system, shard=smtlib.Shard(lookup_prefix=prefix)
                )
                physically_dropped = smtlib.emit_uniqueness_query(
                    replace(self.system, lookups=self.system.lookups[:prefix])
                )
                self.assertEqual(
                    sliced.text.replace(
                        f"[lookups[:{prefix}]]", "[monolithic]"
                    ),
                    physically_dropped.text,
                )

    def test_an_out_of_range_prefix_is_rejected(self) -> None:
        with self.assertRaises(ir.IRError):
            smtlib.emit_uniqueness_query(
                self.system,
                shard=smtlib.Shard(lookup_prefix=len(self.system.lookups) + 1),
            )

    def test_a_full_prefix_is_not_marked_as_weakened(self) -> None:
        query = smtlib.emit_uniqueness_query(
            self.system,
            shard=smtlib.Shard(lookup_prefix=len(self.system.lookups)),
        )
        self.assertFalse(query.weakened)

    @needs_z3
    def test_a_sat_weakened_query_is_not_exported_as_a_counterexample(self) -> None:
        result = solve.check(
            self.system,
            timeout_ms=TIMEOUT_MS,
            shard=smtlib.Shard(lookup_prefix=0),
            probe=False,
        )
        self.assertEqual(result.status, "unknown")
        self.assertEqual(result.witnesses, {})
        self.assertIn("proof-only weakened", result.reason_unknown)

    def test_worker_status_529_is_unknown_not_proof(self) -> None:
        query = smtlib.Query(text="", family="toy", columns={})
        result = solve._fresh_result(query, 529, "", "worker vanished")
        self.assertEqual(result.status, "unknown")
        self.assertIn("status 529", result.reason_unknown)
        self.assertIn("worker vanished", result.reason_unknown)

    @needs_z3
    def test_a_disposable_worker_returns_a_real_verdict(self) -> None:
        query = smtlib.Query(
            text="(set-logic ALL)\n(assert false)\n(check-sat)\n",
            family="toy",
            columns={},
        )
        self.assertEqual(solve.run_query_fresh(query, 2_000).status, "unsat")


@needs_z3
class DivisionArithmeticControlTest(unittest.TestCase):
    """The reduced integer consequence used by the DIV certificate."""

    def test_quotient_remainder_control_has_no_second_answer(self) -> None:
        result = solve.run_query_fresh(solve._division_theorem_query(), 3_000)
        self.assertEqual(result.status, "unsat", result.reason_unknown)

    def test_the_subtracted_carry_balance_is_load_bearing(self) -> None:
        query = solve._division_theorem_query()
        balance = next(
            line
            for line in query.text.splitlines()
            if line.startswith("(assert (= (+ (* C Q_a)")
        )
        mutant = replace(query, text=query.text.replace(balance + "\n", ""))
        result = solve.run_query_fresh(mutant, 3_000)
        self.assertEqual(result.status, "sat", result.reason_unknown)


@unittest.skipUnless(
    DIV_IR.exists(),
    "run the 'uniqueness IR: emit every family' Zig test first",
)
class ProductionDivisionCertificateTest(unittest.TestCase):
    """The manual arithmetic derivation is valid only for one exact IR."""

    def setUp(self) -> None:
        self.system = ir.load(DIV_IR)

    def test_current_ir_matches_the_reviewed_certificate(self) -> None:
        self.assertEqual(
            solve._division_structure_digest(self.system),
            solve.DIVISION_CONTROL_DIGEST,
        )

    def test_constraint_geometry_and_degree_do_not_rise(self) -> None:
        node_degrees = analysis.degrees(self.system)
        self.assertEqual(len(self.system.columns), 68)
        self.assertEqual(len(self.system.constraints), 80)
        self.assertEqual(len(self.system.lookups), 25)
        self.assertEqual(
            max(node_degrees[node] for node in self.system.constraints),
            3,
        )
        [quotient_sign] = [
            lookup
            for lookup in self.system.lookups
            if lookup.domain == "range_check_m31"
        ]
        self.assertEqual(node_degrees[quotient_sign.numerator], 2)

    def test_control_cancels_unranged_dividend_limbs_instead_of_bounding_them(
        self,
    ) -> None:
        columns = {column.name: column for column in self.system.columns}
        self.assertIsNone(columns["rs1_prev_0"].domain)
        self.assertNotIn("(declare-const B ", solve._division_theorem_query().text)

    def test_every_single_obligation_deletion_fails_closed(self) -> None:
        mutants = []
        for index in range(len(self.system.constraints)):
            constraints = (
                self.system.constraints[:index] + self.system.constraints[index + 1 :]
            )
            mutants.append(
                (f"constraint {index}", replace(self.system, constraints=constraints))
            )
        for index in range(len(self.system.lookups)):
            lookups = self.system.lookups[:index] + self.system.lookups[index + 1 :]
            mutants.append((f"lookup {index}", replace(self.system, lookups=lookups)))
        for label, mutant in mutants:
            with self.subTest(obligation=label):
                result = solve.division_control(
                    mutant, solve.DIVISION_SELECTORS[0], 1
                )
                self.assertEqual(result.status, "unknown")
                self.assertIn("does not match", result.reason_unknown)

    def test_node_and_column_mutations_also_fail_closed(self) -> None:
        nodes = list(self.system.nodes)
        nodes[0] = replace(nodes[0], name=nodes[0].name + "_mutated")
        columns = list(self.system.columns)
        columns[0] = replace(columns[0], role="witness")
        for mutant in (
            replace(self.system, nodes=tuple(nodes)),
            replace(self.system, columns=tuple(columns)),
        ):
            result = solve.division_control(
                mutant, solve.DIVISION_SELECTORS[0], 1
            )
            self.assertEqual(result.status, "unknown")

    def test_a_referenced_table_width_mutation_fails_closed(self) -> None:
        with mock.patch.dict(
            tables.BOX_TABLES, {"range_check_8_11": (8, 10)}
        ):
            result = solve.division_control(
                self.system, solve.DIVISION_SELECTORS[0], 1
            )
        self.assertEqual(result.status, "unknown")

    @needs_z3
    def test_every_opcode_closes_and_has_a_complete_known_answer(self) -> None:
        for selector in solve.DIVISION_SELECTORS:
            with self.subTest(selector=selector):
                result = solve.division_control(self.system, selector, 3_000)
                self.assertEqual(result.status, "unsat", result.reason_unknown)
                self.assertIs(
                    solve.division_known_answer_satisfiable(
                        self.system, selector, 3_000
                    ),
                    True,
                )


class InverseProjectionTest(unittest.TestCase):
    """The rewrite that projects single-reader inverse witnesses out."""

    def setUp(self) -> None:
        self.system = ir.load(MULTIPLIER)

    def test_the_marker_is_matched_with_its_a_and_b(self) -> None:
        [(a, b, column)] = list(analysis.eliminable_inverses(self.system).values())
        self.assertEqual(column, "inv")
        self.assertEqual(self.system.nodes[a].name, "addr")
        self.assertEqual(self.system.nodes[b].name, "nonzero")

    def test_a_witness_a_lookup_reads_is_not_projected(self) -> None:
        """Projection is exact only when nothing else reads the witness; a
        lookup component is a reader."""
        payload = json.loads(MULTIPLIER.read_text(encoding="utf-8"))
        payload["lookups"][0]["tuple"][0] = ["col", "inv"]
        self.assertEqual(analysis.eliminable_inverses(ir.from_dict(payload)), {})

    def test_a_witness_two_constraints_read_is_not_projected(self) -> None:
        payload = json.loads(MULTIPLIER.read_text(encoding="utf-8"))
        payload["exprs"]["second_reader"] = ["mul", ["col", "inv"], ["col", "addr"]]
        payload["constraints"].append("second_reader")
        self.assertEqual(analysis.eliminable_inverses(ir.from_dict(payload)), {})

    def test_an_output_is_never_projected(self) -> None:
        """An output is what the conclusion quantifies over."""
        payload = json.loads(MULTIPLIER.read_text(encoding="utf-8"))
        for column in payload["columns"]:
            if column["name"] == "inv":
                column["role"] = "output"
        self.assertEqual(analysis.eliminable_inverses(ir.from_dict(payload)), {})

    def test_the_projected_product_never_enters_the_query(self) -> None:
        query = smtlib.emit_uniqueness_query(self.system)
        [factor] = list(analysis.eliminable_inverses(self.system))
        self.assertIn("witness inv projected out", query.text)
        self.assertNotIn(f"n{factor}@", query.text, "the A*Z - B term itself")
        self.assertEqual(query.eliminated, {"inv": factor})

    @needs_z3
    def test_reconstruction_satisfies_the_projected_constraint(self) -> None:
        """A decoded pair must be replayable against the AIR, which still has
        the constraint the query projected away.  Break the write-back so the
        family goes sat, then require `addr * inv = nonzero` to hold on both
        decoded copies with the reconstructed `inv`."""
        from dataclasses import replace

        mutant = replace(
            self.system,
            constraints=self.system.constraints[:4] + self.system.constraints[5:],
        )
        result = solve.check(mutant, timeout_ms=TIMEOUT_MS, probe=False)
        self.assertEqual(result.status, "sat")
        for copy in smtlib.COPIES:
            witness = result.witnesses[copy]
            columns = {**witness.inputs, **witness.outputs, **witness.witness}
            self.assertEqual(
                (columns["addr"] * columns["inv"] - columns["nonzero"]) % ir.MODULUS,
                0,
                f"copy {copy}",
            )


class BitwiseBitSharingTest(unittest.TestCase):
    """Bits carry the label of the component they decompose.

    Sharing is what lets a `xor` shard close: with per-copy bits of a shared
    operand, the solver must prove an 8-bit decomposition unique before it can
    conclude anything about the result.  Measured on `base_alu_reg`'s xor
    shard: 30.7 s on the one engine that closed it at all before, 0.5 s after.
    """

    def test_shared_operand_bits_are_shared_and_result_bits_are_not(self) -> None:
        text = smtlib.emit_uniqueness_query(ir.load(XOR)).text
        # Operands are inputs, so their bits are one set of eight.
        self.assertEqual(text.count("(declare-const lk0lb0@s Int)"), 1)
        self.assertEqual(text.count("(declare-const lk0lb0@a Int)"), 0)
        # The result is an output: each copy decomposes its own.
        for copy in smtlib.COPIES:
            self.assertEqual(text.count(f"(declare-const lk0vb0@{copy} Int)"), 1)


class VacuousFamilyTest(unittest.TestCase):
    """A family the query cannot speak about must say so, not answer anyway."""

    NO_OUTPUT = {
        "family": "toy_no_output",
        "columns": [{"name": "pc", "role": "input"}, {"name": "w", "role": "witness"}],
        "exprs": {"c": ["mul", ["col", "w"], ["sub", ["col", "w"], ["const", 1]]]},
        "constraints": ["c"],
    }

    def test_the_system_loads_and_reports_why_it_cannot_be_queried(self) -> None:
        system = ir.from_dict(self.NO_OUTPUT)
        self.assertIn("output", system.uniqueness_skip_reason() or "")

    def test_check_returns_skipped_rather_than_a_verdict(self) -> None:
        result = solve.check(ir.from_dict(self.NO_OUTPUT))
        self.assertEqual(result.status, "skipped")
        self.assertFalse(result.unique)
        self.assertIn("skipped", solve.format_result(result))
        self.assertIn(result.skip_reason, solve.format_result(result))

    def test_emitting_a_query_for_it_is_refused(self) -> None:
        with self.assertRaises(ir.IRError):
            smtlib.emit_uniqueness_query(ir.from_dict(self.NO_OUTPUT))


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
