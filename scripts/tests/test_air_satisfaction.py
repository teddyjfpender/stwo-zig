"""Contracts for the independent row-satisfaction and LogUp-closure checker.

Three groups, and they carry different weight.

The FIELD group anchors `air_satisfaction_lib.field` to something outside this
repository's Zig: the public LogUp boundary vector pinned in
`air/public_logup.zig` from the Rust oracle. If the QM31 tower, the relation
combine, or the boundary reimplementation were wrong, that vector would not
reproduce.

The ROW group builds systems and committed rows in memory and checks that the
checker reports exactly what is wrong, including that it refuses layouts it
cannot bind. A checker never shown failing is not evidence.

The EXPORT group runs against `zig-out/committed-trace/*.json` and skips when
those are absent, because producing them needs a Zig test run and hosted CI does
not do one. That is the same posture as `scripts/tests/test_air_uniqueness.py`.

Adversarial self-check, executed 2026-07-27
-------------------------------------------
`field.committed_placement` was replaced by a plain bit reversal --- the exact
mistake the checker exists to be unable to share with the prover --- and the
honest export was re-checked. Real output:

    ROW VIOLATIONS: 4
      base_alu_imm[0] row 2: constraint - constraint 21 of 22 evaluates to 2147483646, not 0
      load_store[2] row 2: constraint - constraint 69 of 70 evaluates to 2147483646, not 0
      load_store[2] row 3: constraint - constraint 69 of 70 evaluates to 2147483646, not 0
      lui[3] row 1: constraint - constraint 8 of 9 evaluates to 2147483646, not 0
      ...
      global sum: (0, 0, 0, 0)
      LOGUP CLOSURE: closed
    exit=1

and this module reported `Ran 20 tests ... FAILED (failures=7)`. `field.py` was
then restored and both went green again.

Two things that run records. The row check is what catches a placement error, so
the permutation is load-bearing rather than decorative. And the CLOSURE check is
NOT: it sums over the whole domain, so it is invariant under any permutation of
the rows, and it stayed at zero throughout. A reader must not treat a closed
ledger as evidence about placement.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from scripts import air_satisfaction
from scripts.air_satisfaction_lib import dump as dump_mod
from scripts.air_satisfaction_lib import field, logup, rows
from scripts.riscv_air_ir_lib import ir

ROOT = Path(__file__).resolve().parents[2]
EXPORTS = ROOT / "zig-out" / "committed-trace"
IR_DIR = ROOT / "zig-out" / "uniqueness-ir"

# `relation_challenges.Relations.dummy()`: one pair, reused for every relation.
DUMMY = dump_mod.Relation(z=field.QM31(1, 2, 3, 4), alpha=field.QM31(4, 3, 2, 1))


def dummy_relations() -> dict[str, dump_mod.Relation]:
    return {
        name: DUMMY
        for name in (
            "registers_state",
            "memory_access",
            "program_access",
            "merkle",
            "poseidon2",
            "poseidon2_io",
            "bitwise",
            "range_check_20",
            "range_check_8_11",
            "range_check_8_8_4",
            "range_check_8_8",
            "range_check_m31",
        )
    }


def pinned_public_data() -> dump_mod.PublicData:
    """The statement of the `public LogUp: exact pinned Stark-V dummy-relation
    vector` test in `air/public_logup.zig`, field for field."""
    regs_initial = [0] * 32
    regs_final = [0] * 32
    last_clock = [0] * 32
    regs_initial[1], regs_final[1], last_clock[1] = 0x0403_0201, 0x0807_0605, 9
    regs_initial[31], regs_final[31] = 11, 12
    return dump_mod.PublicData(
        initial_pc=0x1000,
        final_pc=0x1040,
        clock=17,
        initial_regs=tuple(regs_initial),
        final_regs=tuple(regs_final),
        reg_last_clock=tuple(last_clock),
        program_root=101,
        initial_rw_root=None,
        final_rw_root=303,
        completion_kind="unretired_self_loop",
        completion_address=0x1040,
        completion_value=0x0000_006F,
        completion_clock=0,
        io=dump_mod.IoEntries(
            input_start=0x0018_0000,
            input_len=6,
            input_words=(0x0403_0201, 0x0000_0605),
            output_len=4,
            output_len_addr=0x0010_0004,
            output_data_addr=0x0010_0008,
            output_words=(
                dump_mod.OutputWord(addr=0x0010_0004, value=4, clock=15),
                dump_mod.OutputWord(addr=0x0010_0008, value=0x4443_4241, clock=16),
            ),
        ),
    )


class FieldTest(unittest.TestCase):
    def test_pinned_public_boundary_vector_reproduces(self) -> None:
        # `legacy` in `air/public_logup.zig`, which pins the Rust oracle's value
        # for the three domains below. `program_access` is excluded there and
        # here: the self-loop sentinel term needs a decoded program tuple, which
        # `logup.program_access_sum` deliberately refuses to compute.
        relations = dummy_relations()
        public = pinned_public_data()
        total = (
            logup.registers_state_sum(public, relations)
            + logup.merkle_sum(public, relations)
            + logup.memory_access_sum(public, relations)
        )
        self.assertEqual(
            total.as_tuple(), (673401415, 755770749, 1943640833, 2140834143)
        )

    def test_the_self_loop_completion_is_refused_rather_than_guessed(self) -> None:
        with self.assertRaises(logup.UnsupportedStatement):
            logup.public_boundary(pinned_public_data(), dummy_relations())

    def test_inverse_and_distributivity_hold(self) -> None:
        a = field.QM31(7, 11, 13, 17)
        b = field.QM31(1_000_003, 5, 0, 2_147_483_646)
        c = field.QM31(0, 0, 1, 0)
        self.assertEqual((a * a.inv()).as_tuple(), field.QM31_ONE.as_tuple())
        self.assertEqual((b * b.inv()).as_tuple(), field.QM31_ONE.as_tuple())
        self.assertEqual((a * (b + c)).as_tuple(), (a * b + a * c).as_tuple())
        self.assertEqual(a.mul_base(5).as_tuple(), (a * field.QM31.from_base(5)).as_tuple())
        with self.assertRaises(field.FieldError):
            field.QM31().inv()

    def test_committed_placement_is_a_bijection(self) -> None:
        for log_size in range(0, 9):
            placement = field.committed_placement(log_size)
            self.assertEqual(sorted(placement), list(range(1 << log_size)))
            for logical, committed in enumerate(placement):
                self.assertEqual(
                    field.logical_index_from_committed(committed, log_size),
                    logical,
                )
        # Hand-derived for log_size 2: coset-to-circle sends (0,1,2,3) to
        # (0,3,1,2), and the 2-bit reversal sends (0,1,2,3) to (0,2,1,3), so the
        # composition is (0,3,2,1). A reader who believes the placement is a
        # plain bit reversal would expect (0,2,1,3).
        self.assertEqual(field.committed_placement(2), [0, 3, 2, 1])

        # The sparse fixed-table reader takes this scalar path at log 20; pin
        # representative boundary and interior indices without allocating a
        # second million-entry inverse table.
        placement20 = field.committed_placement(20)
        for logical in (0, 1, 2, 3, 0x12345, (1 << 20) - 2, (1 << 20) - 1):
            committed = placement20[logical]
            self.assertEqual(
                field.logical_index_from_committed(committed, 20),
                logical,
            )


def toy_system(**overrides) -> ir.System:
    """A three-column family: `b` must be `a + 1`, and `(a, b)` must be bytes."""
    payload = {
        "modulus": field.P,
        "family": "toy",
        "columns": [
            {"name": "enabler", "role": "input"},
            {"name": "a", "role": "input"},
            {"name": "b", "role": "output"},
        ],
        "exprs": {
            "residual": ["sub", ["sub", ["col", "b"], ["col", "a"]], ["const", 1]],
        },
        "constraints": ["residual"],
        "lookups": [
            {
                "domain": "range_check_8_8",
                "numerator": ["col", "enabler"],
                "tuple": [["col", "a"], ["col", "b"]],
            }
        ],
    }
    payload.update(overrides)
    return ir.from_dict(payload)


def toy_component(rows_in_natural_order: list[tuple[int, ...]], n_rows: int) -> dump_mod.Component:
    return dump_mod.Component(
        family="toy",
        index=0,
        log_size=2,
        n_rows=n_rows,
        n_columns=3,
        rows=tuple(rows_in_natural_order),
    )


PADDING = (0, 0, 0)


class RowTest(unittest.TestCase):
    def decide(self, system: ir.System, component: dump_mod.Component) -> list[rows.Violation]:
        violations, _ = rows.check_component(rows.prepare(system, component))
        return violations

    def test_a_satisfied_row_reports_nothing(self) -> None:
        component = toy_component([(1, 7, 8), PADDING, PADDING, PADDING], n_rows=1)
        self.assertEqual(self.decide(toy_system(), component), [])

    def test_a_broken_constraint_is_reported_with_its_index(self) -> None:
        component = toy_component([(1, 7, 9), PADDING, PADDING, PADDING], n_rows=1)
        violations = self.decide(toy_system(), component)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].kind, "constraint")
        self.assertIn("constraint 0 of 1", violations[0].detail)

    def test_an_out_of_box_request_is_reported(self) -> None:
        # `b = a + 1` still holds, so only the byte range can reject the row.
        component = toy_component([(1, 255, 256), PADDING, PADDING, PADDING], n_rows=1)
        violations = self.decide(toy_system(), component)
        self.assertEqual([v.kind for v in violations], ["lookup"])
        self.assertIn("exceeds its 8-bit box", violations[0].detail)

    def test_an_inactive_request_is_not_decided(self) -> None:
        # Numerator zero switches the request off, so the same out-of-box tuple
        # is not a violation. Only the constraint still applies.
        component = toy_component([(0, 255, 256), PADDING, PADDING, PADDING], n_rows=1)
        self.assertEqual(self.decide(toy_system(), component), [])

    def test_only_real_rows_are_decided(self) -> None:
        # Row 1 is nonsense but sits past `n_rows`, so it is out of scope.
        component = toy_component([(1, 7, 8), (1, 7, 99), PADDING, PADDING], n_rows=1)
        self.assertEqual(self.decide(toy_system(), component), [])

    def test_a_bitwise_result_mismatch_is_reported(self) -> None:
        system = ir.from_dict(
            {
                "modulus": field.P,
                "family": "toy",
                "columns": [
                    {"name": "enabler", "role": "input"},
                    {"name": "a", "role": "input"},
                    {"name": "b", "role": "output"},
                ],
                "exprs": {"zero": ["const", 0]},
                "constraints": ["zero"],
                "lookups": [
                    {
                        "domain": "bitwise",
                        "numerator": ["col", "enabler"],
                        # (lhs, rhs, value, op) with op = 2 (XOR).
                        "tuple": [["col", "a"], ["const", 15], ["col", "b"], ["const", 2]],
                    }
                ],
            }
        )
        component = toy_component([(1, 1, 15), PADDING, PADDING, PADDING], n_rows=1)
        violations = self.decide(system, component)
        self.assertEqual([v.kind for v in violations], ["lookup"])
        self.assertIn("1 xor 15 = 14, the row claims 15", violations[0].detail)

    def test_a_column_count_mismatch_is_refused(self) -> None:
        component = dump_mod.Component("toy", 0, 2, 1, 2, ((1, 7), PADDING[:2], (0, 0), (0, 0)))
        with self.assertRaises(rows.LayoutMismatch):
            rows.prepare(toy_system(), component)

    def test_a_wrong_family_is_refused(self) -> None:
        component = toy_component([(1, 7, 8), PADDING, PADDING, PADDING], n_rows=1)
        with self.assertRaises(rows.LayoutMismatch):
            rows.prepare(toy_system(family="other"), component)


def aliased_system(alias_in_lookup: bool) -> ir.System:
    """`toy` plus a fourth column that is an alias, not a committed cell."""
    tuple_second = ["col", "shadow"] if alias_in_lookup else ["col", "b"]
    return ir.from_dict(
        {
            "modulus": field.P,
            "family": "toy",
            "columns": [
                {"name": "enabler", "role": "input"},
                {"name": "a", "role": "input"},
                {"name": "b", "role": "output"},
                {"name": "shadow", "role": "output", "alias": "b, under another name"},
            ],
            "exprs": {
                "residual": ["sub", ["sub", ["col", "b"], ["col", "a"]], ["const", 1]],
                "definition": ["sub", ["col", "shadow"], ["col", "b"]],
            },
            "constraints": ["residual", "definition"],
            "lookups": [
                {
                    "domain": "range_check_8_8",
                    "numerator": ["col", "enabler"],
                    "tuple": [["col", "a"], tuple_second],
                }
            ],
        }
    )


class AliasTest(unittest.TestCase):
    def test_an_alias_definition_is_skipped_not_evaluated(self) -> None:
        if "alias" not in {f.name for f in ir.Column.__dataclass_fields__.values()}:
            self.skipTest("this IR revision has no alias columns")
        component = toy_component([(1, 7, 8), PADDING, PADDING, PADDING], n_rows=1)
        prepared = rows.prepare(aliased_system(alias_in_lookup=False), component)
        violations, counts = rows.check_component(prepared)
        self.assertEqual(violations, [])
        # One of the two constraints is the definition of the alias; it names a
        # column the committed trace does not carry, so it is dropped and said
        # to be dropped rather than silently counted as satisfied.
        self.assertEqual(counts.skipped_constraints, 1)
        self.assertEqual(counts.constraints, 1)

    def test_a_lookup_reading_an_alias_is_refused(self) -> None:
        if "alias" not in {f.name for f in ir.Column.__dataclass_fields__.values()}:
            self.skipTest("this IR revision has no alias columns")
        component = toy_component([(1, 7, 8), PADDING, PADDING, PADDING], n_rows=1)
        with self.assertRaises(rows.LayoutMismatch):
            rows.prepare(aliased_system(alias_in_lookup=True), component)


class DumpTest(unittest.TestCase):
    def test_an_unknown_schema_is_refused(self) -> None:
        path = ROOT / "scripts" / "tests" / "fixtures" / "does-not-exist.json"
        self.assertFalse(path.exists())
        with self.assertRaises(FileNotFoundError):
            dump_mod.load(path)


def exports_available() -> bool:
    required = (
        "honest.json",
        "all_families.json",
        "forged_addi_limb.json",
        "forged_bitwise_result.json",
    )
    honest = EXPORTS / "honest.json"
    if (
        any(not (EXPORTS / name).exists() for name in required)
        or not (IR_DIR / "lui.json").exists()
    ):
        return False
    try:
        return dump_mod.load(honest).components != ()
    except (ValueError, KeyError):
        # A stale export is not evidence for the current schema.
        return False


@unittest.skipUnless(
    exports_available(),
    "run the 'committed trace export' and 'uniqueness IR: emit every family' Zig tests first",
)
class ExportTest(unittest.TestCase):
    def test_all_28_transcript_components_are_independently_checked(self) -> None:
        exported = dump_mod.load(EXPORTS / "all_families.json")
        self.assertEqual(len(exported.opcode_components()), 17)
        self.assertEqual(len(exported.infra_components()), 11)
        self.assertEqual(len(exported.components), 28)
        self.assertEqual(len(exported.transcript_claims), 28)
        self.assertTrue(all(component.n_rows > 0 for component in exported.opcode_components()))

        report = air_satisfaction.check(EXPORTS / "all_families.json", IR_DIR)
        self.assertEqual([str(v) for v in report.violations], [])
        self.assertIsNotNone(report.closure)
        assert report.closure is not None
        self.assertEqual(len(report.closure.recomputed_opcode), 17)
        self.assertEqual(len(report.closure.recomputed_infra), 11)
        self.assertEqual(len(report.closure.recomputed_transcript), 28)
        self.assertTrue(report.ok(), report.closure)

    def test_the_honest_run_is_satisfied_and_closed(self) -> None:
        report = air_satisfaction.check(EXPORTS / "honest.json", IR_DIR)
        self.assertEqual([str(v) for v in report.violations], [])
        self.assertTrue(report.closed(), report.closure)
        self.assertTrue(report.ok())

    def test_undoing_the_placement_recovers_execution_order(self) -> None:
        """The placement permutation, checked without transcribing it.

        `Component.rows` is the export after this package undid the committed-row
        placement. Two consequences a wrong permutation could not produce: the
        real rows occupy exactly the prefix `[0, n_rows)` and every padding row
        is zero, and each family's `pc` column is strictly increasing and
        4-aligned across that prefix, because a straight-line guest retires each
        family's rows in address order. Scrambling the domain breaks the second
        even when it happens to preserve the first.
        """
        exported = dump_mod.load(EXPORTS / "honest.json")
        for component in exported.opcode_components():
            with self.subTest(component.family):
                system = ir.load(IR_DIR / f"{component.family}.json")
                pc = [c.name for c in system.columns].index("pc")
                for row in component.rows[component.n_rows :]:
                    self.assertEqual(set(row), {0})
                for row in component.rows[: component.n_rows]:
                    self.assertNotEqual(set(row), {0})
                addresses = [row[pc] for row in component.rows[: component.n_rows]]
                self.assertEqual(addresses, sorted(set(addresses)))
                self.assertTrue(all(address % 4 == 0 for address in addresses))

    def test_the_forged_bitwise_result_is_caught_as_a_lookup_failure(self) -> None:
        report = air_satisfaction.check(EXPORTS / "forged_bitwise_result.json", IR_DIR)
        self.assertEqual(len(report.violations), 1, [str(v) for v in report.violations])
        violation = report.violations[0]
        self.assertEqual(violation.kind, "lookup")
        self.assertEqual(violation.family, "base_alu_reg")
        self.assertIn("bitwise", violation.detail)
        # Every direct constraint still vanishes: that is what makes the
        # rejection attributable to the table and not to a carry chain.
        self.assertFalse(any(v.kind == "constraint" for v in report.violations))
        self.assertFalse(report.closed())
        self.assertFalse(report.ok())

    def test_the_forged_addi_limb_is_caught_as_a_constraint_failure(self) -> None:
        report = air_satisfaction.check(EXPORTS / "forged_addi_limb.json", IR_DIR)
        self.assertTrue(any(v.kind == "constraint" for v in report.violations))
        self.assertTrue(
            all(v.family == "base_alu_imm" for v in report.violations),
            [str(v) for v in report.violations],
        )
        self.assertFalse(report.closed())
        self.assertFalse(report.ok())

    def test_every_forged_export_loses_the_global_sum(self) -> None:
        for name in ("forged_bitwise_result.json", "forged_addi_limb.json"):
            with self.subTest(name):
                report = air_satisfaction.check(EXPORTS / name, IR_DIR)
                assert report.closure is not None
                self.assertFalse(report.closure.total.is_zero())
                # The claims still match the trace they were built from: the
                # prover derived its interaction columns from the forged
                # witness, so the ledger fails at the boundary, not here.
                self.assertEqual(report.closure.disagreeing_claims(), [])


if __name__ == "__main__":
    unittest.main()
