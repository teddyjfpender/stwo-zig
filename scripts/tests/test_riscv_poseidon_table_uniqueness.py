"""Contracts for the Tier-2 Poseidon2/table row-local rigidity checker."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import riscv_poseidon_table_uniqueness as checker


ROOT = Path(__file__).resolve().parents[2]


class RiscVPoseidonTableUniquenessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # The exhaustive table pass is deliberately shared: it covers 2,981,888
        # rows and is the expensive part of this otherwise quick checker.
        cls.report = checker.run_audit(ROOT)

    def test_exact_poseidon_theorem_is_unique_and_nonvacuous(self) -> None:
        result = self.report.poseidon2
        self.assertEqual(result.main_columns, 445)
        self.assertEqual(result.inputs, 16)
        self.assertEqual(result.materialized_cells, 426)
        self.assertEqual(result.permutation_constraints, 427)
        self.assertEqual(result.generic_direct_constraints, 430)
        self.assertEqual(result.component_direct_constraints, 433)
        self.assertEqual(result.component_interaction_constraints, 2)
        self.assertEqual(result.component_total_constraints, 435)
        self.assertEqual(result.nonvacuity_rows, 4)
        self.assertEqual(result.rejected_cell_mutations, 429)
        self.assertTrue(result.inactive_counterexample)
        self.assertIn("all 445 main cells", result.theorem)

    def test_all_six_tables_are_exhaustive_and_transcript_nonvacuous(self) -> None:
        self.assertEqual(
            [table.kind for table in self.report.tables],
            list(checker.TABLE_ORDER),
        )
        self.assertEqual(self.report.total_table_rows, 2_981_888)
        for table in self.report.tables:
            with self.subTest(kind=table.kind):
                self.assertTrue(table.row_to_tuple_deterministic)
                self.assertTrue(table.is_first_deterministic)
                self.assertTrue(table.nonzero_transcript_control)
                self.assertEqual(table.dummy_zero_denominators, 0)
                self.assertEqual(
                    table.semantic_digest,
                    checker.TABLE_SEMANTIC_DIGESTS[table.kind],
                )
        self.assertFalse(
            next(
                table
                for table in self.report.tables
                if table.kind == "range_check_m31"
            ).tuple_to_row_injective
        )

    def test_poseidon_constraint_deletions_and_future_dependency_fail(self) -> None:
        for constraint in (1, 1 + 213, 426):
            with self.subTest(constraint=constraint), self.assertRaises(
                checker.AuditError
            ):
                checker._audit_poseidon_schedule(
                    lambda residuals, index=constraint: residuals.__setitem__(
                        index, checker._Expr.constant(0)
                    )
                )

        with self.assertRaises(checker.AuditError):
            checker._audit_poseidon_schedule(
                lambda residuals: residuals.__setitem__(
                    1,
                    residuals[1]
                    + checker._Expr.atom(
                        f"main_{checker.poseidon2.WIDE_COLUMN - 1}"
                    ),
                )
            )

    def test_table_formula_mutation_is_observed(self) -> None:
        def mutated(kind: str, row: int) -> tuple[int, ...]:
            result = checker.infrastructure.table_tuple(kind, row)
            if kind == "bitwise" and row == 7:
                return result[:2] + ((result[2] + 1) & 0xFF,) + result[3:]
            return result

        with self.assertRaisesRegex(checker.AuditError, "bitwise row 7"):
            checker.audit_tables(mutated)

    def test_source_bindings_fail_closed_for_every_bound_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copied_root = Path(directory)
            originals: dict[str, bytes] = {}
            for relative in checker.SOURCE_BINDINGS:
                source = ROOT / relative
                destination = copied_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
                originals[relative] = destination.read_bytes()

            self.assertEqual(
                checker.verify_source_bindings(copied_root),
                checker.SOURCE_BINDINGS,
            )
            for relative, original in originals.items():
                with self.subTest(source=relative):
                    destination = copied_root / relative
                    destination.write_bytes(original + b"\n// digest mutation\n")
                    with self.assertRaisesRegex(
                        checker.AuditError, "bound source digest changed"
                    ):
                        checker.verify_source_bindings(copied_root)
                    destination.write_bytes(original)

    def test_expected_counterexamples_are_executable_not_just_documented(self) -> None:
        self.assertTrue(checker._poseidon_inactive_counterexample())
        self.assertTrue(checker._zero_denominator_counterexample())
        self.assertIn(
            "inactive/padding Poseidon2 row uniqueness",
            self.report.exclusions,
        )
        self.assertIn(
            "unconditioned zero-denominator transcript uniqueness",
            self.report.exclusions,
        )

    def test_cli_and_explanation_keep_the_scope_narrow(self) -> None:
        explanation = io.StringIO()
        with contextlib.redirect_stdout(explanation):
            self.assertEqual(checker.main(["explain"]), 0)
        text = explanation.getvalue()
        self.assertIn("Padding-row uniqueness is therefore not claimed", text)
        self.assertIn("D(tuple) != 0", text)
        self.assertIn("No proof wire", text)
        self.assertIn("range_check_m31 rows 0 and 32767", text)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            stdout = io.StringIO()
            with mock.patch.object(
                checker, "run_audit", return_value=self.report
            ), contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    checker.main(["check", "--root", str(ROOT), "--json", str(output)]),
                    0,
                )
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["poseidon2"]["main_columns"], 445)
            self.assertEqual(len(payload["tables"]), 6)
            self.assertIn("VERDICT: PASS", stdout.getvalue())
            self.assertIn("not proof-wire verification", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
