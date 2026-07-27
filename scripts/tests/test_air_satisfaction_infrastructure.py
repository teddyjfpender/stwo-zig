"""Focused contracts for the independent infrastructure checker."""

from __future__ import annotations

import unittest

from scripts.air_satisfaction_lib import infrastructure, logup, poseidon2
from scripts.air_satisfaction_lib.dump import Component, Relation
from scripts.air_satisfaction_lib.field import P, QM31


def dense_component(
    kind: str,
    row: tuple[int, ...],
    *,
    n_rows: int = 1,
    log_size: int = 4,
    index: int = 0,
) -> Component:
    rows = (row,) + ((0,) * len(row),) * ((1 << log_size) - 1)
    return Component(
        family=kind,
        index=index,
        log_size=log_size,
        n_rows=n_rows,
        n_columns=len(row),
        rows=rows,
        class_="infra",
    )


class InfrastructureRowsTest(unittest.TestCase):
    def decide(self, component: Component):
        return infrastructure.check_component(component)

    def test_program_constraints_and_requests(self) -> None:
        component = dense_component(
            "program",
            (1, 0x1000, 10, 11, 12, 13, 3, 99, 0x400, 0),
        )
        violations, counts, requests = self.decide(component)
        self.assertEqual(violations, [])
        self.assertEqual(counts.constraints, 3 * component.domain_size())
        self.assertEqual(len(requests), 7)

        bad = list(component.rows[0])
        bad[8] += 1
        forged = dense_component("program", tuple(bad))
        violations, _, _ = self.decide(forged)
        self.assertTrue(any("address recomposition" in v.detail for v in violations))

    def test_memory_signed_multiplicity_and_byte_lookups(self) -> None:
        component = dense_component(
            "memory",
            (0x1000, 7, 1, 2, 3, 4, P - 1, 99),
        )
        violations, _, requests = self.decide(component)
        self.assertEqual(violations, [])
        self.assertEqual(len(requests), 7)

        bad = dense_component("memory", (0x1000, 7, 1, 2, 3, 256, P - 1, 99))
        violations, _, _ = self.decide(bad)
        self.assertEqual([v.kind for v in violations], ["lookup"])

    def test_merkle_exposes_global_recurrence_without_inventing_local_parity(self) -> None:
        component = dense_component(
            "merkle",
            (1, 17, 9, 11, 22, 33, 1, 2, 1, 99),
        )
        violations, counts, requests = self.decide(component)
        self.assertEqual(violations, [])
        self.assertEqual(counts.constraints, 7 * component.domain_size())
        self.assertEqual(len(requests), 5)
        parent = [r for r in requests if r.domain == "merkle"][2]
        self.assertEqual(parent.values[:2], (17 * infrastructure.INV2 % P, 8))

    def test_poseidon_known_answer_and_intermediate_mutation(self) -> None:
        row = poseidon2.fill((1, 2, *([0] * 14)))
        self.assertEqual(row[poseidon2.OUTPUT_START], 1_975_699_496)
        component = dense_component("poseidon2", row)
        violations, counts, requests = self.decide(component)
        self.assertEqual(violations, [])
        self.assertEqual(counts.constraints, 433 * component.domain_size())
        self.assertEqual(len(requests), 2)

        bad = list(row)
        bad[poseidon2.TEMP_START] += 1
        forged = dense_component("poseidon2", tuple(bad))
        violations, _, _ = self.decide(forged)
        self.assertTrue(any("Poseidon2 residual" in v.detail for v in violations))

    def test_clock_predecessor_bound_is_both_recomposed_and_table_checked(self) -> None:
        previous = (63 << 20) + 7
        component = dense_component(
            "clock_update",
            (1, 0, 3, previous, 1, 2, 3, 4, 7, 63),
        )
        violations, _, requests = self.decide(component)
        self.assertEqual(violations, [])
        self.assertEqual(len(requests), 4)

        forged = dense_component(
            "clock_update",
            (1, 0, 3, 64 << 20, 1, 2, 3, 4, 0, 64),
        )
        violations, _, _ = self.decide(forged)
        self.assertEqual([v.kind for v in violations], ["lookup"])
        self.assertIn("8-bit box", violations[0].detail)

    def test_sparse_table_uses_natural_tuple_at_committed_nonzero_row(self) -> None:
        component = Component(
            family="range_check_8_8",
            index=7,
            log_size=16,
            n_rows=1 << 16,
            n_columns=1,
            rows=(),
            class_="infra",
            sparse_rows=((513, (P - 1,)),),
        )
        violations, counts, requests = self.decide(component)
        self.assertEqual(violations, [])
        self.assertEqual(counts.rows, 1)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].values, (1, 2))
        self.assertEqual(requests[0].numerator, 1)

    def test_all_six_table_boundaries_are_exact(self) -> None:
        for kind, log_size in infrastructure.TABLE_LOG_SIZES.items():
            with self.subTest(kind):
                size = 1 << log_size
                first = infrastructure.table_tuple(kind, 0)
                last = infrastructure.table_tuple(kind, size - 1)
                self.assertEqual(len(first), infrastructure.TABLE_ARITIES[kind])
                self.assertEqual(len(last), infrastructure.TABLE_ARITIES[kind])
        self.assertEqual(
            infrastructure.table_tuple("range_check_m31", (1 << 15) - 1),
            (0, 0),
        )

    def test_relation_claim_is_recomputed_term_by_term(self) -> None:
        relation = Relation(QM31(1, 2, 3, 4), QM31(4, 3, 2, 1))
        relations = {"range_check_8_8": relation}
        request = infrastructure.Request("range_check_8_8", P - 1, (1, 2))
        actual = logup.relation_claim((request,), relations)
        expected = relation.combine([QM31.from_base(1), QM31.from_base(2)]).inv()
        expected = expected.mul_base(P - 1)
        self.assertEqual(actual.as_tuple(), expected.as_tuple())


if __name__ == "__main__":
    unittest.main()
