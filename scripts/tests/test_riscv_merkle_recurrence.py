"""Machine-check the sparse-Merkle path and detached-cycle argument."""

from __future__ import annotations

import contextlib
import io
import json
import random
import unittest
from pathlib import Path

from scripts import riscv_merkle_recurrence as recurrence


ROOT = Path(__file__).resolve().parents[2]


class MerkleIndexRecurrenceTests(unittest.TestCase):
    def test_depth_30_symbolic_certificate_covers_every_path_without_wrap(self) -> None:
        certificate = recurrence.index_certificate()

        self.assertEqual(0, certificate.root_index)
        self.assertEqual(30, certificate.path_depth)
        self.assertEqual(
            tuple(1 << shift for shift in range(29, -1, -1)),
            certificate.binary_weights,
        )
        self.assertEqual(0, certificate.minimum_leaf_index)
        self.assertEqual((1 << 30) - 1, certificate.maximum_leaf_index)
        self.assertEqual(1 << 30, certificate.reachable_leaf_indices)
        self.assertLess(certificate.maximum_leaf_index, recurrence.M31_MODULUS)
        self.assertTrue(certificate.canonical_without_wrap)
        self.assertTrue(certificate.parity_is_path_bit)

    def test_fold_is_exactly_the_30_bit_path_integer(self) -> None:
        generator = random.Random(0x5A17_30)
        paths = [
            (0,) * 30,
            (1,) * 30,
            tuple(index % 2 for index in range(30)),
            tuple((index + 1) % 2 for index in range(30)),
        ]
        paths.extend(
            tuple(generator.randrange(2) for _ in range(30))
            for _ in range(256)
        )

        for bits in paths:
            with self.subTest(bits=bits):
                expected = int("".join(str(bit) for bit in bits), 2)
                self.assertEqual(expected, recurrence.fold_path(bits))
                self.assertEqual(
                    expected,
                    recurrence.fold_path(bits, modulus=recurrence.M31_MODULUS),
                )
                self.assertEqual(bits, recurrence.decode_leaf_index(expected, 30))

    def test_reverse_recurrence_forces_parity_globally(self) -> None:
        # Exhaustive at depth 12; the symbolic interval certificate performs
        # the same induction for all 2**30 paths without enumerating a billion.
        depth = 12
        for leaf in range(1 << depth):
            bits = recurrence.decode_leaf_index(leaf, depth)
            self.assertEqual(leaf, recurrence.fold_path(bits))
            child = leaf
            for expected_bit in reversed(bits):
                parent, parity = divmod(child, 2)
                self.assertEqual(expected_bit, parity)
                self.assertEqual(child, 2 * parent + expected_bit)
                child = parent
            self.assertEqual(0, child)

    def test_depth_31_exhibits_the_wrap_excluded_at_depth_30(self) -> None:
        all_right = (1,) * 31
        self.assertEqual(recurrence.M31_MODULUS, recurrence.fold_path(all_right))
        self.assertEqual(
            0,
            recurrence.fold_path(all_right, modulus=recurrence.M31_MODULUS),
        )
        with self.assertRaisesRegex(AssertionError, "can wrap modulus"):
            recurrence.index_certificate(depth=31)


class MerkleDepthCycleTests(unittest.TestCase):
    def test_depth_minus_one_has_additive_order_p(self) -> None:
        certificate = recurrence.depth_cycle_certificate()

        self.assertEqual(recurrence.M31_MODULUS, certificate.field_modulus)
        self.assertEqual(-1, certificate.depth_step)
        self.assertEqual(1, certificate.step_modulus_gcd)
        self.assertEqual(
            recurrence.M31_MODULUS,
            certificate.minimum_positive_cycle_rows,
        )
        self.assertEqual(
            recurrence.M31_MODULUS,
            certificate.distinct_depths_before_repeat,
        )
        self.assertEqual(
            recurrence.M31_MODULUS - 1,
            certificate.maximum_admitted_rows,
        )
        self.assertTrue(certificate.detached_cycle_excluded)

    def test_additive_order_formula_matches_brute_force_small_rings(self) -> None:
        # This independently exercises the theorem used for p without
        # allocating or iterating over p = 2**31 - 1 elements.
        for modulus in range(2, 40):
            for step in range(-modulus, modulus + 1):
                expected = next(
                    count
                    for count in range(1, modulus + 1)
                    if count * step % modulus == 0
                )
                actual = recurrence.additive_order(step, modulus)
                self.assertEqual(expected, actual)
                depths = [
                    (7 + count * step) % modulus
                    for count in range(actual)
                ]
                self.assertEqual(actual, len(set(depths)))

    def test_statement_bound_is_one_row_below_first_possible_cycle(self) -> None:
        p = recurrence.M31_MODULUS
        self.assertNotEqual(0, recurrence.depth_after_rows(0, p - 1, p))
        self.assertEqual(0, recurrence.depth_after_rows(0, p, p))


class MerkleProductionContractTests(unittest.TestCase):
    def test_checker_is_bound_to_shipped_relation_and_admission_sources(self) -> None:
        contract = recurrence.check_production_contract(ROOT)

        self.assertEqual(recurrence.M31_MODULUS, contract.source_modulus)
        self.assertEqual(
            1,
            2 * contract.source_inverse_two % contract.source_modulus,
        )
        self.assertEqual("child = 2 * parent + bit", contract.child_recurrence)
        self.assertEqual(
            "parent_depth = child_depth - 1 (mod p)",
            contract.depth_recurrence,
        )
        self.assertEqual(
            "merkle n_rows < M31 modulus",
            contract.admission_rule,
        )

    def test_cli_emits_a_reviewable_json_certificate(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(0, recurrence.main(["--repo-root", str(ROOT)]))
        report = json.loads(output.getvalue())

        self.assertEqual("stwo-riscv-merkle-recurrence-v1", report["schema"])
        self.assertEqual(
            (1 << 30) - 1,
            report["index_recurrence"]["maximum_leaf_index"],
        )
        self.assertEqual(
            recurrence.M31_MODULUS,
            report["depth_cycle"]["minimum_positive_cycle_rows"],
        )
        self.assertTrue(report["depth_cycle"]["detached_cycle_excluded"])


if __name__ == "__main__":
    unittest.main()
