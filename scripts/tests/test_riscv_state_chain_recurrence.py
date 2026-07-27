"""Machine checks for the state-chain and clock-window arithmetic lemmas."""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from pathlib import Path

from scripts import riscv_state_chain_recurrence as recurrence


ROOT = Path(__file__).resolve().parents[2]


class StateCycleTests(unittest.TestCase):
    def test_plus_one_cycle_needs_p_rows_and_geometry_is_shorter(self) -> None:
        certificate = recurrence.state_cycle_certificate()

        self.assertEqual(recurrence.M31_MODULUS, certificate.minimum_positive_cycle_rows)
        self.assertEqual(1 << 24, certificate.maximum_execution_rows)
        self.assertEqual((1 << 24) + 1, certificate.maximum_public_final_clock)
        self.assertTrue(certificate.final_clock_is_canonical)
        self.assertTrue(certificate.detached_cycle_excluded)

    def test_additive_order_formula_matches_small_rings(self) -> None:
        for modulus in range(2, 60):
            for step in range(-modulus, modulus + 1):
                expected = next(
                    count
                    for count in range(1, modulus + 1)
                    if count * step % modulus == 0
                )
                self.assertEqual(expected, recurrence.additive_order(step, modulus))


class ClockWindowTests(unittest.TestCase):
    def test_production_window_turns_range20_into_integer_monotonicity(self) -> None:
        certificate = recurrence.clock_window_certificate()

        self.assertEqual((1 << 24) - 1, certificate.maximum_synthetic_predecessor)
        self.assertEqual(
            (1 << 24) - 1 + (1 << 20) - 1,
            certificate.maximum_synthetic_output,
        )
        self.assertGreater(
            certificate.minimum_wrapped_backward_gap,
            certificate.maximum_clock_gap,
        )
        self.assertTrue(certificate.wrapped_gap_exceeds_table)
        self.assertTrue(certificate.synthetic_addition_does_not_wrap)

        # Exhaust the same implication over small analogue windows: whenever
        # p - E > D, a field gap <= D between bounded endpoints never points
        # backwards in the integer order.
        for modulus in range(17, 80):
            for bound in range(2, modulus):
                for gap_bound in range(1, modulus):
                    maximum_output = bound - 1 + gap_bound
                    if maximum_output >= modulus or modulus - maximum_output <= gap_bound:
                        continue
                    for current in range(maximum_output + 1):
                        for previous in range(maximum_output + 1):
                            gap = (current - previous) % modulus
                            if gap <= gap_bound:
                                self.assertLessEqual(previous, current)

    def test_bridge_count_and_residual_gap_are_exact(self) -> None:
        step = 13
        for previous in range(0, 40):
            for target in range(previous, 120):
                certificate = recurrence.bridge_certificate(previous, target, step)
                difference = target - previous
                expected = 0 if difference <= step else (difference - 1) // step
                self.assertEqual(expected, certificate["synthetic_rows"])
                self.assertLessEqual(certificate["final_gap"], step)
                self.assertTrue(certificate["strictly_increasing"] or expected == 0)

        production = recurrence.bridge_certificate(0, recurrence.MAX_EXECUTION_STEPS)
        self.assertEqual(16, production["synthetic_rows"])
        self.assertEqual(16, production["final_gap"])
        self.assertLess(production["effective_previous"], recurrence.CLOCK_PREV_BOUND)

    def test_old_wrapped_cycle_is_reproduced_and_new_window_rejects_it(self) -> None:
        attack = recurrence.old_wrapped_cycle_counterexample()

        self.assertEqual(2_048, attack.synthetic_rows)
        self.assertEqual(recurrence.M31_MODULUS - 2_046, attack.endpoint_clock)
        self.assertEqual(2_047, attack.final_opcode_gap)
        self.assertEqual(2_049, attack.total_edges)
        self.assertTrue(attack.closes_mod_field)
        self.assertTrue(attack.every_gap_was_in_old_window)
        self.assertEqual(17, attack.first_rejected_row_zero_based)
        self.assertGreaterEqual(
            attack.first_rejected_predecessor,
            recurrence.CLOCK_PREV_BOUND,
        )


class ProductionContractTests(unittest.TestCase):
    def test_checker_is_bound_to_shipped_relations_and_guards(self) -> None:
        contract = recurrence.check_production_contract(ROOT)

        self.assertEqual(recurrence.M31_MODULUS, contract.source_modulus)
        self.assertEqual(256, contract.source_max_components)
        self.assertEqual(16, contract.source_shard_log_size)
        self.assertEqual(20, contract.source_clock_low_bits)
        self.assertEqual(4, contract.source_clock_high_bits)
        self.assertEqual(
            "(pc, clock) -> (next_pc, clock + 1)",
            contract.state_recurrence,
        )
        self.assertEqual(
            "0 <= clock_prev < 2^24",
            contract.clock_predecessor_range,
        )

    def test_cli_emits_a_reviewable_json_certificate(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(0, recurrence.main(["--repo-root", str(ROOT)]))
        payload = json.loads(output.getvalue())

        self.assertEqual(
            "stwo-riscv-state-chain-recurrence-v1",
            payload["schema"],
        )
        self.assertTrue(payload["state_cycle"]["detached_cycle_excluded"])
        self.assertTrue(payload["clock_window"]["wrapped_gap_exceeds_table"])
        self.assertTrue(payload["old_wrapped_cycle"]["closes_mod_field"])


if __name__ == "__main__":
    unittest.main()
