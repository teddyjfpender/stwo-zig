"""Division, multiplication, and shift witness tests."""

from __future__ import annotations

import subprocess
import unittest

from scripts import riscv_team_b_witnesses as witnesses
from scripts.tests._riscv_team_b_witnesses_support import export_air


class RemainderWitnessTest(unittest.TestCase):
    """REM/REMU as distinct selectors, pinned to the RISC-V conventions."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.air_ir_dir = export_air()
        except (OSError, subprocess.SubprocessError) as error:
            raise unittest.SkipTest(f"production AIR export unavailable: {error}")

    def test_every_remainder_witness_is_reachable_in_production(self):
        report = witnesses.check_rem_witnesses(self.air_ir_dir)
        self.assertIn("13 witnesses reachable", report)
        self.assertIn("dividend's sign", report)

    def test_rem_of_minus_100_by_7_is_minus_2_not_plus_5(self):
        # RISC-V truncated division: the remainder takes the dividend's sign.
        # Python's floor-mod would answer +5, which is exactly the wrong
        # transcription this battery exists to catch.
        _, remainder = witnesses.quotient_and_remainder("rem", 0xFFFFFF9C, 7)
        self.assertEqual(witnesses._signed(remainder), -2)
        self.assertNotEqual(witnesses._signed(remainder), (-100) % 7)

    def test_rem_by_zero_yields_the_dividend_not_all_ones(self):
        # The REM convention differs from DIV's all-ones on the same operands.
        for selector in ("rem", "remu"):
            _, remainder = witnesses.quotient_and_remainder(selector, 0xDEADBEEF, 0)
            self.assertEqual(remainder, 0xDEADBEEF)
        quotient, _ = witnesses.quotient_and_remainder("div", 0xDEADBEEF, 0)
        self.assertEqual(quotient, 0xFFFFFFFF)

    def test_rem_signed_overflow_yields_zero(self):
        _, remainder = witnesses.quotient_and_remainder(
            "rem", witnesses.INT_MIN, 0xFFFFFFFF
        )
        self.assertEqual(remainder, 0)

    def test_the_battery_includes_an_aliased_operand(self):
        # check_rem_witnesses runs rd = rs1 and rd = rs2 aliases in-function;
        # this asserts those rows really are admitted by production.
        for rd in (5, 6):
            assignment, _ = witnesses.division_row("rem", 0xFFFFFF9C, 7, rd=rd)
            report = witnesses.check_witness(self.air_ir_dir, "div", assignment)
            self.assertIn("constraints satisfied", report)

    def test_a_rem_row_retiring_the_quotient_is_refused(self):
        assignment, _ = witnesses.division_row("rem", 100, 7)
        for index, limb in enumerate(witnesses._limbs(14)):
            assignment[f"rd_next_{index}"] = limb
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "div", assignment)

    def test_a_remainder_not_below_its_divisor_is_refused(self):
        # 100 = 7*13 + 9 satisfies the eight-limb product identity, so only
        # the positive_remainder_diff range request on lt_diff - 1 can refuse
        # the claim: 7 - 9 is negative, hence outside the 20-bit table.
        assignment, _ = witnesses.division_row("remu", 100, 7)
        for index, limb in enumerate(witnesses._limbs(13)):
            assignment[f"q_{index}"] = limb
        for index, limb in enumerate(witnesses._limbs(9)):
            assignment[f"r_{index}"] = limb
            assignment[f"r_abs_{index}"] = limb
            assignment[f"rd_next_{index}"] = limb
            assignment[f"r_inv_{index}"] = witnesses.modular_inverse(limb - 256)
        assignment["r_sum_inv"] = witnesses.modular_inverse(9)
        assignment["lt_diff"] = (7 - 9) % witnesses.M31
        with self.assertRaisesRegex(
            witnesses.WitnessError, "outside the 20-bit production table"
        ):
            witnesses.check_witness(self.air_ir_dir, "div", assignment)


class DivisionWitnessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.air_ir_dir = export_air()
        except (OSError, subprocess.SubprocessError) as error:
            raise unittest.SkipTest(f"production AIR export unavailable: {error}")

    def test_every_required_div_witness_is_reachable_in_production(self):
        report = witnesses.check_div_witnesses(self.air_ir_dir)
        self.assertIn("15 witnesses reachable", report)

    def test_quotient_truncates_toward_zero_not_toward_negative_infinity(self):
        # Python's // floors, which would give -15 and remainder 5. RISC-V
        # truncates, giving -14 and remainder -2.
        quotient, remainder = witnesses.quotient_and_remainder(
            "div", 0xFFFFFF9C, 7
        )
        self.assertEqual(witnesses._signed(quotient), -14)
        quotient, remainder = witnesses.quotient_and_remainder(
            "rem", 0xFFFFFF9C, 7
        )
        self.assertEqual(witnesses._signed(remainder), -2)

    def test_remainder_takes_the_sign_of_the_dividend(self):
        _, remainder = witnesses.quotient_and_remainder("rem", 100, 0xFFFFFFF9)
        self.assertEqual(witnesses._signed(remainder), 2)
        _, remainder = witnesses.quotient_and_remainder("rem", 0xFFFFFF9C, 7)
        self.assertEqual(witnesses._signed(remainder), -2)

    def test_every_divisor_zero_convention(self):
        self.assertEqual(witnesses.quotient_and_remainder("div", 42, 0)[0], 0xFFFFFFFF)
        self.assertEqual(witnesses.quotient_and_remainder("divu", 42, 0)[0], 0xFFFFFFFF)
        self.assertEqual(witnesses.quotient_and_remainder("rem", 42, 0)[1], 42)
        self.assertEqual(witnesses.quotient_and_remainder("remu", 42, 0)[1], 42)

    def test_signed_overflow_convention(self):
        quotient, remainder = witnesses.quotient_and_remainder(
            "div", witnesses.INT_MIN, 0xFFFFFFFF
        )
        self.assertEqual(quotient, witnesses.INT_MIN)
        self.assertEqual(remainder, 0)

    def test_high_bit_unsigned_division(self):
        quotient, _ = witnesses.quotient_and_remainder("divu", 0x8ABCDEF1, 1)
        self.assertEqual(quotient, 0x8ABCDEF1)

    def test_a_free_quotient_sign_is_caught(self):
        assignment, _ = witnesses.division_row("div", 0xFFFFFF9C, 7)
        assignment["q_sign"] ^= 1
        with self.assertRaises(witnesses.WitnessError):
            witnesses.check_witness(self.air_ir_dir, "div", assignment)

    def test_a_deleted_zero_divisor_convention_is_caught(self):
        assignment, _ = witnesses.division_row("divu", 42, 0)
        assignment["q_0"] = 0
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "div", assignment)

    def test_a_wrong_remainder_sign_is_caught(self):
        assignment, _ = witnesses.division_row("rem", 0xFFFFFF9C, 7)
        assignment["r_0"] = 2  # +2 instead of the architectural -2
        with self.assertRaises(witnesses.WitnessError):
            witnesses.check_witness(self.air_ir_dir, "div", assignment)

    def test_a_released_comparison_witness_is_caught(self):
        assignment, _ = witnesses.division_row("divu", 100, 7)
        for index in range(4):
            assignment[f"lt_markers_{index}"] = 0
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "div", assignment)

    def test_selector_relabelling_is_caught(self):
        # A DIVU row relabelled REMU keeps the quotient in rd, which no longer
        # matches the remainder the selector demands.
        assignment, _ = witnesses.division_row("divu", 100, 7)
        assignment["is_divu"] = 0
        assignment["is_remu"] = 1
        with self.assertRaises(witnesses.WitnessError):
            witnesses.check_witness(self.air_ir_dir, "div", assignment)

    def test_a_non_byte_divisor_limb_is_caught(self):
        assignment, _ = witnesses.division_row("divu", 100, 7)
        assignment["rs2_next_0"] = 300
        assignment["rs2_previous_0"] = 300
        with self.assertRaises(witnesses.WitnessError):
            witnesses.check_witness(self.air_ir_dir, "div", assignment)

    def test_unknown_selector_fails_closed(self):
        with self.assertRaisesRegex(witnesses.WitnessError, "unknown DIV-family"):
            witnesses.quotient_and_remainder("mulh", 1, 1)


class MultiplyAndShiftWitnessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.air_ir_dir = export_air()
        except (OSError, subprocess.SubprocessError) as error:
            raise unittest.SkipTest(f"production AIR export unavailable: {error}")

    def test_multiply_witnesses_are_reachable_in_production(self):
        self.assertIn(
            "12 witnesses reachable",
            witnesses.check_multiply_witnesses(self.air_ir_dir),
        )

    def test_shift_witnesses_are_reachable_in_production(self):
        self.assertIn(
            "13 witnesses reachable",
            witnesses.check_shift_witnesses(self.air_ir_dir),
        )

    def test_signedness_combination_is_actually_distinguished(self):
        # The same operand pair must give three different high words under the
        # three selectors, otherwise the sign witnesses are not load-bearing.
        _, unsigned = witnesses.multiply_high_row("mulhu", 0xFFFFFFFF, 0xFFFFFFFF)
        _, signed = witnesses.multiply_high_row("mulh", 0xFFFFFFFF, 0xFFFFFFFF)
        _, mixed = witnesses.multiply_high_row("mulhsu", 0xFFFFFFFF, 0xFFFFFFFF)
        self.assertEqual(unsigned, 0xFFFFFFFE)
        self.assertEqual(signed, 0x00000000)
        self.assertEqual(mixed, 0xFFFFFFFF)

    def test_a_free_high_word_limb_is_caught(self):
        assignment, _ = witnesses.multiply_high_row("mulhu", 0xFFFFFFFF, 0xFFFFFFFF)
        assignment["result_0"] = (assignment["result_0"] + 1) % 256
        with self.assertRaises(witnesses.WitnessError):
            witnesses.check_witness(self.air_ir_dir, "mulh", assignment)

    def test_an_unbound_operand_sign_is_caught(self):
        assignment, _ = witnesses.multiply_high_row("mulh", 0xFFFFFFFF, 0xFFFFFFFF)
        assignment["rs1_sign"] = 0
        with self.assertRaises(witnesses.WitnessError):
            witnesses.check_witness(self.air_ir_dir, "mulh", assignment)

    def test_mulhu_may_not_claim_a_signed_operand(self):
        assignment, _ = witnesses.multiply_high_row("mulhu", 0xFFFFFFFF, 0xFFFFFFFF)
        assignment["rs1_sign"] = 1
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "mulh", assignment)

    def test_the_arithmetic_sign_fill_path_is_exercised(self):
        # A shift witness set with no negative SRAI source would leave the
        # sign-fill path untested.
        sign_filled = [
            name
            for name, selector, source, _, _ in witnesses.SHIFT_WITNESSES
            if selector == "sra" and source & witnesses.INT_MIN
        ]
        self.assertGreaterEqual(len(sign_filled), 3)

    def test_srai_and_srli_agree_on_nonnegative_sources(self):
        _, arithmetic = witnesses.shift_immediate_row("sra", 0x12345678, 4)
        _, logical = witnesses.shift_immediate_row("srl", 0x12345678, 4)
        self.assertEqual(arithmetic, logical)

    def test_srai_and_srli_differ_on_negative_sources(self):
        _, arithmetic = witnesses.shift_immediate_row("sra", witnesses.INT_MIN, 4)
        _, logical = witnesses.shift_immediate_row("srl", witnesses.INT_MIN, 4)
        self.assertNotEqual(arithmetic, logical)

    def test_a_released_sign_witness_is_caught(self):
        assignment, _ = witnesses.shift_immediate_row("sra", witnesses.INT_MIN, 4)
        assignment["semantic_rs1_sign"] = 0
        with self.assertRaises(witnesses.WitnessError):
            witnesses.check_witness(self.air_ir_dir, "shifts_imm", assignment)

    def test_a_logical_shift_may_not_claim_a_sign(self):
        assignment, _ = witnesses.shift_immediate_row("srl", witnesses.INT_MIN, 4)
        assignment["semantic_rs1_sign"] = 1
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "shifts_imm", assignment)

    def test_a_mismatched_shift_amount_is_caught(self):
        assignment, _ = witnesses.shift_immediate_row("sll", 0x12345678, 8)
        assignment["imm_truncated"] = 9
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "shifts_imm", assignment)

    def test_unknown_selectors_fail_closed(self):
        with self.assertRaisesRegex(witnesses.WitnessError, "unknown shift"):
            witnesses.shift_immediate_row("rol", 1, 1)
        with self.assertRaisesRegex(witnesses.WitnessError, "unknown multiply-high"):
            witnesses.multiply_high_row("mul", 1, 1)


class RegisterShiftWitnessTest(unittest.TestCase):
    """SLL/SRL/SRA with the amount taken from rs2, masked to five bits."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.air_ir_dir = export_air()
        except (OSError, subprocess.SubprocessError) as error:
            raise unittest.SkipTest(f"production AIR export unavailable: {error}")

    def test_register_shift_witnesses_are_reachable_in_production(self):
        self.assertIn(
            "9 witnesses reachable",
            witnesses.check_register_shift_witnesses(self.air_ir_dir),
        )

    def test_the_masking_path_is_actually_exercised(self):
        # A table where every rs2 value already fits five bits would leave
        # the mask untested; require values whose low five bits differ from
        # the full register, including one with nonzero high limbs.
        masked = [
            (name, rs2)
            for name, _, _, rs2, _ in witnesses.SHIFT_REG_WITNESSES
            if (rs2 & 0xFFFFFFFF) != (rs2 & 31)
        ]
        self.assertGreaterEqual(len(masked), 3)
        self.assertTrue(any(rs2 > 0xFF for _, rs2 in masked))

    def test_amount_extremes_are_covered(self):
        amounts = {
            rs2 & 31 for _, _, _, rs2, _ in witnesses.SHIFT_REG_WITNESSES
        }
        self.assertIn(0, amounts)
        self.assertIn(31, amounts)

    def test_a_negative_sra_source_is_covered(self):
        self.assertTrue(
            any(
                selector == "sra" and source & witnesses.INT_MIN
                for _, selector, source, _, _ in witnesses.SHIFT_REG_WITNESSES
            )
        )

    def test_the_semantics_mask_to_five_bits(self):
        # A shift by rs2 = 33 is a shift by one, and only the low byte of
        # rs2 participates at all.
        _, by_33 = witnesses.shift_register_row("sll", 0x12345678, 33)
        _, by_1 = witnesses.shift_register_row("sll", 0x12345678, 1)
        self.assertEqual(by_33, by_1)
        _, high_limbs = witnesses.shift_register_row("srl", 0x12345678, 0xFFFFFF04)
        _, plain = witnesses.shift_register_row("srl", 0x12345678, 4)
        self.assertEqual(high_limbs, plain)

    def test_an_unmasked_shift_amount_is_refused(self):
        # Internally consistent shift-by-3 columns, but rs2 holds 33: only
        # the production rs2-binding range request can catch the mismatch.
        assignment, _ = witnesses.shift_register_row("sll", 0x12345678, 3)
        for index, limb in enumerate(witnesses._limbs(33)):
            assignment[f"rs2_previous_{index}"] = limb
            assignment[f"rs2_next_{index}"] = limb
        with self.assertRaisesRegex(
            witnesses.WitnessError, "outside the 20-bit production table"
        ):
            witnesses.check_witness(self.air_ir_dir, "shifts_reg", assignment)

    def test_a_released_register_shift_sign_is_refused(self):
        assignment, _ = witnesses.shift_register_row("sra", witnesses.INT_MIN, 0x44)
        assignment["semantic_rs1_sign"] = 0
        with self.assertRaises(witnesses.WitnessError):
            witnesses.check_witness(self.air_ir_dir, "shifts_reg", assignment)

    def test_a_logical_register_shift_may_not_claim_a_sign(self):
        assignment, _ = witnesses.shift_register_row("srl", witnesses.INT_MIN, 4)
        assignment["semantic_rs1_sign"] = 1
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "shifts_reg", assignment)

    def test_unknown_selector_fails_closed(self):
        with self.assertRaisesRegex(witnesses.WitnessError, "unknown shift"):
            witnesses.shift_register_row("ror", 1, 1)
