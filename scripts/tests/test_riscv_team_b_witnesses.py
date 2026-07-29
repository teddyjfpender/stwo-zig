"""Tests for the Team B production-AIR witness cross-check."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts import riscv_team_b_witnesses as witnesses

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXPORT_DIRECTORY = REPOSITORY_ROOT / "zig-out/team-b-ir"


def export_air() -> Path:
    """Export the production symbolic AIR, or reuse a fresh existing export.

    Reuse is gated on the provenance check: an existing export is only
    trusted if no production AIR source is newer than it. A stale export is
    re-derived instead of silently evaluated.
    """
    if (EXPORT_DIRECTORY / "load_store.json").is_file():
        try:
            witnesses.check_export_provenance(EXPORT_DIRECTORY)
            return EXPORT_DIRECTORY
        except witnesses.WitnessError:
            pass  # Stale or unverifiable: fall through and re-export.
    subprocess.run(
        [
            "zig",
            "build",
            "riscv-refinement-ir",
            f"-Driscv-refinement-ir-dir={EXPORT_DIRECTORY.relative_to(REPOSITORY_ROOT)}",
        ],
        cwd=REPOSITORY_ROOT,
        check=True,
        timeout=900,
    )
    return EXPORT_DIRECTORY


class LoadHalfwordWitnessTest(unittest.TestCase):
    """The witnesses are checked against the exported production AIR.

    These tests need a Zig export. They are skipped only when Zig itself is
    unavailable, which is a genuine environment gap rather than a soft pass:
    the hosted Team B workflow always has Zig, so the gate always runs there.
    """

    @classmethod
    def setUpClass(cls):
        try:
            cls.air_ir_dir = export_air()
        except (OSError, subprocess.SubprocessError) as error:
            raise unittest.SkipTest(f"production AIR export unavailable: {error}")

    def test_every_required_lh_witness_is_reachable_in_production(self):
        report = witnesses.check_lh_witnesses(self.air_ir_dir)
        self.assertIn("7 witnesses reachable", report)

    def test_the_sign_path_is_actually_exercised(self):
        # A witness set that never loads a negative halfword would leave sign
        # extension untested, which is exactly the vacuity issue #137 warns
        # about. Assert at least one high-half and one low-half negative case.
        negatives = [
            name
            for name, _, _, _, _, expected in witnesses.LH_WITNESSES
            if expected & 0x80000000
        ]
        self.assertIn("negative-high-half", negatives)
        self.assertIn("negative-low-half", negatives)

    def test_misaligned_effective_address_is_refused(self):
        with self.assertRaisesRegex(witnesses.WitnessError, "not halfword aligned"):
            witnesses.load_halfword_row(0x2000, 1, 0x8ABC1234, 7)

    def test_a_tampered_result_limb_is_caught(self):
        assignment, _ = witnesses.load_halfword_row(0x2000, 2, 0x8ABC1234, 7)
        assignment["result_0"] = (assignment["result_0"] + 1) % 256
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "load_store", assignment)

    def test_a_flipped_sign_witness_is_caught(self):
        assignment, _ = witnesses.load_halfword_row(0x2000, 2, 0x8ABC1234, 7)
        assignment["src_msb"] = 0
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "load_store", assignment)

    def test_swapped_endian_bytes_are_caught(self):
        assignment, _ = witnesses.load_halfword_row(0x2000, 2, 0x8ABC1234, 7)
        assignment["src_next_2"], assignment["src_next_3"] = (
            assignment["src_next_3"],
            assignment["src_next_2"],
        )
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "load_store", assignment)

    def test_selecting_the_wrong_half_is_caught(self):
        assignment, _ = witnesses.load_halfword_row(0x2000, 2, 0x8ABC1234, 7)
        # Keep the high-half address but take the low half's bytes.
        assignment["result_0"] = 0x34
        assignment["result_1"] = 0x12
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "load_store", assignment)

    def test_an_unpreserved_memory_word_is_caught(self):
        assignment, _ = witnesses.load_halfword_row(0x2000, 2, 0x8ABC1234, 7)
        assignment["src_next_0"] = (assignment["src_next_0"] + 1) % 256
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "load_store", assignment)

    def test_an_unpreserved_source_register_is_caught(self):
        assignment, _ = witnesses.load_halfword_row(0x2000, 2, 0x8ABC1234, 7)
        assignment["rs1_next_0"] = (assignment["rs1_next_0"] + 1) % 256
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "load_store", assignment)

    def test_an_address_beyond_the_admitted_range_fails_its_range_lookup(self):
        # The base-address and aligned-address range requests bound admitted
        # addresses well below 2**32, so a 32-bit wrap is unreachable.
        beyond = witnesses.MAX_ADMITTED_ALIGNED_ADDRESS + 4
        assignment, _ = witnesses.load_halfword_row(beyond, 0, 0x0000FFFF, 7)
        with self.assertRaisesRegex(
            witnesses.WitnessError, "outside the 20-bit production table"
        ):
            witnesses.check_witness(self.air_ir_dir, "load_store", assignment)

    def test_the_top_admitted_address_still_passes(self):
        assignment, _ = witnesses.load_halfword_row(
            witnesses.MAX_ADMITTED_ALIGNED_ADDRESS, 0, 0xFFFF7FFF, 7
        )
        report = witnesses.check_witness(self.air_ir_dir, "load_store", assignment)
        self.assertIn("constraints satisfied", report)


class PerOpcodeLoadWitnessTest(unittest.TestCase):
    """LB, LBU, LHU and LW as distinct selectors, discriminated, not just
    reachable: the paired sign-/zero-extension results must differ on the
    same negative datum, and LW must retire the memory word verbatim."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.air_ir_dir = export_air()
        except (OSError, subprocess.SubprocessError) as error:
            raise unittest.SkipTest(f"production AIR export unavailable: {error}")

    def test_every_per_opcode_load_witness_is_reachable_in_production(self):
        report = witnesses.check_load_witnesses(self.air_ir_dir)
        self.assertIn("15 LB/LBU/LHU/LW witnesses reachable", report)
        self.assertIn("discriminated", report)

    def test_lb_and_lbu_disagree_on_the_same_negative_byte(self):
        # Same word, same offset, same byte 0x9C; only the selector differs.
        _, signed = witnesses.load_row("lb", 0x2000, 1, 0xDDCC9CAA, 7)
        _, unsigned = witnesses.load_row("lbu", 0x2000, 1, 0xDDCC9CAA, 7)
        self.assertEqual(signed, 0xFFFFFF9C)
        self.assertEqual(unsigned, 0x0000009C)
        self.assertNotEqual(signed, unsigned)

    def test_lh_and_lhu_disagree_on_the_same_negative_halfword(self):
        _, signed = witnesses.load_row("lh", 0x2000, 2, 0x8ABC1234, 7)
        _, unsigned = witnesses.load_row("lhu", 0x2000, 2, 0x8ABC1234, 7)
        self.assertEqual(signed, 0xFFFF8ABC)
        self.assertEqual(unsigned, 0x00008ABC)
        self.assertNotEqual(signed, unsigned)

    def test_lb_and_lbu_agree_on_a_positive_byte(self):
        # The discrimination is the sign bit, nothing else.
        _, signed = witnesses.load_row("lb", 0x2000, 0, 0xDDCC9C7F, 7)
        _, unsigned = witnesses.load_row("lbu", 0x2000, 0, 0xDDCC9C7F, 7)
        self.assertEqual(signed, unsigned)

    def test_lw_retires_the_memory_word_verbatim(self):
        for word in (0x8ABC1234, 0xDEADBEEF, 0x00000000, 0xFFFFFFFF):
            _, result = witnesses.load_row("lw", 0x2000, 4, word, 7)
            self.assertEqual(result, word)

    def test_lw_witnesses_cover_four_distinct_aligned_addresses(self):
        addresses = {
            base + displacement
            for _, selector, base, displacement, _, _, _ in witnesses.LOAD_WITNESSES
            if selector == "lw"
        }
        self.assertEqual(len(addresses), 4)
        for address in addresses:
            self.assertEqual(address % 4, 0)

    def test_byte_load_witnesses_cover_every_offset(self):
        offsets = {
            (base + displacement) & 3
            for _, selector, base, displacement, _, _, _ in witnesses.LOAD_WITNESSES
            if selector in ("lb", "lbu")
        }
        self.assertEqual(offsets, {0, 1, 2, 3})

    def test_the_lh_builder_still_delegates_to_the_general_one(self):
        via_wrapper, wrapped = witnesses.load_halfword_row(0x2000, 2, 0x8ABC1234, 7)
        via_general, general = witnesses.load_row("lh", 0x2000, 2, 0x8ABC1234, 7)
        self.assertEqual(via_wrapper, via_general)
        self.assertEqual(wrapped, general)

    def test_misaligned_loads_are_outside_the_admitted_language(self):
        with self.assertRaisesRegex(witnesses.WitnessError, "not halfword aligned"):
            witnesses.load_row("lhu", 0x2000, 1, 0, 7)
        with self.assertRaisesRegex(witnesses.WitnessError, "not word aligned"):
            witnesses.load_row("lw", 0x2000, 2, 0, 7)
        with self.assertRaisesRegex(witnesses.WitnessError, "unknown load"):
            witnesses.load_row("ld", 0x2000, 0, 0, 7)

    def test_a_byte_load_at_any_offset_is_admitted(self):
        for offset in range(4):
            assignment, _ = witnesses.load_row("lb", 0x2000, offset, 0x81808180, 7)
            report = witnesses.check_witness(
                self.air_ir_dir, "load_store", assignment
            )
            self.assertIn("constraints satisfied", report)

    def test_an_lb_row_zero_extending_a_negative_byte_is_refused(self):
        # Every polynomial constraint holds on this row; only the is_lb-gated
        # sign-binding range_check_m31 request can refuse it. This is the
        # production fact that makes LB/LBU distinguishable.
        assignment, _ = witnesses.load_row("lb", 0x2000, 1, 0xDDCC9CAA, 7)
        assignment["src_msb"] = 0
        for index, limb in enumerate(witnesses._limbs(0x0000009C)):
            assignment[f"result_{index}"] = limb
            assignment[f"dst_next_{index}"] = limb
        with self.assertRaisesRegex(
            witnesses.WitnessError, "outside the 7-bit production table"
        ):
            witnesses.check_witness(self.air_ir_dir, "load_store", assignment)

    def test_an_lhu_row_claiming_a_sign_extension_is_refused(self):
        assignment, _ = witnesses.load_row("lhu", 0x2000, 2, 0x8ABC1234, 7)
        assignment["src_msb"] = 1
        for index, limb in enumerate(witnesses._limbs(0xFFFF8ABC)):
            assignment[f"result_{index}"] = limb
            assignment[f"dst_next_{index}"] = limb
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "load_store", assignment)

    def test_a_flipped_lb_sign_witness_is_refused(self):
        assignment, _ = witnesses.load_row("lb", 0x2000, 1, 0xDDCC9CAA, 7)
        assignment["src_msb"] = 0
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "load_store", assignment)

    def test_a_tampered_lw_result_limb_is_refused(self):
        assignment, _ = witnesses.load_row("lw", 0x2000, 4, 0xDEADBEEF, 7)
        assignment["result_2"] = (assignment["result_2"] + 1) % 256
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "load_store", assignment)


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


class EvaluatorTest(unittest.TestCase):
    def _payload(self) -> dict:
        return {
            "family": "toy",
            "columns": [{"name": "a", "role": "witness"}],
            "nodes": [
                {"op": "col", "name": "a"},
                {"op": "const", "value": 1},
                {"op": "sub", "args": [0, 1]},
            ],
            "constraints": [2],
            "lookups": [],
        }

    def _directory(self, payload: dict) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "toy.json").write_text(json.dumps(payload))
        return root

    def test_unassigned_column_fails_closed(self):
        root = self._directory(self._payload())
        with self.assertRaisesRegex(witnesses.WitnessError, "unassigned"):
            witnesses.check_witness(root, "toy", {})

    def test_unknown_column_fails_closed(self):
        root = self._directory(self._payload())
        with self.assertRaisesRegex(witnesses.WitnessError, "does not declare"):
            witnesses.check_witness(root, "toy", {"a": 1, "b": 2})

    def test_unsupported_node_operation_fails_closed(self):
        payload = self._payload()
        payload["nodes"].append({"op": "sqrt", "args": [0]})
        root = self._directory(payload)
        with self.assertRaisesRegex(witnesses.WitnessError, "unsupported AIR node"):
            witnesses.check_witness(root, "toy", {"a": 1})

    def test_absent_family_fails_closed(self):
        root = self._directory(self._payload())
        with self.assertRaisesRegex(witnesses.WitnessError, "is absent"):
            witnesses.check_witness(root, "nonexistent", {"a": 1})

    def test_inactive_range_request_asserts_nothing(self):
        payload = self._payload()
        payload["nodes"].extend(
            [
                {"op": "const", "value": 0},
                {"op": "const", "value": 999999999},
            ]
        )
        payload["lookups"] = [
            {
                "label": "request",
                "domain": "range_check_20",
                "numerator": 3,
                "tuple": [4],
            }
        ]
        root = self._directory(payload)
        report = witnesses.check_witness(root, "toy", {"a": 1})
        self.assertIn("0 active range requests", report)

    def test_active_out_of_range_request_fails_closed(self):
        payload = self._payload()
        payload["nodes"].extend(
            [
                {"op": "const", "value": 1},
                {"op": "const", "value": 999999999},
            ]
        )
        payload["lookups"] = [
            {
                "label": "request",
                "domain": "range_check_20",
                "numerator": 3,
                "tuple": [4],
            }
        ]
        root = self._directory(payload)
        with self.assertRaisesRegex(witnesses.WitnessError, "outside the 20-bit"):
            witnesses.check_witness(root, "toy", {"a": 1})

    def test_an_unknown_domain_is_an_error_even_when_inactive(self):
        # Classification is a property of the AIR's shape, not of one row: a
        # numerator of zero must not turn an unknown domain into a silent skip.
        payload = self._payload()
        payload["nodes"].append({"op": "const", "value": 0})
        payload["lookups"] = [
            {
                "label": "request",
                "domain": "range_check_13",
                "numerator": 3,
                "tuple": [0],
            }
        ]
        root = self._directory(payload)
        with self.assertRaisesRegex(witnesses.WitnessError, "does not know"):
            witnesses.check_witness(root, "toy", {"a": 1})

    def test_column_drift_reports_new_renamed_and_removed(self):
        payload = self._payload()
        payload["columns"] = [
            {"name": "alpha", "role": "witness"},
            {"name": "beta_v2", "role": "witness"},
            {"name": "delta", "role": "witness"},
        ]
        with self.assertRaises(witnesses.WitnessError) as caught:
            witnesses.evaluate(payload, {"alpha": 1, "beta_v1": 2, "gamma": 3})
        message = str(caught.exception)
        self.assertIn("likely NEW in the AIR: delta", message)
        self.assertIn("likely RENAMED: beta_v1 -> beta_v2", message)
        self.assertIn("likely REMOVED from the AIR: gamma", message)
        # The message must also carry the exact re-derivation command.
        self.assertIn("zig build riscv-refinement-ir", message)

    def test_column_drift_still_names_both_raw_column_sets(self):
        # The heuristic classification is advice; the raw diff is the record.
        payload = self._payload()
        with self.assertRaises(witnesses.WitnessError) as caught:
            witnesses.evaluate(payload, {"b": 1})
        message = str(caught.exception)
        self.assertIn("unassigned: a", message)
        self.assertIn("does not declare: b", message)

    def test_every_supported_operation_actually_evaluates(self):
        # Guards SUPPORTED_OPERATIONS against drifting from the dispatch: each
        # advertised operation must evaluate, and this test must exercise the
        # whole advertised set.
        payload = {
            "family": "toy",
            "columns": [{"name": "a", "role": "witness"}],
            "nodes": [
                {"op": "const", "value": 5},
                {"op": "col", "name": "a"},
                {"op": "neg", "args": [0]},
                {"op": "add", "args": [0, 1]},
                {"op": "sub", "args": [0, 1]},
                {"op": "mul", "args": [0, 1]},
            ],
            "constraints": [],
            "lookups": [],
        }
        exercised = {node["op"] for node in payload["nodes"]}
        self.assertEqual(exercised, set(witnesses.SUPPORTED_OPERATIONS))
        values = witnesses.evaluate(payload, {"a": 3})
        self.assertEqual(values, [5, 3, witnesses.M31 - 5, 8, 2, 15])


class SchemaAuditTest(unittest.TestCase):
    """The family-agnostic audit of whatever the export happens to contain."""

    def _directory(self, payload: dict) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / f"{payload['family']}.json").write_text(json.dumps(payload))
        return root

    def _payload(self) -> dict:
        return {
            "family": "toy",
            "columns": [{"name": "a", "role": "witness"}],
            "nodes": [
                {"op": "col", "name": "a"},
                {"op": "const", "value": 0},
            ],
            "constraints": [],
            "lookups": [],
        }

    def test_the_full_production_export_passes_the_audit(self):
        try:
            air_ir_dir = export_air()
        except (OSError, subprocess.SubprocessError) as error:
            self.skipTest(f"production AIR export unavailable: {error}")
        report = witnesses.audit_exported_families(air_ir_dir)
        self.assertIn("only supported node operations", report)
        self.assertIn("none ignored", report)

    def test_the_witness_gate_actually_runs_the_audit(self):
        # The audit only closes the new-domain gap if the CI entry point runs
        # it before the per-family witness checks; provenance runs first of
        # all so every later verdict is about a digested, fresh export.
        order = list(witnesses.CHECKS)
        self.assertIs(order[0], witnesses.check_export_provenance)
        audit_at = order.index(witnesses.audit_exported_families)
        for family_check in (
            witnesses.check_lh_witnesses,
            witnesses.check_load_witnesses,
            witnesses.check_div_witnesses,
            witnesses.check_rem_witnesses,
            witnesses.check_multiply_witnesses,
            witnesses.check_shift_witnesses,
            witnesses.check_register_shift_witnesses,
            witnesses.check_store_witnesses,
            witnesses.check_mutation_refusals,
        ):
            self.assertLess(audit_at, order.index(family_check))

    def test_an_unknown_lookup_domain_is_an_error(self):
        payload = self._payload()
        payload["lookups"] = [
            {
                "label": "request",
                "domain": "range_check_640k",
                "numerator": 1,
                "tuple": [0],
            }
        ]
        with self.assertRaises(witnesses.WitnessError) as caught:
            witnesses.audit_exported_families(self._directory(payload))
        message = str(caught.exception)
        self.assertIn("range_check_640k", message)
        self.assertIn("RANGE_DOMAINS or", message)
        self.assertIn("SKIPPED_DOMAINS", message)

    def test_a_known_bus_domain_is_deliberately_skipped_not_ignored(self):
        payload = self._payload()
        payload["lookups"] = [
            {
                "label": "request",
                "domain": "memory_access",
                "numerator": 1,
                "tuple": [0],
            }
        ]
        report = witnesses.audit_exported_families(self._directory(payload))
        self.assertIn("1 deliberately skipped bus domains", report)

    def test_an_unsupported_node_operation_is_an_error(self):
        payload = self._payload()
        payload["nodes"].append({"op": "pow", "args": [0, 1]})
        with self.assertRaisesRegex(witnesses.WitnessError, "does not implement"):
            witnesses.audit_exported_families(self._directory(payload))

    def test_an_empty_export_directory_is_an_error(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        with self.assertRaisesRegex(witnesses.WitnessError, "no exported AIR"):
            witnesses.audit_exported_families(Path(directory.name))

    def test_range_and_skipped_domains_are_disjoint(self):
        # A domain in both sets would make "range-checked" ambiguous.
        overlap = set(witnesses.RANGE_DOMAINS) & set(witnesses.SKIPPED_DOMAINS)
        self.assertEqual(overlap, set())


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


class StoreWitnessTest(unittest.TestCase):
    """SB/SH/SW at every admitted offset, with unselected bytes preserved."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.air_ir_dir = export_air()
        except (OSError, subprocess.SubprocessError) as error:
            raise unittest.SkipTest(f"production AIR export unavailable: {error}")

    def test_store_witnesses_are_reachable_in_production(self):
        report = witnesses.check_store_witnesses(self.air_ir_dir)
        self.assertIn("10 witnesses reachable", report)
        self.assertIn("unselected bytes preserved", report)

    def test_every_byte_offset_and_both_half_offsets_are_covered(self):
        offsets = {"sb": set(), "sh": set(), "sw": set()}
        for _, selector, base, displacement, _, _, _ in witnesses.STORE_WITNESSES:
            offsets[selector].add((base + displacement) & 3)
        self.assertEqual(offsets["sb"], {0, 1, 2, 3})
        self.assertEqual(offsets["sh"], {0, 2})
        self.assertEqual(offsets["sw"], {0})

    def test_the_builder_preserves_unselected_bytes(self):
        assignment, new_word = witnesses.store_row(
            "sb", 0x2000, 1, 0xDDCCBBAA, 0x11223344
        )
        for lane in (0, 2, 3):
            self.assertEqual(
                assignment[f"dst_next_{lane}"], assignment[f"dst_previous_{lane}"]
            )
        self.assertEqual(new_word, 0xDDCC44AA)

    def test_a_clobbered_unselected_byte_is_refused(self):
        assignment, _ = witnesses.store_row("sb", 0x2000, 1, 0xDDCCBBAA, 0x11223344)
        assignment["dst_next_3"] = (assignment["dst_next_3"] + 1) % 256
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "load_store", assignment)

    def test_a_byte_written_at_the_wrong_offset_is_refused(self):
        assignment, _ = witnesses.store_row("sb", 0x2000, 1, 0xDDCCBBAA, 0x11223344)
        assignment["dst_next_1"] = assignment["dst_previous_1"]
        assignment["dst_next_2"] = 0x44
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "load_store", assignment)

    def test_a_half_written_at_the_wrong_offset_is_refused(self):
        assignment, _ = witnesses.store_row("sh", 0x2000, 0, 0xDDCCBBAA, 0x11223344)
        assignment["dst_next_0"] = assignment["dst_previous_0"]
        assignment["dst_next_1"] = assignment["dst_previous_1"]
        assignment["dst_next_2"] = 0x44
        assignment["dst_next_3"] = 0x33
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "load_store", assignment)

    def test_a_truncated_word_write_is_refused(self):
        assignment, _ = witnesses.store_row("sw", 0x2000, 0, 0xDDCCBBAA, 0x11223344)
        assignment["dst_next_2"] = assignment["dst_previous_2"]
        assignment["dst_next_3"] = assignment["dst_previous_3"]
        with self.assertRaisesRegex(witnesses.WitnessError, "constraint roots"):
            witnesses.check_witness(self.air_ir_dir, "load_store", assignment)

    def test_only_the_low_half_of_the_stored_register_reaches_memory(self):
        _, new_word = witnesses.store_row("sh", 0x2000, 2, 0, 0xFFFF8ABC)
        self.assertEqual(new_word, 0x8ABC0000)

    def test_misaligned_stores_are_outside_the_admitted_language(self):
        with self.assertRaisesRegex(witnesses.WitnessError, "not halfword aligned"):
            witnesses.store_row("sh", 0x2000, 1, 0, 0)
        with self.assertRaisesRegex(witnesses.WitnessError, "not word aligned"):
            witnesses.store_row("sw", 0x2000, 2, 0, 0)
        with self.assertRaisesRegex(witnesses.WitnessError, "unknown store"):
            witnesses.store_row("sd", 0x2000, 0, 0, 0)


class MutationBatteryTest(unittest.TestCase):
    """The CLI-invocable battery of rows production must refuse."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.air_ir_dir = export_air()
        except (OSError, subprocess.SubprocessError) as error:
            raise unittest.SkipTest(f"production AIR export unavailable: {error}")

    def test_every_mutation_is_refused_by_production(self):
        report = witnesses.check_mutation_refusals(self.air_ir_dir)
        self.assertIn("all refused", report)

    def test_the_battery_is_wired_into_the_cli_gate(self):
        # The coverage ledger says this script checks "witnesses and their
        # mutations"; that wording is only true if the CLI entry point runs
        # the mutation battery, not just the unittest module.
        self.assertIn(witnesses.check_mutation_refusals, witnesses.CHECKS)

    def test_every_witnessed_family_has_a_mutation_counter_check(self):
        families = {family for _, family, _ in witnesses.mutation_counter_cases()}
        self.assertEqual(
            families, {"load_store", "div", "mulh", "shifts_imm", "shifts_reg"}
        )

    def test_the_required_counter_checks_are_present_by_name(self):
        names = {name for name, _, _ in witnesses.mutation_counter_cases()}
        self.assertIn("sb-clobbered-unselected-byte", names)
        self.assertIn("sb-byte-at-wrong-offset", names)
        self.assertIn("sll-reg-unmasked-shift-amount", names)
        # The per-opcode load and remainder counter-checks (issue #137 F4):
        # a flipped LB sign, a zero-extending LHU claiming a sign, a REM row
        # retiring the quotient, a remainder not below its divisor.
        self.assertIn("lb-flipped-sign-witness", names)
        self.assertIn("lb-zero-extended-negative-byte", names)
        self.assertIn("lhu-claimed-sign-extension", names)
        self.assertIn("rem-retired-the-quotient", names)
        self.assertIn("remu-remainder-not-below-divisor", names)

    def test_mutation_names_are_unique(self):
        names = [name for name, _, _ in witnesses.mutation_counter_cases()]
        self.assertEqual(len(names), len(set(names)))

    def test_an_accepted_mutation_fails_the_gate(self):
        # Feed the battery a family whose constraints accept anything; the
        # gate must fail loudly rather than count it as refused.
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        for family in ("load_store", "div", "mulh", "shifts_imm", "shifts_reg"):
            sample = next(
                assignment
                for _, fam, assignment in witnesses.mutation_counter_cases()
                if fam == family
            )
            (root / f"{family}.json").write_text(
                json.dumps(
                    {
                        "family": family,
                        "columns": [{"name": name} for name in sample],
                        "nodes": [{"op": "const", "value": 0}],
                        "constraints": [],
                        "lookups": [],
                    }
                )
            )
        with self.assertRaisesRegex(witnesses.WitnessError, "ACCEPTED"):
            witnesses.check_mutation_refusals(root)


class ExportProvenanceTest(unittest.TestCase):
    """The gate digests what it evaluates and refuses a stale export."""

    def _export(self) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        export = root / "export"
        export.mkdir()
        (export / "toy.json").write_text(
            json.dumps(
                {
                    "family": "toy",
                    "columns": [{"name": "a"}],
                    "nodes": [{"op": "col", "name": "a"}],
                    "constraints": [],
                    "lookups": [],
                }
            )
        )
        return root

    def test_a_fresh_export_reports_its_digest(self):
        root = self._export()
        source = root / "src"
        source.mkdir()
        (source / "air.zig").write_text("// air")
        # Make the source strictly older than the export.
        old = (root / "export" / "toy.json").stat().st_mtime_ns - 10**9
        os.utime(source / "air.zig", ns=(old, old))
        report = witnesses.check_export_provenance(
            root / "export", source_root=source
        )
        self.assertIn("sha256", report)
        self.assertIn("no production AIR source is newer", report)

    def test_a_stale_export_is_refused_with_the_re_derivation_command(self):
        root = self._export()
        source = root / "src"
        source.mkdir()
        (source / "air.zig").write_text("// air")
        new = (root / "export" / "toy.json").stat().st_mtime_ns + 10**9
        os.utime(source / "air.zig", ns=(new, new))
        with self.assertRaisesRegex(witnesses.WitnessError, "STALE") as caught:
            witnesses.check_export_provenance(root / "export", source_root=source)
        self.assertIn("zig build riscv-refinement-ir", str(caught.exception))

    def test_an_absent_source_tree_fails_closed(self):
        root = self._export()
        with self.assertRaisesRegex(witnesses.WitnessError, "freshness"):
            witnesses.check_export_provenance(
                root / "export", source_root=root / "nonexistent"
            )

    def test_the_digest_is_stable_and_content_sensitive(self):
        root = self._export()
        first = witnesses.export_digest(root / "export")
        self.assertEqual(first, witnesses.export_digest(root / "export"))
        (root / "export" / "toy.json").write_text("{}")
        self.assertNotEqual(first, witnesses.export_digest(root / "export"))

    def test_the_real_export_passes_provenance(self):
        try:
            air_ir_dir = export_air()
        except (OSError, subprocess.SubprocessError) as error:
            self.skipTest(f"production AIR export unavailable: {error}")
        report = witnesses.check_export_provenance(air_ir_dir)
        self.assertIn("sha256", report)


class AddressAliasingRegressionTest(unittest.TestCase):
    """The fixed `load_store` AIR rejects the historical aliasing row."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.air_ir_dir = export_air()
        except (OSError, subprocess.SubprocessError) as error:
            raise unittest.SkipTest(f"production AIR export unavailable: {error}")

    def test_the_aliasing_row_is_rejected_by_the_new_constraint(self):
        report = witnesses.check_address_aliasing_rejected(self.air_ir_dir)
        self.assertIn("constraint root 69 rejects it", report)

    def test_the_counterexample_has_a_nonzero_high_base_byte(self):
        self.assertNotEqual((witnesses.ALIASING_BASE >> 24) & 0xFF, 0)

    def test_the_two_addresses_really_differ(self):
        _, architectural, field_address = witnesses.address_aliasing_row()
        self.assertEqual(architectural, 0x80000003)
        self.assertEqual(field_address, 0x00000004)
        self.assertNotEqual(architectural, field_address)

    def test_the_architectural_address_is_not_even_word_aligned(self):
        # So the architectural access would trap, while the AIR admits an
        # aligned read somewhere else entirely.
        _, architectural, _ = witnesses.address_aliasing_row()
        self.assertNotEqual(architectural % 4, 0)

    def test_a_zero_high_byte_base_does_not_alias(self):
        base = 0x003FFFF8
        assignment, architectural, field_address = witnesses.address_aliasing_row(
            base=base, displacement=4
        )
        self.assertEqual(architectural, field_address)
        report = witnesses.check_witness(
            self.air_ir_dir, "load_store", assignment
        )
        self.assertIn("constraints satisfied", report)


if __name__ == "__main__":
    unittest.main()
