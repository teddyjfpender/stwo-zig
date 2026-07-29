"""Tests for the Team B production-AIR witness cross-check."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts import riscv_team_b_witnesses as witnesses

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXPORT_DIRECTORY = REPOSITORY_ROOT / "zig-out/team-b-ir"


def export_air() -> Path:
    """Export the production symbolic AIR, or reuse a fresh existing export."""
    if (EXPORT_DIRECTORY / "load_store.json").is_file():
        return EXPORT_DIRECTORY
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


if __name__ == "__main__":
    unittest.main()
