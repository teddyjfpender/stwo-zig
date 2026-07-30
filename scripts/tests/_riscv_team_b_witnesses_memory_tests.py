"""Load, store, and address-aliasing witness tests."""

from __future__ import annotations

import subprocess
import unittest

from scripts import riscv_team_b_witnesses as witnesses
from scripts.tests._riscv_team_b_witnesses_support import export_air


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
