#!/usr/bin/env python3
"""Generate and check the LUI/ADDI Universal AIR-to-Sail Lean pilot."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    from riscv_refinement_lib import codec, negative, render, sail
    from riscv_refinement_lib.model import (
        FULL_OPCODE_COUNT,
        PILOT_OPCODES,
        SCHEMA_VERSION,
        Paths,
        RefinementError,
        repository_root,
    )
except ModuleNotFoundError:
    from scripts.riscv_refinement_lib import codec, negative, render, sail
    from scripts.riscv_refinement_lib.model import (
        FULL_OPCODE_COUNT,
        PILOT_OPCODES,
        SCHEMA_VERSION,
        Paths,
        RefinementError,
        repository_root,
)

AUDITED_THEOREMS = (
    "RiscvRefinement.Air.Family.DivHolds.absSameLimb0",
    "RiscvRefinement.Air.Family.DivHolds.absSameLimb1",
    "RiscvRefinement.Air.Family.DivHolds.absSameLimb2",
    "RiscvRefinement.Air.Family.DivHolds.absSameLimb3",
    "RiscvRefinement.Air.Family.DivHolds.clockPositive",
    "RiscvRefinement.Air.Family.DivHolds.destinationClock",
    "RiscvRefinement.Air.Family.DivHolds.destinationFlag",
    "RiscvRefinement.Air.Family.DivHolds.destinationLimb0",
    "RiscvRefinement.Air.Family.DivHolds.destinationLimb1",
    "RiscvRefinement.Air.Family.DivHolds.destinationLimb2",
    "RiscvRefinement.Air.Family.DivHolds.destinationLimb3",
    "RiscvRefinement.Air.Family.DivHolds.dividendSignBit",
    "RiscvRefinement.Air.Family.DivHolds.divisorNonzero",
    "RiscvRefinement.Air.Family.DivHolds.divisorSignBit",
    "RiscvRefinement.Air.Family.DivHolds.ltDiffLower",
    "RiscvRefinement.Air.Family.DivHolds.ltDiffUpper",
    "RiscvRefinement.Air.Family.DivHolds.negationRecurrence",
    "RiscvRefinement.Air.Family.DivHolds.nextPcResult",
    "RiscvRefinement.Air.Family.DivHolds.productRecurrence",
    "RiscvRefinement.Air.Family.DivHolds.quotientSignBit",
    "RiscvRefinement.Air.Family.DivHolds.quotientSignImpliesXor",
    "RiscvRefinement.Air.Family.DivHolds.quotientSignMatches",
    "RiscvRefinement.Air.Family.DivHolds.remainderNonzero",
    "RiscvRefinement.Air.Family.DivHolds.remainderZeroLimb0",
    "RiscvRefinement.Air.Family.DivHolds.remainderZeroLimb1",
    "RiscvRefinement.Air.Family.DivHolds.remainderZeroLimb2",
    "RiscvRefinement.Air.Family.DivHolds.remainderZeroLimb3",
    "RiscvRefinement.Air.Family.DivHolds.scanEqual0",
    "RiscvRefinement.Air.Family.DivHolds.scanEqual1",
    "RiscvRefinement.Air.Family.DivHolds.scanEqual2",
    "RiscvRefinement.Air.Family.DivHolds.scanEqual3",
    "RiscvRefinement.Air.Family.DivHolds.scanMarker0",
    "RiscvRefinement.Air.Family.DivHolds.scanMarker1",
    "RiscvRefinement.Air.Family.DivHolds.scanMarker2",
    "RiscvRefinement.Air.Family.DivHolds.scanMarker3",
    "RiscvRefinement.Air.Family.DivHolds.scanTotal",
    "RiscvRefinement.Air.Family.DivHolds.selectorUnique",
    "RiscvRefinement.Air.Family.DivHolds.signXorDefinition",
    "RiscvRefinement.Air.Family.DivHolds.sourceOneClock",
    "RiscvRefinement.Air.Family.DivHolds.sourceOneLimb0",
    "RiscvRefinement.Air.Family.DivHolds.sourceOneLimb1",
    "RiscvRefinement.Air.Family.DivHolds.sourceOneLimb2",
    "RiscvRefinement.Air.Family.DivHolds.sourceOneLimb3",
    "RiscvRefinement.Air.Family.DivHolds.sourceTwoClock",
    "RiscvRefinement.Air.Family.DivHolds.sourceTwoLimb0",
    "RiscvRefinement.Air.Family.DivHolds.sourceTwoLimb1",
    "RiscvRefinement.Air.Family.DivHolds.sourceTwoLimb2",
    "RiscvRefinement.Air.Family.DivHolds.sourceTwoLimb3",
    "RiscvRefinement.Air.Family.DivHolds.specialExclusive",
    "RiscvRefinement.Air.Family.DivHolds.unsignedDividendSign",
    "RiscvRefinement.Air.Family.DivHolds.unsignedDivisorSign",
    "RiscvRefinement.Air.Family.DivHolds.zeroDivisorLimb0",
    "RiscvRefinement.Air.Family.DivHolds.zeroDivisorLimb1",
    "RiscvRefinement.Air.Family.DivHolds.zeroDivisorLimb2",
    "RiscvRefinement.Air.Family.DivHolds.zeroDivisorLimb3",
    "RiscvRefinement.Air.Family.DivHolds.zeroDivisorQuotient0",
    "RiscvRefinement.Air.Family.DivHolds.zeroDivisorQuotient1",
    "RiscvRefinement.Air.Family.DivHolds.zeroDivisorQuotient2",
    "RiscvRefinement.Air.Family.DivHolds.zeroDivisorQuotient3",
    "RiscvRefinement.Air.Family.DivHolds.zeroDivisorQuotientSign",
    "RiscvRefinement.Air.Family.LoadStoreHolds.alignedQuarterRange",
    "RiscvRefinement.Air.Family.LoadStoreHolds.baseClock",
    "RiscvRefinement.Air.Family.LoadStoreHolds.baseHighLimbRange",
    "RiscvRefinement.Air.Family.LoadStoreHolds.baseLimbsCanonical",
    "RiscvRefinement.Air.Family.LoadStoreHolds.baseReadOnly",
    "RiscvRefinement.Air.Family.LoadStoreHolds.byteLoadExtension",
    "RiscvRefinement.Air.Family.LoadStoreHolds.byteLoadSelect",
    "RiscvRefinement.Air.Family.LoadStoreHolds.byteMarkerSum",
    "RiscvRefinement.Air.Family.LoadStoreHolds.byteShiftAmount",
    "RiscvRefinement.Air.Family.LoadStoreHolds.byteSignWitness",
    "RiscvRefinement.Air.Family.LoadStoreHolds.byteStoreSelect",
    "RiscvRefinement.Air.Family.LoadStoreHolds.clockPositive",
    "RiscvRefinement.Air.Family.LoadStoreHolds.destinationFlag",
    "RiscvRefinement.Air.Family.LoadStoreHolds.halfLoadExtension",
    "RiscvRefinement.Air.Family.LoadStoreHolds.halfLoadHigh",
    "RiscvRefinement.Air.Family.LoadStoreHolds.halfLoadLow",
    "RiscvRefinement.Air.Family.LoadStoreHolds.halfMarkerSum",
    "RiscvRefinement.Air.Family.LoadStoreHolds.halfShiftAmount",
    "RiscvRefinement.Air.Family.LoadStoreHolds.halfShiftId",
    "RiscvRefinement.Air.Family.LoadStoreHolds.halfSignWitness",
    "RiscvRefinement.Air.Family.LoadStoreHolds.halfStoreHigh",
    "RiscvRefinement.Air.Family.LoadStoreHolds.halfStoreLow",
    "RiscvRefinement.Air.Family.LoadStoreHolds.immFeltRange",
    "RiscvRefinement.Air.Family.LoadStoreHolds.loadDestination",
    "RiscvRefinement.Air.Family.LoadStoreHolds.memoryAddress",
    "RiscvRefinement.Air.Family.LoadStoreHolds.memoryClock",
    "RiscvRefinement.Air.Family.LoadStoreHolds.nextPcResult",
    "RiscvRefinement.Air.Family.LoadStoreHolds.operandClock",
    "RiscvRefinement.Air.Family.LoadStoreHolds.partialStorePreserve",
    "RiscvRefinement.Air.Family.LoadStoreHolds.selectorSum",
    "RiscvRefinement.Air.Family.LoadStoreHolds.signWitnessCanonical",
    "RiscvRefinement.Air.Family.LoadStoreHolds.sourceReadOnly",
    "RiscvRefinement.Air.Family.LoadStoreHolds.storeResultZero",
    "RiscvRefinement.Air.Family.LoadStoreHolds.wordLoad",
    "RiscvRefinement.Air.Family.LoadStoreHolds.wordShiftAmount",
    "RiscvRefinement.Air.Family.LoadStoreHolds.wordStore",
    "RiscvRefinement.Air.Family.MulHolds.clockPositive",
    "RiscvRefinement.Air.Family.MulHolds.destinationClock",
    "RiscvRefinement.Air.Family.MulHolds.destinationFlag",
    "RiscvRefinement.Air.Family.MulHolds.destinationLimb0",
    "RiscvRefinement.Air.Family.MulHolds.destinationLimb1",
    "RiscvRefinement.Air.Family.MulHolds.destinationLimb2",
    "RiscvRefinement.Air.Family.MulHolds.destinationLimb3",
    "RiscvRefinement.Air.Family.MulHolds.nextPcResult",
    "RiscvRefinement.Air.Family.MulHolds.productLimb0",
    "RiscvRefinement.Air.Family.MulHolds.productLimb1",
    "RiscvRefinement.Air.Family.MulHolds.productLimb2",
    "RiscvRefinement.Air.Family.MulHolds.productLimb3",
    "RiscvRefinement.Air.Family.MulHolds.sourceOneClock",
    "RiscvRefinement.Air.Family.MulHolds.sourceOneLimb0",
    "RiscvRefinement.Air.Family.MulHolds.sourceOneLimb1",
    "RiscvRefinement.Air.Family.MulHolds.sourceOneLimb2",
    "RiscvRefinement.Air.Family.MulHolds.sourceOneLimb3",
    "RiscvRefinement.Air.Family.MulHolds.sourceTwoClock",
    "RiscvRefinement.Air.Family.MulHolds.sourceTwoLimb0",
    "RiscvRefinement.Air.Family.MulHolds.sourceTwoLimb1",
    "RiscvRefinement.Air.Family.MulHolds.sourceTwoLimb2",
    "RiscvRefinement.Air.Family.MulHolds.sourceTwoLimb3",
    "RiscvRefinement.Air.Family.MulhHolds.clockPositive",
    "RiscvRefinement.Air.Family.MulhHolds.destinationClock",
    "RiscvRefinement.Air.Family.MulhHolds.destinationFlag",
    "RiscvRefinement.Air.Family.MulhHolds.destinationLimb0",
    "RiscvRefinement.Air.Family.MulhHolds.destinationLimb1",
    "RiscvRefinement.Air.Family.MulhHolds.destinationLimb2",
    "RiscvRefinement.Air.Family.MulhHolds.destinationLimb3",
    "RiscvRefinement.Air.Family.MulhHolds.nextPcResult",
    "RiscvRefinement.Air.Family.MulhHolds.productLimb0",
    "RiscvRefinement.Air.Family.MulhHolds.productLimb1",
    "RiscvRefinement.Air.Family.MulhHolds.productLimb2",
    "RiscvRefinement.Air.Family.MulhHolds.productLimb3",
    "RiscvRefinement.Air.Family.MulhHolds.productLimb4",
    "RiscvRefinement.Air.Family.MulhHolds.productLimb5",
    "RiscvRefinement.Air.Family.MulhHolds.productLimb6",
    "RiscvRefinement.Air.Family.MulhHolds.productLimb7",
    "RiscvRefinement.Air.Family.MulhHolds.signedSourceOne",
    "RiscvRefinement.Air.Family.MulhHolds.signedSourceTwo",
    "RiscvRefinement.Air.Family.MulhHolds.sourceOneClock",
    "RiscvRefinement.Air.Family.MulhHolds.sourceOneLimb0",
    "RiscvRefinement.Air.Family.MulhHolds.sourceOneLimb1",
    "RiscvRefinement.Air.Family.MulhHolds.sourceOneLimb2",
    "RiscvRefinement.Air.Family.MulhHolds.sourceOneLimb3",
    "RiscvRefinement.Air.Family.MulhHolds.sourceTwoClock",
    "RiscvRefinement.Air.Family.MulhHolds.sourceTwoLimb0",
    "RiscvRefinement.Air.Family.MulhHolds.sourceTwoLimb1",
    "RiscvRefinement.Air.Family.MulhHolds.sourceTwoLimb2",
    "RiscvRefinement.Air.Family.MulhHolds.sourceTwoLimb3",
    "RiscvRefinement.Air.Family.MulhHolds.unsignedSourceOne",
    "RiscvRefinement.Air.Family.MulhHolds.unsignedSourceTwo",
    "RiscvRefinement.Air.Family.ShiftHolds.bitIndexRange",
    "RiscvRefinement.Air.Family.ShiftHolds.carry0Range",
    "RiscvRefinement.Air.Family.ShiftHolds.carry1Range",
    "RiscvRefinement.Air.Family.ShiftHolds.carry2Range",
    "RiscvRefinement.Air.Family.ShiftHolds.carry3Range",
    "RiscvRefinement.Air.Family.ShiftHolds.destinationFlag",
    "RiscvRefinement.Air.Family.ShiftHolds.destinationLimb0",
    "RiscvRefinement.Air.Family.ShiftHolds.destinationLimb1",
    "RiscvRefinement.Air.Family.ShiftHolds.destinationLimb2",
    "RiscvRefinement.Air.Family.ShiftHolds.destinationLimb3",
    "RiscvRefinement.Air.Family.ShiftHolds.leftMovement",
    "RiscvRefinement.Air.Family.ShiftHolds.limbIndexRange",
    "RiscvRefinement.Air.Family.ShiftHolds.rightMovement",
    "RiscvRefinement.Air.Family.ShiftHolds.signIsLogicalZero",
    "RiscvRefinement.Air.Family.ShiftHolds.signLowerBound",
    "RiscvRefinement.Air.Family.ShiftHolds.signUpperBound",
    "RiscvRefinement.Air.Family.ShiftHolds.sourceReadOnly",
    "RiscvRefinement.Air.Family.ShiftRow.multiplier_pos",
    "RiscvRefinement.Air.Family.ShiftsImmHolds.clockPositive",
    "RiscvRefinement.Air.Family.ShiftsImmHolds.core",
    "RiscvRefinement.Air.Family.ShiftsImmHolds.destinationClock",
    "RiscvRefinement.Air.Family.ShiftsImmHolds.immediateBinds",
    "RiscvRefinement.Air.Family.ShiftsImmHolds.nextPcResult",
    "RiscvRefinement.Air.Family.ShiftsImmHolds.sourceClock",
    "RiscvRefinement.Air.Family.ShiftsRegHolds.clockPositive",
    "RiscvRefinement.Air.Family.ShiftsRegHolds.core",
    "RiscvRefinement.Air.Family.ShiftsRegHolds.destinationClock",
    "RiscvRefinement.Air.Family.ShiftsRegHolds.nextPcResult",
    "RiscvRefinement.Air.Family.ShiftsRegHolds.secondSourceClock",
    "RiscvRefinement.Air.Family.ShiftsRegHolds.secondSourceReadOnly",
    "RiscvRefinement.Air.Family.ShiftsRegHolds.shiftAmountBinds",
    "RiscvRefinement.Air.Family.ShiftsRegHolds.sourceClock",
    "RiscvRefinement.Air.Family.bitValue_false",
    "RiscvRefinement.Air.Family.bitValue_true",
    "RiscvRefinement.Air.Family.bit_markers_hot",
    "RiscvRefinement.Air.Family.div_abs_negated",
    "RiscvRefinement.Air.Family.div_compare_negative",
    "RiscvRefinement.Air.Family.div_compare_positive",
    "RiscvRefinement.Air.Family.div_conv_expand",
    "RiscvRefinement.Air.Family.div_conv_sum_telescope",
    "RiscvRefinement.Air.Family.div_destination_word",
    "RiscvRefinement.Air.Family.div_extended_cast",
    "RiscvRefinement.Air.Family.div_flags_div",
    "RiscvRefinement.Air.Family.div_flags_divu",
    "RiscvRefinement.Air.Family.div_flags_rem",
    "RiscvRefinement.Air.Family.div_flags_remu",
    "RiscvRefinement.Air.Family.div_msb_value",
    "RiscvRefinement.Air.Family.div_opcode_id_div",
    "RiscvRefinement.Air.Family.div_opcode_id_divu",
    "RiscvRefinement.Air.Family.div_opcode_id_rem",
    "RiscvRefinement.Air.Family.div_opcode_id_remu",
    "RiscvRefinement.Air.Family.div_product_identity",
    "RiscvRefinement.Air.Family.div_result_word",
    "RiscvRefinement.Air.Family.div_scan_facts",
    "RiscvRefinement.Air.Family.div_selector_cases",
    "RiscvRefinement.Air.Family.div_signed_bound",
    "RiscvRefinement.Air.Family.div_signed_bound_of_msb",
    "RiscvRefinement.Air.Family.div_signed_congruence",
    "RiscvRefinement.Air.Family.div_signed_identity",
    "RiscvRefinement.Air.Family.div_signed_int_eq",
    "RiscvRefinement.Air.Family.div_signed_remainder_bound",
    "RiscvRefinement.Air.Family.div_signed_result",
    "RiscvRefinement.Air.Family.div_source_one_word",
    "RiscvRefinement.Air.Family.div_source_two_word",
    "RiscvRefinement.Air.Family.div_unsigned_exact",
    "RiscvRefinement.Air.Family.div_unsigned_extensions",
    "RiscvRefinement.Air.Family.div_unsigned_remainder_lt",
    "RiscvRefinement.Air.Family.div_unsigned_result",
    "RiscvRefinement.Air.Family.div_unsigned_signs",
    "RiscvRefinement.Air.Family.div_unsigned_value_word",
    "RiscvRefinement.Air.Family.div_word_eq_zero_iff",
    "RiscvRefinement.Air.Family.div_wrap_signed_int",
    "RiscvRefinement.Air.Family.div_zero_divisor_facts",
    "RiscvRefinement.Air.Family.divu_result_word",
    "RiscvRefinement.Air.Family.limb_markers_hot",
    "RiscvRefinement.Air.Family.mulDestinationValue",
    "RiscvRefinement.Air.Family.mulLowProduct",
    "RiscvRefinement.Air.Family.mulResultWord",
    "RiscvRefinement.Air.Family.mulSourceOneStable",
    "RiscvRefinement.Air.Family.mulSourceTwoStable",
    "RiscvRefinement.Air.Family.mul_word_value",
    "RiscvRefinement.Air.Family.mulhDestinationValue",
    "RiscvRefinement.Air.Family.mulhHighWord",
    "RiscvRefinement.Air.Family.mulhLowWord",
    "RiscvRefinement.Air.Family.mulhProductRecurrence",
    "RiscvRefinement.Air.Family.mulhSourceOneStable",
    "RiscvRefinement.Air.Family.mulhSourceTwoStable",
    "RiscvRefinement.Air.Family.multiplyRowExpand",
    "RiscvRefinement.Air.Family.multiplySignIsMsb",
    "RiscvRefinement.Air.Family.multiplyValueMul",
    "RiscvRefinement.Air.Family.rem_result_word",
    "RiscvRefinement.Air.Family.remu_result_word",
    "RiscvRefinement.Air.Family.shift_amount_lt_32",
    "RiscvRefinement.Air.Family.shift_destination_value",
    "RiscvRefinement.Air.Family.shift_left_value",
    "RiscvRefinement.Air.Family.shift_left_word",
    "RiscvRefinement.Air.Family.shift_limb_cases",
    "RiscvRefinement.Air.Family.shift_multiplier_le",
    "RiscvRefinement.Air.Family.shift_pow_split",
    "RiscvRefinement.Air.Family.shift_right_arithmetic_word",
    "RiscvRefinement.Air.Family.shift_right_logical_value",
    "RiscvRefinement.Air.Family.shift_right_logical_word",
    "RiscvRefinement.Air.Family.shift_right_signed_value",
    "RiscvRefinement.Air.Family.shift_selector_hot",
    "RiscvRefinement.Air.Family.shift_source_msb_false",
    "RiscvRefinement.Air.Family.shift_source_msb_true",
    "RiscvRefinement.Air.Family.shifts_reg_amount_is_masked",
    "RiscvRefinement.Air.Generated.AddiHolds.carryRecurrence",
    "RiscvRefinement.Air.Generated.AddiHolds.clockPositive",
    "RiscvRefinement.Air.Generated.AddiHolds.destinationClock",
    "RiscvRefinement.Air.Generated.AddiHolds.destinationFlag",
    "RiscvRefinement.Air.Generated.AddiHolds.destinationLimb0",
    "RiscvRefinement.Air.Generated.AddiHolds.destinationLimb1",
    "RiscvRefinement.Air.Generated.AddiHolds.destinationLimb2",
    "RiscvRefinement.Air.Generated.AddiHolds.destinationLimb3",
    "RiscvRefinement.Air.Generated.AddiHolds.nextPcResult",
    "RiscvRefinement.Air.Generated.AddiHolds.sourceClock",
    "RiscvRefinement.Air.Generated.AddiHolds.sourceLimb0",
    "RiscvRefinement.Air.Generated.AddiHolds.sourceLimb1",
    "RiscvRefinement.Air.Generated.AddiHolds.sourceLimb2",
    "RiscvRefinement.Air.Generated.AddiHolds.sourceLimb3",
    "RiscvRefinement.Air.Generated.LuiHolds.clockPositive",
    "RiscvRefinement.Air.Generated.LuiHolds.destinationClock",
    "RiscvRefinement.Air.Generated.LuiHolds.destinationFlag",
    "RiscvRefinement.Air.Generated.LuiHolds.destinationLimb0",
    "RiscvRefinement.Air.Generated.LuiHolds.destinationLimb1",
    "RiscvRefinement.Air.Generated.LuiHolds.destinationLimb2",
    "RiscvRefinement.Air.Generated.LuiHolds.destinationLimb3",
    "RiscvRefinement.Air.Generated.LuiHolds.nextPcResult",
    "RiscvRefinement.Arith.allOnesWord_signedValue",
    "RiscvRefinement.Arith.allOnesWord_unsignedValue",
    "RiscvRefinement.Arith.div_mod_unique",
    "RiscvRefinement.Arith.divideSigned_high_bit",
    "RiscvRefinement.Arith.divideSigned_high_bit_by_two",
    "RiscvRefinement.Arith.divideSigned_overflow",
    "RiscvRefinement.Arith.divideSigned_zero",
    "RiscvRefinement.Arith.divideUnsigned_high_bit",
    "RiscvRefinement.Arith.divideUnsigned_high_bit_by_two",
    "RiscvRefinement.Arith.divideUnsigned_zero",
    "RiscvRefinement.Arith.intMinWord_signedValue",
    "RiscvRefinement.Arith.minusOneWord_signedValue",
    "RiscvRefinement.Arith.remainderSigned_overflow",
    "RiscvRefinement.Arith.remainderSigned_zero",
    "RiscvRefinement.Arith.remainderUnsigned_high_bit",
    "RiscvRefinement.Arith.remainderUnsigned_zero",
    "RiscvRefinement.Arith.signedValue_eq_sub",
    "RiscvRefinement.Arith.signedValue_lower",
    "RiscvRefinement.Arith.signedValue_nonneg_iff",
    "RiscvRefinement.Arith.signedValue_upper",
    "RiscvRefinement.Arith.signedValue_wrapSigned",
    "RiscvRefinement.Arith.tdiv_identity",
    "RiscvRefinement.Arith.tdiv_tmod_unique",
    "RiscvRefinement.Arith.tmod_natAbs_lt",
    "RiscvRefinement.Arith.tmod_nonneg_of_nonneg",
    "RiscvRefinement.Arith.tmod_nonpos_of_nonpos",
    "RiscvRefinement.Arith.unsignedValue_lt",
    "RiscvRefinement.Arith.wrapSigned_ofNat",
    "RiscvRefinement.Arith.wrapSigned_sub",
    "RiscvRefinement.Coverage.pilot_coverage_exact",
    "RiscvRefinement.Decode.base_and_m_extension_are_disjoint",
    "RiscvRefinement.Decode.encode_addi_is_canonical",
    "RiscvRefinement.Decode.encode_div_is_canonical",
    "RiscvRefinement.Decode.encode_divu_is_canonical",
    "RiscvRefinement.Decode.encode_lb_is_canonical",
    "RiscvRefinement.Decode.encode_lbu_is_canonical",
    "RiscvRefinement.Decode.encode_lh_is_canonical",
    "RiscvRefinement.Decode.encode_lhu_is_canonical",
    "RiscvRefinement.Decode.encode_load_is_canonical",
    "RiscvRefinement.Decode.encode_lui_is_canonical",
    "RiscvRefinement.Decode.encode_lw_is_canonical",
    "RiscvRefinement.Decode.encode_mul_is_canonical",
    "RiscvRefinement.Decode.encode_mulh_is_canonical",
    "RiscvRefinement.Decode.encode_mulhsu_is_canonical",
    "RiscvRefinement.Decode.encode_mulhu_is_canonical",
    "RiscvRefinement.Decode.encode_rem_is_canonical",
    "RiscvRefinement.Decode.encode_remu_is_canonical",
    "RiscvRefinement.Decode.encode_rtype_is_canonical",
    "RiscvRefinement.Decode.encode_sb_is_canonical",
    "RiscvRefinement.Decode.encode_sh_is_canonical",
    "RiscvRefinement.Decode.encode_shift_imm_is_canonical",
    "RiscvRefinement.Decode.encode_sll_is_canonical",
    "RiscvRefinement.Decode.encode_slli_is_canonical",
    "RiscvRefinement.Decode.encode_sra_is_canonical",
    "RiscvRefinement.Decode.encode_srai_is_canonical",
    "RiscvRefinement.Decode.encode_srl_is_canonical",
    "RiscvRefinement.Decode.encode_srli_is_canonical",
    "RiscvRefinement.Decode.encode_store_is_canonical",
    "RiscvRefinement.Decode.encode_sw_is_canonical",
    "RiscvRefinement.Decode.fence_i_is_not_admitted",
    "RiscvRefinement.Decode.isLoad_fields",
    "RiscvRefinement.Decode.isRType_fields",
    "RiscvRefinement.Decode.isShiftImm_fields",
    "RiscvRefinement.Decode.isStore_fields",
    "RiscvRefinement.Decode.load_selectors_are_disjoint",
    "RiscvRefinement.Decode.multiply_and_divide_selectors_are_disjoint",
    "RiscvRefinement.Decode.shapes_are_disjoint",
    "RiscvRefinement.Decode.shift_selectors_are_disjoint",
    "RiscvRefinement.Memory.address_split",
    "RiscvRefinement.Memory.applyMask_byte_single",
    "RiscvRefinement.Memory.applyMask_half_preserves_other",
    "RiscvRefinement.Memory.applyMask_limb0_preserved",
    "RiscvRefinement.Memory.applyMask_limb1_preserved",
    "RiscvRefinement.Memory.applyMask_limb2_preserved",
    "RiscvRefinement.Memory.applyMask_limb3_preserved",
    "RiscvRefinement.Memory.applyMask_word",
    "RiscvRefinement.Memory.busAddress_isWordAligned",
    "RiscvRefinement.Memory.busAddress_of_wordAligned",
    "RiscvRefinement.Memory.byteOffset_split",
    "RiscvRefinement.Memory.effectiveAddress_toNat",
    "RiscvRefinement.Memory.halfAligned_byteOffset",
    "RiscvRefinement.Memory.highHalf_extract",
    "RiscvRefinement.Memory.lowHalf_extract",
    "RiscvRefinement.Memory.selectHalf_high",
    "RiscvRefinement.Memory.selectHalf_low",
    "RiscvRefinement.Memory.signExtendByte_fill",
    "RiscvRefinement.Memory.signExtendByte_negative",
    "RiscvRefinement.Memory.signExtendByte_nonnegative",
    "RiscvRefinement.Memory.signExtendHalf_fill",
    "RiscvRefinement.Memory.signExtendHalf_low",
    "RiscvRefinement.Memory.signExtendHalf_negative",
    "RiscvRefinement.Memory.signExtendHalf_nonnegative",
    "RiscvRefinement.Mutation.MutationControl.refutes",
    "RiscvRefinement.Mutation.MutationControl.satisfies",
    "RiscvRefinement.Mutation.MutationControl.strictly_weaker",
    "RiscvRefinement.Mutation.MutationControl.witness_not_sound",
    "RiscvRefinement.NonVacuity.addi_exists",
    "RiscvRefinement.NonVacuity.honest_addi_holds",
    "RiscvRefinement.NonVacuity.honest_lui_holds",
    "RiscvRefinement.NonVacuity.lui_exists",
    "RiscvRefinement.Opcodes.AddiEnvironment.destinationBinds",
    "RiscvRefinement.Opcodes.AddiEnvironment.pcBinds",
    "RiscvRefinement.Opcodes.AddiEnvironment.sourceBinds",
    "RiscvRefinement.Opcodes.AddiEnvironment.wordBinds",
    "RiscvRefinement.Opcodes.AddiRefinement.decode",
    "RiscvRefinement.Opcodes.AddiRefinement.destinationConsume",
    "RiscvRefinement.Opcodes.AddiRefinement.destinationEmit",
    "RiscvRefinement.Opcodes.AddiRefinement.programTuple",
    "RiscvRefinement.Opcodes.AddiRefinement.retirement",
    "RiscvRefinement.Opcodes.AddiRefinement.sourceConsume",
    "RiscvRefinement.Opcodes.AddiRefinement.sourceEmit",
    "RiscvRefinement.Opcodes.AddiRefinement.stateConsume",
    "RiscvRefinement.Opcodes.AddiRefinement.stateEmit",
    "RiscvRefinement.Opcodes.DivEnvironment.destinationBinds",
    "RiscvRefinement.Opcodes.DivEnvironment.dividendBinds",
    "RiscvRefinement.Opcodes.DivEnvironment.divisorBinds",
    "RiscvRefinement.Opcodes.DivEnvironment.pcBinds",
    "RiscvRefinement.Opcodes.DivRefinement.destinationConsume",
    "RiscvRefinement.Opcodes.DivRefinement.destinationEmit",
    "RiscvRefinement.Opcodes.DivRefinement.nextPcResult",
    "RiscvRefinement.Opcodes.DivRefinement.noRead",
    "RiscvRefinement.Opcodes.DivRefinement.noStore",
    "RiscvRefinement.Opcodes.DivRefinement.programTuple",
    "RiscvRefinement.Opcodes.DivRefinement.retirement",
    "RiscvRefinement.Opcodes.DivRefinement.sourceOneConsume",
    "RiscvRefinement.Opcodes.DivRefinement.sourceOneEmit",
    "RiscvRefinement.Opcodes.DivRefinement.sourceTwoConsume",
    "RiscvRefinement.Opcodes.DivRefinement.sourceTwoEmit",
    "RiscvRefinement.Opcodes.DivRefinement.stateConsume",
    "RiscvRefinement.Opcodes.DivRefinement.stateEmit",
    "RiscvRefinement.Opcodes.LhRefinement.aligned",
    "RiscvRefinement.Opcodes.LhRefinement.baseConsume",
    "RiscvRefinement.Opcodes.LhRefinement.baseEmit",
    "RiscvRefinement.Opcodes.LhRefinement.basePreserved",
    "RiscvRefinement.Opcodes.LhRefinement.busAddress",
    "RiscvRefinement.Opcodes.LhRefinement.decode",
    "RiscvRefinement.Opcodes.LhRefinement.effectiveAddress",
    "RiscvRefinement.Opcodes.LhRefinement.memoryConsume",
    "RiscvRefinement.Opcodes.LhRefinement.memoryEmit",
    "RiscvRefinement.Opcodes.LhRefinement.memoryPreserved",
    "RiscvRefinement.Opcodes.LhRefinement.operandConsume",
    "RiscvRefinement.Opcodes.LhRefinement.operandEmit",
    "RiscvRefinement.Opcodes.LhRefinement.programTuple",
    "RiscvRefinement.Opcodes.LhRefinement.retirement",
    "RiscvRefinement.Opcodes.LhRefinement.stateConsume",
    "RiscvRefinement.Opcodes.LhRefinement.stateEmit",
    "RiscvRefinement.Opcodes.LoadRefinement.baseConsume",
    "RiscvRefinement.Opcodes.LoadRefinement.baseEmit",
    "RiscvRefinement.Opcodes.LoadRefinement.basePreserved",
    "RiscvRefinement.Opcodes.LoadRefinement.busAddress",
    "RiscvRefinement.Opcodes.LoadRefinement.decode",
    "RiscvRefinement.Opcodes.LoadRefinement.effectiveAddress",
    "RiscvRefinement.Opcodes.LoadRefinement.memoryConsume",
    "RiscvRefinement.Opcodes.LoadRefinement.memoryEmit",
    "RiscvRefinement.Opcodes.LoadRefinement.memoryPreserved",
    "RiscvRefinement.Opcodes.LoadRefinement.operandConsume",
    "RiscvRefinement.Opcodes.LoadRefinement.operandEmit",
    "RiscvRefinement.Opcodes.LoadRefinement.programTuple",
    "RiscvRefinement.Opcodes.LoadRefinement.retirement",
    "RiscvRefinement.Opcodes.LoadRefinement.stateConsume",
    "RiscvRefinement.Opcodes.LoadRefinement.stateEmit",
    "RiscvRefinement.Opcodes.LoadStoreDecode.encode_load_is_canonical",
    "RiscvRefinement.Opcodes.LoadStoreDecode.encode_store_is_canonical",
    "RiscvRefinement.Opcodes.LoadStoreEnvironment.baseBinds",
    "RiscvRefinement.Opcodes.LoadStoreEnvironment.baseInFieldRange",
    "RiscvRefinement.Opcodes.LoadStoreEnvironment.busAddress_eq",
    "RiscvRefinement.Opcodes.LoadStoreEnvironment.effectiveAddress_eq",
    "RiscvRefinement.Opcodes.LoadStoreEnvironment.immBinds",
    "RiscvRefinement.Opcodes.LoadStoreEnvironment.memoryBinds",
    "RiscvRefinement.Opcodes.LoadStoreEnvironment.memoryWord_eq",
    "RiscvRefinement.Opcodes.LoadStoreEnvironment.operandBinds",
    "RiscvRefinement.Opcodes.LoadStoreEnvironment.pcBinds",
    "RiscvRefinement.Opcodes.LoadStoreEnvironment.wordBinds",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.alignedQuarterRange",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.baseClock",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.baseHighLimbRange",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.baseLimbsCanonical",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.baseReadOnly",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.byteLoadExtension",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.byteLoadSelect",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.byteMarkerSum",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.byteShiftAmount",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.byteSignWitness",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.byteStoreSelect",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.clockPositive",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.destinationFlag",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.halfLoadExtension",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.halfLoadLow",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.halfMarkerSum",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.halfShiftAmount",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.halfShiftId",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.halfSignWitness",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.halfStoreHigh",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.halfStoreLow",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.immFeltRange",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.loadDestination",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.memoryAddress",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.memoryClock",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.nextPcResult",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.operandClock",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.partialStorePreserve",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.selectorSum",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.signWitnessCanonical",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.sourceReadOnly",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.storeResultZero",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.wordLoad",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.wordShiftAmount",
    "RiscvRefinement.Opcodes.LoadStoreHoldsWithoutHalfLoadHigh.wordStore",
    "RiscvRefinement.Opcodes.LuiEnvironment.destinationBinds",
    "RiscvRefinement.Opcodes.LuiEnvironment.pcBinds",
    "RiscvRefinement.Opcodes.LuiEnvironment.wordBinds",
    "RiscvRefinement.Opcodes.LuiRefinement.decode",
    "RiscvRefinement.Opcodes.LuiRefinement.destinationConsume",
    "RiscvRefinement.Opcodes.LuiRefinement.destinationEmit",
    "RiscvRefinement.Opcodes.LuiRefinement.programTuple",
    "RiscvRefinement.Opcodes.LuiRefinement.retirement",
    "RiscvRefinement.Opcodes.LuiRefinement.stateConsume",
    "RiscvRefinement.Opcodes.LuiRefinement.stateEmit",
    "RiscvRefinement.Opcodes.MulEnvironment.destinationBinds",
    "RiscvRefinement.Opcodes.MulEnvironment.pcBinds",
    "RiscvRefinement.Opcodes.MulEnvironment.sourceOneBinds",
    "RiscvRefinement.Opcodes.MulEnvironment.sourceTwoBinds",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.clockPositive",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.destinationClock",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.destinationFlag",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.destinationLimb0",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.destinationLimb1",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.destinationLimb2",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.destinationLimb3",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.nextPcResult",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.productLimb1",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.productLimb2",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.productLimb3",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.sourceOneClock",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.sourceOneLimb0",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.sourceOneLimb1",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.sourceOneLimb2",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.sourceOneLimb3",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.sourceTwoClock",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.sourceTwoLimb0",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.sourceTwoLimb1",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.sourceTwoLimb2",
    "RiscvRefinement.Opcodes.MulHoldsWithoutProductLimb0.sourceTwoLimb3",
    "RiscvRefinement.Opcodes.MulRefinement.destinationConsume",
    "RiscvRefinement.Opcodes.MulRefinement.destinationEmit",
    "RiscvRefinement.Opcodes.MulRefinement.nextProgramCounter",
    "RiscvRefinement.Opcodes.MulRefinement.noMemoryRead",
    "RiscvRefinement.Opcodes.MulRefinement.noMemoryWrite",
    "RiscvRefinement.Opcodes.MulRefinement.programTuple",
    "RiscvRefinement.Opcodes.MulRefinement.retirement",
    "RiscvRefinement.Opcodes.MulRefinement.sourceOneConsume",
    "RiscvRefinement.Opcodes.MulRefinement.sourceOneEmit",
    "RiscvRefinement.Opcodes.MulRefinement.sourceTwoConsume",
    "RiscvRefinement.Opcodes.MulRefinement.sourceTwoEmit",
    "RiscvRefinement.Opcodes.MulRefinement.stateConsume",
    "RiscvRefinement.Opcodes.MulRefinement.stateEmit",
    "RiscvRefinement.Opcodes.MulRefinement.zeroDestination",
    "RiscvRefinement.Opcodes.MulhBusRefinement.destinationConsume",
    "RiscvRefinement.Opcodes.MulhBusRefinement.nextProgramCounter",
    "RiscvRefinement.Opcodes.MulhBusRefinement.noMemoryRead",
    "RiscvRefinement.Opcodes.MulhBusRefinement.noMemoryWrite",
    "RiscvRefinement.Opcodes.MulhBusRefinement.sourceOneConsume",
    "RiscvRefinement.Opcodes.MulhBusRefinement.sourceOneEmit",
    "RiscvRefinement.Opcodes.MulhBusRefinement.sourceTwoConsume",
    "RiscvRefinement.Opcodes.MulhBusRefinement.sourceTwoEmit",
    "RiscvRefinement.Opcodes.MulhBusRefinement.stateConsume",
    "RiscvRefinement.Opcodes.MulhBusRefinement.stateEmit",
    "RiscvRefinement.Opcodes.MulhBusRefinement.zeroDestination",
    "RiscvRefinement.Opcodes.MulhEnvironment.destinationBinds",
    "RiscvRefinement.Opcodes.MulhEnvironment.pcBinds",
    "RiscvRefinement.Opcodes.MulhEnvironment.sourceOneBinds",
    "RiscvRefinement.Opcodes.MulhEnvironment.sourceTwoBinds",
    "RiscvRefinement.Opcodes.MulhRefinement.bus",
    "RiscvRefinement.Opcodes.MulhRefinement.destinationEmit",
    "RiscvRefinement.Opcodes.MulhRefinement.programTuple",
    "RiscvRefinement.Opcodes.MulhRefinement.retirement",
    "RiscvRefinement.Opcodes.MulhsuRefinement.bus",
    "RiscvRefinement.Opcodes.MulhsuRefinement.destinationEmit",
    "RiscvRefinement.Opcodes.MulhsuRefinement.programTuple",
    "RiscvRefinement.Opcodes.MulhsuRefinement.retirement",
    "RiscvRefinement.Opcodes.MulhuRefinement.bus",
    "RiscvRefinement.Opcodes.MulhuRefinement.destinationEmit",
    "RiscvRefinement.Opcodes.MulhuRefinement.programTuple",
    "RiscvRefinement.Opcodes.MulhuRefinement.retirement",
    "RiscvRefinement.Opcodes.NonVacuity.lb_exists",
    "RiscvRefinement.Opcodes.NonVacuity.lb_holds",
    "RiscvRefinement.Opcodes.NonVacuity.lbu_exists",
    "RiscvRefinement.Opcodes.NonVacuity.lbu_holds",
    "RiscvRefinement.Opcodes.NonVacuity.lhAlias_holds",
    "RiscvRefinement.Opcodes.NonVacuity.lhHigh_holds",
    "RiscvRefinement.Opcodes.NonVacuity.lhLow_holds",
    "RiscvRefinement.Opcodes.NonVacuity.lhWrap_holds",
    "RiscvRefinement.Opcodes.NonVacuity.lhZero_holds",
    "RiscvRefinement.Opcodes.NonVacuity.lh_alias_exists",
    "RiscvRefinement.Opcodes.NonVacuity.lh_high_negative_exists",
    "RiscvRefinement.Opcodes.NonVacuity.lh_low_exists",
    "RiscvRefinement.Opcodes.NonVacuity.lh_wrap_exists",
    "RiscvRefinement.Opcodes.NonVacuity.lh_zero_destination_exists",
    "RiscvRefinement.Opcodes.NonVacuity.lhu_exists",
    "RiscvRefinement.Opcodes.NonVacuity.lhu_holds",
    "RiscvRefinement.Opcodes.NonVacuity.lw_exists",
    "RiscvRefinement.Opcodes.NonVacuity.lw_holds",
    "RiscvRefinement.Opcodes.NonVacuity.sb_exists",
    "RiscvRefinement.Opcodes.NonVacuity.sb_holds",
    "RiscvRefinement.Opcodes.NonVacuity.sh_exists",
    "RiscvRefinement.Opcodes.NonVacuity.sh_holds",
    "RiscvRefinement.Opcodes.NonVacuity.sw_exists",
    "RiscvRefinement.Opcodes.NonVacuity.sw_holds",
    "RiscvRefinement.Opcodes.ShiftsImmEnvironment.destinationBinds",
    "RiscvRefinement.Opcodes.ShiftsImmEnvironment.pcBinds",
    "RiscvRefinement.Opcodes.ShiftsImmEnvironment.sourceBinds",
    "RiscvRefinement.Opcodes.ShiftsImmEnvironment.wordBinds",
    "RiscvRefinement.Opcodes.ShiftsImmRefinement.decode",
    "RiscvRefinement.Opcodes.ShiftsImmRefinement.destinationConsume",
    "RiscvRefinement.Opcodes.ShiftsImmRefinement.destinationEmit",
    "RiscvRefinement.Opcodes.ShiftsImmRefinement.maskedAmount",
    "RiscvRefinement.Opcodes.ShiftsImmRefinement.noMemoryEffect",
    "RiscvRefinement.Opcodes.ShiftsImmRefinement.programTuple",
    "RiscvRefinement.Opcodes.ShiftsImmRefinement.retirement",
    "RiscvRefinement.Opcodes.ShiftsImmRefinement.sourceConsume",
    "RiscvRefinement.Opcodes.ShiftsImmRefinement.sourceEmit",
    "RiscvRefinement.Opcodes.ShiftsImmRefinement.stateConsume",
    "RiscvRefinement.Opcodes.ShiftsImmRefinement.stateEmit",
    "RiscvRefinement.Opcodes.ShiftsRegEnvironment.destinationBinds",
    "RiscvRefinement.Opcodes.ShiftsRegEnvironment.pcBinds",
    "RiscvRefinement.Opcodes.ShiftsRegEnvironment.secondSourceBinds",
    "RiscvRefinement.Opcodes.ShiftsRegEnvironment.sourceBinds",
    "RiscvRefinement.Opcodes.ShiftsRegEnvironment.wordBinds",
    "RiscvRefinement.Opcodes.ShiftsRegRefinement.decode",
    "RiscvRefinement.Opcodes.ShiftsRegRefinement.destinationConsume",
    "RiscvRefinement.Opcodes.ShiftsRegRefinement.destinationEmit",
    "RiscvRefinement.Opcodes.ShiftsRegRefinement.maskedAmount",
    "RiscvRefinement.Opcodes.ShiftsRegRefinement.noMemoryEffect",
    "RiscvRefinement.Opcodes.ShiftsRegRefinement.programTuple",
    "RiscvRefinement.Opcodes.ShiftsRegRefinement.retirement",
    "RiscvRefinement.Opcodes.ShiftsRegRefinement.secondSourceConsume",
    "RiscvRefinement.Opcodes.ShiftsRegRefinement.secondSourceEmit",
    "RiscvRefinement.Opcodes.ShiftsRegRefinement.sourceConsume",
    "RiscvRefinement.Opcodes.ShiftsRegRefinement.sourceEmit",
    "RiscvRefinement.Opcodes.ShiftsRegRefinement.stateConsume",
    "RiscvRefinement.Opcodes.ShiftsRegRefinement.stateEmit",
    "RiscvRefinement.Opcodes.StoreRefinement.baseConsume",
    "RiscvRefinement.Opcodes.StoreRefinement.baseEmit",
    "RiscvRefinement.Opcodes.StoreRefinement.basePreserved",
    "RiscvRefinement.Opcodes.StoreRefinement.busAddress",
    "RiscvRefinement.Opcodes.StoreRefinement.decode",
    "RiscvRefinement.Opcodes.StoreRefinement.effectiveAddress",
    "RiscvRefinement.Opcodes.StoreRefinement.memoryConsume",
    "RiscvRefinement.Opcodes.StoreRefinement.memoryEmit",
    "RiscvRefinement.Opcodes.StoreRefinement.memoryUpdated",
    "RiscvRefinement.Opcodes.StoreRefinement.noRead",
    "RiscvRefinement.Opcodes.StoreRefinement.noRegisterWrite",
    "RiscvRefinement.Opcodes.StoreRefinement.operandConsume",
    "RiscvRefinement.Opcodes.StoreRefinement.operandEmit",
    "RiscvRefinement.Opcodes.StoreRefinement.programTuple",
    "RiscvRefinement.Opcodes.StoreRefinement.retirement",
    "RiscvRefinement.Opcodes.StoreRefinement.sourcePreserved",
    "RiscvRefinement.Opcodes.StoreRefinement.stateConsume",
    "RiscvRefinement.Opcodes.StoreRefinement.stateEmit",
    "RiscvRefinement.Opcodes.addi_arithmetic_from_constraints",
    "RiscvRefinement.Opcodes.addi_destination_from_constraints",
    "RiscvRefinement.Opcodes.addi_immediate_refines",
    "RiscvRefinement.Opcodes.addi_immediate_value_lt",
    "RiscvRefinement.Opcodes.addi_refines",
    "RiscvRefinement.Opcodes.addi_source_from_constraints",
    "RiscvRefinement.Opcodes.addi_value_refines",
    "RiscvRefinement.Opcodes.aliasedMulRow_holds",
    "RiscvRefinement.Opcodes.aliasedMulhuRow_holds",
    "RiscvRefinement.Opcodes.base_lt_modulus",
    "RiscvRefinement.Opcodes.busAddress_toNat",
    "RiscvRefinement.Opcodes.byteOffset_toNat",
    "RiscvRefinement.Opcodes.byte_marker_cases",
    "RiscvRefinement.Opcodes.byte_selected",
    "RiscvRefinement.Opcodes.divWitnessAliasedOperands_holds",
    "RiscvRefinement.Opcodes.divWitnessAliasedOperands_sources",
    "RiscvRefinement.Opcodes.divWitnessHighBitUnsigned_holds",
    "RiscvRefinement.Opcodes.divWitnessHighBitUnsigned_quotient",
    "RiscvRefinement.Opcodes.divWitnessNegativeRemainder_holds",
    "RiscvRefinement.Opcodes.divWitnessNegativeRemainder_quotient",
    "RiscvRefinement.Opcodes.divWitnessOverflowRemainder_holds",
    "RiscvRefinement.Opcodes.divWitnessOverflowRemainder_result",
    "RiscvRefinement.Opcodes.divWitnessOverflow_holds",
    "RiscvRefinement.Opcodes.divWitnessOverflow_quotient",
    "RiscvRefinement.Opcodes.divWitnessZeroDestination_holds",
    "RiscvRefinement.Opcodes.divWitnessZeroDestination_quotient",
    "RiscvRefinement.Opcodes.divWitnessZeroDestination_writes_nothing",
    "RiscvRefinement.Opcodes.divWitnessZeroDivisor_holds",
    "RiscvRefinement.Opcodes.divWitnessZeroDivisor_quotient",
    "RiscvRefinement.Opcodes.divWitness_architectural_agreement",
    "RiscvRefinement.Opcodes.divWitness_no_memory",
    "RiscvRefinement.Opcodes.div_family_refines",
    "RiscvRefinement.Opcodes.div_operands",
    "RiscvRefinement.Opcodes.div_refines",
    "RiscvRefinement.Opcodes.div_retires_as_reviewed",
    "RiscvRefinement.Opcodes.divu_refines",
    "RiscvRefinement.Opcodes.divu_retires_as_reviewed",
    "RiscvRefinement.Opcodes.effective_address_toNat",
    "RiscvRefinement.Opcodes.extract_limb0",
    "RiscvRefinement.Opcodes.extract_limb1",
    "RiscvRefinement.Opcodes.extract_limb2",
    "RiscvRefinement.Opcodes.extract_limb3",
    "RiscvRefinement.Opcodes.freeLowLimbRow_refutes",
    "RiscvRefinement.Opcodes.freeLowLimbRow_satisfies",
    "RiscvRefinement.Opcodes.halfSelector_toNat",
    "RiscvRefinement.Opcodes.half_access_aligned",
    "RiscvRefinement.Opcodes.half_marker_cases",
    "RiscvRefinement.Opcodes.half_selected",
    "RiscvRefinement.Opcodes.half_sign_bit",
    "RiscvRefinement.Opcodes.honestMulRow_holds",
    "RiscvRefinement.Opcodes.honestMulhRow_holds",
    "RiscvRefinement.Opcodes.honestMulhsuRow_holds",
    "RiscvRefinement.Opcodes.honestMulhuRow_holds",
    "RiscvRefinement.Opcodes.immFieldValue_neg",
    "RiscvRefinement.Opcodes.immFieldValue_nonneg",
    "RiscvRefinement.Opcodes.lb_flags",
    "RiscvRefinement.Opcodes.lb_refines",
    "RiscvRefinement.Opcodes.lb_result_value",
    "RiscvRefinement.Opcodes.lbu_flags",
    "RiscvRefinement.Opcodes.lbu_refines",
    "RiscvRefinement.Opcodes.lbu_result_value",
    "RiscvRefinement.Opcodes.lhWrongHalfRow_refutes",
    "RiscvRefinement.Opcodes.lhWrongHalfRow_satisfies",
    "RiscvRefinement.Opcodes.lh_flags",
    "RiscvRefinement.Opcodes.lh_high_half_selection_is_load_bearing",
    "RiscvRefinement.Opcodes.lh_refines",
    "RiscvRefinement.Opcodes.lh_result_value",
    "RiscvRefinement.Opcodes.lh_satisfies_load_interface",
    "RiscvRefinement.Opcodes.lh_shift",
    "RiscvRefinement.Opcodes.lh_write_value",
    "RiscvRefinement.Opcodes.lhu_flags",
    "RiscvRefinement.Opcodes.lhu_refines",
    "RiscvRefinement.Opcodes.lhu_result_value",
    "RiscvRefinement.Opcodes.loadStoreHolds_weakens",
    "RiscvRefinement.Opcodes.loadStoreRetirement_load",
    "RiscvRefinement.Opcodes.loadStoreRetirement_store",
    "RiscvRefinement.Opcodes.load_destination_value",
    "RiscvRefinement.Opcodes.load_memory_word",
    "RiscvRefinement.Opcodes.load_refines",
    "RiscvRefinement.Opcodes.load_to_x0_discards",
    "RiscvRefinement.Opcodes.load_write_value",
    "RiscvRefinement.Opcodes.lowBit_toNat",
    "RiscvRefinement.Opcodes.lui_destination_from_constraints",
    "RiscvRefinement.Opcodes.lui_refines",
    "RiscvRefinement.Opcodes.lui_result_bytes_refine",
    "RiscvRefinement.Opcodes.lui_value_refines",
    "RiscvRefinement.Opcodes.lw_flags",
    "RiscvRefinement.Opcodes.lw_refines",
    "RiscvRefinement.Opcodes.lw_result_value",
    "RiscvRefinement.Opcodes.m31_sum_cases",
    "RiscvRefinement.Opcodes.mask_sb",
    "RiscvRefinement.Opcodes.mask_sh",
    "RiscvRefinement.Opcodes.mask_sw",
    "RiscvRefinement.Opcodes.memoryAfter_load",
    "RiscvRefinement.Opcodes.memoryAfter_store",
    "RiscvRefinement.Opcodes.memoryBefore_load",
    "RiscvRefinement.Opcodes.memoryBefore_store",
    "RiscvRefinement.Opcodes.memoryPreviousClock_load",
    "RiscvRefinement.Opcodes.memoryPreviousClock_store",
    "RiscvRefinement.Opcodes.mulHolds_weakens",
    "RiscvRefinement.Opcodes.mulValueRefines",
    "RiscvRefinement.Opcodes.mul_aliased_exists",
    "RiscvRefinement.Opcodes.mul_exists",
    "RiscvRefinement.Opcodes.mul_product_limb0_is_load_bearing",
    "RiscvRefinement.Opcodes.mul_refines",
    "RiscvRefinement.Opcodes.mulhResultFromOperands",
    "RiscvRefinement.Opcodes.mulhSourceOneSign",
    "RiscvRefinement.Opcodes.mulhSourceTwoSign",
    "RiscvRefinement.Opcodes.mulhValueRefines",
    "RiscvRefinement.Opcodes.mulh_bus_refines",
    "RiscvRefinement.Opcodes.mulh_exists",
    "RiscvRefinement.Opcodes.mulh_refines",
    "RiscvRefinement.Opcodes.mulhsuValueRefines",
    "RiscvRefinement.Opcodes.mulhsu_exists",
    "RiscvRefinement.Opcodes.mulhsu_refines",
    "RiscvRefinement.Opcodes.mulhuValueRefines",
    "RiscvRefinement.Opcodes.mulhu_aliased_exists",
    "RiscvRefinement.Opcodes.mulhu_exists",
    "RiscvRefinement.Opcodes.mulhu_refines",
    "RiscvRefinement.Opcodes.multiplyExtendedSetWidth",
    "RiscvRefinement.Opcodes.multiplyExtendedSignExtend",
    "RiscvRefinement.Opcodes.operandAfter_load",
    "RiscvRefinement.Opcodes.operandAfter_store",
    "RiscvRefinement.Opcodes.operandBefore_load",
    "RiscvRefinement.Opcodes.operandBefore_store",
    "RiscvRefinement.Opcodes.operandPreviousClock_load",
    "RiscvRefinement.Opcodes.operandPreviousClock_store",
    "RiscvRefinement.Opcodes.rem_refines",
    "RiscvRefinement.Opcodes.rem_retires_as_reviewed",
    "RiscvRefinement.Opcodes.remu_refines",
    "RiscvRefinement.Opcodes.remu_retires_as_reviewed",
    "RiscvRefinement.Opcodes.row_busAddress",
    "RiscvRefinement.Opcodes.row_byteOffset",
    "RiscvRefinement.Opcodes.row_halfSelector",
    "RiscvRefinement.Opcodes.sb_flags",
    "RiscvRefinement.Opcodes.sb_memory_after",
    "RiscvRefinement.Opcodes.sb_refines",
    "RiscvRefinement.Opcodes.selector_cases",
    "RiscvRefinement.Opcodes.sh_flags",
    "RiscvRefinement.Opcodes.sh_memory_after",
    "RiscvRefinement.Opcodes.sh_refines",
    "RiscvRefinement.Opcodes.shift_amount_lt_four",
    "RiscvRefinement.Opcodes.shifts_imm_decodes",
    "RiscvRefinement.Opcodes.shifts_imm_destination_word",
    "RiscvRefinement.Opcodes.shifts_imm_refines",
    "RiscvRefinement.Opcodes.shifts_imm_result_word",
    "RiscvRefinement.Opcodes.shifts_imm_shamt_toNat",
    "RiscvRefinement.Opcodes.shifts_imm_source_word",
    "RiscvRefinement.Opcodes.shifts_reg_amount_toNat",
    "RiscvRefinement.Opcodes.shifts_reg_decodes",
    "RiscvRefinement.Opcodes.shifts_reg_destination_word",
    "RiscvRefinement.Opcodes.shifts_reg_refines",
    "RiscvRefinement.Opcodes.shifts_reg_result_word",
    "RiscvRefinement.Opcodes.shifts_reg_second_source_word",
    "RiscvRefinement.Opcodes.shifts_reg_source_word",
    "RiscvRefinement.Opcodes.signExtend_toNat_neg",
    "RiscvRefinement.Opcodes.signExtend_toNat_nonneg",
    "RiscvRefinement.Opcodes.sll_exists",
    "RiscvRefinement.Opcodes.sll_refines",
    "RiscvRefinement.Opcodes.sll_witness_holds",
    "RiscvRefinement.Opcodes.slli_exists",
    "RiscvRefinement.Opcodes.slli_refines",
    "RiscvRefinement.Opcodes.slli_witness_holds",
    "RiscvRefinement.Opcodes.sra_exists",
    "RiscvRefinement.Opcodes.sra_refines",
    "RiscvRefinement.Opcodes.sra_witness_holds",
    "RiscvRefinement.Opcodes.srai_exists",
    "RiscvRefinement.Opcodes.srai_refines",
    "RiscvRefinement.Opcodes.srai_witness_holds",
    "RiscvRefinement.Opcodes.srl_exists",
    "RiscvRefinement.Opcodes.srl_refines",
    "RiscvRefinement.Opcodes.srl_witness_holds",
    "RiscvRefinement.Opcodes.srli_exists",
    "RiscvRefinement.Opcodes.srli_refines",
    "RiscvRefinement.Opcodes.srli_witness_holds",
    "RiscvRefinement.Opcodes.store_memory_word",
    "RiscvRefinement.Opcodes.store_no_write",
    "RiscvRefinement.Opcodes.store_operand_value",
    "RiscvRefinement.Opcodes.store_preserves_unselected",
    "RiscvRefinement.Opcodes.store_refines",
    "RiscvRefinement.Opcodes.sw_flags",
    "RiscvRefinement.Opcodes.sw_memory_after",
    "RiscvRefinement.Opcodes.sw_refines",
    "RiscvRefinement.Opcodes.word_access_aligned",
    "RiscvRefinement.Opcodes.word_of_negative_byte",
    "RiscvRefinement.Opcodes.word_of_negative_half",
    "RiscvRefinement.Opcodes.word_of_nonnegative_byte",
    "RiscvRefinement.Opcodes.word_of_nonnegative_half",
    "RiscvRefinement.Opcodes.word_of_zero_extended_byte",
    "RiscvRefinement.Opcodes.word_of_zero_extended_half",
    "RiscvRefinement.Outcome.retirement?_rejected",
    "RiscvRefinement.Outcome.retirement?_retired",
    "RiscvRefinement.PreState.x0IsZero",
    "RiscvRefinement.Sail.Reviewed.arithmetic_and_logical_right_shifts_differ",
    "RiscvRefinement.Sail.Reviewed.executeDiv_overflow",
    "RiscvRefinement.Sail.Reviewed.executeDiv_zero_divisor",
    "RiscvRefinement.Sail.Reviewed.executeDivision_next_pc",
    "RiscvRefinement.Sail.Reviewed.executeDivision_no_memory",
    "RiscvRefinement.Sail.Reviewed.executeDivu_zero_divisor",
    "RiscvRefinement.Sail.Reviewed.executeLoad_no_store",
    "RiscvRefinement.Sail.Reviewed.executeMulValue_eq_mul",
    "RiscvRefinement.Sail.Reviewed.executeMul_no_memory",
    "RiscvRefinement.Sail.Reviewed.executeMulh_no_memory",
    "RiscvRefinement.Sail.Reviewed.executeMulhsu_no_memory",
    "RiscvRefinement.Sail.Reviewed.executeMulhu_no_memory",
    "RiscvRefinement.Sail.Reviewed.executeRem_overflow",
    "RiscvRefinement.Sail.Reviewed.executeRem_zero_divisor",
    "RiscvRefinement.Sail.Reviewed.executeRemu_zero_divisor",
    "RiscvRefinement.Sail.Reviewed.executeStore_no_write",
    "RiscvRefinement.Sail.Reviewed.executeSw_full_overwrite",
    "RiscvRefinement.Sail.Reviewed.registerShiftAmount_toNat",
    "RiscvRefinement.Sail.Reviewed.shift_by_zero",
    "RiscvRefinement.Sail.Reviewed.shifts_advance_pc",
    "RiscvRefinement.Sail.Reviewed.shifts_have_no_memory_effect",
    "RiscvRefinement.Sail.Reviewed.shifts_to_x0_are_silent",
    "RiscvRefinement.Sail.Reviewed.storeWordPayload_word",
    "RiscvRefinement.WordBytes.eq_of_limbs",
    "RiscvRefinement.WordBytes.value_lt",
    "RiscvRefinement.WordBytes.word_append",
    "RiscvRefinement.WordBytes.word_halves",
    "RiscvRefinement.WordBytes.word_toNat",
    "RiscvRefinement.WordBytes.zero_word",
    "RiscvRefinement.architecturalValue_zero",
    "RiscvRefinement.architecturalWrite_value",
    "RiscvRefinement.architecturalWrite_zero",
    "RiscvRefinement.toNat_append_arith",
)
APPROVED_LEAN_AXIOMS = frozenset(
    {
        "propext",
        "Classical.choice",
        "Quot.sound",
    }
)
CLAIM_BOUNDARY = (
    "kernel-checked normalized LUI/ADDI AIR predicate to reviewed "
    "Sail expression capsule; serialized-M31 and generated-monad "
    "normalization theorems remain open"
)
NEGATIVE_CONTROLS = (
    "lui-free-low-limb",
    "addi-free-high-carry",
)
LIVE_SAIL_OPTIONS = (
    "sail_riscv_dir",
    "sail_bin",
    "sail_generated_file",
)
AUDIT_COMMAND = ("lake", "env", "lean", "RiscvRefinement/AxiomAudit.lean")
AUDITED_THEOREMS_BLOCK = re.compile(
    r"^AUDITED_THEOREMS = \(\n(?:    \"[^\"\\\n]+\",\n)+\)$",
    re.MULTILINE,
)
AUDITED_THEOREMS_REFRESH = (
    "refresh the pin with "
    "'python3 scripts/riscv_refinement.py audited-theorems --write' "
    "and review the diff"
)


def common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--sail-riscv-dir", type=Path)
    parser.add_argument("--sail-bin", type=Path)
    parser.add_argument("--sail-generated-file", type=Path)
    parser.add_argument(
        "--no-export-air",
        action="store_true",
        help="consume an already exported AIR directory",
    )
    parser.add_argument(
        "--air-ir-dir",
        type=Path,
        help="exact AIR directory supplied by an upstream exporter",
    )
    parser.add_argument(
        "--reuse-committed-sail-evidence",
        action="store_true",
        help=(
            "rebuild the Sail evidence from the committed manifest provenance "
            "instead of a live Sail toolchain; refuses unless every Sail input "
            "is byte-identical and the Sail artifacts are reproduced exactly"
        ),
    )


def reuses_committed_sail_evidence(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "reuse_committed_sail_evidence", False))


def evidence(args: argparse.Namespace, paths: Paths) -> sail.SailEvidence:
    if reuses_committed_sail_evidence(args):
        supplied = sorted(
            option for option in LIVE_SAIL_OPTIONS if getattr(args, option, None)
        )
        if supplied:
            raise RefinementError(
                "--reuse-committed-sail-evidence consumes no live Sail "
                "toolchain; drop "
                + ", ".join(f"--{option.replace('_', '-')}" for option in supplied)
            )
        return sail.carried_evidence(paths)
    return sail.collect_evidence(
        paths.root,
        args.sail_riscv_dir,
        args.sail_bin,
        args.sail_generated_file,
    )


def prepared_outputs(
    args: argparse.Namespace,
    paths: Paths,
) -> dict[Path, bytes]:
    if not args.no_export_air:
        render.export_air(paths)
    else:
        render.validate_air_export(paths.uniqueness_ir)
    return render.artifacts(paths, evidence(args, paths))


def generate(args: argparse.Namespace, paths: Paths) -> None:
    outputs = prepared_outputs(args, paths)
    render.write_artifacts(paths, outputs)
    print(f"generated {len(outputs)} refinement artifacts")


def check_generated(args: argparse.Namespace, paths: Paths) -> None:
    outputs = prepared_outputs(args, paths)
    render.check_artifacts(paths, outputs)
    print(f"checked {len(outputs)} byte-identical refinement artifacts")


def opcode_manifest(paths: Paths) -> tuple[str, ...]:
    source = (
        paths.root / "src" / "frontends" / "riscv" / "opcode_manifest.zig"
    ).read_text(encoding="utf-8")
    names = tuple(re.findall(r'proof\(\.[^,]+,\s*"([^"]+)"', source))
    if len(names) != FULL_OPCODE_COUNT or len(set(names)) != len(names):
        raise RefinementError(
            f"opcode manifest yielded {len(names)} unique proof entries, "
            f"expected {FULL_OPCODE_COUNT}"
        )
    return names


def coverage(paths: Paths, require_full: bool = False) -> None:
    manifest = codec.load_json(paths.manifest)
    if (
        manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("kind")
        != "stwo-riscv-refinement-generated-manifest"
        or manifest.get("tier") != "level-1-normalized-pilot"
        or manifest.get("canonical_digest") != codec.content_digest(manifest)
    ):
        raise RefinementError("generated refinement manifest identity is invalid")
    entries = manifest.get("opcodes")
    if not isinstance(entries, list) or len(entries) != len(PILOT_OPCODES):
        raise RefinementError("generated refinement opcode mapping is malformed")
    expected_theorems = {
        "lui": (
            35,
            "RiscvRefinement.Opcodes.lui_refines",
            "RiscvRefinement.NonVacuity.lui_exists",
        ),
        "addi": (
            10,
            "RiscvRefinement.Opcodes.addi_refines",
            "RiscvRefinement.NonVacuity.addi_exists",
        ),
    }
    covered_names: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "air_digest",
            "coverage_kind",
            "id",
            "mnemonic",
            "non_vacuity_theorem",
            "refinement_theorem",
        }:
            raise RefinementError("generated refinement opcode entry drifted")
        mnemonic = entry["mnemonic"]
        if not isinstance(mnemonic, str) or mnemonic not in expected_theorems:
            raise RefinementError("generated refinement opcode name drifted")
        opcode_id, theorem, non_vacuity = expected_theorems[mnemonic]
        if (
            entry["id"] != opcode_id
            or entry["coverage_kind"] != "normalized-predicate"
            or entry["refinement_theorem"] != theorem
            or entry["non_vacuity_theorem"] != non_vacuity
            or not isinstance(entry["air_digest"], str)
            or len(entry["air_digest"]) != 64
        ):
            raise RefinementError(
                f"generated refinement mapping for {mnemonic} drifted"
            )
        covered_names.append(mnemonic)
    covered = tuple(covered_names)
    available = opcode_manifest(paths)
    if covered != PILOT_OPCODES:
        raise RefinementError(
            f"pilot coverage is {covered!r}, expected {PILOT_OPCODES!r}"
        )
    unknown = sorted(set(covered) - set(available))
    if unknown:
        raise RefinementError(f"proof coverage names unknown opcodes: {unknown}")
    if require_full and set(covered) != set(available):
        missing = sorted(set(available) - set(covered))
        raise RefinementError(
            "full refinement coverage is incomplete: " + ", ".join(missing)
        )
    print(
        f"refinement coverage: {len(covered)}/{len(available)} opcodes "
        f"({', '.join(covered)}); tier=level-1-normalized-pilot"
    )


def negative_controls(paths: Paths) -> None:
    results = negative.run(paths.uniqueness_ir)
    print(
        "negative controls: "
        + ", ".join(f"{item['name']}={item['status']}" for item in results)
    )


def _run(argv: list[str], cwd: Path, timeout: int = 600) -> str:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        output = exc.stdout.strip() if isinstance(exc, subprocess.CalledProcessError) else ""
        if len(output) > 8000:
            output = "... " + output[-8000:]
        raise RefinementError(
            f"command failed: {' '.join(argv)}" + (f"\n{output}" if output else "")
        ) from exc
    return completed.stdout


def _scan_forbidden_proof_terms(paths: Paths) -> None:
    forbidden = re.compile(r"\b(sorry|admit|axiom|unsafe|native_decide)\b")
    errors: list[str] = []
    sources = [
        paths.formal / "RiscvRefinement.lean",
        *sorted((paths.formal / "RiscvRefinement").rglob("*.lean")),
    ]
    for source in sources:
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("--", 1)[0]
            if forbidden.search(code):
                errors.append(f"{source.relative_to(paths.root)}:{number}")
    if errors:
        raise RefinementError(
            "forbidden proof escape appears at " + ", ".join(errors)
        )


def _parse_audit_records(output: str) -> dict[str, list[str]]:
    """Read the Lean audit transcript without deciding which theorems belong."""
    theorem_pattern = re.compile(
        r"^REFINEMENT_THEOREM (?P<theorem>RiscvRefinement\.[^\s]+)$"
    )
    axiom_pattern = re.compile(
        r"^REFINEMENT_AXIOM "
        r"(?P<theorem>RiscvRefinement\.[^\s]+) "
        r"(?P<axiom>[^\s]+)$"
    )
    report: dict[str, list[str]] = {}
    for line in output.splitlines():
        stripped = line.strip()
        match = theorem_pattern.fullmatch(stripped)
        if match is not None:
            theorem = match.group("theorem")
            if theorem in report:
                raise RefinementError(
                    f"axiom audit repeated theorem record {theorem}"
                )
            report[theorem] = []
            continue
        if stripped.startswith("REFINEMENT_THEOREM"):
            raise RefinementError(
                f"axiom audit emitted a malformed theorem record: {stripped}"
            )
        match = axiom_pattern.fullmatch(stripped)
        if match is not None:
            theorem = match.group("theorem")
            axiom = match.group("axiom")
            if theorem not in report:
                raise RefinementError(
                    f"axiom audit reported an undeclared theorem {theorem}"
                )
            if axiom in report[theorem]:
                raise RefinementError(
                    f"axiom audit repeated axiom {axiom} for {theorem}"
                )
            report[theorem].append(axiom)
            continue
        if stripped.startswith("REFINEMENT_AXIOM"):
            raise RefinementError(
                f"axiom audit emitted a malformed axiom record: {stripped}"
            )
    return report


def _audit_axioms(output: str) -> dict[str, list[str]]:
    report = _parse_audit_records(output)
    missing = sorted(set(AUDITED_THEOREMS) - set(report))
    extra = sorted(set(report) - set(AUDITED_THEOREMS))
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unexpected " + ", ".join(extra))
        raise RefinementError(
            "axiom audit declaration coverage drifted: "
            + "; ".join(details)
            + f"; {AUDITED_THEOREMS_REFRESH}"
        )
    unexpected = {
        axiom
        for axioms in report.values()
        for axiom in axioms
        if axiom not in APPROVED_LEAN_AXIOMS
    }
    if unexpected:
        raise RefinementError(
            "exported theorem has unapproved axioms: "
            + ", ".join(sorted(unexpected))
        )
    return {
        theorem: sorted(report[theorem])
        for theorem in sorted(report)
    }


def _render_audited_theorems(theorems: tuple[str, ...]) -> str:
    if not theorems:
        raise RefinementError("the axiom audit reported no refinement theorems")
    unquotable = sorted(
        theorem
        for theorem in theorems
        if not theorem or set(theorem) & set('"\\\n')
    )
    if unquotable:
        raise RefinementError(
            "audited theorem name cannot be pinned as a source literal: "
            + ", ".join(unquotable)
        )
    body = "".join(f'    "{theorem}",\n' for theorem in theorems)
    return f"AUDITED_THEOREMS = (\n{body})"


def _rewrite_audited_theorems(
    source: Path,
    theorems: tuple[str, ...],
) -> None:
    """Repin the audited theorem list in source, keeping it a reviewable diff."""
    text = source.read_text(encoding="utf-8")
    replacement = _render_audited_theorems(theorems)
    updated, count = AUDITED_THEOREMS_BLOCK.subn(
        lambda _: replacement,
        text,
        count=1,
    )
    if count != 1:
        raise RefinementError(
            f"{source}: the AUDITED_THEOREMS pin is not in its expected shape"
        )
    codec.atomic_write(source, updated.encode("utf-8"))


def _live_audited_theorems(
    args: argparse.Namespace,
    paths: Paths,
) -> tuple[str, ...]:
    if args.audit_output is not None:
        try:
            output = args.audit_output.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise RefinementError(
                f"{args.audit_output}: unreadable axiom audit transcript"
            ) from exc
    else:
        _run(["lake", "build"], paths.formal)
        output = _run(list(AUDIT_COMMAND), paths.formal)
    return tuple(sorted(_parse_audit_records(output)))


def audited_theorems(args: argparse.Namespace, paths: Paths) -> None:
    """Refresh or check the pinned theorem set; never relax the equality gate."""
    live = _live_audited_theorems(args, paths)
    pinned = tuple(AUDITED_THEOREMS)
    missing = sorted(set(pinned) - set(live))
    extra = sorted(set(live) - set(pinned))
    if not args.write:
        if not missing and not extra:
            print(f"audited theorems pinned exactly: {len(live)} theorems")
            return
        details: list[str] = []
        if extra:
            details.append("unpinned " + ", ".join(extra))
        if missing:
            details.append("retired " + ", ".join(missing))
        raise RefinementError(
            "pinned audited theorem set differs from the live Lean environment: "
            + "; ".join(details)
            + f"; {AUDITED_THEOREMS_REFRESH}"
        )
    source = args.pin_file or (paths.root / "scripts" / "riscv_refinement.py")
    _rewrite_audited_theorems(source, live)
    print(
        f"repinned {len(live)} audited theorems in "
        f"{source} (+{len(extra)}, -{len(missing)}); review the diff"
    )


@dataclass(frozen=True)
class Verification:
    theorem_axioms: dict[str, list[str]]


def verify(args: argparse.Namespace, paths: Paths) -> Verification:
    check_generated(args, paths)
    coverage(paths)
    negative_controls(paths)
    _scan_forbidden_proof_terms(paths)
    _run(
        [
            sys.executable,
            "-m",
            "unittest",
            "scripts.tests.test_riscv_refinement",
        ],
        paths.root,
    )
    _run(["lake", "build"], paths.formal)
    axiom_report = _audit_axioms(_run(list(AUDIT_COMMAND), paths.formal))
    print(
        "refinement pilot verified: fresh artifacts, 2/46 coverage, "
        "negative controls, unit tests, Lean build, and axiom audit"
    )
    return Verification(theorem_axioms=axiom_report)


def _tool(
    name: str,
    version_argv: list[str],
    cwd: Path,
) -> dict[str, str]:
    found = shutil.which(name)
    if found is None:
        raise RefinementError(f"required tool {name!r} is not on PATH")
    binary = Path(found).resolve()
    version = _run([str(binary), *version_argv], cwd).strip().splitlines()[0]
    return {
        "sha256": codec.sha256_file(binary),
        "version": version,
    }


def _toolchain(paths: Paths) -> dict[str, dict[str, str]]:
    python = Path(sys.executable).resolve()
    lean_path = Path(
        _run(["lake", "env", "which", "lean"], paths.formal).strip()
    ).resolve()
    if not lean_path.is_file():
        raise RefinementError("pinned Lean executable could not be resolved")
    return {
        "python": {
            "sha256": codec.sha256_file(python),
            "version": sys.version.split()[0],
        },
        "zig": _tool("zig", ["version"], paths.root),
        "lake": _tool("lake", ["--version"], paths.formal),
        "lean": {
            "sha256": codec.sha256_file(lean_path),
            "version": _run(
                [str(lean_path), "--version"],
                paths.formal,
            ).strip().splitlines()[0],
        },
    }


def _repository_state(paths: Paths) -> tuple[str, list[str]]:
    revision = _run(["git", "rev-parse", "HEAD"], paths.root).strip()
    status = _run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        paths.root,
    )
    receipt_path = paths.receipt.relative_to(paths.root).as_posix()
    dirty_paths = sorted(
        line[3:]
        for line in status.splitlines()
        if line and line[3:] != receipt_path
    )
    return revision, dirty_paths


def receipt(args: argparse.Namespace, paths: Paths) -> None:
    if args.no_export_air:
        raise RefinementError(
            "release receipts require a fresh production AIR export; "
            "--no-export-air is forbidden"
        )
    if reuses_committed_sail_evidence(args):
        raise RefinementError(
            "release receipts require live Sail toolchain evidence; "
            "--reuse-committed-sail-evidence is forbidden"
        )
    verification = verify(args, paths)
    sail_evidence = evidence(args, paths)
    manifest = codec.load_json(paths.manifest)
    revision, dirty_paths = _repository_state(paths)
    if dirty_paths:
        raise RefinementError(
            "release receipt requires a clean repository; dirty paths: "
            + ", ".join(dirty_paths)
        )
    payload = {
        "schema_version": 1,
        "kind": "stwo-riscv-refinement-receipt",
        "tier": "level-1-normalized-pilot",
        "claim_boundary": CLAIM_BOUNDARY,
        "repository_revision": revision,
        "repository_dirty": bool(dirty_paths),
        "repository_dirty_paths": dirty_paths,
        "generated_manifest_digest": manifest["canonical_digest"],
        "opcodes": list(PILOT_OPCODES),
        "lean_build": "passed",
        "coverage": {
            "proved_normalized_opcodes": len(PILOT_OPCODES),
            "production_opcodes": FULL_OPCODE_COUNT,
        },
        "negative_controls": list(NEGATIVE_CONTROLS),
        "approved_lean_axioms": sorted(APPROVED_LEAN_AXIOMS),
        "theorem_axioms": verification.theorem_axioms,
        "proof_escape_scan": "passed",
        "toolchain": _toolchain(paths),
        "semantic_toolchain": sail.toolchain(sail_evidence),
    }
    payload["canonical_digest"] = codec.content_digest(payload)
    codec.atomic_write(paths.receipt, codec.pretty_bytes(payload))
    print(
        "refinement receipt: "
        f"{payload['canonical_digest']} "
        "(Level-1 LUI/ADDI, no unapproved axioms)"
    )


def _receipt_revision_matches(paths: Paths, revision: str) -> None:
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise RefinementError("refinement receipt repository revision is invalid")
    current, dirty_paths = _repository_state(paths)
    if dirty_paths:
        raise RefinementError(
            "receipt verification requires a clean repository; dirty paths: "
            + ", ".join(dirty_paths)
        )
    if current == revision:
        return
    try:
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", revision, current],
            cwd=paths.root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        unchanged = subprocess.run(
            [
                "git",
                "diff",
                "--quiet",
                revision,
                current,
                "--",
                ".",
                f":(exclude){paths.receipt.relative_to(paths.root).as_posix()}",
            ],
            cwd=paths.root,
            check=False,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RefinementError(
            "could not validate refinement receipt repository revision"
        ) from exc
    if unchanged.returncode != 0:
        raise RefinementError(
            "repository changed beyond the committed refinement receipt"
        )


def _validate_receipt_theorem_axioms(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != set(AUDITED_THEOREMS)
    ):
        raise RefinementError("refinement receipt theorem set is invalid")
    for theorem, axioms in value.items():
        if (
            not isinstance(theorem, str)
            or not isinstance(axioms, list)
            or any(not isinstance(axiom, str) for axiom in axioms)
        ):
            raise RefinementError(
                "refinement receipt theorem-axiom schema is invalid"
            )


def _validate_receipt_numeric_identity(payload: dict[str, object]) -> None:
    coverage_value = payload.get("coverage")
    expected_coverage = {
        "proved_normalized_opcodes": len(PILOT_OPCODES),
        "production_opcodes": FULL_OPCODE_COUNT,
    }
    if (
        type(payload.get("schema_version")) is not int
        or payload["schema_version"] != 1
        or not isinstance(coverage_value, dict)
        or set(coverage_value) != set(expected_coverage)
        or any(
            type(coverage_value[key]) is not int
            or coverage_value[key] != expected
            for key, expected in expected_coverage.items()
        )
    ):
        raise RefinementError(
            "refinement receipt numeric identity is invalid"
        )


def verify_receipt(args: argparse.Namespace, paths: Paths) -> None:
    if args.no_export_air:
        raise RefinementError(
            "receipt verification requires a fresh production AIR export; "
            "--no-export-air is forbidden"
        )
    if reuses_committed_sail_evidence(args):
        raise RefinementError(
            "receipt verification requires live Sail toolchain evidence; "
            "--reuse-committed-sail-evidence is forbidden"
        )
    payload = codec.load_json(paths.receipt)
    required = {
        "approved_lean_axioms",
        "canonical_digest",
        "claim_boundary",
        "coverage",
        "generated_manifest_digest",
        "kind",
        "lean_build",
        "negative_controls",
        "opcodes",
        "proof_escape_scan",
        "repository_dirty",
        "repository_dirty_paths",
        "repository_revision",
        "schema_version",
        "semantic_toolchain",
        "theorem_axioms",
        "tier",
        "toolchain",
    }
    if set(payload) != required:
        raise RefinementError("refinement receipt schema drifted")
    _validate_receipt_numeric_identity(payload)
    _validate_receipt_theorem_axioms(payload["theorem_axioms"])
    verification = verify(args, paths)
    if (
        payload["kind"] != "stwo-riscv-refinement-receipt"
        or payload["tier"] != "level-1-normalized-pilot"
        or payload["claim_boundary"] != CLAIM_BOUNDARY
        or payload["canonical_digest"] != codec.content_digest(payload)
        or payload["opcodes"] != list(PILOT_OPCODES)
        or payload["negative_controls"] != list(NEGATIVE_CONTROLS)
        or payload["lean_build"] != "passed"
        or payload["proof_escape_scan"] != "passed"
        or payload["repository_dirty"] is not False
        or payload["repository_dirty_paths"] != []
        or payload["approved_lean_axioms"] != sorted(APPROVED_LEAN_AXIOMS)
        or payload["theorem_axioms"] != verification.theorem_axioms
    ):
        raise RefinementError("refinement receipt identity or theorem set is invalid")
    manifest = codec.load_json(paths.manifest)
    render.validate_committed_manifest(paths, manifest)
    coverage(paths)
    if (
        payload["generated_manifest_digest"] != manifest["canonical_digest"]
        or manifest.get("sail") != sail.provenance(evidence(args, paths))
    ):
        raise RefinementError("refinement receipt does not bind the current manifest")
    if payload["toolchain"] != _toolchain(paths):
        raise RefinementError(
            "refinement receipt does not bind the current proof toolchain"
        )
    if payload["semantic_toolchain"] != sail.toolchain(evidence(args, paths)):
        raise RefinementError(
            "refinement receipt does not bind the current Sail toolchain"
        )
    _receipt_revision_matches(paths, payload["repository_revision"])
    unexpected = {
        axiom
        for axioms in payload["theorem_axioms"].values()
        for axiom in axioms
        if axiom not in APPROVED_LEAN_AXIOMS
    }
    if unexpected:
        raise RefinementError(
            "receipt contains unapproved axioms: " + ", ".join(sorted(unexpected))
        )
    print(f"refinement receipt verified: {payload['canonical_digest']}")


def prepare_sail(args: argparse.Namespace, paths: Paths) -> None:
    prepared = sail.prepare_exact_backend(
        paths.root,
        args.sail_riscv_dir,
        args.sail_bin,
        args.force,
    )
    print(
        "prepared exact RV32IM Sail theorem backend: "
        f"{prepared.generated_file_sha256}"
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("generate", "check-generated", "verify", "receipt"):
        command = commands.add_parser(name)
        common_arguments(command)
    prepare_parser = commands.add_parser("prepare-sail")
    prepare_parser.add_argument("--sail-riscv-dir", type=Path)
    prepare_parser.add_argument("--sail-bin", type=Path)
    prepare_parser.add_argument("--force", action="store_true")
    coverage_parser = commands.add_parser("coverage")
    coverage_parser.add_argument("--require-full", action="store_true")
    audited_parser = commands.add_parser("audited-theorems")
    audited_parser.add_argument(
        "--write",
        action="store_true",
        help="repin AUDITED_THEOREMS from the live Lean environment",
    )
    audited_parser.add_argument(
        "--audit-output",
        type=Path,
        help="replay a captured axiom-audit transcript instead of running Lean",
    )
    audited_parser.add_argument(
        "--pin-file",
        type=Path,
        help="source file holding the AUDITED_THEOREMS pin",
    )
    commands.add_parser("negative-controls")
    verify_receipt_parser = commands.add_parser("verify-receipt")
    common_arguments(verify_receipt_parser)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    root = repository_root()
    air_ir_dir = getattr(args, "air_ir_dir", None)
    paths = Paths(root, air_ir_dir)
    try:
        if air_ir_dir is not None and not getattr(args, "no_export_air", False):
            raise RefinementError("--air-ir-dir requires --no-export-air")
        if args.command == "generate":
            generate(args, paths)
        elif args.command == "check-generated":
            check_generated(args, paths)
        elif args.command == "coverage":
            coverage(paths, args.require_full)
        elif args.command == "audited-theorems":
            audited_theorems(args, paths)
        elif args.command == "negative-controls":
            negative_controls(paths)
        elif args.command == "prepare-sail":
            prepare_sail(args, paths)
        elif args.command == "verify":
            verify(args, paths)
        elif args.command == "receipt":
            receipt(args, paths)
        elif args.command == "verify-receipt":
            verify_receipt(args, paths)
        else:
            raise AssertionError(args.command)
    except RefinementError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
