-- REVIEWED-CAPSULE BOUNDARY. Hand-written file; not generated, and not a
-- generated-Sail theorem. The architectural conclusion this mutation control
-- certifies -- LH's high-half selection -- is stated against the reviewed
-- normalized capsule RiscvRefinement/Sail/Reviewed/LoadStore.lean, which is
-- hand-written with no generator, no digest, and no derivation from any Sail
-- artifact (see its header). Nothing in this file is publication-level for
-- the architectural side.

import RiscvRefinement.Air.Family.LoadStore
import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.LoadStore

/-!
# Load-bearing mutation control for `LH`

Issue #137 names "wrong high-half selection" as a required publication mutation
for the memory stress gate. This file is that control.

`LoadStoreHoldsWithoutHalfLoadHigh` is `LoadStoreHolds` with exactly one field
deleted: `halfLoadHigh`, the constraint pinning the loaded halfword to the high
half of the aligned word when `shift_id = 5`. Everything else is copied
verbatim, so the counterexample is unambiguous about which deletion admits it.

The witness is the negative-high-half row with its result replaced by the
sign-extension of the *low* half. Every surviving constraint still holds --
`halfLoadLow` is gated on `shift_id = 1` and is vacuous here, the sign mask and
the sign witness are consistent with the low half's clear top bit, and the
destination still mirrors `result` -- so the row is admitted by the weakened
system while retiring the wrong halfword.
-/

namespace RiscvRefinement.Opcodes

open RiscvRefinement
open RiscvRefinement.Air.Family
open RiscvRefinement.Mutation
open RiscvRefinement.Opcodes.NonVacuity

structure LoadStoreHoldsWithoutHalfLoadHigh (row : LoadStoreRow) : Prop where
  /-- The instruction clock of a placed row. -/
  clockPositive : 0 < row.clock
  /-- C00 and C70: `active * (active - 1) = 0` together with the placement
  residual `active - 1 = 0`, so exactly one opcode flag is set. -/
  selectorSum : row.selectorSum = 1
  /-- C10: `(1 - is_signed) * src_msb = 0`. -/
  signWitnessCanonical : row.isSigned = false → row.srcMsb = false
  /-- C18: `opcode_b * (1 - marker_sum) = 0`. -/
  byteMarkerSum : row.isByte = true → row.markerSum = 1
  /-- C19: `opcode_h * (2 - marker_sum) = 0`. -/
  halfMarkerSum : row.isHalf = true → row.markerSum = 2
  /-- C20: `opcode_h * (1 - shift_id) * (5 - shift_id) = 0`. -/
  halfShiftId : row.isHalf = true → row.shiftId = 1 ∨ row.shiftId = 5
  /-- C15, byte branch: `shift_amount = opcode_b * shift_id`. -/
  byteShiftAmount : row.isByte = true → row.shiftAmount = row.shiftId
  /-- C15, halfword branch: `shift_amount = opcode_h * (shift_id - 1) / 2`.
  C20 pins `shift_id ∈ {1, 5}`, so over the canonical representatives this is
  exactly `2 * shift_amount + 1 = shift_id`. -/
  halfShiftAmount : row.isHalf = true → 2 * row.shiftAmount + 1 = row.shiftId
  /-- C15, word branch: neither `opcode_b` nor `opcode_h` fires. -/
  wordShiftAmount : row.isWord = true → row.shiftAmount = 0
  /-- L06: the aligned word address divided by four is a 20-bit value, so the
  modelled address space is the aligned 4 MiB region `[0, 2^22)`. -/
  alignedQuarterRange : row.alignedQuarter < 2 ^ 20
  /-- C16 and C17 jointly: whichever of the two address selectors carries the
  memory address equals `compose(rs1_next) + imm_felt - shift_amount` in the
  base field, and L06 pins that selector to `4 * aligned_quarter`. The right
  hand side is below `2^22 + 4`, hence already canonical. -/
  memoryAddress :
    (row.rs1Next.value + row.immFelt) % m31Modulus =
      row.alignedAddress + row.shiftAmount
  /-- `imm_felt` is a base-field element. -/
  immFeltRange : row.immFelt < m31Modulus
  /-- L07, first component: `rs1_next_0` is a byte (typing) and, second
  component, `rs1_next_3` is a seven-bit value. -/
  baseHighLimbRange : row.rs1Next.limb3.toNat < 128
  baseHighLimbZero : row.rs1Next.limb3 = 0
  /-- L07: the `range_check_m31` table omits the tuple `(255, 127)`, which is
  exactly what keeps `compose(rs1_next)` below the modulus. -/
  baseLimbsCanonical :
    row.rs1Next.limb0.toNat ≠ 255 ∨ row.rs1Next.limb3.toNat ≠ 127
  /-- C21-C23: `load_b * (signed_mask - result_i) = 0` for `i ∈ {1,2,3}`. -/
  byteLoadExtension :
    row.isByteLoad = true →
      row.result.limb1 = row.signMask ∧
        row.result.limb2 = row.signMask ∧
        row.result.limb3 = row.signMask
  /-- C24, C26, C28, C30: `load_b * (result_0 - src_next_i) * markers_i = 0`. -/
  byteLoadSelect :
    row.isByteLoad = true →
      (row.marker0 = true → row.result.limb0 = row.srcNext.limb0) ∧
        (row.marker1 = true → row.result.limb0 = row.srcNext.limb1) ∧
        (row.marker2 = true → row.result.limb0 = row.srcNext.limb2) ∧
        (row.marker3 = true → row.result.limb0 = row.srcNext.limb3)
  /-- C25, C27, C29, C31: `is_sb * (dst_next_i - src_next_0) * markers_i = 0`. -/
  byteStoreSelect :
    row.isSb = true →
      (row.marker0 = true → row.dstNext.limb0 = row.srcNext.limb0) ∧
        (row.marker1 = true → row.dstNext.limb1 = row.srcNext.limb0) ∧
        (row.marker2 = true → row.dstNext.limb2 = row.srcNext.limb0) ∧
        (row.marker3 = true → row.dstNext.limb3 = row.srcNext.limb0)
  /-- C32-C33: `load_h * (signed_mask - result_i) = 0` for `i ∈ {2,3}`. -/
  halfLoadExtension :
    row.isHalfLoad = true →
      row.result.limb2 = row.signMask ∧ row.result.limb3 = row.signMask
  /-- C34-C35: `load_h * ((5 - shift_id) / 4) * (result_i - src_next_i) = 0`.
  The gate is `1` exactly when `shift_id = 1`. -/
  halfLoadLow :
    row.isHalfLoad = true → row.shiftId = 1 →
      row.result.limb0 = row.srcNext.limb0 ∧
        row.result.limb1 = row.srcNext.limb1
  -- halfLoadHigh is deliberately absent: this is the mutation.
  halfStoreLow :
    row.isSh = true → row.shiftId = 1 →
      row.dstNext.limb0 = row.srcNext.limb0 ∧
        row.dstNext.limb1 = row.srcNext.limb1
  /-- C40-C41. -/
  halfStoreHigh :
    row.isSh = true → row.shiftId = 5 →
      row.dstNext.limb2 = row.srcNext.limb0 ∧
        row.dstNext.limb3 = row.srcNext.limb1
  /-- C42-C45, load half: `is_lw * (result_i - src_next_i) = 0`. -/
  wordLoad : row.isLw = true → row.result = row.srcNext
  /-- C42-C45, store half: `is_sw * (dst_next_i - src_next_i) = 0`. -/
  wordStore : row.isSw = true → row.dstNext = row.srcNext
  /-- C46-C49: the base register access is read-only. -/
  baseReadOnly : row.rs1Next = row.rs1Previous
  /-- C50-C53: the source access is read-only in both directions. For a load
  this is the memory-preservation constraint; for a store it is `rs2`. -/
  sourceReadOnly : row.srcNext = row.srcPrevious
  /-- C54-C57: `(is_sb + is_sh) * (1 - markers_i) * (dst_next_i - dst_previous_i)`
  — an unmarked byte of a partial store survives unchanged. -/
  partialStorePreserve :
    row.isSb = true ∨ row.isSh = true →
      (row.marker0 = false → row.dstNext.limb0 = row.dstPrevious.limb0) ∧
        (row.marker1 = false → row.dstNext.limb1 = row.dstPrevious.limb1) ∧
        (row.marker2 = false → row.dstNext.limb2 = row.dstPrevious.limb2) ∧
        (row.marker3 = false → row.dstNext.limb3 = row.dstPrevious.limb3)
  /-- C58-C60: `nonzero * (nonzero - 1) = 0`, `r2_idx * (1 - nonzero) = 0` and
  `r2_idx * inverse - nonzero = 0` jointly say exactly this. -/
  destinationFlag :
    row.destinationNonzero = decide (row.r2Idx ≠ zeroRegister)
  /-- C61-C64: `is_load * (dst_next_i - nonzero * result_i) = 0`. -/
  loadDestination :
    row.isLoad = true →
      row.dstNext = if row.destinationNonzero then row.result else WordBytes.zero
  /-- C65-C68: `(1 - is_load) * result_i = 0`. -/
  storeResultZero : row.isStore = true → row.result = WordBytes.zero
  /-- L14: `range_check_m31` on `(0, result_0 - 128 * src_msb)` forces the
  residual into seven bits, so `src_msb` is bit 7 of the selected byte. -/
  byteSignWitness : row.isLb = true → row.srcMsb = row.result.limb0.getLsbD 7
  /-- L15: `range_check_m31` on `(0, result_1 - 128 * src_msb)` forces the
  residual into seven bits, so `src_msb` is bit 15 of the selected halfword. -/
  halfSignWitness : row.isLh = true → row.srcMsb = row.result.limb1.getLsbD 7
  /-- L05: the base register access advances the register clock. -/
  baseClock : validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  /-- L10 for a store and L13 for a load: the `r2_idx` register access sits at
  ordinal two. -/
  operandClock :
    validPreviousClock row.operandPreviousClock (accessClock row.clock 2)
  /-- L13 for a store and L10 for a load: the memory access sits at ordinal
  three. -/
  memoryClock :
    validPreviousClock row.memoryPreviousClock (accessClock row.clock 3)
  /-- C72: `bus_value_57 = pc + 4`. -/
  nextPcResult : row.claimedNextPc = nextPc row.pc

/-- Deleting the constraint really is a deletion: every honest row still
satisfies the weakened predicate, so the control is not about a predicate
nothing satisfies. -/
theorem loadStoreHolds_weakens
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    LoadStoreHoldsWithoutHalfLoadHigh row where
  clockPositive := holds.clockPositive
  selectorSum := holds.selectorSum
  signWitnessCanonical := holds.signWitnessCanonical
  byteMarkerSum := holds.byteMarkerSum
  halfMarkerSum := holds.halfMarkerSum
  halfShiftId := holds.halfShiftId
  byteShiftAmount := holds.byteShiftAmount
  halfShiftAmount := holds.halfShiftAmount
  wordShiftAmount := holds.wordShiftAmount
  alignedQuarterRange := holds.alignedQuarterRange
  memoryAddress := holds.memoryAddress
  immFeltRange := holds.immFeltRange
  baseHighLimbRange := holds.baseHighLimbRange
  baseHighLimbZero := holds.baseHighLimbZero
  baseLimbsCanonical := holds.baseLimbsCanonical
  byteLoadExtension := holds.byteLoadExtension
  byteLoadSelect := holds.byteLoadSelect
  byteStoreSelect := holds.byteStoreSelect
  halfLoadExtension := holds.halfLoadExtension
  halfLoadLow := holds.halfLoadLow
  halfStoreLow := holds.halfStoreLow
  halfStoreHigh := holds.halfStoreHigh
  wordLoad := holds.wordLoad
  wordStore := holds.wordStore
  baseReadOnly := holds.baseReadOnly
  sourceReadOnly := holds.sourceReadOnly
  partialStorePreserve := holds.partialStorePreserve
  destinationFlag := holds.destinationFlag
  loadDestination := holds.loadDestination
  storeResultZero := holds.storeResultZero
  byteSignWitness := holds.byteSignWitness
  halfSignWitness := holds.halfSignWitness
  baseClock := holds.baseClock
  operandClock := holds.operandClock
  memoryClock := holds.memoryClock
  nextPcResult := holds.nextPcResult

/-- The negative-high-half row, but claiming the low halfword `0x2211`
sign-extended (which is nonnegative, so zero-extended) instead of the high
halfword `0x8000`. -/
def lhWrongHalfRow : LoadStoreRow :=
  { lhHighRow with
    srcMsb := false
    result := limbs 0x11 0x22 0x00 0x00
    dstNext := limbs 0x11 0x22 0x00 0x00 }

theorem lhWrongHalfRow_satisfies :
    LoadStoreHoldsWithoutHalfLoadHigh lhWrongHalfRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

/-- The architectural content of an `LH` on the high half: the retired word is
the sign extension of the high halfword of the memory word.

Row-parameterised and stated with the architectural `signExtendHalf`, so it is
neither of the two ways a mutation control goes wrong. It is not a constant --
that would make the soundness hypothesis false and the control vacuous. And it
is not a restatement of the deleted byte-level constraint `halfLoadHigh`, which
says nothing about sign extension. -/
def LhRetiresHighHalf (row : LoadStoreRow) : Prop :=
  row.isLh = true → row.shiftId = 5 →
    row.result.word = Memory.signExtendHalf row.srcNext.highHalf

/-- The sign witness really does pin bit 15 of the selected halfword. -/
theorem highHalf_signBit (bytes : WordBytes) :
    bytes.highHalf.getLsbD 15 = bytes.limb3.getLsbD 7 := by
  simp only [WordBytes.highHalf]
  bv_decide

/-- The claim is what the unweakened row predicate delivers.

Proving this rather than assuming it is what makes the control unconditional:
the soundness hypothesis is discharged here, so the load-bearing theorem does
not rest on an assumption that might be false. -/
theorem loadStoreHolds_retires_high_half
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    LhRetiresHighHalf row := by
  intro isLh high
  have half : row.isHalfLoad = true := by
    simp [LoadStoreRow.isHalfLoad, isLh]
  have signed : row.isSigned = true := by
    simp [LoadStoreRow.isSigned, isLh]
  have select := holds.halfLoadHigh half high
  have extension := holds.halfLoadExtension half
  have witness := holds.halfSignWitness isLh
  have mask :
      row.signMask =
        if row.srcMsb then BitVec.ofNat 8 255 else BitVec.ofNat 8 0 := by
    simp [LoadStoreRow.signMask, signed]
  -- bit 15 of the selected halfword is bit 7 of `result.limb1`, which the AIR
  -- sign witness pins to `src_msb`.
  have bit : row.srcNext.highHalf.getLsbD 15 = row.srcMsb := by
    rw [highHalf_signBit, ← select.2, ← witness]
  rw [WordBytes.word_halves, Memory.signExtendHalf_fill, bit,
    select.1, select.2, extension.1, extension.2, mask]
  cases row.srcMsb <;>
    simp only [Bool.false_eq_true, if_false, if_true, WordBytes.highHalf] <;>
    bv_decide

theorem lhWrongHalfRow_refutes : ¬ LhRetiresHighHalf lhWrongHalfRow := by
  intro claim
  have := claim rfl (by decide)
  revert this
  decide

/-- The published control: deleting the halfword-selection constraint admits a
row that retires the low halfword where the architecture requires the sign
extension of the high one. -/
def lhWrongHighHalf :
    MutationControl LoadStoreHoldsWithoutHalfLoadHigh LhRetiresHighHalf where
  name := "lh-wrong-high-half"
  witness := lhWrongHalfRow
  satisfies := lhWrongHalfRow_satisfies
  refutes := lhWrongHalfRow_refutes

/-- The deletion is not free. Unconditional: the soundness hypothesis is
discharged by `loadStoreHolds_retires_high_half` rather than assumed. -/
theorem lh_high_half_selection_is_load_bearing :
    ¬ (∀ row, LoadStoreHoldsWithoutHalfLoadHigh row → LoadStoreHolds row) :=
  lhWrongHighHalf.strictly_weaker LoadStoreHolds
    loadStoreHolds_retires_high_half

end RiscvRefinement.Opcodes
