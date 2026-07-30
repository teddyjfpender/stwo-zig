import RiscvRefinement.Air.Family.LoadStore
import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.LoadStore

/-!
# Load-bearing mutation controls for the stores `SB`, `SH` and `SW`

Stores are where the memory-safety content of the `load_store` family sits: a
store is the only row shape that mutates architectural memory, and the AIR is
the only thing standing between an honest masked write and a prover that
rewrites bytes it never addressed. This file is the mutation matrix for that
surface, in the `MutationControl` form of `RiscvRefinement/Mutation.lean`.

Each control is a copy of `LoadStoreHolds` with exactly **one** field deleted, a
proof that the deletion really is a weakening, a concrete store row that
satisfies everything left, and a proof that the row gets the architectural
answer wrong.

## The architectural conclusions, and why they are not vacuous

The three conclusions below (`SbCommitsByteStore`, `ShCommitsHalfStore`,
`SwCommitsWordStore`) are stated:

* **row-parameterised, against the row's own pre-state.** The right-hand side is
  `Memory.applyMask row.memoryBefore (payload row.operandBefore.word) row.mask`
  — the row's own consumed memory word, its own consumed operand register, and
  its own published byte-enable mask. No literal constant appears anywhere. A
  conclusion pinned to a constant word would be false for nearly every row,
  which would make its soundness hypothesis false and every corollary vacuous.
* **guarded on the row's own selector.** Each is gated on `isSb` / `isSh` /
  `isSw`, so an honest row of a different opcode cannot refute it and soundness
  is provable for the whole family at once.
* **not a restatement of any deleted constraint.** They are the architectural
  store semantics of `Sail/Reviewed/LoadStore.lean` (`Memory.applyMask` with the
  reviewed `storeBytePayload` / `storeHalfPayload` / `storeWordPayload`), which
  is exactly what `sb_refines`, `sh_refines` and `sw_refines` conclude. Every
  deletion below is refuted through that architectural claim, never through the
  residual it deletes.

Soundness is *proved in this file* — `sb_byte_store_sound`,
`sh_half_store_sound`, `sw_word_store_sound` derive each conclusion from the
unweakened `LoadStoreHolds` — so every `..._is_load_bearing` corollary here is
unconditional.

The one exception is `storeResultZero`, which has no honest architectural
conclusion in this transcription; see the comment on Control 5, which uses
`Mutation.strictly_weaker_of_not_original` instead and says so.

Everything lives in the `StoreMutation` sub-namespace so that these names never
collide with the load-side controls in `Opcodes/LoadStoreMutation.lean` and
`Opcodes/LoadStoreMutationExtra.lean`.
-/

namespace RiscvRefinement.Opcodes.StoreMutation

open RiscvRefinement
open RiscvRefinement.Air.Family
open RiscvRefinement.Sail.Reviewed
open RiscvRefinement.Mutation
open RiscvRefinement.Opcodes
open RiscvRefinement.Opcodes.NonVacuity

/-! ## The architectural conclusions -/

/-- The architectural post-state of an `SB`: the row's **own** consumed memory
word with the addressed byte of the row's **own** consumed operand register
committed under the row's published byte-enable mask.

This is `Sail/Reviewed/LoadStore.lean`'s store semantics, the same claim
`sb_refines` discharges. It mentions no constant and no committed post-state
column other than the one it constrains, so it can neither be vacuous nor
circular. -/
def SbCommitsByteStore (row : LoadStoreRow) : Prop :=
  row.isSb = true →
    row.memoryAfter =
      Memory.applyMask row.memoryBefore
        (storeBytePayload row.operandBefore.word) row.mask

/-- The same claim for `SH`, against the reviewed halfword payload. -/
def ShCommitsHalfStore (row : LoadStoreRow) : Prop :=
  row.isSh = true →
    row.memoryAfter =
      Memory.applyMask row.memoryBefore
        (storeHalfPayload row.operandBefore.word) row.mask

/-- The same claim for `SW`, against the reviewed word payload. -/
def SwCommitsWordStore (row : LoadStoreRow) : Prop :=
  row.isSw = true →
    row.memoryAfter =
      Memory.applyMask row.memoryBefore
        (storeWordPayload row.operandBefore.word) row.mask

/-! ### Soundness, discharged here rather than assumed

Each proof is the row-internal form of `sb_memory_after` / `sh_memory_after` /
`sw_memory_after`: the environment's `memoryWord` and `operandValue` are
replaced by the row's own `memoryBefore` and `operandBefore`, which
`memoryBefore_store`, `operandBefore_store` and C50-C53 identify with them. -/

/-- `SB` soundness: C25-C31 (placement) with C54-C57 (preservation), C18/C15
(the marker/offset agreement) and C50-C53 (the operand register is read-only)
give exactly the reviewed masked write. -/
theorem sb_byte_store_sound
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    SbCommitsByteStore row := by
  intro selector
  have isStore : row.isStore = true := by simp [LoadStoreRow.isStore, selector]
  have isByte : row.isByte = true := by simp [LoadStoreRow.isByte, selector]
  have sum := holds.byteMarkerSum isByte
  have amount := holds.byteShiftAmount isByte
  obtain ⟨s0, s1, s2, s3⟩ := holds.byteStoreSelect selector
  obtain ⟨p0, p1, p2, p3⟩ := holds.partialStorePreserve (Or.inl selector)
  simp only [LoadStoreRow.markerSum] at sum
  simp only [LoadStoreRow.shiftId] at amount
  rw [memoryAfter_store row isStore, memoryBefore_store row isStore,
    operandBefore_store row isStore, ← holds.sourceReadOnly,
    mask_sb row selector]
  simp only [LoadStoreRow.byteOffset]
  rcases byte_marker_cases row.marker0 row.marker1 row.marker2 row.marker3 sum
    with ⟨m0, m1, m2, m3, sid⟩ | ⟨m0, m1, m2, m3, sid⟩ |
      ⟨m0, m1, m2, m3, sid⟩ | ⟨m0, m1, m2, m3, sid⟩
  · have offset : row.shiftAmount = 0 := by omega
    rw [offset]
    refine WordBytes.eq_of_limbs _ _ ?_ ?_ ?_ ?_ <;>
      simp [Memory.applyMask, Memory.byteMask, storeBytePayload, extract_limb0,
        s0 m0, p1 m1, p2 m2, p3 m3]
  · have offset : row.shiftAmount = 1 := by omega
    rw [offset]
    refine WordBytes.eq_of_limbs _ _ ?_ ?_ ?_ ?_ <;>
      simp [Memory.applyMask, Memory.byteMask, storeBytePayload, extract_limb0,
        s1 m1, p0 m0, p2 m2, p3 m3]
  · have offset : row.shiftAmount = 2 := by omega
    rw [offset]
    refine WordBytes.eq_of_limbs _ _ ?_ ?_ ?_ ?_ <;>
      simp [Memory.applyMask, Memory.byteMask, storeBytePayload, extract_limb0,
        s2 m2, p0 m0, p1 m1, p3 m3]
  · have offset : row.shiftAmount = 3 := by omega
    rw [offset]
    refine WordBytes.eq_of_limbs _ _ ?_ ?_ ?_ ?_ <;>
      simp [Memory.applyMask, Memory.byteMask, storeBytePayload, extract_limb0,
        s3 m3, p0 m0, p1 m1, p2 m2]

/-- `SH` soundness: C38-C41 with C54-C57, C19/C20/C15 and C50-C53. -/
theorem sh_half_store_sound
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    ShCommitsHalfStore row := by
  intro selector
  obtain ⟨_, _, _, _, _, isSb, _⟩ := sh_flags row holds selector
  have isStore : row.isStore = true := by simp [LoadStoreRow.isStore, selector]
  have isHalf : row.isHalf = true := by simp [LoadStoreRow.isHalf, selector]
  have sum := holds.halfMarkerSum isHalf
  have amount := holds.halfShiftAmount isHalf
  obtain ⟨p0, p1, p2, p3⟩ := holds.partialStorePreserve (Or.inr selector)
  simp only [LoadStoreRow.markerSum] at sum
  have identifiers := holds.halfShiftId isHalf
  simp only [LoadStoreRow.shiftId] at identifiers
  rw [memoryAfter_store row isStore, memoryBefore_store row isStore,
    operandBefore_store row isStore, ← holds.sourceReadOnly,
    mask_sh row selector isSb]
  rcases half_marker_cases row.marker0 row.marker1 row.marker2 row.marker3 sum
      identifiers with ⟨m0, m1, m2, m3⟩ | ⟨m0, m1, m2, m3⟩
  · have sid : row.shiftId = 1 := by
      simp [LoadStoreRow.shiftId, m1, m2, m3]
    obtain ⟨d0, d1⟩ := holds.halfStoreLow selector sid
    have offset : row.shiftAmount = 0 := by omega
    simp only [LoadStoreRow.halfSelector, offset, Nat.reduceDiv]
    refine WordBytes.eq_of_limbs _ _ ?_ ?_ ?_ ?_ <;>
      simp [Memory.applyMask, Memory.halfMask, storeHalfPayload, extract_limb0,
        extract_limb1, d0, d1, p2 m2, p3 m3]
  · have sid : row.shiftId = 5 := by
      simp [LoadStoreRow.shiftId, m1, m2, m3]
    obtain ⟨d2, d3⟩ := holds.halfStoreHigh selector sid
    have offset : row.shiftAmount = 2 := by omega
    simp only [LoadStoreRow.halfSelector, offset, Nat.reduceDiv]
    refine WordBytes.eq_of_limbs _ _ ?_ ?_ ?_ ?_ <;>
      simp [Memory.applyMask, Memory.halfMask, storeHalfPayload, extract_limb0,
        extract_limb1, d2, d3, p0 m0, p1 m1]

/-- `SW` soundness: C42-C45 with C50-C53. -/
theorem sw_word_store_sound
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    SwCommitsWordStore row := by
  intro selector
  obtain ⟨_, _, _, _, _, isSb, isSh⟩ := sw_flags row holds selector
  have isStore : row.isStore = true := by simp [LoadStoreRow.isStore, selector]
  rw [memoryAfter_store row isStore, memoryBefore_store row isStore,
    operandBefore_store row isStore, ← holds.sourceReadOnly,
    mask_sw row isSb isSh, Memory.applyMask_word, holds.wordStore selector]
  refine WordBytes.eq_of_limbs _ _ ?_ ?_ ?_ ?_ <;>
    simp [storeWordPayload, extract_limb0, extract_limb1, extract_limb2,
      extract_limb3]

/-! ## Control 1 — clobbered unselected bytes

*Delete `partialStorePreserve` (C54-C57); exhibit an `SB` row that overwrites
bytes outside its mask.*

This is the single most important store control in the family. C25-C31 pin only
the **marked** limb of the destination word to the operand byte; nothing else in
the AIR mentions `dst_next` on a byte store. C54-C57 are therefore the sole
reason a one-byte store is a one-byte store, and with them deleted an `SB` may
rewrite the entire aligned word — the classic partial-store escape.

Certifies `SB` (and by the shared `is_sb + is_sh` gate the same residuals carry
`SH`; the witness here is on the `SB` selector).
-/

structure StoreHoldsWithoutPartialStorePreserve (row : LoadStoreRow) : Prop where
  /-- The instruction clock of a placed row. -/
  clockPositive :
    0 < row.clock
  /-- C00 and C70: exactly one opcode flag is set. -/
  selectorSum :
    row.selectorSum = 1
  /-- C10: `(1 - is_signed) * src_msb = 0`. -/
  signWitnessCanonical :
    row.isSigned = false → row.srcMsb = false
  /-- C18: `opcode_b * (1 - marker_sum) = 0`. -/
  byteMarkerSum :
    row.isByte = true → row.markerSum = 1
  /-- C19: `opcode_h * (2 - marker_sum) = 0`. -/
  halfMarkerSum :
    row.isHalf = true → row.markerSum = 2
  /-- C20: `opcode_h * (1 - shift_id) * (5 - shift_id) = 0`. -/
  halfShiftId :
    row.isHalf = true → row.shiftId = 1 ∨ row.shiftId = 5
  /-- C15, byte branch: `shift_amount = opcode_b * shift_id`. -/
  byteShiftAmount :
    row.isByte = true → row.shiftAmount = row.shiftId
  /-- C15, halfword branch: `2 * shift_amount + 1 = shift_id`. -/
  halfShiftAmount :
    row.isHalf = true → 2 * row.shiftAmount + 1 = row.shiftId
  /-- C15, word branch: neither `opcode_b` nor `opcode_h` fires. -/
  wordShiftAmount :
    row.isWord = true → row.shiftAmount = 0
  /-- L06: the aligned word address divided by four is a 20-bit value. -/
  alignedQuarterRange :
    row.alignedQuarter < 2 ^ 20
  /-- C16 and C17 with L06: the memory address selector is
    `compose(rs1_next) + imm_felt - shift_amount`, pinned to `4 * aligned_quarter`. -/
  memoryAddress :
    (row.rs1Next.value + row.immFelt) % m31Modulus =
          row.alignedAddress + row.shiftAmount
  /-- `imm_felt` is a base-field element. -/
  immFeltRange :
    row.immFelt < m31Modulus
  /-- L07, second component: `rs1_next_3` is a seven-bit value. -/
  baseHighLimbRange :
    row.rs1Next.limb3.toNat < 128
  baseHighLimbZero :
    row.rs1Next.limb3 = 0
  /-- L07: the `range_check_m31` table omits the tuple `(255, 127)`. -/
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
  /-- C34-C35, gated on `shift_id = 1`. -/
  halfLoadLow :
    row.isHalfLoad = true → row.shiftId = 1 →
          row.result.limb0 = row.srcNext.limb0 ∧
            row.result.limb1 = row.srcNext.limb1
  /-- C36-C37, gated on `shift_id = 5`. -/
  halfLoadHigh :
    row.isHalfLoad = true → row.shiftId = 5 →
          row.result.limb0 = row.srcNext.limb2 ∧
            row.result.limb1 = row.srcNext.limb3
  /-- C38-C39: the low-half placement of an `SH`. -/
  halfStoreLow :
    row.isSh = true → row.shiftId = 1 →
          row.dstNext.limb0 = row.srcNext.limb0 ∧
            row.dstNext.limb1 = row.srcNext.limb1
  /-- C40-C41: the high-half placement of an `SH`. -/
  halfStoreHigh :
    row.isSh = true → row.shiftId = 5 →
          row.dstNext.limb2 = row.srcNext.limb0 ∧
            row.dstNext.limb3 = row.srcNext.limb1
  /-- C42-C45, load half: `is_lw * (result_i - src_next_i) = 0`. -/
  wordLoad :
    row.isLw = true → row.result = row.srcNext
  /-- C42-C45, store half: `is_sw * (dst_next_i - src_next_i) = 0`. -/
  wordStore :
    row.isSw = true → row.dstNext = row.srcNext
  /-- C46-C49: the base register access is read-only. -/
  baseReadOnly :
    row.rs1Next = row.rs1Previous
  /-- C50-C53: the source access is read-only in both directions. For a load
    this is the memory-preservation constraint; for a store it is `rs2`. -/
  sourceReadOnly :
    row.srcNext = row.srcPrevious
  -- `partialStorePreserve` is deliberately absent: this is the mutation.
  -- C54-C57: `(is_sb + is_sh) * (1 - markers_i) * (dst_next_i - dst_previous_i)`,
  -- the survival of every byte a partial store does not select.
  /-- C58-C60: the write-enable witness is exact. -/
  destinationFlag :
    row.destinationNonzero = decide (row.r2Idx ≠ zeroRegister)
  /-- C61-C64: `is_load * (dst_next_i - nonzero * result_i) = 0`. -/
  loadDestination :
    row.isLoad = true →
          row.dstNext = if row.destinationNonzero then row.result else WordBytes.zero
  /-- C65-C68: `(1 - is_load) * result_i = 0`. -/
  storeResultZero :
    row.isStore = true → row.result = WordBytes.zero
  /-- L14: `src_msb` is bit 7 of the selected byte. -/
  byteSignWitness :
    row.isLb = true → row.srcMsb = row.result.limb0.getLsbD 7
  /-- L15: `src_msb` is bit 15 of the selected halfword. -/
  halfSignWitness :
    row.isLh = true → row.srcMsb = row.result.limb1.getLsbD 7
  /-- L05: the base register access advances the register clock. -/
  baseClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  /-- L10 for a store and L13 for a load: the `r2_idx` register access sits at
    ordinal two. -/
  operandClock :
    validPreviousClock row.operandPreviousClock (accessClock row.clock 2)
  /-- L13 for a store and L10 for a load: the memory access sits at ordinal
    three. -/
  memoryClock :
    validPreviousClock row.memoryPreviousClock (accessClock row.clock 3)
  /-- C72: `bus_value_57 = pc + 4`. -/
  nextPcResult :
    row.claimedNextPc = nextPc row.pc

/-- Deleting the constraint really is a deletion: every honest row still
satisfies the weakened predicate, so the control below is not a statement
about a predicate nothing satisfies. -/
theorem storeHolds_weakens_partialStorePreserve
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    StoreHoldsWithoutPartialStorePreserve row where
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
  halfLoadHigh := holds.halfLoadHigh
  halfStoreLow := holds.halfStoreLow
  halfStoreHigh := holds.halfStoreHigh
  wordLoad := holds.wordLoad
  wordStore := holds.wordStore
  baseReadOnly := holds.baseReadOnly
  sourceReadOnly := holds.sourceReadOnly
  destinationFlag := holds.destinationFlag
  loadDestination := holds.loadDestination
  storeResultZero := holds.storeResultZero
  byteSignWitness := holds.byteSignWitness
  halfSignWitness := holds.halfSignWitness
  baseClock := holds.baseClock
  operandClock := holds.operandClock
  memoryClock := holds.memoryClock
  nextPcResult := holds.nextPcResult

/-- `SB x7, 5(x5)` storing `0xab` at byte offset 1 of the live word
`0x04030201`. The marked limb still receives the operand byte, so C25-C31 hold;
with the preservation residuals gone the other three limbs are zeroed. -/
def sbClobberedBytesRow : LoadStoreRow :=
  { sbRow with dstNext := limbs 0x00 0xab 0x00 0x00 }

theorem sbClobberedBytesRow_satisfies :
    StoreHoldsWithoutPartialStorePreserve sbClobberedBytesRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

theorem sbClobberedBytesRow_refutes :
    ¬ SbCommitsByteStore sbClobberedBytesRow := by
  intro claim
  have := claim rfl
  revert this
  decide

/-- The published control. -/
def sbClobbersUnselectedBytes :
    MutationControl StoreHoldsWithoutPartialStorePreserve SbCommitsByteStore where
  name := "sb-clobbered-unselected-bytes"
  witness := sbClobberedBytesRow
  satisfies := sbClobberedBytesRow_satisfies
  refutes := sbClobberedBytesRow_refutes

/-- The deletion is not free. Unconditional: the soundness hypothesis is
discharged by `sb_byte_store_sound` rather than assumed. -/
theorem sb_partial_store_preserve_is_load_bearing :
    ¬ (∀ row, StoreHoldsWithoutPartialStorePreserve row → LoadStoreHolds row) :=
  sbClobbersUnselectedBytes.strictly_weaker LoadStoreHolds sb_byte_store_sound

/-! ## Control 2 — wrong byte placement

*Delete `byteStoreSelect` (C25, C27, C29, C31); exhibit an `SB` row writing its
byte at the wrong offset.*

C25-C31 are the only residuals that put the operand byte **where the address
says**. C54-C57 survive, so the three unmarked limbs are still pinned to the
pre-state word; but the marked limb is now free, and the byte may show up
somewhere else in the word entirely. The witness below addresses byte offset 1
and leaves offset 1 holding its stale value while the operand byte `0xab` sits
at offset 2.

Certifies `SB`.
-/

structure StoreHoldsWithoutByteStoreSelect (row : LoadStoreRow) : Prop where
  /-- The instruction clock of a placed row. -/
  clockPositive :
    0 < row.clock
  /-- C00 and C70: exactly one opcode flag is set. -/
  selectorSum :
    row.selectorSum = 1
  /-- C10: `(1 - is_signed) * src_msb = 0`. -/
  signWitnessCanonical :
    row.isSigned = false → row.srcMsb = false
  /-- C18: `opcode_b * (1 - marker_sum) = 0`. -/
  byteMarkerSum :
    row.isByte = true → row.markerSum = 1
  /-- C19: `opcode_h * (2 - marker_sum) = 0`. -/
  halfMarkerSum :
    row.isHalf = true → row.markerSum = 2
  /-- C20: `opcode_h * (1 - shift_id) * (5 - shift_id) = 0`. -/
  halfShiftId :
    row.isHalf = true → row.shiftId = 1 ∨ row.shiftId = 5
  /-- C15, byte branch: `shift_amount = opcode_b * shift_id`. -/
  byteShiftAmount :
    row.isByte = true → row.shiftAmount = row.shiftId
  /-- C15, halfword branch: `2 * shift_amount + 1 = shift_id`. -/
  halfShiftAmount :
    row.isHalf = true → 2 * row.shiftAmount + 1 = row.shiftId
  /-- C15, word branch: neither `opcode_b` nor `opcode_h` fires. -/
  wordShiftAmount :
    row.isWord = true → row.shiftAmount = 0
  /-- L06: the aligned word address divided by four is a 20-bit value. -/
  alignedQuarterRange :
    row.alignedQuarter < 2 ^ 20
  /-- C16 and C17 with L06: the memory address selector is
    `compose(rs1_next) + imm_felt - shift_amount`, pinned to `4 * aligned_quarter`. -/
  memoryAddress :
    (row.rs1Next.value + row.immFelt) % m31Modulus =
          row.alignedAddress + row.shiftAmount
  /-- `imm_felt` is a base-field element. -/
  immFeltRange :
    row.immFelt < m31Modulus
  /-- L07, second component: `rs1_next_3` is a seven-bit value. -/
  baseHighLimbRange :
    row.rs1Next.limb3.toNat < 128
  baseHighLimbZero :
    row.rs1Next.limb3 = 0
  /-- L07: the `range_check_m31` table omits the tuple `(255, 127)`. -/
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
  -- `byteStoreSelect` is deliberately absent: this is the mutation.
  -- C25, C27, C29, C31: `is_sb * (dst_next_i - src_next_0) * markers_i = 0`,
  -- the byte-selection residuals of a byte store.
  /-- C32-C33: `load_h * (signed_mask - result_i) = 0` for `i ∈ {2,3}`. -/
  halfLoadExtension :
    row.isHalfLoad = true →
          row.result.limb2 = row.signMask ∧ row.result.limb3 = row.signMask
  /-- C34-C35, gated on `shift_id = 1`. -/
  halfLoadLow :
    row.isHalfLoad = true → row.shiftId = 1 →
          row.result.limb0 = row.srcNext.limb0 ∧
            row.result.limb1 = row.srcNext.limb1
  /-- C36-C37, gated on `shift_id = 5`. -/
  halfLoadHigh :
    row.isHalfLoad = true → row.shiftId = 5 →
          row.result.limb0 = row.srcNext.limb2 ∧
            row.result.limb1 = row.srcNext.limb3
  /-- C38-C39: the low-half placement of an `SH`. -/
  halfStoreLow :
    row.isSh = true → row.shiftId = 1 →
          row.dstNext.limb0 = row.srcNext.limb0 ∧
            row.dstNext.limb1 = row.srcNext.limb1
  /-- C40-C41: the high-half placement of an `SH`. -/
  halfStoreHigh :
    row.isSh = true → row.shiftId = 5 →
          row.dstNext.limb2 = row.srcNext.limb0 ∧
            row.dstNext.limb3 = row.srcNext.limb1
  /-- C42-C45, load half: `is_lw * (result_i - src_next_i) = 0`. -/
  wordLoad :
    row.isLw = true → row.result = row.srcNext
  /-- C42-C45, store half: `is_sw * (dst_next_i - src_next_i) = 0`. -/
  wordStore :
    row.isSw = true → row.dstNext = row.srcNext
  /-- C46-C49: the base register access is read-only. -/
  baseReadOnly :
    row.rs1Next = row.rs1Previous
  /-- C50-C53: the source access is read-only in both directions. For a load
    this is the memory-preservation constraint; for a store it is `rs2`. -/
  sourceReadOnly :
    row.srcNext = row.srcPrevious
  /-- C54-C57: `(is_sb + is_sh) * (1 - markers_i) * (dst_next_i - dst_previous_i)`
    — an unmarked byte of a partial store survives unchanged. -/
  partialStorePreserve :
    row.isSb = true ∨ row.isSh = true →
          (row.marker0 = false → row.dstNext.limb0 = row.dstPrevious.limb0) ∧
            (row.marker1 = false → row.dstNext.limb1 = row.dstPrevious.limb1) ∧
            (row.marker2 = false → row.dstNext.limb2 = row.dstPrevious.limb2) ∧
            (row.marker3 = false → row.dstNext.limb3 = row.dstPrevious.limb3)
  /-- C58-C60: the write-enable witness is exact. -/
  destinationFlag :
    row.destinationNonzero = decide (row.r2Idx ≠ zeroRegister)
  /-- C61-C64: `is_load * (dst_next_i - nonzero * result_i) = 0`. -/
  loadDestination :
    row.isLoad = true →
          row.dstNext = if row.destinationNonzero then row.result else WordBytes.zero
  /-- C65-C68: `(1 - is_load) * result_i = 0`. -/
  storeResultZero :
    row.isStore = true → row.result = WordBytes.zero
  /-- L14: `src_msb` is bit 7 of the selected byte. -/
  byteSignWitness :
    row.isLb = true → row.srcMsb = row.result.limb0.getLsbD 7
  /-- L15: `src_msb` is bit 15 of the selected halfword. -/
  halfSignWitness :
    row.isLh = true → row.srcMsb = row.result.limb1.getLsbD 7
  /-- L05: the base register access advances the register clock. -/
  baseClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  /-- L10 for a store and L13 for a load: the `r2_idx` register access sits at
    ordinal two. -/
  operandClock :
    validPreviousClock row.operandPreviousClock (accessClock row.clock 2)
  /-- L13 for a store and L10 for a load: the memory access sits at ordinal
    three. -/
  memoryClock :
    validPreviousClock row.memoryPreviousClock (accessClock row.clock 3)
  /-- C72: `bus_value_57 = pc + 4`. -/
  nextPcResult :
    row.claimedNextPc = nextPc row.pc

/-- Deleting the constraint really is a deletion: every honest row still
satisfies the weakened predicate, so the control below is not a statement
about a predicate nothing satisfies. -/
theorem storeHolds_weakens_byteStoreSelect
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    StoreHoldsWithoutByteStoreSelect row where
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
  halfLoadExtension := holds.halfLoadExtension
  halfLoadLow := holds.halfLoadLow
  halfLoadHigh := holds.halfLoadHigh
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

/-- `SB x7, 5(x5)` again, addressing byte offset 1. The pre-state word already
carries `0xab` at offset 2, and the row retires it unchanged: the operand byte
appears in the word, but one limb away from the address it was written to. The
three unmarked limbs still match the pre-state, so C54-C57 hold. -/
def sbMisplacedByteRow : LoadStoreRow :=
  { sbRow with
    dstPrevious := limbs 0x01 0x02 0xab 0x04
    dstNext := limbs 0x01 0x02 0xab 0x04 }

theorem sbMisplacedByteRow_satisfies :
    StoreHoldsWithoutByteStoreSelect sbMisplacedByteRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

theorem sbMisplacedByteRow_refutes :
    ¬ SbCommitsByteStore sbMisplacedByteRow := by
  intro claim
  have := claim rfl
  revert this
  decide

/-- The published control. -/
def sbWrongBytePlacement :
    MutationControl StoreHoldsWithoutByteStoreSelect SbCommitsByteStore where
  name := "sb-wrong-byte-placement"
  witness := sbMisplacedByteRow
  satisfies := sbMisplacedByteRow_satisfies
  refutes := sbMisplacedByteRow_refutes

/-- The deletion is not free. Unconditional. -/
theorem sb_byte_store_select_is_load_bearing :
    ¬ (∀ row, StoreHoldsWithoutByteStoreSelect row → LoadStoreHolds row) :=
  sbWrongBytePlacement.strictly_weaker LoadStoreHolds sb_byte_store_sound

/-! ## Control 3 — wrong half placement

*Delete `halfStoreHigh` (C40-C41); exhibit an `SH` row writing the halfword at
the wrong offset.*

C40-C41 are the high-half placement of a halfword store. `halfStoreLow`
(C38-C39) survives but is gated on `shift_id = 1` and so is vacuous on a
high-half row, and C54-C57 pin only the *unmarked* low pair. Deleting C40-C41
therefore frees the addressed high half completely: the witness stores the
halfword `0x1234` into the low half of the word and leaves the addressed high
half holding its stale content.

Certifies `SH`.
-/

structure StoreHoldsWithoutHalfStoreHigh (row : LoadStoreRow) : Prop where
  /-- The instruction clock of a placed row. -/
  clockPositive :
    0 < row.clock
  /-- C00 and C70: exactly one opcode flag is set. -/
  selectorSum :
    row.selectorSum = 1
  /-- C10: `(1 - is_signed) * src_msb = 0`. -/
  signWitnessCanonical :
    row.isSigned = false → row.srcMsb = false
  /-- C18: `opcode_b * (1 - marker_sum) = 0`. -/
  byteMarkerSum :
    row.isByte = true → row.markerSum = 1
  /-- C19: `opcode_h * (2 - marker_sum) = 0`. -/
  halfMarkerSum :
    row.isHalf = true → row.markerSum = 2
  /-- C20: `opcode_h * (1 - shift_id) * (5 - shift_id) = 0`. -/
  halfShiftId :
    row.isHalf = true → row.shiftId = 1 ∨ row.shiftId = 5
  /-- C15, byte branch: `shift_amount = opcode_b * shift_id`. -/
  byteShiftAmount :
    row.isByte = true → row.shiftAmount = row.shiftId
  /-- C15, halfword branch: `2 * shift_amount + 1 = shift_id`. -/
  halfShiftAmount :
    row.isHalf = true → 2 * row.shiftAmount + 1 = row.shiftId
  /-- C15, word branch: neither `opcode_b` nor `opcode_h` fires. -/
  wordShiftAmount :
    row.isWord = true → row.shiftAmount = 0
  /-- L06: the aligned word address divided by four is a 20-bit value. -/
  alignedQuarterRange :
    row.alignedQuarter < 2 ^ 20
  /-- C16 and C17 with L06: the memory address selector is
    `compose(rs1_next) + imm_felt - shift_amount`, pinned to `4 * aligned_quarter`. -/
  memoryAddress :
    (row.rs1Next.value + row.immFelt) % m31Modulus =
          row.alignedAddress + row.shiftAmount
  /-- `imm_felt` is a base-field element. -/
  immFeltRange :
    row.immFelt < m31Modulus
  /-- L07, second component: `rs1_next_3` is a seven-bit value. -/
  baseHighLimbRange :
    row.rs1Next.limb3.toNat < 128
  baseHighLimbZero :
    row.rs1Next.limb3 = 0
  /-- L07: the `range_check_m31` table omits the tuple `(255, 127)`. -/
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
  /-- C34-C35, gated on `shift_id = 1`. -/
  halfLoadLow :
    row.isHalfLoad = true → row.shiftId = 1 →
          row.result.limb0 = row.srcNext.limb0 ∧
            row.result.limb1 = row.srcNext.limb1
  /-- C36-C37, gated on `shift_id = 5`. -/
  halfLoadHigh :
    row.isHalfLoad = true → row.shiftId = 5 →
          row.result.limb0 = row.srcNext.limb2 ∧
            row.result.limb1 = row.srcNext.limb3
  /-- C38-C39: the low-half placement of an `SH`. -/
  halfStoreLow :
    row.isSh = true → row.shiftId = 1 →
          row.dstNext.limb0 = row.srcNext.limb0 ∧
            row.dstNext.limb1 = row.srcNext.limb1
  -- `halfStoreHigh` is deliberately absent: this is the mutation.
  -- C40-C41: the high-half placement residuals of a halfword store.
  /-- C42-C45, load half: `is_lw * (result_i - src_next_i) = 0`. -/
  wordLoad :
    row.isLw = true → row.result = row.srcNext
  /-- C42-C45, store half: `is_sw * (dst_next_i - src_next_i) = 0`. -/
  wordStore :
    row.isSw = true → row.dstNext = row.srcNext
  /-- C46-C49: the base register access is read-only. -/
  baseReadOnly :
    row.rs1Next = row.rs1Previous
  /-- C50-C53: the source access is read-only in both directions. For a load
    this is the memory-preservation constraint; for a store it is `rs2`. -/
  sourceReadOnly :
    row.srcNext = row.srcPrevious
  /-- C54-C57: `(is_sb + is_sh) * (1 - markers_i) * (dst_next_i - dst_previous_i)`
    — an unmarked byte of a partial store survives unchanged. -/
  partialStorePreserve :
    row.isSb = true ∨ row.isSh = true →
          (row.marker0 = false → row.dstNext.limb0 = row.dstPrevious.limb0) ∧
            (row.marker1 = false → row.dstNext.limb1 = row.dstPrevious.limb1) ∧
            (row.marker2 = false → row.dstNext.limb2 = row.dstPrevious.limb2) ∧
            (row.marker3 = false → row.dstNext.limb3 = row.dstPrevious.limb3)
  /-- C58-C60: the write-enable witness is exact. -/
  destinationFlag :
    row.destinationNonzero = decide (row.r2Idx ≠ zeroRegister)
  /-- C61-C64: `is_load * (dst_next_i - nonzero * result_i) = 0`. -/
  loadDestination :
    row.isLoad = true →
          row.dstNext = if row.destinationNonzero then row.result else WordBytes.zero
  /-- C65-C68: `(1 - is_load) * result_i = 0`. -/
  storeResultZero :
    row.isStore = true → row.result = WordBytes.zero
  /-- L14: `src_msb` is bit 7 of the selected byte. -/
  byteSignWitness :
    row.isLb = true → row.srcMsb = row.result.limb0.getLsbD 7
  /-- L15: `src_msb` is bit 15 of the selected halfword. -/
  halfSignWitness :
    row.isLh = true → row.srcMsb = row.result.limb1.getLsbD 7
  /-- L05: the base register access advances the register clock. -/
  baseClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  /-- L10 for a store and L13 for a load: the `r2_idx` register access sits at
    ordinal two. -/
  operandClock :
    validPreviousClock row.operandPreviousClock (accessClock row.clock 2)
  /-- L13 for a store and L10 for a load: the memory access sits at ordinal
    three. -/
  memoryClock :
    validPreviousClock row.memoryPreviousClock (accessClock row.clock 3)
  /-- C72: `bus_value_57 = pc + 4`. -/
  nextPcResult :
    row.claimedNextPc = nextPc row.pc

/-- Deleting the constraint really is a deletion: every honest row still
satisfies the weakened predicate, so the control below is not a statement
about a predicate nothing satisfies. -/
theorem storeHolds_weakens_halfStoreHigh
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    StoreHoldsWithoutHalfStoreHigh row where
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
  halfLoadHigh := holds.halfLoadHigh
  halfStoreLow := holds.halfStoreLow
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

/-- `SH x7, 2(x5)` addressing the **high** half of the word at `0x200`. The
pre-state word already carries `0x1234` in its low half and the row retires it
unchanged, so the stored halfword lands two bytes below the address it was
written to and the addressed high half keeps its stale `0x4433`. C38-C39 are
gated on `shift_id = 1` and vacuous here; C54-C57 pin the unmarked low pair,
which the witness respects. -/
def shMisplacedHalfRow : LoadStoreRow :=
  { shRow with
    dstPrevious := limbs 0x34 0x12 0x33 0x44
    dstNext := limbs 0x34 0x12 0x33 0x44 }

theorem shMisplacedHalfRow_satisfies :
    StoreHoldsWithoutHalfStoreHigh shMisplacedHalfRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

theorem shMisplacedHalfRow_refutes :
    ¬ ShCommitsHalfStore shMisplacedHalfRow := by
  intro claim
  have := claim rfl
  revert this
  decide

/-- The published control. -/
def shWrongHalfPlacement :
    MutationControl StoreHoldsWithoutHalfStoreHigh ShCommitsHalfStore where
  name := "sh-wrong-half-placement"
  witness := shMisplacedHalfRow
  satisfies := shMisplacedHalfRow_satisfies
  refutes := shMisplacedHalfRow_refutes

/-- The deletion is not free. Unconditional. -/
theorem sh_half_store_high_is_load_bearing :
    ¬ (∀ row, StoreHoldsWithoutHalfStoreHigh row → LoadStoreHolds row) :=
  shWrongHalfPlacement.strictly_weaker LoadStoreHolds sh_half_store_sound

/-! ## Control 4 — spurious register write on a store

*Delete `sourceReadOnly` (C50-C53); exhibit a store row that also writes a
register.*

On a store the `src` access block **is** the `rs2` register cell: `L11`/`L12`
route it to the register bus, `operandBefore`/`operandAfter` project it, and
C50-C53 (`src_next_i - src_previous_i = 0`) are the only residuals forcing the
emitted cell to equal the consumed one. Delete them and the store writes `rs2`:
the row consumes `x7 = 0xab` on the register bus and emits `x7 = 0xcc`, then
commits the fabricated `0xcc` to memory.

That second half is what makes this refutable through an architectural claim
rather than through the residual itself. `SbCommitsByteStore` takes its payload
from `operandBefore` — the value `rs2` actually held before the instruction —
so the witness is caught committing a byte its own source register never
contained.

Certifies `SB`, and through the shared C50-C53 block the same residuals carry
`SH` and `SW`.
-/

structure StoreHoldsWithoutStoreSourceReadOnly (row : LoadStoreRow) : Prop where
  /-- The instruction clock of a placed row. -/
  clockPositive :
    0 < row.clock
  /-- C00 and C70: exactly one opcode flag is set. -/
  selectorSum :
    row.selectorSum = 1
  /-- C10: `(1 - is_signed) * src_msb = 0`. -/
  signWitnessCanonical :
    row.isSigned = false → row.srcMsb = false
  /-- C18: `opcode_b * (1 - marker_sum) = 0`. -/
  byteMarkerSum :
    row.isByte = true → row.markerSum = 1
  /-- C19: `opcode_h * (2 - marker_sum) = 0`. -/
  halfMarkerSum :
    row.isHalf = true → row.markerSum = 2
  /-- C20: `opcode_h * (1 - shift_id) * (5 - shift_id) = 0`. -/
  halfShiftId :
    row.isHalf = true → row.shiftId = 1 ∨ row.shiftId = 5
  /-- C15, byte branch: `shift_amount = opcode_b * shift_id`. -/
  byteShiftAmount :
    row.isByte = true → row.shiftAmount = row.shiftId
  /-- C15, halfword branch: `2 * shift_amount + 1 = shift_id`. -/
  halfShiftAmount :
    row.isHalf = true → 2 * row.shiftAmount + 1 = row.shiftId
  /-- C15, word branch: neither `opcode_b` nor `opcode_h` fires. -/
  wordShiftAmount :
    row.isWord = true → row.shiftAmount = 0
  /-- L06: the aligned word address divided by four is a 20-bit value. -/
  alignedQuarterRange :
    row.alignedQuarter < 2 ^ 20
  /-- C16 and C17 with L06: the memory address selector is
    `compose(rs1_next) + imm_felt - shift_amount`, pinned to `4 * aligned_quarter`. -/
  memoryAddress :
    (row.rs1Next.value + row.immFelt) % m31Modulus =
          row.alignedAddress + row.shiftAmount
  /-- `imm_felt` is a base-field element. -/
  immFeltRange :
    row.immFelt < m31Modulus
  /-- L07, second component: `rs1_next_3` is a seven-bit value. -/
  baseHighLimbRange :
    row.rs1Next.limb3.toNat < 128
  baseHighLimbZero :
    row.rs1Next.limb3 = 0
  /-- L07: the `range_check_m31` table omits the tuple `(255, 127)`. -/
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
  /-- C34-C35, gated on `shift_id = 1`. -/
  halfLoadLow :
    row.isHalfLoad = true → row.shiftId = 1 →
          row.result.limb0 = row.srcNext.limb0 ∧
            row.result.limb1 = row.srcNext.limb1
  /-- C36-C37, gated on `shift_id = 5`. -/
  halfLoadHigh :
    row.isHalfLoad = true → row.shiftId = 5 →
          row.result.limb0 = row.srcNext.limb2 ∧
            row.result.limb1 = row.srcNext.limb3
  /-- C38-C39: the low-half placement of an `SH`. -/
  halfStoreLow :
    row.isSh = true → row.shiftId = 1 →
          row.dstNext.limb0 = row.srcNext.limb0 ∧
            row.dstNext.limb1 = row.srcNext.limb1
  /-- C40-C41: the high-half placement of an `SH`. -/
  halfStoreHigh :
    row.isSh = true → row.shiftId = 5 →
          row.dstNext.limb2 = row.srcNext.limb0 ∧
            row.dstNext.limb3 = row.srcNext.limb1
  /-- C42-C45, load half: `is_lw * (result_i - src_next_i) = 0`. -/
  wordLoad :
    row.isLw = true → row.result = row.srcNext
  /-- C42-C45, store half: `is_sw * (dst_next_i - src_next_i) = 0`. -/
  wordStore :
    row.isSw = true → row.dstNext = row.srcNext
  /-- C46-C49: the base register access is read-only. -/
  baseReadOnly :
    row.rs1Next = row.rs1Previous
  -- `sourceReadOnly` is deliberately absent: this is the mutation.
  -- C50-C53: `src_next_i - src_previous_i = 0`. On a store this is the
  -- read-only discipline of the `rs2` register cell.
  /-- C54-C57: `(is_sb + is_sh) * (1 - markers_i) * (dst_next_i - dst_previous_i)`
    — an unmarked byte of a partial store survives unchanged. -/
  partialStorePreserve :
    row.isSb = true ∨ row.isSh = true →
          (row.marker0 = false → row.dstNext.limb0 = row.dstPrevious.limb0) ∧
            (row.marker1 = false → row.dstNext.limb1 = row.dstPrevious.limb1) ∧
            (row.marker2 = false → row.dstNext.limb2 = row.dstPrevious.limb2) ∧
            (row.marker3 = false → row.dstNext.limb3 = row.dstPrevious.limb3)
  /-- C58-C60: the write-enable witness is exact. -/
  destinationFlag :
    row.destinationNonzero = decide (row.r2Idx ≠ zeroRegister)
  /-- C61-C64: `is_load * (dst_next_i - nonzero * result_i) = 0`. -/
  loadDestination :
    row.isLoad = true →
          row.dstNext = if row.destinationNonzero then row.result else WordBytes.zero
  /-- C65-C68: `(1 - is_load) * result_i = 0`. -/
  storeResultZero :
    row.isStore = true → row.result = WordBytes.zero
  /-- L14: `src_msb` is bit 7 of the selected byte. -/
  byteSignWitness :
    row.isLb = true → row.srcMsb = row.result.limb0.getLsbD 7
  /-- L15: `src_msb` is bit 15 of the selected halfword. -/
  halfSignWitness :
    row.isLh = true → row.srcMsb = row.result.limb1.getLsbD 7
  /-- L05: the base register access advances the register clock. -/
  baseClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  /-- L10 for a store and L13 for a load: the `r2_idx` register access sits at
    ordinal two. -/
  operandClock :
    validPreviousClock row.operandPreviousClock (accessClock row.clock 2)
  /-- L13 for a store and L10 for a load: the memory access sits at ordinal
    three. -/
  memoryClock :
    validPreviousClock row.memoryPreviousClock (accessClock row.clock 3)
  /-- C72: `bus_value_57 = pc + 4`. -/
  nextPcResult :
    row.claimedNextPc = nextPc row.pc

/-- Deleting the constraint really is a deletion: every honest row still
satisfies the weakened predicate, so the control below is not a statement
about a predicate nothing satisfies. -/
theorem storeHolds_weakens_sourceReadOnly
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    StoreHoldsWithoutStoreSourceReadOnly row where
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
  halfLoadHigh := holds.halfLoadHigh
  halfStoreLow := holds.halfStoreLow
  halfStoreHigh := holds.halfStoreHigh
  wordLoad := holds.wordLoad
  wordStore := holds.wordStore
  baseReadOnly := holds.baseReadOnly
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

/-- `SB x7, 5(x5)` with `x7 = 0xab`. The row emits `x7 = 0xcc` on the register
bus — a register write a store may not perform — and commits that fabricated
byte to memory. C25-C31 are satisfied against the *emitted* cell, and C54-C57
against the pre-state word, so everything left of the deletion holds. -/
def sbForgedOperandRow : LoadStoreRow :=
  { sbRow with
    srcNext := limbs 0xcc 0x00 0x00 0x00
    dstNext := limbs 0x01 0xcc 0x03 0x04 }

theorem sbForgedOperandRow_satisfies :
    StoreHoldsWithoutStoreSourceReadOnly sbForgedOperandRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

/-- The witness really does write its source register: the value it emits on the
register bus for `r2_idx` differs from the one it consumed. Recorded separately
so the control's claim about "a store that also writes a register" is checked
and not merely asserted in a comment. -/
theorem sbForgedOperandRow_writes_operand_register :
    (loadStoreRelations sbForgedOperandRow).operandEmit.value ≠
      (loadStoreRelations sbForgedOperandRow).operandConsume.value := by
  decide

theorem sbForgedOperandRow_refutes :
    ¬ SbCommitsByteStore sbForgedOperandRow := by
  intro claim
  have := claim rfl
  revert this
  decide

/-- The published control. -/
def sbSpuriousRegisterWrite :
    MutationControl StoreHoldsWithoutStoreSourceReadOnly SbCommitsByteStore where
  name := "sb-spurious-register-write"
  witness := sbForgedOperandRow
  satisfies := sbForgedOperandRow_satisfies
  refutes := sbForgedOperandRow_refutes

/-- The deletion is not free. Unconditional. -/
theorem store_source_read_only_is_load_bearing :
    ¬ (∀ row, StoreHoldsWithoutStoreSourceReadOnly row → LoadStoreHolds row) :=
  sbSpuriousRegisterWrite.strictly_weaker LoadStoreHolds sb_byte_store_sound

/-! ## Control 5 — released store result columns

*Delete `storeResultZero` (C65-C68); a store row may then commit arbitrary
`result` limbs.*

**This control uses the honest fallback `Mutation.strictly_weaker_of_not_original`
rather than an architectural conclusion, and here is why.** In this
transcription the `result_*` columns are projected out of a store's normalized
retirement: `loadStoreRetirement` sets `write := none` and `store := ...
row.dstNext.word` on every `is_store` row, and `loadStoreRelations` never reads
`result` either. So on a store row `result` reaches no bus, no relation and no
architectural field. Any predicate a released-`result` witness could refute
would therefore have to be "the result columns are zero on a store", which *is*
C65-C68 — a circular control of exactly the kind `Mutation.lean` forbids.

The honest statement is the weaker one: C65-C68 are not implied by the rest of
the system. That is what `strictly_weaker_of_not_original` proves, with the
soundness side replaced by a direct `¬ LoadStoreHolds` on the witness, so the
corollary is still unconditional.

Note also which constraint really stops a store from writing a register: it is
C50-C53, and Control 4 above is that control.

Certifies `SB`, `SH` and `SW`: C65-C68 are gated on `is_store` alone.
-/

structure StoreHoldsWithoutStoreResultZeroOnStores (row : LoadStoreRow) : Prop where
  /-- The instruction clock of a placed row. -/
  clockPositive :
    0 < row.clock
  /-- C00 and C70: exactly one opcode flag is set. -/
  selectorSum :
    row.selectorSum = 1
  /-- C10: `(1 - is_signed) * src_msb = 0`. -/
  signWitnessCanonical :
    row.isSigned = false → row.srcMsb = false
  /-- C18: `opcode_b * (1 - marker_sum) = 0`. -/
  byteMarkerSum :
    row.isByte = true → row.markerSum = 1
  /-- C19: `opcode_h * (2 - marker_sum) = 0`. -/
  halfMarkerSum :
    row.isHalf = true → row.markerSum = 2
  /-- C20: `opcode_h * (1 - shift_id) * (5 - shift_id) = 0`. -/
  halfShiftId :
    row.isHalf = true → row.shiftId = 1 ∨ row.shiftId = 5
  /-- C15, byte branch: `shift_amount = opcode_b * shift_id`. -/
  byteShiftAmount :
    row.isByte = true → row.shiftAmount = row.shiftId
  /-- C15, halfword branch: `2 * shift_amount + 1 = shift_id`. -/
  halfShiftAmount :
    row.isHalf = true → 2 * row.shiftAmount + 1 = row.shiftId
  /-- C15, word branch: neither `opcode_b` nor `opcode_h` fires. -/
  wordShiftAmount :
    row.isWord = true → row.shiftAmount = 0
  /-- L06: the aligned word address divided by four is a 20-bit value. -/
  alignedQuarterRange :
    row.alignedQuarter < 2 ^ 20
  /-- C16 and C17 with L06: the memory address selector is
    `compose(rs1_next) + imm_felt - shift_amount`, pinned to `4 * aligned_quarter`. -/
  memoryAddress :
    (row.rs1Next.value + row.immFelt) % m31Modulus =
          row.alignedAddress + row.shiftAmount
  /-- `imm_felt` is a base-field element. -/
  immFeltRange :
    row.immFelt < m31Modulus
  /-- L07, second component: `rs1_next_3` is a seven-bit value. -/
  baseHighLimbRange :
    row.rs1Next.limb3.toNat < 128
  baseHighLimbZero :
    row.rs1Next.limb3 = 0
  /-- L07: the `range_check_m31` table omits the tuple `(255, 127)`. -/
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
  /-- C34-C35, gated on `shift_id = 1`. -/
  halfLoadLow :
    row.isHalfLoad = true → row.shiftId = 1 →
          row.result.limb0 = row.srcNext.limb0 ∧
            row.result.limb1 = row.srcNext.limb1
  /-- C36-C37, gated on `shift_id = 5`. -/
  halfLoadHigh :
    row.isHalfLoad = true → row.shiftId = 5 →
          row.result.limb0 = row.srcNext.limb2 ∧
            row.result.limb1 = row.srcNext.limb3
  /-- C38-C39: the low-half placement of an `SH`. -/
  halfStoreLow :
    row.isSh = true → row.shiftId = 1 →
          row.dstNext.limb0 = row.srcNext.limb0 ∧
            row.dstNext.limb1 = row.srcNext.limb1
  /-- C40-C41: the high-half placement of an `SH`. -/
  halfStoreHigh :
    row.isSh = true → row.shiftId = 5 →
          row.dstNext.limb2 = row.srcNext.limb0 ∧
            row.dstNext.limb3 = row.srcNext.limb1
  /-- C42-C45, load half: `is_lw * (result_i - src_next_i) = 0`. -/
  wordLoad :
    row.isLw = true → row.result = row.srcNext
  /-- C42-C45, store half: `is_sw * (dst_next_i - src_next_i) = 0`. -/
  wordStore :
    row.isSw = true → row.dstNext = row.srcNext
  /-- C46-C49: the base register access is read-only. -/
  baseReadOnly :
    row.rs1Next = row.rs1Previous
  /-- C50-C53: the source access is read-only in both directions. For a load
    this is the memory-preservation constraint; for a store it is `rs2`. -/
  sourceReadOnly :
    row.srcNext = row.srcPrevious
  /-- C54-C57: `(is_sb + is_sh) * (1 - markers_i) * (dst_next_i - dst_previous_i)`
    — an unmarked byte of a partial store survives unchanged. -/
  partialStorePreserve :
    row.isSb = true ∨ row.isSh = true →
          (row.marker0 = false → row.dstNext.limb0 = row.dstPrevious.limb0) ∧
            (row.marker1 = false → row.dstNext.limb1 = row.dstPrevious.limb1) ∧
            (row.marker2 = false → row.dstNext.limb2 = row.dstPrevious.limb2) ∧
            (row.marker3 = false → row.dstNext.limb3 = row.dstPrevious.limb3)
  /-- C58-C60: the write-enable witness is exact. -/
  destinationFlag :
    row.destinationNonzero = decide (row.r2Idx ≠ zeroRegister)
  /-- C61-C64: `is_load * (dst_next_i - nonzero * result_i) = 0`. -/
  loadDestination :
    row.isLoad = true →
          row.dstNext = if row.destinationNonzero then row.result else WordBytes.zero
  -- `storeResultZero` is deliberately absent: this is the mutation.
  -- C65-C68: `(1 - is_load) * result_i = 0`.
  /-- L14: `src_msb` is bit 7 of the selected byte. -/
  byteSignWitness :
    row.isLb = true → row.srcMsb = row.result.limb0.getLsbD 7
  /-- L15: `src_msb` is bit 15 of the selected halfword. -/
  halfSignWitness :
    row.isLh = true → row.srcMsb = row.result.limb1.getLsbD 7
  /-- L05: the base register access advances the register clock. -/
  baseClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  /-- L10 for a store and L13 for a load: the `r2_idx` register access sits at
    ordinal two. -/
  operandClock :
    validPreviousClock row.operandPreviousClock (accessClock row.clock 2)
  /-- L13 for a store and L10 for a load: the memory access sits at ordinal
    three. -/
  memoryClock :
    validPreviousClock row.memoryPreviousClock (accessClock row.clock 3)
  /-- C72: `bus_value_57 = pc + 4`. -/
  nextPcResult :
    row.claimedNextPc = nextPc row.pc

/-- Deleting the constraint really is a deletion: every honest row still
satisfies the weakened predicate, so the control below is not a statement
about a predicate nothing satisfies. -/
theorem storeHolds_weakens_storeResultZero
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    StoreHoldsWithoutStoreResultZeroOnStores row where
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
  halfLoadHigh := holds.halfLoadHigh
  halfStoreLow := holds.halfStoreLow
  halfStoreHigh := holds.halfStoreHigh
  wordLoad := holds.wordLoad
  wordStore := holds.wordStore
  baseReadOnly := holds.baseReadOnly
  sourceReadOnly := holds.sourceReadOnly
  partialStorePreserve := holds.partialStorePreserve
  destinationFlag := holds.destinationFlag
  loadDestination := holds.loadDestination
  byteSignWitness := holds.byteSignWitness
  halfSignWitness := holds.halfSignWitness
  baseClock := holds.baseClock
  operandClock := holds.operandClock
  memoryClock := holds.memoryClock
  nextPcResult := holds.nextPcResult

/-- The honest `SB` row with all-ones `result` limbs. Every load-side residual
that mentions `result` is gated on a load selector and vacuous here, and
`loadDestination` is gated on `is_load`, so nothing left constrains the columns
at all. -/
def sbSpuriousResultRow : LoadStoreRow :=
  { sbRow with result := limbs 0xff 0xff 0xff 0xff }

theorem sbSpuriousResultRow_satisfies :
    StoreHoldsWithoutStoreResultZeroOnStores sbSpuriousResultRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

/-- The witness fails the unweakened system, and it fails it *at the deleted
residual*: the row is a store with a nonzero `result`. This is the honest
fallback's soundness side, discharged directly rather than through an
architectural conclusion. -/
theorem sbSpuriousResultRow_refutes_holds :
    ¬ LoadStoreHolds sbSpuriousResultRow := by
  intro holds
  exact absurd (holds.storeResultZero (by decide)) (by decide)

/-- The deletion is not free. Weaker than the controls above by construction —
it shows C65-C68 are not redundant, not that they are load-bearing for a named
architectural fact — because on a store `result` reaches nothing architectural
and any refutable conclusion would restate C65-C68. -/
theorem store_result_zero_is_not_redundant :
    ¬ (∀ row, StoreHoldsWithoutStoreResultZeroOnStores row → LoadStoreHolds row) :=
  Mutation.strictly_weaker_of_not_original sbSpuriousResultRow
    sbSpuriousResultRow_satisfies sbSpuriousResultRow_refutes_holds

/-! ## Control 6 — dropped word store

*Delete `wordStore` (C42-C45, store half); exhibit an `SW` row that leaves the
target word untouched.*

`SW` is the one store with no preservation obligation — C54-C57 are gated on
`is_sb + is_sh` and are vacuous here — so C42-C45 alone carry the whole of the
`SW` post-state. Deleting them leaves `dst_next` completely unconstrained, and
the witness below simply drops the store: it retires with the target word still
holding its pre-state content while the program believes `rs2` was committed.

Certifies `SW`.
-/

structure StoreHoldsWithoutWordStore (row : LoadStoreRow) : Prop where
  /-- The instruction clock of a placed row. -/
  clockPositive :
    0 < row.clock
  /-- C00 and C70: exactly one opcode flag is set. -/
  selectorSum :
    row.selectorSum = 1
  /-- C10: `(1 - is_signed) * src_msb = 0`. -/
  signWitnessCanonical :
    row.isSigned = false → row.srcMsb = false
  /-- C18: `opcode_b * (1 - marker_sum) = 0`. -/
  byteMarkerSum :
    row.isByte = true → row.markerSum = 1
  /-- C19: `opcode_h * (2 - marker_sum) = 0`. -/
  halfMarkerSum :
    row.isHalf = true → row.markerSum = 2
  /-- C20: `opcode_h * (1 - shift_id) * (5 - shift_id) = 0`. -/
  halfShiftId :
    row.isHalf = true → row.shiftId = 1 ∨ row.shiftId = 5
  /-- C15, byte branch: `shift_amount = opcode_b * shift_id`. -/
  byteShiftAmount :
    row.isByte = true → row.shiftAmount = row.shiftId
  /-- C15, halfword branch: `2 * shift_amount + 1 = shift_id`. -/
  halfShiftAmount :
    row.isHalf = true → 2 * row.shiftAmount + 1 = row.shiftId
  /-- C15, word branch: neither `opcode_b` nor `opcode_h` fires. -/
  wordShiftAmount :
    row.isWord = true → row.shiftAmount = 0
  /-- L06: the aligned word address divided by four is a 20-bit value. -/
  alignedQuarterRange :
    row.alignedQuarter < 2 ^ 20
  /-- C16 and C17 with L06: the memory address selector is
    `compose(rs1_next) + imm_felt - shift_amount`, pinned to `4 * aligned_quarter`. -/
  memoryAddress :
    (row.rs1Next.value + row.immFelt) % m31Modulus =
          row.alignedAddress + row.shiftAmount
  /-- `imm_felt` is a base-field element. -/
  immFeltRange :
    row.immFelt < m31Modulus
  /-- L07, second component: `rs1_next_3` is a seven-bit value. -/
  baseHighLimbRange :
    row.rs1Next.limb3.toNat < 128
  baseHighLimbZero :
    row.rs1Next.limb3 = 0
  /-- L07: the `range_check_m31` table omits the tuple `(255, 127)`. -/
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
  /-- C34-C35, gated on `shift_id = 1`. -/
  halfLoadLow :
    row.isHalfLoad = true → row.shiftId = 1 →
          row.result.limb0 = row.srcNext.limb0 ∧
            row.result.limb1 = row.srcNext.limb1
  /-- C36-C37, gated on `shift_id = 5`. -/
  halfLoadHigh :
    row.isHalfLoad = true → row.shiftId = 5 →
          row.result.limb0 = row.srcNext.limb2 ∧
            row.result.limb1 = row.srcNext.limb3
  /-- C38-C39: the low-half placement of an `SH`. -/
  halfStoreLow :
    row.isSh = true → row.shiftId = 1 →
          row.dstNext.limb0 = row.srcNext.limb0 ∧
            row.dstNext.limb1 = row.srcNext.limb1
  /-- C40-C41: the high-half placement of an `SH`. -/
  halfStoreHigh :
    row.isSh = true → row.shiftId = 5 →
          row.dstNext.limb2 = row.srcNext.limb0 ∧
            row.dstNext.limb3 = row.srcNext.limb1
  /-- C42-C45, load half: `is_lw * (result_i - src_next_i) = 0`. -/
  wordLoad :
    row.isLw = true → row.result = row.srcNext
  -- `wordStore` is deliberately absent: this is the mutation.
  -- C42-C45, store half: `is_sw * (dst_next_i - src_next_i) = 0`.
  /-- C46-C49: the base register access is read-only. -/
  baseReadOnly :
    row.rs1Next = row.rs1Previous
  /-- C50-C53: the source access is read-only in both directions. For a load
    this is the memory-preservation constraint; for a store it is `rs2`. -/
  sourceReadOnly :
    row.srcNext = row.srcPrevious
  /-- C54-C57: `(is_sb + is_sh) * (1 - markers_i) * (dst_next_i - dst_previous_i)`
    — an unmarked byte of a partial store survives unchanged. -/
  partialStorePreserve :
    row.isSb = true ∨ row.isSh = true →
          (row.marker0 = false → row.dstNext.limb0 = row.dstPrevious.limb0) ∧
            (row.marker1 = false → row.dstNext.limb1 = row.dstPrevious.limb1) ∧
            (row.marker2 = false → row.dstNext.limb2 = row.dstPrevious.limb2) ∧
            (row.marker3 = false → row.dstNext.limb3 = row.dstPrevious.limb3)
  /-- C58-C60: the write-enable witness is exact. -/
  destinationFlag :
    row.destinationNonzero = decide (row.r2Idx ≠ zeroRegister)
  /-- C61-C64: `is_load * (dst_next_i - nonzero * result_i) = 0`. -/
  loadDestination :
    row.isLoad = true →
          row.dstNext = if row.destinationNonzero then row.result else WordBytes.zero
  /-- C65-C68: `(1 - is_load) * result_i = 0`. -/
  storeResultZero :
    row.isStore = true → row.result = WordBytes.zero
  /-- L14: `src_msb` is bit 7 of the selected byte. -/
  byteSignWitness :
    row.isLb = true → row.srcMsb = row.result.limb0.getLsbD 7
  /-- L15: `src_msb` is bit 15 of the selected halfword. -/
  halfSignWitness :
    row.isLh = true → row.srcMsb = row.result.limb1.getLsbD 7
  /-- L05: the base register access advances the register clock. -/
  baseClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  /-- L10 for a store and L13 for a load: the `r2_idx` register access sits at
    ordinal two. -/
  operandClock :
    validPreviousClock row.operandPreviousClock (accessClock row.clock 2)
  /-- L13 for a store and L10 for a load: the memory access sits at ordinal
    three. -/
  memoryClock :
    validPreviousClock row.memoryPreviousClock (accessClock row.clock 3)
  /-- C72: `bus_value_57 = pc + 4`. -/
  nextPcResult :
    row.claimedNextPc = nextPc row.pc

/-- Deleting the constraint really is a deletion: every honest row still
satisfies the weakened predicate, so the control below is not a statement
about a predicate nothing satisfies. -/
theorem storeHolds_weakens_wordStore
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    StoreHoldsWithoutWordStore row where
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
  halfLoadHigh := holds.halfLoadHigh
  halfStoreLow := holds.halfStoreLow
  halfStoreHigh := holds.halfStoreHigh
  wordLoad := holds.wordLoad
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

/-- `SW x7, 4(x5)` with `x7 = 0x89abcdef` into the zero word at `0x104`. The row
retires with the target word still zero: the store is dropped. -/
def swDroppedStoreRow : LoadStoreRow :=
  { swRow with dstNext := WordBytes.zero }

theorem swDroppedStoreRow_satisfies :
    StoreHoldsWithoutWordStore swDroppedStoreRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

theorem swDroppedStoreRow_refutes :
    ¬ SwCommitsWordStore swDroppedStoreRow := by
  intro claim
  have := claim rfl
  revert this
  decide

/-- The published control. -/
def swDroppedWordStore :
    MutationControl StoreHoldsWithoutWordStore SwCommitsWordStore where
  name := "sw-dropped-word-store"
  witness := swDroppedStoreRow
  satisfies := swDroppedStoreRow_satisfies
  refutes := swDroppedStoreRow_refutes

/-- The deletion is not free. Unconditional. -/
theorem sw_word_store_is_load_bearing :
    ¬ (∀ row, StoreHoldsWithoutWordStore row → LoadStoreHolds row) :=
  swDroppedWordStore.strictly_weaker LoadStoreHolds sw_word_store_sound

/-! ## The honest rows still satisfy every conclusion

A last guard against a vacuous conclusion: if any of the three claims above were
unsatisfiable, its soundness theorem would be a proof about an empty predicate.
These three discharge that worry constructively on the family's own non-vacuity
witnesses. -/

theorem sbRow_commits_byte_store : SbCommitsByteStore sbRow :=
  sb_byte_store_sound sbRow sb_holds

theorem shRow_commits_half_store : ShCommitsHalfStore shRow :=
  sh_half_store_sound shRow sh_holds

theorem swRow_commits_word_store : SwCommitsWordStore swRow :=
  sw_word_store_sound swRow sw_holds

end RiscvRefinement.Opcodes.StoreMutation
