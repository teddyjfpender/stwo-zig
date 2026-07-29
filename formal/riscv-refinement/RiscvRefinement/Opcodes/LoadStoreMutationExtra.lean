import RiscvRefinement.Air.Family.LoadStore
import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.LoadStore

/-!
# Load-bearing mutation controls for the rest of the `load_store` family

`Opcodes/LoadStoreMutation.lean` carries the single `LH` control
(`lh-wrong-high-half`). Issue #137 names six further publication mutations for
the memory stress gate, covering the byte loads, the word load, halfword
alignment, memory preservation and the partial stores. This file is those
controls.

Each control follows the device of `RiscvRefinement/Mutation.lean` exactly:

1. a `LoadStoreHoldsWithout<Field>` structure, which is `LoadStoreHolds` with
   **exactly one** field deleted and every other field, doc comment included,
   copied verbatim -- these structures were produced mechanically from the family
   capsule rather than by hand, so no constraint is silently altered;
2. a `loadStoreHolds_weakens_<field>` lemma, proving field by field that the
   deletion is a real weakening rather than a predicate nothing satisfies;
3. a concrete row that passes the weakened predicate;
4. an architectural conclusion the row gets wrong, stated on an
   architecturally observable quantity rather than on the deleted constraint;
5. the `MutationControl` and its `strictly_weaker` corollary, whose soundness
   hypothesis `∀ row, LoadStoreHolds row → Conclusion row` is **proved**, not
   assumed. A control whose conclusion is false of honest rows makes that
   hypothesis false, and a corollary conditional on a false hypothesis
   certifies nothing. Every `..._is_load_bearing` theorem in this file is
   therefore unconditional, exactly as
   `Opcodes/LoadStoreMutation.lean::lh_high_half_selection_is_load_bearing` is.

The two ways a conclusion goes wrong, both of which this file has had to
repair, are: pinning it to a **constant**, which no other row of the family
satisfies, so the soundness hypothesis is false; and leaving it **unguarded**,
so that rows of other widths are asserted to satisfy a claim only one width
owes. Every conclusion here is now row-relative and selector-guarded.

The published controls, and the opcodes each one certifies:

| control | deleted constraint | certifies |
| --- | --- | --- |
| `lb-free-sign-witness` | `byteSignWitness` | `LB`, and `LB` vs `LBU` |
| `lw-swapped-endian-bytes` | `wordLoad` | `LW` |
| `lh-released-alignment` | `halfShiftId` | `LH`, `LHU`, `SH` |
| `sb-unselected-bytes-clobbered` | `partialStorePreserve` | `SB`, `SH` |
| `sw-free-store-result` | `storeResultZero` | `SB`, `SH`, `SW` |

`sourceReadOnly` (`LB`, `LH`, `LW`, `LBU`, `LHU`) gets no `MutationControl`.
On a load its architectural content -- memory preservation -- *is* the
constraint, so any conclusion the witness refutes restates the deletion and the
control would be circular. What is published for it is the strictly weaker
`source_read_only_is_strict`, built from
`Mutation.strictly_weaker_of_not_original`, which shows the constraint is not
redundant without claiming an independent architectural fact. The reasoning is
spelled out at `LoadPreservesMemoryWord`.

`halfShiftId`, `sourceReadOnly`, `partialStorePreserve` and `storeResultZero`
are each shared by several opcodes of the family, which is why one control
apiece settles them for every opcode whose selector gates the constraint.
-/

namespace RiscvRefinement.Opcodes

open RiscvRefinement
open RiscvRefinement.Air.Family
open RiscvRefinement.Mutation
open RiscvRefinement.Sail.Reviewed
open RiscvRefinement.Opcodes.NonVacuity

/-! ## The family's uniform architectural result specification

Three of the six controls below refute the same architectural claim: that the
`result` columns carry the architectural load value of the row's own opcode.
`familyLoadResult` states that value once, for all eight opcodes, out of the
memory word the row emits on the bus and the offset its address selects. It is
the row-level form of the `*_result_value` theorems in
`Opcodes/LoadStore.lean` (`lb_result_value`, `lbu_result_value`,
`lh_result_value`, `lhu_result_value`, `lw_result_value`) together with the
fact that a store loads nothing.

Phrasing the conclusion this way keeps the three controls non-circular: it is a
total specification of an architectural value, not a restatement of any of the
gated constraint equations that were deleted. -/

/-- The architectural load value of a `load_store` row. A store loads nothing,
so its architectural result is the zero word. -/
def familyLoadResult (row : LoadStoreRow) : Word :=
  if row.isLb then
    Memory.signExtendByte (Memory.selectByte row.srcNext row.byteOffset)
  else if row.isLbu then
    Memory.zeroExtendByte (Memory.selectByte row.srcNext row.byteOffset)
  else if row.isLh then
    Memory.signExtendHalf (Memory.selectHalf row.srcNext row.halfSelector)
  else if row.isLhu then
    Memory.zeroExtendHalf (Memory.selectHalf row.srcNext row.halfSelector)
  else if row.isLw then row.srcNext.word
  else zeroWord

/-- The architectural claim the family's refinement theorems reach about the
`result` columns. -/
def LoadStoreResultIsArchitectural (row : LoadStoreRow) : Prop :=
  row.result.word = familyLoadResult row

/-! ### Discharging the result specification

A mutation control is only worth as much as its soundness hypothesis. If
`∀ row, LoadStoreHolds row → Conclusion row` is *false*, the corollary derived
from the control is vacuous and certifies nothing, so the hypothesis has to be
proved rather than assumed -- exactly as `Opcodes/LoadStoreMutation.lean` proves
`loadStoreHolds_retires_high_half`.

`Opcodes/LoadStore.lean` proves the five `*_result_value` theorems against a
`LoadStoreEnvironment`, which an arbitrary row need not carry. The lemmas below
are their row-relative forms: they consume only `LoadStoreHolds`, which is what
lets `loadStoreHolds_result_is_architectural` be stated for *every* row and the
three controls that refute it be unconditional. -/

/-- C24-C30 without an environment: `result_0` of a byte load is the
little-endian byte the row's own shift amount selects out of the memory word. -/
theorem row_byte_selected
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row)
    (selector : row.isByteLoad = true)
    (isByte : row.isByte = true) :
    Memory.selectByte row.srcNext row.byteOffset = row.result.limb0 := by
  have sum := holds.byteMarkerSum isByte
  have amount := holds.byteShiftAmount isByte
  obtain ⟨limb0, limb1, limb2, limb3⟩ := holds.byteLoadSelect selector
  simp only [LoadStoreRow.markerSum] at sum
  simp only [LoadStoreRow.shiftId] at amount
  rcases byte_marker_cases row.marker0 row.marker1 row.marker2 row.marker3 sum
    with ⟨m0, _, _, _, sid⟩ | ⟨_, m1, _, _, sid⟩ | ⟨_, _, m2, _, sid⟩ |
      ⟨_, _, _, m3, sid⟩
  · have offset : row.shiftAmount = 0 := by omega
    simp only [LoadStoreRow.byteOffset, offset]
    simp only [Memory.selectByte]
    norm_cast
    exact (limb0 m0).symm
  · have offset : row.shiftAmount = 1 := by omega
    simp only [LoadStoreRow.byteOffset, offset]
    simp only [Memory.selectByte]
    norm_cast
    exact (limb1 m1).symm
  · have offset : row.shiftAmount = 2 := by omega
    simp only [LoadStoreRow.byteOffset, offset]
    simp only [Memory.selectByte]
    norm_cast
    exact (limb2 m2).symm
  · have offset : row.shiftAmount = 3 := by omega
    simp only [LoadStoreRow.byteOffset, offset]
    simp only [Memory.selectByte]
    norm_cast
    exact (limb3 m3).symm

/-- C34-C37 without an environment: the two low result limbs of a halfword load
are the halfword the row's own shift amount selects. -/
theorem row_half_selected
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row)
    (selector : row.isHalfLoad = true)
    (isHalf : row.isHalf = true) :
    Memory.selectHalf row.srcNext row.halfSelector =
      row.result.limb1.append row.result.limb0 := by
  rcases lh_shift row holds isHalf with ⟨identifier, amount⟩ | ⟨identifier, amount⟩
  · obtain ⟨low, high⟩ := holds.halfLoadLow selector identifier
    simp only [LoadStoreRow.halfSelector, amount, Nat.reduceDiv,
      Memory.selectHalf_low, WordBytes.lowHalf, low, high]
  · obtain ⟨low, high⟩ := holds.halfLoadHigh selector identifier
    simp only [LoadStoreRow.halfSelector, amount, Nat.reduceDiv,
      Memory.selectHalf_high, WordBytes.highHalf, low, high]

/-- C21-C23 with L14: the `LB` result word is the sign extension of the selected
byte. -/
theorem row_lb_result
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row)
    (selector : row.isLb = true) :
    row.result.word =
      Memory.signExtendByte (Memory.selectByte row.srcNext row.byteOffset) := by
  have isByteLoad : row.isByteLoad = true := by
    simp [LoadStoreRow.isByteLoad, selector]
  have isByte : row.isByte = true := by simp [LoadStoreRow.isByte, selector]
  have isSigned : row.isSigned = true := by
    simp [LoadStoreRow.isSigned, selector]
  obtain ⟨limb1, limb2, limb3⟩ := holds.byteLoadExtension isByteLoad
  have sign := holds.byteSignWitness selector
  rw [row_byte_selected row holds isByteLoad isByte]
  cases msb : row.srcMsb
  · refine word_of_nonnegative_byte row.result ?_ ?_ ?_ ?_
    · rw [← sign, msb]
    · rw [limb1]; simp [LoadStoreRow.signMask, msb]
    · rw [limb2]; simp [LoadStoreRow.signMask, msb]
    · rw [limb3]; simp [LoadStoreRow.signMask, msb]
  · refine word_of_negative_byte row.result ?_ ?_ ?_ ?_
    · rw [← sign, msb]
    · rw [limb1]; simp [LoadStoreRow.signMask, msb, isSigned]
    · rw [limb2]; simp [LoadStoreRow.signMask, msb, isSigned]
    · rw [limb3]; simp [LoadStoreRow.signMask, msb, isSigned]

/-- C21-C23: the `LBU` result word is the zero extension of the selected
byte. -/
theorem row_lbu_result
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row)
    (selector : row.isLbu = true) :
    row.result.word =
      Memory.zeroExtendByte (Memory.selectByte row.srcNext row.byteOffset) := by
  obtain ⟨isLb, isLh, _, _, _, _, _⟩ := lbu_flags row holds selector
  have isByteLoad : row.isByteLoad = true := by
    simp [LoadStoreRow.isByteLoad, selector]
  have isByte : row.isByte = true := by simp [LoadStoreRow.isByte, selector]
  have isSigned : row.isSigned = false := by
    simp [LoadStoreRow.isSigned, isLb, isLh]
  obtain ⟨limb1, limb2, limb3⟩ := holds.byteLoadExtension isByteLoad
  rw [row_byte_selected row holds isByteLoad isByte]
  refine word_of_zero_extended_byte row.result ?_ ?_ ?_
  · rw [limb1]; simp [LoadStoreRow.signMask, isSigned]
  · rw [limb2]; simp [LoadStoreRow.signMask, isSigned]
  · rw [limb3]; simp [LoadStoreRow.signMask, isSigned]

/-- C32-C33 with L15: the `LH` result word is the sign extension of the selected
halfword. -/
theorem row_lh_result
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row)
    (selector : row.isLh = true) :
    row.result.word =
      Memory.signExtendHalf (Memory.selectHalf row.srcNext row.halfSelector) := by
  have isHalfLoad : row.isHalfLoad = true := by
    simp [LoadStoreRow.isHalfLoad, selector]
  have isHalf : row.isHalf = true := by simp [LoadStoreRow.isHalf, selector]
  have isSigned : row.isSigned = true := by
    simp [LoadStoreRow.isSigned, selector]
  obtain ⟨limb2, limb3⟩ := holds.halfLoadExtension isHalfLoad
  have sign := holds.halfSignWitness selector
  rw [row_half_selected row holds isHalfLoad isHalf]
  cases msb : row.srcMsb
  · refine word_of_nonnegative_half row.result ?_ ?_ ?_
    · rw [← sign, msb]
    · rw [limb2]; simp [LoadStoreRow.signMask, msb]
    · rw [limb3]; simp [LoadStoreRow.signMask, msb]
  · refine word_of_negative_half row.result ?_ ?_ ?_
    · rw [← sign, msb]
    · rw [limb2]; simp [LoadStoreRow.signMask, msb, isSigned]
    · rw [limb3]; simp [LoadStoreRow.signMask, msb, isSigned]

/-- C32-C33: the `LHU` result word is the zero extension of the selected
halfword. -/
theorem row_lhu_result
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row)
    (selector : row.isLhu = true) :
    row.result.word =
      Memory.zeroExtendHalf (Memory.selectHalf row.srcNext row.halfSelector) := by
  obtain ⟨isLb, isLh, _, _, _, _, _⟩ := lhu_flags row holds selector
  have isHalfLoad : row.isHalfLoad = true := by
    simp [LoadStoreRow.isHalfLoad, selector]
  have isHalf : row.isHalf = true := by simp [LoadStoreRow.isHalf, selector]
  have isSigned : row.isSigned = false := by
    simp [LoadStoreRow.isSigned, isLb, isLh]
  obtain ⟨limb2, limb3⟩ := holds.halfLoadExtension isHalfLoad
  rw [row_half_selected row holds isHalfLoad isHalf]
  refine word_of_zero_extended_half row.result ?_ ?_
  · rw [limb2]; simp [LoadStoreRow.signMask, isSigned]
  · rw [limb3]; simp [LoadStoreRow.signMask, isSigned]

/-- The `result` columns of every `load_store` row carry the architectural load
value of that row's own opcode.

This is the soundness hypothesis the `byteSignWitness`, `wordLoad` and
`storeResultZero` controls need, discharged rather than assumed, which is what
makes their corollaries unconditional. -/
theorem loadStoreHolds_result_is_architectural
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    LoadStoreResultIsArchitectural row := by
  have store : row.isStore = true → row.result.word = zeroWord := by
    intro isStore
    rw [holds.storeResultZero isStore, WordBytes.zero_word]
  rcases selector_cases row holds with
    ⟨f0, f1, f2, f3, f4, f5, f6, f7⟩ | ⟨f0, f1, f2, f3, f4, f5, f6, f7⟩ |
    ⟨f0, f1, f2, f3, f4, f5, f6, f7⟩ | ⟨f0, f1, f2, f3, f4, f5, f6, f7⟩ |
    ⟨f0, f1, f2, f3, f4, f5, f6, f7⟩ | ⟨f0, f1, f2, f3, f4, f5, f6, f7⟩ |
    ⟨f0, f1, f2, f3, f4, f5, f6, f7⟩ | ⟨f0, f1, f2, f3, f4, f5, f6, f7⟩
  · simpa [LoadStoreResultIsArchitectural, familyLoadResult, f0]
      using row_lb_result row holds f0
  · simpa [LoadStoreResultIsArchitectural, familyLoadResult, f0, f1, f2, f3]
      using row_lh_result row holds f1
  · simpa [LoadStoreResultIsArchitectural, familyLoadResult, f0, f1, f2]
      using row_lbu_result row holds f2
  · simpa [LoadStoreResultIsArchitectural, familyLoadResult, f0, f1, f2, f3]
      using row_lhu_result row holds f3
  · simpa [LoadStoreResultIsArchitectural, familyLoadResult, f0, f1, f2, f3, f4]
      using congrArg WordBytes.word (holds.wordLoad f4)
  · have isStore : row.isStore = true := by simp [LoadStoreRow.isStore, f5]
    simpa [LoadStoreResultIsArchitectural, familyLoadResult, f0, f1, f2, f3, f4]
      using store isStore
  · have isStore : row.isStore = true := by simp [LoadStoreRow.isStore, f6]
    simpa [LoadStoreResultIsArchitectural, familyLoadResult, f0, f1, f2, f3, f4]
      using store isStore
  · have isStore : row.isStore = true := by simp [LoadStoreRow.isStore, f7]
    simpa [LoadStoreResultIsArchitectural, familyLoadResult, f0, f1, f2, f3, f4]
      using store isStore

/-! ## Free sign witness: `byteSignWitness` (`LB`)

L14 range-checks `result_0 - 128 * src_msb` into seven bits, which is what makes
`src_msb` *be* bit seven of the byte `LB` selected. Delete it and `src_msb`
floats free of the loaded byte, so the signed byte load may claim the
zero-extension the *unsigned* byte load is supposed to produce: `LB` and `LBU`
become interchangeable.
-/

structure LoadStoreHoldsWithoutByteSignWitness (row : LoadStoreRow) : Prop where
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
  /-- C36-C37: `load_h * ((shift_id - 1) / 4) * (result_i - src_next_{i+2}) = 0`.
  The gate is `1` exactly when `shift_id = 5`. -/
  halfLoadHigh :
    row.isHalfLoad = true → row.shiftId = 5 →
      row.result.limb0 = row.srcNext.limb2 ∧
        row.result.limb1 = row.srcNext.limb3
  /-- C38-C39. -/
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
  -- byteSignWitness is deliberately absent: this is the mutation.
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

/-- Deleting `byteSignWitness` really is a deletion: every honest row still
satisfies the weakened predicate, so the control is not about a predicate
nothing satisfies. -/
theorem loadStoreHolds_weakens_byteSignWitness
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    LoadStoreHoldsWithoutByteSignWitness row where
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
  storeResultZero := holds.storeResultZero
  halfSignWitness := holds.halfSignWitness
  baseClock := holds.baseClock
  operandClock := holds.operandClock
  memoryClock := holds.memoryClock
  nextPcResult := holds.nextPcResult

/-- The honest `LB x7, 5(x5)` row of `NonVacuity.lbRow`, which selects the
negative byte `0x9c` at offset one, with its sign witness lowered and its result
replaced by the **zero**-extension of that byte.

Every surviving constraint still holds. `signed_mask` is now zero because
`src_msb` is, so C21-C23 (`byteLoadExtension`) are satisfied by the cleared
upper limbs; C24-C30 (`byteLoadSelect`) still see the correct byte `0x9c` in
`result_0`; and C61-C64 (`loadDestination`) still mirror `result` into `rd`.
Only the deleted L14 witness objected. -/
def lbFreeSignRow : LoadStoreRow :=
  { lbRow with
    srcMsb := false
    result := limbs 0x9c 0x00 0x00 0x00
    dstNext := limbs 0x9c 0x00 0x00 0x00 }

theorem lbFreeSignRow_satisfies :
    LoadStoreHoldsWithoutByteSignWitness lbFreeSignRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

/-- The row retires `0x0000009c` where `LB` owes `0xffffff9c`: exactly the
`LBU` answer under an `LB` selector. -/
theorem lbFreeSignRow_refutes :
    ¬ LoadStoreResultIsArchitectural lbFreeSignRow := by
  unfold LoadStoreResultIsArchitectural
  decide

/-- The published control. -/
def lbFreeSignWitness :
    MutationControl LoadStoreHoldsWithoutByteSignWitness
      LoadStoreResultIsArchitectural where
  name := "lb-free-sign-witness"
  witness := lbFreeSignRow
  satisfies := lbFreeSignRow_satisfies
  refutes := lbFreeSignRow_refutes

/-- The deletion is not free: `LB`'s sign extension cannot be recovered from the
remaining constraints. Unconditional: the soundness hypothesis is discharged by
`loadStoreHolds_result_is_architectural` rather than assumed. -/
theorem lb_sign_witness_is_load_bearing :
    ¬ (∀ row, LoadStoreHoldsWithoutByteSignWitness row → LoadStoreHolds row) :=
  lbFreeSignWitness.strictly_weaker LoadStoreHolds
    loadStoreHolds_result_is_architectural

/-! ## Swapped endian bytes: `wordLoad` (`LW`)

C42-C45 on the load side are the only constraints that tie `LW`'s four result
limbs to the four limbs of the memory word; no marker, mask or range check
touches them. Delete the field and the little-endian limb order is free, so a
row may transpose the memory word's byte pairs and still be accepted.
-/

structure LoadStoreHoldsWithoutWordLoad (row : LoadStoreRow) : Prop where
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
  /-- C36-C37: `load_h * ((shift_id - 1) / 4) * (result_i - src_next_{i+2}) = 0`.
  The gate is `1` exactly when `shift_id = 5`. -/
  halfLoadHigh :
    row.isHalfLoad = true → row.shiftId = 5 →
      row.result.limb0 = row.srcNext.limb2 ∧
        row.result.limb1 = row.srcNext.limb3
  /-- C38-C39. -/
  halfStoreLow :
    row.isSh = true → row.shiftId = 1 →
      row.dstNext.limb0 = row.srcNext.limb0 ∧
        row.dstNext.limb1 = row.srcNext.limb1
  /-- C40-C41. -/
  halfStoreHigh :
    row.isSh = true → row.shiftId = 5 →
      row.dstNext.limb2 = row.srcNext.limb0 ∧
        row.dstNext.limb3 = row.srcNext.limb1
  -- wordLoad is deliberately absent: this is the mutation.
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

/-- Deleting `wordLoad` really is a deletion. -/
theorem loadStoreHolds_weakens_wordLoad
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    LoadStoreHoldsWithoutWordLoad row where
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

/-- The honest `LW x7, 4(x5)` row of `NonVacuity.lwRow`, reading the aligned
word `0xeeff1234` (limbs `34 12 ff ee`), with its result and its destination
byte-pair transposed to `0xffee3412` (limbs `12 34 ee ff`).

`LW` sets no markers, `opcode_b` and `opcode_h` are both clear, and
`is_signed` is clear, so C18-C31, C32-C41, L14 and L15 are all vacuous here;
C61-C64 still mirror `result` into `rd`. Nothing but the deleted C42-C45
constrained the limb order. -/
def lwSwappedBytesRow : LoadStoreRow :=
  { lwRow with
    result := limbs 0x12 0x34 0xee 0xff
    dstNext := limbs 0x12 0x34 0xee 0xff }

theorem lwSwappedBytesRow_satisfies :
    LoadStoreHoldsWithoutWordLoad lwSwappedBytesRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

/-- The row retires `0xffee3412` where the memory word is `0xeeff1234`. -/
theorem lwSwappedBytesRow_refutes :
    ¬ LoadStoreResultIsArchitectural lwSwappedBytesRow := by
  unfold LoadStoreResultIsArchitectural
  decide

/-- The published control. -/
def lwSwappedEndianBytes :
    MutationControl LoadStoreHoldsWithoutWordLoad
      LoadStoreResultIsArchitectural where
  name := "lw-swapped-endian-bytes"
  witness := lwSwappedBytesRow
  satisfies := lwSwappedBytesRow_satisfies
  refutes := lwSwappedBytesRow_refutes

/-- The deletion is not free: `LW`'s little-endian limb order cannot be
recovered from the remaining constraints. Unconditional: the soundness
hypothesis is discharged by `loadStoreHolds_result_is_architectural`. -/
theorem lw_word_load_is_load_bearing :
    ¬ (∀ row, LoadStoreHoldsWithoutWordLoad row → LoadStoreHolds row) :=
  lwSwappedEndianBytes.strictly_weaker LoadStoreHolds
    loadStoreHolds_result_is_architectural

/-! ## Released alignment: `halfShiftId` (`LH`, `LHU`, `SH`)

C20 pins a halfword access's `shift_id` to `{1, 5}`, which is what
`Opcodes/LoadStore.lean`'s `lh_shift` turns into `shift_amount ∈ {0, 2}` and
`half_access_aligned` turns into natural halfword alignment of the effective
address. Delete C20 and `shift_id = 3` survives: two markers are still set, so
C19 is satisfied, and `2 * shift_amount + 1 = shift_id` is still satisfiable --
at `shift_amount = 1`. That is a halfword straddling bytes one and two of its
aligned word, which the architecture never permits.

Both half-selection gates, C34-C37, are keyed to `shift_id ∈ {1, 5}` and are
therefore vacuous at `shift_id = 3`: the result of a straddling access is
completely unconstrained by the weakened system.
-/

structure LoadStoreHoldsWithoutHalfShiftId (row : LoadStoreRow) : Prop where
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
  -- halfShiftId is deliberately absent: this is the mutation.
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
  /-- C36-C37: `load_h * ((shift_id - 1) / 4) * (result_i - src_next_{i+2}) = 0`.
  The gate is `1` exactly when `shift_id = 5`. -/
  halfLoadHigh :
    row.isHalfLoad = true → row.shiftId = 5 →
      row.result.limb0 = row.srcNext.limb2 ∧
        row.result.limb1 = row.srcNext.limb3
  /-- C38-C39. -/
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

/-- Deleting `halfShiftId` really is a deletion. -/
theorem loadStoreHolds_weakens_halfShiftId
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    LoadStoreHoldsWithoutHalfShiftId row where
  clockPositive := holds.clockPositive
  selectorSum := holds.selectorSum
  signWitnessCanonical := holds.signWitnessCanonical
  byteMarkerSum := holds.byteMarkerSum
  halfMarkerSum := holds.halfMarkerSum
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
  storeResultZero := holds.storeResultZero
  byteSignWitness := holds.byteSignWitness
  halfSignWitness := holds.halfSignWitness
  baseClock := holds.baseClock
  operandClock := holds.operandClock
  memoryClock := holds.memoryClock
  nextPcResult := holds.nextPcResult

/-- `LH x7, 5(x5)` with `x5 = 0x100`: a halfword at the **odd** address `0x105`,
straddling bytes one and two of the aligned word at `0x104`. Markers one and two
are set, so `marker_sum = 2` and `shift_id = 3`, and `shift_amount = 1` keeps
C15's halfword branch satisfied. The result is the straddling halfword `0xff12`
sign-extended, which is consistent with C32-C33 and L15 but is not any
architectural `LH` value. -/
def lhOddOffsetRow : LoadStoreRow :=
  { lhLowRow with
    immFelt := 5
    shiftAmount := 1
    srcMsb := true
    marker0 := false
    marker1 := true
    marker2 := true
    marker3 := false
    result := limbs 0x12 0xff 0xff 0xff
    dstNext := limbs 0x12 0xff 0xff 0xff }

theorem lhOddOffsetRow_satisfies :
    LoadStoreHoldsWithoutHalfShiftId lhOddOffsetRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

/-- The architectural claim `half_access_aligned` reaches: the effective address
of a halfword access is naturally aligned. Stated on the address the row names
-- aligned word base plus byte offset -- rather than on `shift_id`, so the
control is not circular.

The `opcode_h` antecedent is load-bearing in the *statement*. Without it the
claim is asserted of every row of the family, and an honest byte load at an odd
effective address -- `NonVacuity.lbRow` reads `0x105` -- already refutes it. An
unguarded version therefore has a false soundness hypothesis, which would make
the corollary below vacuous. -/
def HalfAccessNaturallyAligned (row : LoadStoreRow) : Prop :=
  row.isHalf = true → (row.alignedAddress + row.shiftAmount) % 2 = 0

/-- The claim is what the unweakened row predicate delivers.

C20 pins `shift_id ∈ {1, 5}` for a halfword access and C15's halfword branch
relates it to `shift_amount` by `2 * shift_amount + 1 = shift_id`, so
`shift_amount ∈ {0, 2}`; the aligned base `4 * aligned_quarter` is even, so the
sum is even. This is the row-relative form of `half_access_aligned`, which
`Opcodes/LoadStore.lean` states against a decoding environment.

Proving this rather than assuming it is what makes the control unconditional. -/
theorem loadStoreHolds_half_access_aligned
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    HalfAccessNaturallyAligned row := by
  intro isHalf
  have amount := holds.halfShiftAmount isHalf
  simp only [LoadStoreRow.alignedAddress]
  rcases holds.halfShiftId isHalf with identifier | identifier <;>
    rw [identifier] at amount <;> omega

/-- The row names the effective address `0x105`, which is odd, under a halfword
selector. -/
theorem lhOddOffsetRow_refutes :
    ¬ HalfAccessNaturallyAligned lhOddOffsetRow := by
  unfold HalfAccessNaturallyAligned
  decide

/-- The published control. -/
def lhReleasedAlignment :
    MutationControl LoadStoreHoldsWithoutHalfShiftId
      HalfAccessNaturallyAligned where
  name := "lh-released-alignment"
  witness := lhOddOffsetRow
  satisfies := lhOddOffsetRow_satisfies
  refutes := lhOddOffsetRow_refutes

/-- The deletion is not free: natural halfword alignment cannot be recovered
from the remaining constraints. Unconditional: the soundness hypothesis is
discharged by `loadStoreHolds_half_access_aligned` rather than assumed. -/
theorem half_shift_id_is_load_bearing :
    ¬ (∀ row, LoadStoreHoldsWithoutHalfShiftId row → LoadStoreHolds row) :=
  lhReleasedAlignment.strictly_weaker LoadStoreHolds
    loadStoreHolds_half_access_aligned

/-! ## Unpreserved memory word: `sourceReadOnly` (every load)

C50-C53 make the source access block read-only. For a load that block *is* the
memory word, so C50-C53 are the whole of memory preservation: they are what
`LoadRefinement.memoryPreserved` is proved from. Delete them and a load may
re-emit a different word on the memory bus than the one it consumed, silently
rewriting memory.

The witness is deliberately arranged so that the load still returns the correct
architectural value -- the byte it selects is untouched. Only the rest of the
memory word is destroyed, which is precisely the failure mode a value-only
review would miss.

That arrangement is also why this deletion gets the weaker device. The witness
is invisible to every architectural quantity of the family *except* memory
preservation, and memory preservation on a load is the deleted constraint
itself. The published result is therefore strictness rather than architectural
load-bearing; see `LoadPreservesMemoryWord` below for the full argument.
-/

structure LoadStoreHoldsWithoutSourceReadOnly (row : LoadStoreRow) : Prop where
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
  /-- C36-C37: `load_h * ((shift_id - 1) / 4) * (result_i - src_next_{i+2}) = 0`.
  The gate is `1` exactly when `shift_id = 5`. -/
  halfLoadHigh :
    row.isHalfLoad = true → row.shiftId = 5 →
      row.result.limb0 = row.srcNext.limb2 ∧
        row.result.limb1 = row.srcNext.limb3
  /-- C38-C39. -/
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
  -- sourceReadOnly is deliberately absent: this is the mutation.
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

/-- Deleting `sourceReadOnly` really is a deletion. -/
theorem loadStoreHolds_weakens_sourceReadOnly
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    LoadStoreHoldsWithoutSourceReadOnly row where
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

/-- The honest `LB x7, 5(x5)` row of `NonVacuity.lbRow`, whose memory word
`0x22119c34` is consumed correctly and re-emitted as `0x00009c00`: byte one, the
one the load selects, survives so C24-C30 and L14 are still satisfied, and the
other three bytes of the live memory word are zeroed. -/
def lbMutatesMemoryRow : LoadStoreRow :=
  { lbRow with srcNext := limbs 0x00 0x9c 0x00 0x00 }

theorem lbMutatesMemoryRow_satisfies :
    LoadStoreHoldsWithoutSourceReadOnly lbMutatesMemoryRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

/-- Memory preservation across a load, stated relative to the row's own
pre-state: the word the row emits on the memory bus is the word it consumed.
This is `LoadRefinement.memoryPreserved`.

**This deletion gets the weaker control, and the reason is worth stating
plainly.** On a load `memoryAfter` and `memoryBefore` are `srcNext` and
`srcPrevious` (`memoryAfter_load`, `memoryBefore_load`), so this claim unfolds
to `row.srcNext = row.srcPrevious`, which is exactly the deleted constraint
C50-C53 restricted to loads. The architectural fact and the constraint coincide.
A `MutationControl` on it would therefore be circular in precisely the sense
`RiscvRefinement/Mutation.lean` warns about: it would prove only that deleting a
constraint makes that constraint false.

Pinning the conclusion to a constant instead -- the memory image
`limbs 0x34 0x9c 0x11 0x22` of `NonVacuity.lbEnvironment`, as an earlier version
of this file did -- does not rescue it. No constant claim holds of every row of
the family; the honest `sbRow` refutes that one. The soundness hypothesis was
false, so the corollary drawn from it was vacuous and certified nothing.

What is published instead is `source_read_only_is_strict`, via
`Mutation.strictly_weaker_of_not_original`, which needs no architectural
conclusion and therefore cannot be vacuous. The definition and the two theorems
here are what record the coincidence. -/
def LoadPreservesMemoryWord (row : LoadStoreRow) : Prop :=
  row.isLoad = true → row.memoryAfter = row.memoryBefore

/-- C50-C53 are the whole of memory preservation across a load: no other field
of the row predicate is consulted. This is the formal statement of the
coincidence described above. -/
theorem loadStoreHolds_preserves_memory_word
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    LoadPreservesMemoryWord row := by
  intro isLoad
  have isStore : row.isStore = false := by
    simpa [LoadStoreRow.isLoad] using isLoad
  rw [memoryAfter_load row isStore, memoryBefore_load row isStore,
    holds.sourceReadOnly]

/-- The row emits `0x00009c00` where it consumed `0x22119c34`. -/
theorem lbMutatesMemoryRow_refutes :
    ¬ LoadPreservesMemoryWord lbMutatesMemoryRow := by
  unfold LoadPreservesMemoryWord
  decide

/-- The witness really is outside the unweakened system, proved directly from
the deleted field. This is all the strictness statement needs, and unlike a
soundness hypothesis it cannot be silently false. -/
theorem lbMutatesMemoryRow_violates_holds :
    ¬ LoadStoreHolds lbMutatesMemoryRow := by
  intro holds
  have source := holds.sourceReadOnly
  revert source
  decide

/-- The deletion is not free: `lbMutatesMemoryRow` passes the weakened predicate
and fails the original, so `LoadStoreHoldsWithoutSourceReadOnly` is strictly
weaker than `LoadStoreHolds`.

Unconditional, and deliberately *strictness* rather than architectural
load-bearing. As set out at `LoadPreservesMemoryWord`, for this deletion the
architectural claim and the deleted constraint coincide, so no non-circular
`MutationControl` is available. This theorem establishes that C50-C53 are not
redundant; it does not exhibit an independent architectural fact that only they
deliver, and it does not pretend to. -/
theorem source_read_only_is_strict :
    ¬ (∀ row, LoadStoreHoldsWithoutSourceReadOnly row → LoadStoreHolds row) :=
  strictly_weaker_of_not_original lbMutatesMemoryRow
    lbMutatesMemoryRow_satisfies lbMutatesMemoryRow_violates_holds

/-- The mutated row still returns the architecturally correct `LB` value. The
damage is entirely on the memory bus, so a control stated only on the load
result would have missed it. -/
theorem lbMutatesMemoryRow_result_still_correct :
    LoadStoreResultIsArchitectural lbMutatesMemoryRow := by
  unfold LoadStoreResultIsArchitectural
  decide

/-! ## Unselected store bytes clobbered: `partialStorePreserve` (`SB`, `SH`)

C54-C57 are the only constraints that say anything at all about the bytes of a
partial store's target word that its mask does *not* select: C25-C31 pin the
selected byte and stop there. Delete C54-C57 and an `SB` may overwrite the whole
aligned word while claiming a one-byte mask -- the single most damaging
store-side mutation in the family, because the memory argument would still see a
well-formed masked write.
-/

structure LoadStoreHoldsWithoutPartialStorePreserve (row : LoadStoreRow) : Prop where
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
  /-- C36-C37: `load_h * ((shift_id - 1) / 4) * (result_i - src_next_{i+2}) = 0`.
  The gate is `1` exactly when `shift_id = 5`. -/
  halfLoadHigh :
    row.isHalfLoad = true → row.shiftId = 5 →
      row.result.limb0 = row.srcNext.limb2 ∧
        row.result.limb1 = row.srcNext.limb3
  /-- C38-C39. -/
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
  -- partialStorePreserve is deliberately absent: this is the mutation.
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

/-- Deleting `partialStorePreserve` really is a deletion. -/
theorem loadStoreHolds_weakens_partialStorePreserve
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    LoadStoreHoldsWithoutPartialStorePreserve row where
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

/-- The honest `SB x7, 5(x5)` row of `NonVacuity.sbRow`, which writes `0xab`
into byte one of the live word `0x04030201`, with the other three bytes of the
committed word zeroed. C25-C31 still place `0xab` in byte one and C65-C68 still
zero the result, so the only objection came from the deleted C54-C57. -/
def sbClobbersRow : LoadStoreRow :=
  { sbRow with dstNext := limbs 0x00 0xab 0x00 0x00 }

theorem sbClobbersRow_satisfies :
    LoadStoreHoldsWithoutPartialStorePreserve sbClobbersRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

/-- The architectural claim `StoreRefinement.memoryUpdated` reaches, stated
relative to the row's own pre-state: the word an `SB` commits is the word it
consumed with the reviewed byte payload applied under the byte-enable mask.
This is the row-relative form of `sb_memory_after`.

Two things keep it honest. It is not a constant: an earlier version pinned the
pre-state word and the payload to the constants of `NonVacuity.sbEnvironment`,
which no other row of the family satisfies, so the soundness hypothesis was
false and the corollary drawn from it vacuous. And it is not a restatement of
the deleted C54-C57: the mask here is `Memory.byteMask row.byteOffset`, derived
from the *address*, where C54-C57 speak of the marker columns; the selected
byte is pinned by C25-C31 and the marker-to-offset correspondence by C18 and
C15. C54-C57 contribute exactly the survival of the other three bytes, which is
what the witness destroys. -/
def SbCommitsMaskedWord (row : LoadStoreRow) : Prop :=
  row.isSb = true →
    row.memoryAfter =
      Memory.applyMask row.memoryBefore
        (storeBytePayload row.srcPrevious.word) row.mask

/-- The claim is what the unweakened row predicate delivers.

Proving this rather than assuming it is what makes the corollary below
unconditional: the soundness hypothesis is discharged here, so the control does
not rest on an assumption that might be false. -/
theorem loadStoreHolds_commits_masked_word
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    SbCommitsMaskedWord row := by
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
    ← holds.sourceReadOnly, mask_sb row selector]
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

/-- The row commits `0x0000ab00` where the masked store owes `0x0403ab01`. -/
theorem sbClobbersRow_refutes : ¬ SbCommitsMaskedWord sbClobbersRow := by
  unfold SbCommitsMaskedWord
  decide

/-- The published control. -/
def sbUnselectedBytesClobbered :
    MutationControl LoadStoreHoldsWithoutPartialStorePreserve
      SbCommitsMaskedWord where
  name := "sb-unselected-bytes-clobbered"
  witness := sbClobbersRow
  satisfies := sbClobbersRow_satisfies
  refutes := sbClobbersRow_refutes

/-- The deletion is not free: the survival of the bytes a partial store does not
select cannot be recovered from the remaining constraints. Unconditional: the
soundness hypothesis is discharged by `loadStoreHolds_commits_masked_word`
rather than assumed. -/
theorem partial_store_preserve_is_load_bearing :
    ¬ (∀ row, LoadStoreHoldsWithoutPartialStorePreserve row →
        LoadStoreHolds row) :=
  sbUnselectedBytesClobbered.strictly_weaker LoadStoreHolds
    loadStoreHolds_commits_masked_word

/-- The honest row does satisfy the architectural claim, so the conclusion is
not one that no row of the family reaches. -/
theorem sbRow_commits_masked_word : SbCommitsMaskedWord sbRow := by
  unfold SbCommitsMaskedWord
  decide

/-! ## Free store result: `storeResultZero` (`SB`, `SH`, `SW`)

C65-C68 are the only constraints a store's `result` columns appear in: every
other occurrence of `result` in the family is gated on `load_b`, `load_h`,
`is_lw`, `is_lb`, `is_lh` or `is_load`, all of which are clear on a store.
Delete C65-C68 and the `result` columns of a store row are completely
unconstrained, so the family's uniform statement that `result` carries the
architectural load value -- zero when nothing is loaded -- fails.
-/

structure LoadStoreHoldsWithoutStoreResultZero (row : LoadStoreRow) : Prop where
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
  /-- C36-C37: `load_h * ((shift_id - 1) / 4) * (result_i - src_next_{i+2}) = 0`.
  The gate is `1` exactly when `shift_id = 5`. -/
  halfLoadHigh :
    row.isHalfLoad = true → row.shiftId = 5 →
      row.result.limb0 = row.srcNext.limb2 ∧
        row.result.limb1 = row.srcNext.limb3
  /-- C38-C39. -/
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
  -- storeResultZero is deliberately absent: this is the mutation.
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

/-- Deleting `storeResultZero` really is a deletion. -/
theorem loadStoreHolds_weakens_storeResultZero
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    LoadStoreHoldsWithoutStoreResultZero row where
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

/-- The honest `SW x7, 4(x5)` row of `NonVacuity.swRow` with the stored word
`0x89abcdef` leaked into the result columns. Every remaining constraint that
mentions `result` is gated on a load selector, so nothing objects. -/
def swFreeResultRow : LoadStoreRow :=
  { swRow with result := limbs 0xef 0xcd 0xab 0x89 }

theorem swFreeResultRow_satisfies :
    LoadStoreHoldsWithoutStoreResultZero swFreeResultRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

/-- The row claims a load result of `0x89abcdef` on an instruction that loads
nothing. -/
theorem swFreeResultRow_refutes :
    ¬ LoadStoreResultIsArchitectural swFreeResultRow := by
  unfold LoadStoreResultIsArchitectural
  decide

/-- The published control. -/
def swFreeStoreResult :
    MutationControl LoadStoreHoldsWithoutStoreResultZero
      LoadStoreResultIsArchitectural where
  name := "sw-free-store-result"
  witness := swFreeResultRow
  satisfies := swFreeResultRow_satisfies
  refutes := swFreeResultRow_refutes

/-- The deletion is not free: the absence of a load result on a store cannot be
recovered from the remaining constraints. Unconditional: the soundness
hypothesis is discharged by `loadStoreHolds_result_is_architectural`. -/
theorem store_result_zero_is_load_bearing :
    ¬ (∀ row, LoadStoreHoldsWithoutStoreResultZero row → LoadStoreHolds row) :=
  swFreeStoreResult.strictly_weaker LoadStoreHolds
    loadStoreHolds_result_is_architectural

/-! ## The honest witnesses do satisfy the architectural result specification

`familyLoadResult` is the conclusion of three of the six controls above, so it
has to be a claim the family actually reaches; otherwise those controls would be
refuting something no row ever satisfies. These check it on the honest
non-vacuity witnesses of all five load opcodes and all three stores. -/

theorem honest_results_are_architectural :
    LoadStoreResultIsArchitectural lbRow ∧
      LoadStoreResultIsArchitectural lbuRow ∧
      LoadStoreResultIsArchitectural lhLowRow ∧
      LoadStoreResultIsArchitectural lhHighRow ∧
      LoadStoreResultIsArchitectural lhuRow ∧
      LoadStoreResultIsArchitectural lwRow ∧
      LoadStoreResultIsArchitectural sbRow ∧
      LoadStoreResultIsArchitectural shRow ∧
      LoadStoreResultIsArchitectural swRow := by
  unfold LoadStoreResultIsArchitectural
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> decide

/-- The honest halfword witnesses are naturally aligned, on both halves. -/
theorem honest_half_accesses_are_aligned :
    HalfAccessNaturallyAligned lhLowRow ∧
      HalfAccessNaturallyAligned lhHighRow ∧
      HalfAccessNaturallyAligned lhuRow ∧
      HalfAccessNaturallyAligned shRow := by
  unfold HalfAccessNaturallyAligned
  refine ⟨?_, ?_, ?_, ?_⟩ <;> decide

/-- The honest `LB` witness preserves the memory word it read. -/
theorem honest_load_preserves_memory_word : LoadPreservesMemoryWord lbRow := by
  unfold LoadPreservesMemoryWord
  decide

end RiscvRefinement.Opcodes
