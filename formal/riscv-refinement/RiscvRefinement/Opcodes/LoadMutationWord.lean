-- REVIEWED-CAPSULE BOUNDARY. Hand-written file; not generated, and not a
-- generated-Sail theorem. The two architectural conclusions these controls
-- certify -- LW's identity load and LHU's zero-filled halfword load -- are
-- stated against the reviewed normalized capsule
-- RiscvRefinement/Sail/Reviewed/LoadStore.lean, which is hand-written with no
-- generator, no digest, and no derivation from any Sail artifact (see its
-- header). Nothing in this file is publication-level for the architectural
-- side.

import RiscvRefinement.Air.Family.LoadStore
import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.LoadStore

/-!
# Per-opcode load-bearing mutation controls for `LW` and `LHU`

The `load_store` family already carries controls at *family* granularity: the
byte, halfword and word residuals are each certified by some witness. What was
missing, and what this file supplies, is a control whose witness row carries the
`is_lw` selector and a control whose witness row carries the `is_lhu` selector,
with the refuted conclusion guarded on that same selector. Without those, no
per-opcode credit is owed to `LW` or to `LHU`: a control on a sibling selector
says nothing about the opcode whose flag never fires in the witness.

Three controls live here.

| control | deleted constraint | the escape it opens |
| --- | --- | --- |
| `lw-identity-broken` | `wordLoad` (C42-C45, load half) | an `is_lw` row retires a truncated word |
| `lhu-zero-fill-broken` | `halfLoadExtension` (C32-C33) | an `is_lhu` row sign-extends, i.e. behaves as `LH` |
| `lhu-wrong-half-selected` | `halfLoadHigh` (C36-C37) | an `is_lhu` row retires the other halfword |

## Why the two conclusions are neither vacuous nor circular

`LwRetiresMemoryWord` and `LhuRetiresZeroExtendedHalf` are both stated on the
row's **normalized retirement** -- the guarded architectural register write of
`Air/Family/LoadStore.lean::loadStoreRetirement` -- rather than on the `result`
columns the deleted residuals mention. Each is:

* **row-parameterised.** Both sides are functions of the row: its own `r2_idx`,
  its own emitted memory word, its own halfword selector. No literal constant
  appears. A conclusion pinned to a constant would be false of nearly every
  honest row, its soundness hypothesis would be false, and the corollary would
  certify nothing.
* **guarded on its own selector**, `is_lw` and `is_lhu` respectively, so an
  honest row of any other opcode of the family satisfies it and soundness is
  provable for the whole family at once. This is also exactly what makes the
  control count *for that opcode*.
* **not a restatement of the deleted constraint.** The deletions are residuals
  on `result`; the conclusions are claims about the architectural value written
  to `rd`, reached through C61-C64 and C58-C60. The `LHU` conclusion is refuted
  by two different deletions -- a wrong extension and a wrong selection -- which
  is only possible because it is the architectural load value rather than either
  residual. `lwValue_matches_capsule` and `lhuValue_matches_capsule` then
  identify the row-level right-hand sides with the reviewed capsule's
  `loadWordValue` and `loadHalfUnsignedValue` under a decoding environment.

Soundness is **proved in this file** (`loadStoreHolds_lw_retires_memory_word`,
`loadStoreHolds_lhu_retires_zero_extended_half`), so all three
`..._is_load_bearing` corollaries below are unconditional.

Everything sits in the `LoadMutationWord` sub-namespace so that no name here
collides with the family-level controls in `Opcodes/LoadStoreMutation.lean` and
`Opcodes/LoadStoreMutationExtra.lean`, or with the byte-load controls.
-/

namespace RiscvRefinement.Opcodes.LoadMutationWord

open RiscvRefinement
open RiscvRefinement.Air.Family
open RiscvRefinement.Sail.Reviewed
open RiscvRefinement.Mutation
open RiscvRefinement.Opcodes
open RiscvRefinement.Opcodes.NonVacuity

/-! ## The two architectural conclusions -/

/-- `LW` is the identity load: the value it writes to `rd` is the whole aligned
memory word it emits on the bus, with no reinterpretation.

Stated on the row's normalized retirement and against the reviewed capsule's
`loadWordValue`. `lwValue_matches_capsule` below shows `row.srcNext` is the
capsule's `memoryWord` for any `LW` row of the unweakened system. -/
def LwRetiresMemoryWord (row : LoadStoreRow) : Prop :=
  row.isLw = true →
    (loadStoreRetirement row).write =
      architecturalWrite row.r2Idx (loadWordValue row.srcNext)

/-- `LHU` zero-fills: the value it writes to `rd` is the selected halfword of
the emitted memory word with a **zero** upper half, whatever the sign of that
halfword. This is the whole architectural difference between `LHU` and `LH`,
and it is also what pins the selection to the addressed half.

The row-level right-hand side is the capsule's `loadHalfUnsignedValue` with the
address-derived selector replaced by the AIR's `row.halfSelector`;
`lhuValue_matches_capsule` proves the two agree under a decoding
environment. -/
def LhuRetiresZeroExtendedHalf (row : LoadStoreRow) : Prop :=
  row.isLhu = true →
    (loadStoreRetirement row).write =
      architecturalWrite row.r2Idx
        (Memory.zeroExtendHalf (Memory.selectHalf row.srcNext row.halfSelector))

/-! ### The capsule anchors

Both conclusions above are row-level, because a `MutationControl` conclusion is
a predicate on rows alone. These two lemmas tie them back to the reviewed
capsule of `Sail/Reviewed/LoadStore.lean`, so the architectural claim being
refuted is the capsule's, not a row-shaped approximation of it. -/

/-- The word an `LW` row emits on the bus is the capsule's observed memory
word. -/
theorem lwValue_matches_capsule
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isLw = true) :
    loadWordValue row.srcNext = loadWordValue env.memoryWord := by
  obtain ⟨_, _, _, _, isSb, isSh, isSw⟩ := lw_flags row holds selector
  have isStore : row.isStore = false := by
    simp [LoadStoreRow.isStore, isSb, isSh, isSw]
  rw [load_memory_word row env holds isStore]

/-- The row-level zero-extended halfword of an `LHU` row is the capsule's
`loadHalfUnsignedValue` at the architectural effective address. -/
theorem lhuValue_matches_capsule
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isLhu = true) :
    Memory.zeroExtendHalf (Memory.selectHalf row.srcNext row.halfSelector) =
      loadHalfUnsignedValue env.baseValue env.imm env.memoryWord := by
  obtain ⟨_, _, _, _, isSb, isSh, isSw⟩ := lhu_flags row holds selector
  have isStore : row.isStore = false := by
    simp [LoadStoreRow.isStore, isSb, isSh, isSw]
  have memory := load_memory_word row env holds isStore
  simp only [loadHalfUnsignedValue, LoadStoreEnvironment.effectiveAddress_eq,
    memory, row_halfSelector row env holds]

/-! ### Discharging the soundness hypotheses

A control is worth exactly as much as its soundness hypothesis
`∀ row, LoadStoreHolds row → Conclusion row` is true: if that is false the
corollary is vacuous. Both are proved here rather than assumed, which is what
makes every corollary in this file unconditional. -/

/-- C42-C45 on the load side, with C61-C64 and C58-C60: an `LW` row writes the
emitted memory word to `rd`, and writes nothing when `rd` is `x0`. -/
theorem loadStoreHolds_lw_retires_memory_word
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    LwRetiresMemoryWord row := by
  intro selector
  obtain ⟨_, _, _, _, isSb, isSh, isSw⟩ := lw_flags row holds selector
  have isStore : row.isStore = false := by
    simp [LoadStoreRow.isStore, isSb, isSh, isSw]
  have isLoad : row.isLoad = true := by simp [LoadStoreRow.isLoad, isStore]
  have write :
      (loadStoreRetirement row).write =
        architecturalWrite row.r2Idx row.dstNext.word := by
    rw [loadStoreRetirement_load row isStore]
  rw [write, load_write_value row holds isLoad,
    show loadWordValue row.srcNext = row.srcNext.word from rfl,
    holds.wordLoad selector]

/-- C34-C37 without an environment: the two low `result` limbs of an `LHU` row
are the halfword its own shift amount selects out of the emitted memory word. -/
theorem lhu_half_selected
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row)
    (selector : row.isLhu = true) :
    Memory.selectHalf row.srcNext row.halfSelector =
      row.result.limb1.append row.result.limb0 := by
  have isHalfLoad : row.isHalfLoad = true := by
    simp [LoadStoreRow.isHalfLoad, selector]
  have isHalf : row.isHalf = true := by simp [LoadStoreRow.isHalf, selector]
  rcases lh_shift row holds isHalf with ⟨identifier, amount⟩ | ⟨identifier, amount⟩
  · obtain ⟨low, high⟩ := holds.halfLoadLow isHalfLoad identifier
    simp only [LoadStoreRow.halfSelector, amount, Nat.reduceDiv,
      Memory.selectHalf_low, WordBytes.lowHalf, low, high]
  · obtain ⟨low, high⟩ := holds.halfLoadHigh isHalfLoad identifier
    simp only [LoadStoreRow.halfSelector, amount, Nat.reduceDiv,
      Memory.selectHalf_high, WordBytes.highHalf, low, high]

/-- C32-C33 with C10: the `LHU` result word is the zero extension of the
selected halfword. `is_signed` is clear on an `LHU` row by definition, so the
signed mask is the zero byte and the upper limbs are cleared. -/
theorem lhu_result_zero_extends
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row)
    (selector : row.isLhu = true) :
    row.result.word =
      Memory.zeroExtendHalf (Memory.selectHalf row.srcNext row.halfSelector) := by
  obtain ⟨isLb, isLh, _, _, _, _, _⟩ := lhu_flags row holds selector
  have isHalfLoad : row.isHalfLoad = true := by
    simp [LoadStoreRow.isHalfLoad, selector]
  have isSigned : row.isSigned = false := by
    simp [LoadStoreRow.isSigned, isLb, isLh]
  obtain ⟨limb2, limb3⟩ := holds.halfLoadExtension isHalfLoad
  rw [lhu_half_selected row holds selector]
  refine word_of_zero_extended_half row.result ?_ ?_
  · rw [limb2]; simp [LoadStoreRow.signMask, isSigned]
  · rw [limb3]; simp [LoadStoreRow.signMask, isSigned]

/-- C32-C37 with C61-C64 and C58-C60: an `LHU` row writes the zero-extended
selected halfword to `rd`. -/
theorem loadStoreHolds_lhu_retires_zero_extended_half
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    LhuRetiresZeroExtendedHalf row := by
  intro selector
  obtain ⟨_, _, _, _, isSb, isSh, isSw⟩ := lhu_flags row holds selector
  have isStore : row.isStore = false := by
    simp [LoadStoreRow.isStore, isSb, isSh, isSw]
  have isLoad : row.isLoad = true := by simp [LoadStoreRow.isLoad, isStore]
  have write :
      (loadStoreRetirement row).write =
        architecturalWrite row.r2Idx row.dstNext.word := by
    rw [loadStoreRetirement_load row isStore]
  rw [write, load_write_value row holds isLoad,
    lhu_result_zero_extends row holds selector]

/-! ## Control 1 — `LW` identity broken

*Delete `wordLoad` (C42-C45, load half); exhibit an `is_lw` row whose retired
word is not the memory word.*

C42-C45 on the load side are the only constraints in the entire family that
mention an `LW` row's `result` limbs: `opcode_b` and `opcode_h` are both clear,
so C18-C31 and C32-C41 are vacuous, and L14/L15 are gated on `is_lb` and
`is_lh`. `LW` is the identity load, so this single field is its whole
architectural content. With it deleted, `result` is free and C61-C64 dutifully
mirror whatever it holds into `rd`.

The witness below retires the low byte alone -- an `LW` that behaves as an
`LBU`. It is a different escape from the byte-transposition witness of the
family-level `wordLoad` control, and unlike that one its selector is `is_lw` and
the conclusion it refutes is guarded on `is_lw`.
-/

structure HoldsWithoutWordLoad (row : LoadStoreRow) : Prop where
  /-- The instruction clock of a placed row. -/
  clockPositive : 0 < row.clock
  /-- C00 and C69: `active * (active - 1) = 0` together with the placement
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
  -- C42-C45 on the load side, the identity of LW's four result limbs.
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
  /-- C71: `bus_value_57 = pc + 4`. -/
  nextPcResult : row.claimedNextPc = nextPc row.pc

/-- Deleting `wordLoad` really is a deletion: every honest row still
satisfies the weakened predicate, so the control is not about a predicate
nothing satisfies. -/
theorem loadStoreHolds_weakens_wordLoad
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    HoldsWithoutWordLoad row where
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

/-- The honest `LW x7, 4(x5)` row of `NonVacuity.lwRow`, which reads the aligned
word `0xeeff1234`, with its result and its destination truncated to the low byte
`0x34`.

Every surviving constraint still holds. `LW` sets no markers and neither
`opcode_b` nor `opcode_h` fires, so C18-C31, C32-C41, L14 and L15 are all
vacuous here; C10 is satisfied because `is_signed` and `src_msb` are both clear;
C15's word branch still sees `shift_amount = 0`; and C61-C64 still mirror
`result` into `rd`. Only the deleted C42-C45 objected. -/
def lwTruncatedRow : LoadStoreRow :=
  { lwRow with
    result := limbs 0x34 0x00 0x00 0x00
    dstNext := limbs 0x34 0x00 0x00 0x00 }

/-- The witness carries the `is_lw` selector, so this control is per-opcode
evidence for `LW` rather than for a sibling width of the family. -/
theorem lwTruncatedRow_isLw : lwTruncatedRow.isLw = true := rfl

theorem lwTruncatedRow_satisfies :
    HoldsWithoutWordLoad lwTruncatedRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

/-- The row writes `0x00000034` to `x7` where the memory word it emitted on the
bus is `0xeeff1234`. -/
theorem lwTruncatedRow_refutes : ¬ LwRetiresMemoryWord lwTruncatedRow := by
  intro claim
  have := claim rfl
  revert this
  decide

/-- The published control. -/
def lwIdentityBroken :
    MutationControl HoldsWithoutWordLoad LwRetiresMemoryWord where
  name := "lw-identity-broken"
  witness := lwTruncatedRow
  satisfies := lwTruncatedRow_satisfies
  refutes := lwTruncatedRow_refutes

/-- The deletion is not free: `LW`'s identity load cannot be recovered from the
remaining constraints. Unconditional -- the soundness hypothesis is discharged
by `loadStoreHolds_lw_retires_memory_word` rather than assumed. -/
theorem lw_identity_is_load_bearing :
    ¬ (∀ row, HoldsWithoutWordLoad row → LoadStoreHolds row) :=
  lwIdentityBroken.strictly_weaker LoadStoreHolds
    loadStoreHolds_lw_retires_memory_word

/-! ## Control 2 — `LHU` zero fill broken

*Delete `halfLoadExtension` (C32-C33); exhibit an `is_lhu` row that
sign-extends a negative halfword, i.e. behaves as `LH`.*

C10 is not the constraint that makes `LHU` unsigned. `signed_mask` is
`is_signed * src_msb * 255` and `is_signed = is_lb + is_lh`, so an `LHU` row's
mask is the zero byte whatever `src_msb` does; deleting C10 buys an attacker
nothing on this selector. The constraint that actually zero-fills `LHU` is
C32-C33, which pins the two upper result limbs to that zero mask. Delete it and
the upper half of an `LHU` result is unconstrained.

The witness takes the honest `LHU x7, 2(x5)` row over the negative halfword
`0x8000` and fills its upper limbs with `0xff`. That row is bit-for-bit the
answer `LH` owes on the same memory word, retired under the `is_lhu` selector:
this is the control that separates `LHU` from `LH`.
-/

structure HoldsWithoutHalfLoadExtension (row : LoadStoreRow) : Prop where
  /-- The instruction clock of a placed row. -/
  clockPositive : 0 < row.clock
  /-- C00 and C69: `active * (active - 1) = 0` together with the placement
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
  -- halfLoadExtension is deliberately absent: this is the mutation.
  -- C32-C33, the upper-limb fill of a halfword load.
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
  /-- C71: `bus_value_57 = pc + 4`. -/
  nextPcResult : row.claimedNextPc = nextPc row.pc

/-- Deleting `halfLoadExtension` really is a deletion. -/
theorem loadStoreHolds_weakens_halfLoadExtension
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    HoldsWithoutHalfLoadExtension row where
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
  baseLimbsCanonical := holds.baseLimbsCanonical
  byteLoadExtension := holds.byteLoadExtension
  byteLoadSelect := holds.byteLoadSelect
  byteStoreSelect := holds.byteStoreSelect
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

/-- The honest `LHU x7, 2(x5)` row of `NonVacuity.lhuRow`, which selects the
negative halfword `0x8000`, with its result and its destination sign-extended
instead of zero-extended.

Every surviving constraint still holds. C36-C37 (`halfLoadHigh`) still see the
correct halfword in the two low limbs, C34-C35 are gated on `shift_id = 1` and
are vacuous at `shift_id = 5`, L15 is gated on `is_lh`, and C10 is satisfied
because `src_msb` is clear. Only the deleted C32-C33 objected. -/
def lhuSignExtendedRow : LoadStoreRow :=
  { lhuRow with
    result := limbs 0x00 0x80 0xff 0xff
    dstNext := limbs 0x00 0x80 0xff 0xff }

/-- The witness carries the `is_lhu` selector. -/
theorem lhuSignExtendedRow_isLhu : lhuSignExtendedRow.isLhu = true := rfl

theorem lhuSignExtendedRow_satisfies :
    HoldsWithoutHalfLoadExtension lhuSignExtendedRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

/-- The row writes `0xffff8000` to `x7` where `LHU` owes `0x00008000`: exactly
the `LH` answer under an `LHU` selector. -/
theorem lhuSignExtendedRow_refutes :
    ¬ LhuRetiresZeroExtendedHalf lhuSignExtendedRow := by
  intro claim
  have := claim rfl
  revert this
  decide

/-- The published control. -/
def lhuZeroFillBroken :
    MutationControl HoldsWithoutHalfLoadExtension LhuRetiresZeroExtendedHalf where
  name := "lhu-zero-fill-broken"
  witness := lhuSignExtendedRow
  satisfies := lhuSignExtendedRow_satisfies
  refutes := lhuSignExtendedRow_refutes

/-- The deletion is not free: `LHU`'s zero fill, and with it the whole
`LHU`/`LH` distinction, cannot be recovered from the remaining constraints.
Unconditional -- the soundness hypothesis is discharged by
`loadStoreHolds_lhu_retires_zero_extended_half`. -/
theorem lhu_zero_fill_is_load_bearing :
    ¬ (∀ row, HoldsWithoutHalfLoadExtension row → LoadStoreHolds row) :=
  lhuZeroFillBroken.strictly_weaker LoadStoreHolds
    loadStoreHolds_lhu_retires_zero_extended_half

/-! ## Control 3 — wrong half selected on `LHU`

*Delete `halfLoadHigh` (C36-C37); exhibit an `is_lhu` row taking the other
halfword.*

C34-C37 are the halfword selection, split into a `shift_id = 1` gate and a
`shift_id = 5` gate. Nothing else in the family ties an `LHU` row's low result
limbs to the addressed half of the emitted word, so with the high gate deleted
an `LHU` addressing the high half may retire the low one. The address it
publishes on the memory bus, the word it emits there, its markers and its shift
amount are all unchanged -- only the halfword it claims to have selected moves.

The witness is the honest `LHU x7, 2(x5)` row over `0x8000`, retiring the low
halfword `0x2211` instead. This is the `LHU` counterpart of the family's
`lh-wrong-high-half` control, and unlike it, it carries the `is_lhu` selector.
-/

structure HoldsWithoutHalfLoadHigh (row : LoadStoreRow) : Prop where
  /-- The instruction clock of a placed row. -/
  clockPositive : 0 < row.clock
  /-- C00 and C69: `active * (active - 1) = 0` together with the placement
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
  -- C36-C37, the high-half selection gate of a halfword load.
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
  /-- C71: `bus_value_57 = pc + 4`. -/
  nextPcResult : row.claimedNextPc = nextPc row.pc

/-- Deleting `halfLoadHigh` really is a deletion. -/
theorem loadStoreHolds_weakens_halfLoadHigh
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    HoldsWithoutHalfLoadHigh row where
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

/-- The honest `LHU x7, 2(x5)` row of `NonVacuity.lhuRow`, addressing the high
halfword `0x8000` but retiring the low halfword `0x2211`.

Every surviving constraint still holds. C32-C33 (`halfLoadExtension`) are
satisfied because the upper limbs are still the zero mask, C34-C35 are gated on
`shift_id = 1` and are vacuous at `shift_id = 5`, C19/C20/C15 still see two
markers, `shift_id = 5` and `shift_amount = 2`, and C61-C64 still mirror
`result` into `rd`. Only the deleted C36-C37 objected. -/
def lhuWrongHalfRow : LoadStoreRow :=
  { lhuRow with
    result := limbs 0x11 0x22 0x00 0x00
    dstNext := limbs 0x11 0x22 0x00 0x00 }

/-- The witness carries the `is_lhu` selector, and it addresses the high half:
`shift_id = 5`, so the deleted gate is the one its own address opens. -/
theorem lhuWrongHalfRow_isLhu : lhuWrongHalfRow.isLhu = true := rfl

theorem lhuWrongHalfRow_addressesHighHalf : lhuWrongHalfRow.shiftId = 5 := rfl

theorem lhuWrongHalfRow_satisfies :
    HoldsWithoutHalfLoadHigh lhuWrongHalfRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

/-- The row writes `0x00002211` to `x7` where the halfword its own address
selects is `0x8000`. -/
theorem lhuWrongHalfRow_refutes :
    ¬ LhuRetiresZeroExtendedHalf lhuWrongHalfRow := by
  intro claim
  have := claim rfl
  revert this
  decide

/-- The published control. -/
def lhuWrongHalfSelected :
    MutationControl HoldsWithoutHalfLoadHigh LhuRetiresZeroExtendedHalf where
  name := "lhu-wrong-half-selected"
  witness := lhuWrongHalfRow
  satisfies := lhuWrongHalfRow_satisfies
  refutes := lhuWrongHalfRow_refutes

/-- The deletion is not free: `LHU`'s halfword selection cannot be recovered
from the remaining constraints. Unconditional -- the soundness hypothesis is
discharged by `loadStoreHolds_lhu_retires_zero_extended_half`. -/
theorem lhu_half_selection_is_load_bearing :
    ¬ (∀ row, HoldsWithoutHalfLoadHigh row → LoadStoreHolds row) :=
  lhuWrongHalfSelected.strictly_weaker LoadStoreHolds
    loadStoreHolds_lhu_retires_zero_extended_half

/-! ## What the three controls jointly certify

`lw_identity_is_load_bearing` is witnessed by a row whose `is_lw` flag is set
and refutes a conclusion guarded on `is_lw`; the two `LHU` theorems are
witnessed by rows whose `is_lhu` flag is set and refute a conclusion guarded on
`is_lhu`. Neither opcode's credit rests on a sibling selector.

All three corollaries are unconditional, and the witnesses are genuinely outside
the unweakened system: `MutationControl.witness_not_sound` turns each control
plus its proved soundness lemma into `¬ LoadStoreHolds witness` directly. -/

theorem lwTruncatedRow_not_sound : ¬ LoadStoreHolds lwTruncatedRow :=
  lwIdentityBroken.witness_not_sound LoadStoreHolds
    loadStoreHolds_lw_retires_memory_word

theorem lhuSignExtendedRow_not_sound : ¬ LoadStoreHolds lhuSignExtendedRow :=
  lhuZeroFillBroken.witness_not_sound LoadStoreHolds
    loadStoreHolds_lhu_retires_zero_extended_half

theorem lhuWrongHalfRow_not_sound : ¬ LoadStoreHolds lhuWrongHalfRow :=
  lhuWrongHalfSelected.witness_not_sound LoadStoreHolds
    loadStoreHolds_lhu_retires_zero_extended_half

end RiscvRefinement.Opcodes.LoadMutationWord
