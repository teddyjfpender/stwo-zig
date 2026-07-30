-- REVIEWED-CAPSULE BOUNDARY. Hand-written file; not generated, and not a
-- generated-Sail theorem. The architectural conclusions the controls in this
-- file certify -- LB's sign-extended byte and LBU's zero-extended byte -- are
-- stated against the reviewed normalized capsule
-- RiscvRefinement/Sail/Reviewed/LoadStore.lean, which is hand-written with no
-- generator, no digest, and no derivation from any Sail artifact (see its
-- header). Nothing in this file is publication-level for the architectural
-- side.

import RiscvRefinement.Air.Family.LoadStore
import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.LoadStore
import RiscvRefinement.Opcodes.LoadStoreMutationExtra

/-!
# Per-opcode load-bearing mutation controls for `LB` and `LBU`

`Opcodes/LoadStoreMutationExtra.lean` publishes six controls for the
`load_store` family, and every one of them is unconditional. What none of them
does is separate `LB` from `LBU`: their conclusion,
`LoadStoreResultIsArchitectural`, is the family-wide result specification, so a
control refuting it certifies the *family* rather than either byte-load opcode.
Per-opcode credit for `LB` and `LBU` was refused on exactly that ground.

This file supplies what was missing. The two conclusions here are

* guarded on `row.isLb` and `row.isLbu` **specifically** — not on the
  family-level `isByteLoad`, which is the guard that made the earlier controls
  family-granular. An honest row of any other opcode satisfies each conclusion
  by the guard, which is what lets the soundness hypotheses be proved for the
  whole family at once;
* row-parameterised — the right-hand side is the row's **own** emitted memory
  word `row.srcNext` at the byte offset the row's **own** `shift_amount`
  selects. No constant appears. A conclusion pinned to a constant is false of
  nearly every row, which makes its soundness hypothesis false and every
  corollary drawn through it vacuous; that failure has been found twice in this
  development and is not repeated here;
* stated in the reviewed capsule's byte-load semantics,
  `Sail.Reviewed.loadByteSignedValue` and `Sail.Reviewed.loadByteUnsignedValue`,
  quantified over every architectural `(base, imm)` pair whose effective address
  carries the byte offset the row published. That is the same claim `lb_refines`
  and `lbu_refines` discharge, so it is an architectural fact rather than a
  restatement of any constraint deleted below.

Each of the four controls deletes exactly one field of
`Air.Family.LoadStoreHolds`, copies every other field verbatim, proves the
deletion is a real weakening, exhibits a row that carries the `is_lb` or
`is_lbu` selector and passes everything that is left, and refutes the
per-opcode conclusion. Soundness is proved in this file, so every
`..._is_load_bearing` corollary here is unconditional.

| control | deleted constraint | selector the witness carries |
| --- | --- | --- |
| `lb-zero-extended-negative-byte` | `byteSignWitness` (L14) | `is_lb` |
| `lbu-sign-filled-byte` | `byteLoadExtension` (C21-C23) | `is_lbu` |
| `lb-wrong-byte-offset` | `byteLoadSelect` (C24-C30) | `is_lb` |
| `lbu-wrong-byte-offset` | `byteLoadSelect` (C24-C30) | `is_lbu` |

The first two are the pair that separates the two opcodes: the first is an
`LB` row that zero-extends a negative byte, that is, an `LB` behaving as `LBU`;
the second is an `LBU` row that sign-fills, that is, an `LBU` behaving as `LB`.

## Why the mirror control deletes C21-C23 and not C10

The natural reading of "sign asserted on an unsigned load" is to delete C10
(`signWitnessCanonical`, `(1 - is_signed) * src_msb = 0`) and let an `LBU` row
claim `src_msb = true`. In this transcription that control does not exist, and
the reason is structural rather than an oversight. `signed_mask` is the derived
column `is_signed * src_msb * 255`, transcribed as
`LoadStoreRow.signMask`, and `is_signed = is_lb + is_lh` is clear on an `LBU`
row. So `signed_mask` is zero on an `LBU` row **whatever `src_msb` says**, and
C21-C23 still force the three upper result limbs to zero: releasing C10 changes
no architectural quantity of an `LBU` row at all. Its whole content there is
canonicalisation of a witness column that only L14 and L15 — both gated on
`is_lb` and `is_lh` — ever read. Deleting it and refuting `src_msb = false`
would be a restatement of the deleted constraint, which the `MutationControl`
contract forbids.

The constraint that actually stands between `LBU` and a sign-filled result is
therefore C21-C23, and `lbu-sign-filled-byte` deletes that. It is not a
restatement of its own deletion either: C21-C23 tie three result limbs to
`signed_mask` and say nothing about which byte is selected or about
`zeroExtendByte`, while the conclusion is the complete architectural load value
of the opcode.

Everything lives in the `ByteLoadMutation` sub-namespace so that these names
never collide with the family controls in `Opcodes/LoadStoreMutation.lean` and
`Opcodes/LoadStoreMutationExtra.lean`.
-/

namespace RiscvRefinement.Opcodes.ByteLoadMutation

open RiscvRefinement
open RiscvRefinement.Air.Family
open RiscvRefinement.Mutation
open RiscvRefinement.Sail.Reviewed
open RiscvRefinement.Opcodes
open RiscvRefinement.Opcodes.NonVacuity

/-! ## The two per-opcode architectural conclusions

Both are stated through the reviewed capsule. The capsule's byte-load value
takes an architectural `(base, imm)` pair and reads the byte at
`Memory.byteOffset (Memory.effectiveAddress base imm)`; a row publishes its
offset as `row.byteOffset`, so the claim is made for exactly those `(base, imm)`
pairs that address the byte the row says it addresses. Quantifying rather than
naming one pair is what keeps the conclusion free of constants while still
being a statement about the row in front of it. -/

/-- `LB`'s architectural retirement value: the sign extension of the selected
byte of the row's own memory word, in the reviewed capsule's own words.

Guarded on `is_lb` alone. Dropping the guard would assert the signed byte value
of every row of the family, which an honest `LBU`, `LH` or store row refutes;
the soundness hypothesis would then be false and every corollary below
vacuous. -/
def LbRetiresSignedByte (row : LoadStoreRow) : Prop :=
  row.isLb = true →
    ∀ (base : Word) (imm : BitVec 12),
      Memory.byteOffset (Memory.effectiveAddress base imm) = row.byteOffset →
        row.result.word = loadByteSignedValue base imm row.srcNext

/-- `LBU`'s architectural retirement value: the zero extension of the same
selected byte. Guarded on `is_lbu` alone, for the same reason. -/
def LbuRetiresUnsignedByte (row : LoadStoreRow) : Prop :=
  row.isLbu = true →
    ∀ (base : Word) (imm : BitVec 12),
      Memory.byteOffset (Memory.effectiveAddress base imm) = row.byteOffset →
        row.result.word = loadByteUnsignedValue base imm row.srcNext

/-! ### Soundness, discharged here rather than assumed

A control is worth exactly as much as its soundness hypothesis is true: if
`∀ row, LoadStoreHolds row → Conclusion row` is false then the corollary drawn
from the control certifies nothing. Both hypotheses are therefore proved.

`row_lb_result` and `row_lbu_result` of `Opcodes/LoadStoreMutationExtra.lean`
are the row-relative forms of the family's `lb_result_value` and
`lbu_result_value`: they consume only `LoadStoreHolds` and no decoding
environment, which is what lets these two hold of *every* row. All that is
added here is the capsule's address plumbing. -/

/-- `LB` soundness: C21-C30 with L14 give the sign extension of the selected
byte, and the capsule reads that same byte whenever the offsets agree. -/
theorem loadStoreHolds_lb_retires_signed_byte
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    LbRetiresSignedByte row := by
  intro selector base imm addresses
  unfold loadByteSignedValue
  rw [addresses]
  exact row_lb_result row holds selector

/-- `LBU` soundness: C21-C30 with a clear `is_signed` give the zero
extension. -/
theorem loadStoreHolds_lbu_retires_unsigned_byte
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    LbuRetiresUnsignedByte row := by
  intro selector base imm addresses
  unfold loadByteUnsignedValue
  rw [addresses]
  exact row_lbu_result row holds selector

/-! The honest witnesses of `Opcodes/LoadStore.lean` satisfy both conclusions.
This is the anchor that fixes the conclusions as claims about real rows before
any deletion is made. -/

theorem lbRow_retires_signed_byte : LbRetiresSignedByte lbRow :=
  loadStoreHolds_lb_retires_signed_byte lbRow lb_holds

theorem lbuRow_retires_unsigned_byte : LbuRetiresUnsignedByte lbuRow :=
  loadStoreHolds_lbu_retires_unsigned_byte lbuRow lbu_holds

/-! ## Control 1 — an `LB` that zero-extends a negative byte

*Delete `byteSignWitness` (L14); exhibit an `is_lb` row that returns the `LBU`
answer.*

L14 range-checks `result_0 - 128 * src_msb` into seven bits, which is what makes
`src_msb` **be** bit seven of the byte `LB` selected. Delete it and `src_msb`
floats free of the loaded byte. Lowering it clears `signed_mask`, so C21-C23 are
satisfied by cleared upper limbs, and the signed byte load returns the
zero-extension that belongs to the unsigned one: the two opcodes become
interchangeable under an `is_lb` selector. -/

structure ByteLoadHoldsWithoutByteSignWitness (row : LoadStoreRow) : Prop where
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
theorem byteLoadHolds_weakens_byteSignWitness
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    ByteLoadHoldsWithoutByteSignWitness row where
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
and destination replaced by the **zero** extension of that byte.

The `is_lb` selector is untouched, so this is an `LB` row throughout. Every
surviving constraint still holds: `signed_mask` is zero because `src_msb` is, so
C21-C23 accept the cleared upper limbs; C24-C30 still see the correct byte
`0x9c` in `result_0`; C61-C64 still mirror `result` into `rd`. Only the deleted
L14 witness objected. -/
def lbZeroExtendedByteRow : LoadStoreRow :=
  { lbRow with
    srcMsb := false
    result := limbs 0x9c 0x00 0x00 0x00
    dstNext := limbs 0x9c 0x00 0x00 0x00 }

theorem lbZeroExtendedByteRow_is_lb : lbZeroExtendedByteRow.isLb = true := rfl

theorem lbZeroExtendedByteRow_satisfies :
    ByteLoadHoldsWithoutByteSignWitness lbZeroExtendedByteRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

/-- And the deleted field is exactly the one it fails, stated as the L14
residual itself. Together with `lbZeroExtendedByteRow_satisfies` this pins the
counterexample to this deletion and no other. -/
theorem lbZeroExtendedByteRow_violates_byteSignWitness :
    ¬ (lbZeroExtendedByteRow.isLb = true →
        lbZeroExtendedByteRow.srcMsb =
          lbZeroExtendedByteRow.result.limb0.getLsbD 7) := by
  decide

/-- The row retires `0x0000009c` where `LB` owes `0xffffff9c`. -/
theorem lbZeroExtendedByteRow_refutes :
    ¬ LbRetiresSignedByte lbZeroExtendedByteRow := by
  intro claim
  have value :=
    claim lbZeroExtendedByteRow_is_lb (BitVec.ofNat 32 1) (BitVec.ofNat 12 0)
      (by decide)
  revert value
  decide

/-- What the row retires is exactly the `LBU` answer, under an `is_lb`
selector: this control is the one that separates the two byte loads. -/
theorem lbZeroExtendedByteRow_is_the_lbu_answer :
    lbZeroExtendedByteRow.result.word =
      Memory.zeroExtendByte
        (Memory.selectByte lbZeroExtendedByteRow.srcNext
          lbZeroExtendedByteRow.byteOffset) := by
  decide

/-- The published control. -/
def lbZeroExtendedNegativeByte :
    MutationControl ByteLoadHoldsWithoutByteSignWitness LbRetiresSignedByte where
  name := "lb-zero-extended-negative-byte"
  witness := lbZeroExtendedByteRow
  satisfies := lbZeroExtendedByteRow_satisfies
  refutes := lbZeroExtendedByteRow_refutes

/-- The deletion is not free for `LB` specifically: `LB`'s sign extension cannot
be recovered from the remaining constraints. Unconditional — the soundness
hypothesis is discharged by `loadStoreHolds_lb_retires_signed_byte` rather than
assumed. -/
theorem lb_byte_sign_witness_is_load_bearing :
    ¬ (∀ row, ByteLoadHoldsWithoutByteSignWitness row → LoadStoreHolds row) :=
  lbZeroExtendedNegativeByte.strictly_weaker LoadStoreHolds
    loadStoreHolds_lb_retires_signed_byte

/-- The same fact in the per-opcode form, with the selector and the opcode's own
conclusion visible in the statement rather than only in the proof term: a row
that **carries `is_lb`** survives the deletion and gets `LB`'s architectural
value wrong. This is the shape the family-granular controls of
`Opcodes/LoadStoreMutationExtra.lean` cannot take, and the reason per-opcode
credit was refused for `LB` before this file. -/
theorem lb_byte_sign_witness_is_load_bearing_for_lb :
    ∃ row, row.isLb = true ∧ ByteLoadHoldsWithoutByteSignWitness row ∧
      ¬ LbRetiresSignedByte row :=
  ⟨lbZeroExtendedByteRow, lbZeroExtendedByteRow_is_lb,
    lbZeroExtendedByteRow_satisfies, lbZeroExtendedByteRow_refutes⟩

/-! ## Control 2 — an `LBU` that sign-fills

*Delete `byteLoadExtension` (C21-C23); exhibit an `is_lbu` row that returns the
`LB` answer.*

This is the mirror of Control 1. C21-C23 are the only constraints tying the
three upper result limbs of a byte load to `signed_mask`, and on an `LBU` row
`signed_mask` is zero because `is_signed = is_lb + is_lh` is. Delete them and
the upper limbs are free, so the unsigned byte load may fill them with `0xff`
and retire the sign extension that belongs to `LB`. The byte selection C24-C30
is untouched and still sees `0x9c` in `result_0`, so the row differs from the
honest one in exactly the extension.

The conclusion is not a restatement of this deletion. C21-C23 relate three
committed limbs to the derived `signed_mask` column and say nothing about which
byte the row selected or about `zeroExtendByte`, while `LbuRetiresUnsignedByte`
is the complete architectural load value of the opcode in the reviewed capsule's
vocabulary — the claim `lbu_refines` discharges. That is the same standing the
published `lw-swapped-endian-bytes` and `lh-wrong-high-half` controls have
against their own deletions. -/

structure ByteLoadHoldsWithoutByteLoadExtension (row : LoadStoreRow) : Prop where
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
  -- byteLoadExtension is deliberately absent: this is the mutation.
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

/-- Deleting `byteLoadExtension` really is a deletion. -/
theorem byteLoadHolds_weakens_byteLoadExtension
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    ByteLoadHoldsWithoutByteLoadExtension row where
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

/-- The honest `LBU x7, 5(x5)` row of `NonVacuity.lbuRow`, reading the same byte
`0x9c` at offset one, with its result and destination sign-filled.

The `is_lbu` selector is untouched. `src_msb` stays clear, so C10 is satisfied;
`is_lb` is clear, so L14 is vacuous; C24-C30 still place `0x9c` in `result_0`;
C61-C64 still mirror `result` into `rd`. Only the deleted C21-C23 objected. -/
def lbuSignFilledByteRow : LoadStoreRow :=
  { lbuRow with
    result := limbs 0x9c 0xff 0xff 0xff
    dstNext := limbs 0x9c 0xff 0xff 0xff }

theorem lbuSignFilledByteRow_is_lbu : lbuSignFilledByteRow.isLbu = true := rfl

theorem lbuSignFilledByteRow_satisfies :
    ByteLoadHoldsWithoutByteLoadExtension lbuSignFilledByteRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

/-- The deleted field is exactly the one it fails. -/
theorem lbuSignFilledByteRow_violates_byteLoadExtension :
    ¬ (lbuSignFilledByteRow.isByteLoad = true →
        lbuSignFilledByteRow.result.limb1 = lbuSignFilledByteRow.signMask ∧
          lbuSignFilledByteRow.result.limb2 = lbuSignFilledByteRow.signMask ∧
            lbuSignFilledByteRow.result.limb3 =
              lbuSignFilledByteRow.signMask) := by
  decide

/-- The row retires `0xffffff9c` where `LBU` owes `0x0000009c`. -/
theorem lbuSignFilledByteRow_refutes :
    ¬ LbuRetiresUnsignedByte lbuSignFilledByteRow := by
  intro claim
  have value :=
    claim lbuSignFilledByteRow_is_lbu (BitVec.ofNat 32 1) (BitVec.ofNat 12 0)
      (by decide)
  revert value
  decide

/-- What the row retires is exactly the `LB` answer, under an `is_lbu`
selector: the mirror of `lbZeroExtendedByteRow_is_the_lbu_answer`. -/
theorem lbuSignFilledByteRow_is_the_lb_answer :
    lbuSignFilledByteRow.result.word =
      Memory.signExtendByte
        (Memory.selectByte lbuSignFilledByteRow.srcNext
          lbuSignFilledByteRow.byteOffset) := by
  decide

/-- The published control. -/
def lbuSignFilledByte :
    MutationControl ByteLoadHoldsWithoutByteLoadExtension
      LbuRetiresUnsignedByte where
  name := "lbu-sign-filled-byte"
  witness := lbuSignFilledByteRow
  satisfies := lbuSignFilledByteRow_satisfies
  refutes := lbuSignFilledByteRow_refutes

/-- The deletion is not free for `LBU` specifically: `LBU`'s zero extension
cannot be recovered from the remaining constraints. Unconditional — the
soundness hypothesis is discharged by
`loadStoreHolds_lbu_retires_unsigned_byte`. -/
theorem lbu_byte_load_extension_is_load_bearing :
    ¬ (∀ row, ByteLoadHoldsWithoutByteLoadExtension row → LoadStoreHolds row) :=
  lbuSignFilledByte.strictly_weaker LoadStoreHolds
    loadStoreHolds_lbu_retires_unsigned_byte

/-- The per-opcode form: a row that **carries `is_lbu`** survives the deletion
and gets `LBU`'s architectural value wrong. -/
theorem lbu_byte_load_extension_is_load_bearing_for_lbu :
    ∃ row, row.isLbu = true ∧ ByteLoadHoldsWithoutByteLoadExtension row ∧
      ¬ LbuRetiresUnsignedByte row :=
  ⟨lbuSignFilledByteRow, lbuSignFilledByteRow_is_lbu,
    lbuSignFilledByteRow_satisfies, lbuSignFilledByteRow_refutes⟩

/-! ## Controls 3 and 4 — the wrong byte of the aligned word

*Delete `byteLoadSelect` (C24, C26, C28, C30); exhibit `is_lb` and `is_lbu` rows
whose `result_0` is the byte at an offset the row never addressed.*

C24-C30 are the only constraints that tie a byte load's `result_0` to a limb of
the memory word. The markers, `marker_sum` (C18) and `shift_amount` (C15) still
agree with each other and with the effective address after the deletion — the
row keeps publishing offset one — so nothing left in the system notices that
`result_0` now carries the byte at offset zero. The extension machinery is
untouched, so each witness differs from its honest counterpart in the selected
byte alone.

One deletion, two witnesses: the same weakened predicate is refuted once under
each selector, which is what makes the two corollaries per-opcode rather than
family-wide. -/

structure ByteLoadHoldsWithoutByteLoadSelect (row : LoadStoreRow) : Prop where
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
  -- byteLoadSelect is deliberately absent: this is the mutation.
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

/-- Deleting `byteLoadSelect` really is a deletion. -/
theorem byteLoadHolds_weakens_byteLoadSelect
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    ByteLoadHoldsWithoutByteLoadSelect row where
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

/-- The honest `LB x7, 5(x5)` row of `NonVacuity.lbRow`, still addressing offset
one of the aligned word at `0x104`, but retiring the byte at offset **zero**,
`0x34`, sign-extended.

`0x34` is non-negative, so lowering `src_msb` keeps L14 and C21-C23 consistent
with the forged result. The markers, `marker_sum`, `shift_id` and
`shift_amount` are all left exactly as the honest row published them, so the row
still names the byte at offset one on the address side. -/
def lbWrongByteRow : LoadStoreRow :=
  { lbRow with
    srcMsb := false
    result := limbs 0x34 0x00 0x00 0x00
    dstNext := limbs 0x34 0x00 0x00 0x00 }

theorem lbWrongByteRow_is_lb : lbWrongByteRow.isLb = true := rfl

theorem lbWrongByteRow_satisfies :
    ByteLoadHoldsWithoutByteLoadSelect lbWrongByteRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

/-- The deleted field is exactly the one it fails: marker one is set, so C26
demanded `result_0 = src_next_1`. -/
theorem lbWrongByteRow_violates_byteLoadSelect :
    ¬ (lbWrongByteRow.isByteLoad = true →
        (lbWrongByteRow.marker0 = true →
            lbWrongByteRow.result.limb0 = lbWrongByteRow.srcNext.limb0) ∧
          (lbWrongByteRow.marker1 = true →
              lbWrongByteRow.result.limb0 = lbWrongByteRow.srcNext.limb1) ∧
            (lbWrongByteRow.marker2 = true →
                lbWrongByteRow.result.limb0 = lbWrongByteRow.srcNext.limb2) ∧
              (lbWrongByteRow.marker3 = true →
                lbWrongByteRow.result.limb0 = lbWrongByteRow.srcNext.limb3)) := by
  decide

/-- The row retires `0x00000034` where `LB` at offset one owes `0xffffff9c`. -/
theorem lbWrongByteRow_refutes : ¬ LbRetiresSignedByte lbWrongByteRow := by
  intro claim
  have value :=
    claim lbWrongByteRow_is_lb (BitVec.ofNat 32 1) (BitVec.ofNat 12 0)
      (by decide)
  revert value
  decide

/-- The published control for `LB`. -/
def lbWrongByteOffset :
    MutationControl ByteLoadHoldsWithoutByteLoadSelect LbRetiresSignedByte where
  name := "lb-wrong-byte-offset"
  witness := lbWrongByteRow
  satisfies := lbWrongByteRow_satisfies
  refutes := lbWrongByteRow_refutes

/-- The honest `LBU x7, 5(x5)` row of `NonVacuity.lbuRow`, retiring the byte at
offset **zero**, `0x34`, zero-extended, while still addressing offset one. -/
def lbuWrongByteRow : LoadStoreRow :=
  { lbuRow with
    result := limbs 0x34 0x00 0x00 0x00
    dstNext := limbs 0x34 0x00 0x00 0x00 }

theorem lbuWrongByteRow_is_lbu : lbuWrongByteRow.isLbu = true := rfl

theorem lbuWrongByteRow_satisfies :
    ByteLoadHoldsWithoutByteLoadSelect lbuWrongByteRow := by
  constructor <;> first | decide | (unfold validPreviousClock; decide)

/-- The deleted field is exactly the one it fails. -/
theorem lbuWrongByteRow_violates_byteLoadSelect :
    ¬ (lbuWrongByteRow.isByteLoad = true →
        (lbuWrongByteRow.marker0 = true →
            lbuWrongByteRow.result.limb0 = lbuWrongByteRow.srcNext.limb0) ∧
          (lbuWrongByteRow.marker1 = true →
              lbuWrongByteRow.result.limb0 = lbuWrongByteRow.srcNext.limb1) ∧
            (lbuWrongByteRow.marker2 = true →
                lbuWrongByteRow.result.limb0 = lbuWrongByteRow.srcNext.limb2) ∧
              (lbuWrongByteRow.marker3 = true →
                lbuWrongByteRow.result.limb0 =
                  lbuWrongByteRow.srcNext.limb3)) := by
  decide

/-- The row retires `0x00000034` where `LBU` at offset one owes
`0x0000009c`. -/
theorem lbuWrongByteRow_refutes : ¬ LbuRetiresUnsignedByte lbuWrongByteRow := by
  intro claim
  have value :=
    claim lbuWrongByteRow_is_lbu (BitVec.ofNat 32 1) (BitVec.ofNat 12 0)
      (by decide)
  revert value
  decide

/-- The published control for `LBU`. -/
def lbuWrongByteOffset :
    MutationControl ByteLoadHoldsWithoutByteLoadSelect
      LbuRetiresUnsignedByte where
  name := "lbu-wrong-byte-offset"
  witness := lbuWrongByteRow
  satisfies := lbuWrongByteRow_satisfies
  refutes := lbuWrongByteRow_refutes

/-- The deletion is not free for `LB`: byte selection cannot be recovered from
the remaining constraints. Unconditional. -/
theorem lb_byte_load_select_is_load_bearing :
    ¬ (∀ row, ByteLoadHoldsWithoutByteLoadSelect row → LoadStoreHolds row) :=
  lbWrongByteOffset.strictly_weaker LoadStoreHolds
    loadStoreHolds_lb_retires_signed_byte

/-- The same deletion, refuted independently under the `is_lbu` selector and
through `LBU`'s own conclusion. The two corollaries share a statement because
they weaken the same predicate; they do not share a proof, and it is the proof
that carries the opcode. The two theorems below say which. -/
theorem lbu_byte_load_select_is_load_bearing :
    ¬ (∀ row, ByteLoadHoldsWithoutByteLoadSelect row → LoadStoreHolds row) :=
  lbuWrongByteOffset.strictly_weaker LoadStoreHolds
    loadStoreHolds_lbu_retires_unsigned_byte

/-- The per-opcode form for `LB`. -/
theorem lb_byte_load_select_is_load_bearing_for_lb :
    ∃ row, row.isLb = true ∧ ByteLoadHoldsWithoutByteLoadSelect row ∧
      ¬ LbRetiresSignedByte row :=
  ⟨lbWrongByteRow, lbWrongByteRow_is_lb, lbWrongByteRow_satisfies,
    lbWrongByteRow_refutes⟩

/-- The per-opcode form for `LBU`. -/
theorem lbu_byte_load_select_is_load_bearing_for_lbu :
    ∃ row, row.isLbu = true ∧ ByteLoadHoldsWithoutByteLoadSelect row ∧
      ¬ LbuRetiresUnsignedByte row :=
  ⟨lbuWrongByteRow, lbuWrongByteRow_is_lbu, lbuWrongByteRow_satisfies,
    lbuWrongByteRow_refutes⟩

/-! ## Published identities

The stable names the Team B certificate index refers to. -/

theorem byte_load_mutation_control_names :
    lbZeroExtendedNegativeByte.name = "lb-zero-extended-negative-byte" ∧
      lbuSignFilledByte.name = "lbu-sign-filled-byte" ∧
      lbWrongByteOffset.name = "lb-wrong-byte-offset" ∧
      lbuWrongByteOffset.name = "lbu-wrong-byte-offset" :=
  ⟨rfl, rfl, rfl, rfl⟩

/-- Every witness in this file carries the opcode selector its conclusion is
guarded on. This is the property the family-granular controls of
`Opcodes/LoadStoreMutationExtra.lean` do not establish, and it is what makes the
four corollaries above per-opcode. -/
theorem byte_load_mutation_witness_selectors :
    lbZeroExtendedNegativeByte.witness.isLb = true ∧
      lbuSignFilledByte.witness.isLbu = true ∧
      lbWrongByteOffset.witness.isLb = true ∧
      lbuWrongByteOffset.witness.isLbu = true :=
  ⟨rfl, rfl, rfl, rfl⟩

end RiscvRefinement.Opcodes.ByteLoadMutation
