-- REVIEWED-CAPSULE BOUNDARY. Hand-written file; not generated, and not a
-- generated-Sail theorem. The architectural conclusions these mutation
-- controls certify are stated against the reviewed normalized capsule
-- RiscvRefinement/Sail/Reviewed/Shifts.lean, which is hand-written with no
-- generator, no digest, and no derivation from any Sail artifact (see its
-- boundary note). Nothing in this file is publication-level for the
-- architectural side.

import RiscvRefinement.Air.Family.Shifts
import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.Shifts

/-!
# Load-bearing mutation controls for the six shift opcodes

Issue #137 names four required shift mutations. This file is those four
controls, one per deleted constraint, each a `MutationControl`: a concrete row
that satisfies the shift row predicate with exactly one constraint removed and
still retires the wrong architectural value.

| control | deleted constraint | opcodes certified |
| --- | --- | --- |
| `sraiReleasedSign` | lookup 15 / 19, lower half | `SRAI`, `SRA` |
| `slliFreeShiftAmount` | constraint 65 | `SLLI`, `SRLI`, `SRAI` |
| `srliLogicalArithmeticConfusion` | constraint 5 | `SRLI`, `SRL` |
| `sllFreeResultLowByte` | constraint 22 | `SLL`, `SLLI` |

Three of the four delete a constraint of the *shared* `shift_common.zig` layer,
so each of those also certifies the sibling family: `ShiftHolds` is embedded
verbatim by both `ShiftsImmHolds` and `ShiftsRegHolds`, and a counterexample to
the shared layer lifts to either.

## Stronger than the `MUL` and `LH` controls

`mul_product_limb0_is_load_bearing` and `lh_high_half_selection_is_load_bearing`
take the soundness of the unweakened predicate as a hypothesis, because their
architectural conclusion is only reachable through a decode environment. The
four conclusions below are stated purely in terms of the row -- the source
operand is read off `rs1_previous`, which `sourceReadOnly` and the register
lookup pin to the architectural `X(rs1)` -- so soundness is *proved* here rather
than assumed, and every `..._is_load_bearing` corollary is unconditional.

## Non-circularity

Every conclusion is a retirement equality against the reviewed architectural
capsule `RiscvRefinement/Sail/Reviewed/Shifts.lean`, i.e. the claim the
`*_refines` theorems reach. None of them restates the deleted constraint, so no
control degenerates into "deleting a constraint makes that constraint false".
-/

namespace RiscvRefinement.Opcodes

open RiscvRefinement
open RiscvRefinement.Air.Family
open RiscvRefinement.Mutation
open RiscvRefinement.Sail.Reviewed

/-- Little-endian byte literal helper, local to the controls so the witnesses do
not depend on the layout of any other witness block. -/
def mutationBytes (b0 b1 b2 b3 : Nat) : WordBytes where
  limb0 := BitVec.ofNat 8 b0
  limb1 := BitVec.ofNat 8 b1
  limb2 := BitVec.ofNat 8 b2
  limb3 := BitVec.ofNat 8 b3

/-! ## Control 1: the released sign witness (`SRAI`, `SRA`)

Lookup 15 of `shifts_imm` and lookup 19 of `shifts_reg` both request
`range_check_m31 (0, rs1_next_3 - 128 * rs1_sign)` on an `is_sra` row. The `m31`
range check carries two halves: the requested residue is non-negative, which is
`128 * rs1_sign ≤ rs1_next_3`, and it is a seven-bit value, which is
`rs1_next_3 < 128 * rs1_sign + 128`. The capsule transcribes them as the two
fields `signLowerBound` and `signUpperBound`.

`signLowerBound` is the half that forbids claiming a sign fill on a
*non-negative* operand. Delete it and an `SRAI` row can set `rs1_sign = 1` with
`rs1_next_3 = 0`, which drives the `255 * rs1_sign` fill of the discarded limbs
and sign-fills a positive operand. -/

/-- `ShiftHolds` with the lower half of the sign range check deleted, and
nothing else changed. -/
structure ShiftHoldsWithoutSignLowerBound (row : ShiftRow) : Prop where
  /-- `limb_markers_hot`. -/
  limbIndexRange : row.limbIndex < 4
  /-- `bit_markers_hot`. -/
  bitIndexRange : row.bitIndex < 8
  /-- Constraint 5, `(1 - is_sra) * rs1_sign = 0`: only an arithmetic right
  shift may carry a sign witness, so every other kind zero-fills. -/
  signIsLogicalZero : row.kind ≠ ShiftKind.sra → row.rs1Sign = false
  -- signLowerBound is deliberately absent: this is the mutation. It is the
  -- non-negativity half of lookup 15 / 19,
  -- `range_check_m31 (0, rs1_next_3 - 128 * rs1_sign)`.
  /-- Lookup 15 / 19, `range_check_m31 (0, rs1_next_3 - 128 * rs1_sign)`: the
  residue is a seven-bit value. Requested only on `is_sra` rows. -/
  signUpperBound :
    row.kind = ShiftKind.sra →
      row.rs1Next.limb3.toNat < 128 * row.signNat + 128
  /-- `carryRangePairs`: `range_check_8_8 (carry_k, bit_multiplier - carry_k -
  1)` makes both components bytes, which on an active row is exactly
  `carry_k < bit_multiplier`. -/
  carry0Range : row.carry0 < row.multiplier
  carry1Range : row.carry1 < row.multiplier
  carry2Range : row.carry2 < row.multiplier
  carry3Range : row.carry3 < row.multiplier
  /-- Constraints 61-64, `readOnlyAccessConstraints(rs1, enabler)`. -/
  sourceReadOnly : row.rs1Next = row.rs1Previous
  /-- Constraints 22-37. -/
  leftMovement :
    row.kind = ShiftKind.sll →
      shiftLeftEquations row.limbIndex row.multiplier row.rs1Next row.result
        row.carry0 row.carry1 row.carry2 row.carry3
  /-- Constraints 38-53. -/
  rightMovement :
    row.kind ≠ ShiftKind.sll →
      shiftRightEquations row.limbIndex row.multiplier row.signNat
        row.rs1Next row.result row.carry0 row.carry1 row.carry2 row.carry3
  /-- Constraints 54-56, `destinationConstraints`. -/
  destinationFlag : row.rdNonzero = decide (row.rd ≠ zeroRegister)
  /-- Constraints 57-60, `destinationResultConstraints`. -/
  destinationLimb0 :
    row.rdNext.limb0 =
      if row.rdNonzero then row.result.limb0 else WordBytes.zero.limb0
  destinationLimb1 :
    row.rdNext.limb1 =
      if row.rdNonzero then row.result.limb1 else WordBytes.zero.limb1
  destinationLimb2 :
    row.rdNext.limb2 =
      if row.rdNonzero then row.result.limb2 else WordBytes.zero.limb2
  destinationLimb3 :
    row.rdNext.limb3 =
      if row.rdNonzero then row.result.limb3 else WordBytes.zero.limb3

/-- The deletion is a real weakening of the shared layer: every honest shift row
still satisfies it. Without this the control could be about a predicate nothing
satisfies. -/
theorem shiftHolds_weakens_signLowerBound
    (row : ShiftRow)
    (holds : ShiftHolds row) :
    ShiftHoldsWithoutSignLowerBound row where
  limbIndexRange := holds.limbIndexRange
  bitIndexRange := holds.bitIndexRange
  signIsLogicalZero := holds.signIsLogicalZero
  signUpperBound := holds.signUpperBound
  carry0Range := holds.carry0Range
  carry1Range := holds.carry1Range
  carry2Range := holds.carry2Range
  carry3Range := holds.carry3Range
  sourceReadOnly := holds.sourceReadOnly
  leftMovement := holds.leftMovement
  rightMovement := holds.rightMovement
  destinationFlag := holds.destinationFlag
  destinationLimb0 := holds.destinationLimb0
  destinationLimb1 := holds.destinationLimb1
  destinationLimb2 := holds.destinationLimb2
  destinationLimb3 := holds.destinationLimb3

/-- `ShiftsImmHolds` with the shared layer weakened by exactly that one
deletion; the four immediate-family constraints are copied verbatim. -/
structure ShiftsImmHoldsWithoutSignLowerBound (row : ShiftsImmRow) : Prop where
  core : ShiftHoldsWithoutSignLowerBound row.semantic
  clockPositive : 0 < row.clock
  sourceClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 2)
  /-- Constraint 65: `imm_truncated - shift_amount = 0`. -/
  immediateBinds : row.immTruncated = row.semantic.shiftAmount
  nextPcResult : row.claimedNextPc = nextPc row.pc

theorem shiftsImmHolds_weakens_signLowerBound
    (row : ShiftsImmRow)
    (holds : ShiftsImmHolds row) :
    ShiftsImmHoldsWithoutSignLowerBound row where
  core := shiftHolds_weakens_signLowerBound row.semantic holds.core
  clockPositive := holds.clockPositive
  sourceClock := holds.sourceClock
  destinationClock := holds.destinationClock
  immediateBinds := holds.immediateBinds
  nextPcResult := holds.nextPcResult

/-- The architectural claim `srai_refines` reaches: an `SRAI` row retires the
arithmetic right shift of `X(rs1)` by the instruction's `shamt` field. Stated
against the reviewed capsule, so it is not a restatement of the sign range
check. -/
def SraiRetiresArithmeticShift (row : ShiftsImmRow) : Prop :=
  row.semantic.kind = ShiftKind.sra →
    shiftsImmRetirement row =
      executeSrai row.pc row.semantic.rs1Previous.word row.semantic.rd
        (shiftsImmShamt row)

theorem srai_retires_arithmetic_shift
    (row : ShiftsImmRow)
    (holds : ShiftsImmHolds row) :
    SraiRetiresArithmeticShift row := by
  intro kind
  have amount := shifts_imm_shamt_toNat row holds
  have result :
      row.semantic.result.word =
        executeSraValue row.semantic.rs1Previous.word (shiftsImmShamt row) := by
    rw [← holds.core.sourceReadOnly]
    simp only [executeSraValue, amount]
    exact shift_right_arithmetic_word row.semantic holds.core kind
  have write :
      architecturalWrite row.semantic.rd row.semantic.rdNext.word =
        architecturalWrite row.semantic.rd
          (executeSraValue row.semantic.rs1Previous.word
            (shiftsImmShamt row)) := by
    rw [shift_destination_value row.semantic holds.core,
      architecturalWrite_value, result]
  simp only [shiftsImmRetirement, executeSrai, holds.nextPcResult, write]

/-- `SRAI x7, x5, 8` on the *positive* operand `0x00000100`, with the released
sign witness set. The remaining constraints are all repaired: `bit_multiplier`
is one, so every carry is zero and in range, the seven-bit upper half of the
sign lookup still passes (`0 < 256`), the right-shift movement equations hold
with `rs1_sign = 1` -- including `result_3 = 255 * rs1_sign` -- and the
destination mirrors `result`. -/
def sraiReleasedSignSemantic : ShiftRow where
  rs1Previous := mutationBytes 0 1 0 0
  rs1Next := mutationBytes 0 1 0 0
  rs1Sign := true
  kind := ShiftKind.sra
  limbIndex := 1
  bitIndex := 0
  carry0 := 0
  carry1 := 0
  carry2 := 0
  carry3 := 0
  result := mutationBytes 1 0 0 0xff
  rd := BitVec.ofNat 5 7
  rdPrevious := WordBytes.zero
  rdNext := mutationBytes 1 0 0 0xff
  rdNonzero := true

def sraiReleasedSignRow : ShiftsImmRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rdPreviousClock := 0
  immTruncated := 8
  semantic := sraiReleasedSignSemantic
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem sraiReleasedSignRow_satisfies :
    ShiftsImmHoldsWithoutSignLowerBound sraiReleasedSignRow := by
  refine {
    core := ?_
    clockPositive := by decide
    sourceClock := ?_
    destinationClock := ?_
    immediateBinds := rfl
    nextPcResult := rfl
  }
  · refine {
      limbIndexRange := by decide
      bitIndexRange := by decide
      signIsLogicalZero := fun h => absurd rfl h
      signUpperBound := fun _ => by decide
      carry0Range := by decide
      carry1Range := by decide
      carry2Range := by decide
      carry3Range := by decide
      sourceReadOnly := rfl
      leftMovement := fun h => absurd h (by decide)
      rightMovement := ?_
      destinationFlag := by decide
      destinationLimb0 := by decide
      destinationLimb1 := by decide
      destinationLimb2 := by decide
      destinationLimb3 := by decide
    }
    intro _
    refine ⟨?_, ?_, ?_, ?_⟩ <;> decide
  · simp [validPreviousClock, accessClock, sraiReleasedSignRow]
  · simp [validPreviousClock, accessClock, sraiReleasedSignRow]

/-- The row retires `0xff000001` where `SRAI` of `0x00000100` by eight is
`0x00000001`: a sign fill on a non-negative operand. -/
theorem sraiReleasedSignRow_refutes :
    ¬ SraiRetiresArithmeticShift sraiReleasedSignRow := by
  unfold SraiRetiresArithmeticShift
  decide

/-- The failure mode, spelled out: the operand's bit 31 is clear, so the
architecture zero-fills, and the row fills with ones instead. -/
theorem sraiReleasedSignRow_is_a_sign_fill_on_a_positive_operand :
    sraiReleasedSignRow.semantic.rs1Next.word.msb = false ∧
      sraiReleasedSignRow.semantic.rs1Sign = true ∧
      sraiReleasedSignRow.semantic.result.word = BitVec.ofNat 32 0xff000001 ∧
      executeSraValue sraiReleasedSignRow.semantic.rs1Previous.word
          (shiftsImmShamt sraiReleasedSignRow) =
        BitVec.ofNat 32 0x00000001 :=
  ⟨by decide, rfl, by decide, by decide⟩

/-- The published control. -/
def sraiReleasedSign :
    MutationControl ShiftsImmHoldsWithoutSignLowerBound
      SraiRetiresArithmeticShift where
  name := "srai-released-sign"
  witness := sraiReleasedSignRow
  satisfies := sraiReleasedSignRow_satisfies
  refutes := sraiReleasedSignRow_refutes

/-- The witness is genuinely outside the honest system, which is what stops a
control from being manufactured by deleting a constraint that never mattered. -/
theorem sraiReleasedSignRow_not_sound : ¬ ShiftsImmHolds sraiReleasedSignRow :=
  sraiReleasedSign.witness_not_sound ShiftsImmHolds
    srai_retires_arithmetic_shift

/-- The deletion is not free: the sign witness cannot be recovered from the
remaining constraints, so bit 31 of the operand is genuinely what drives the
arithmetic fill. -/
theorem srai_sign_lower_bound_is_load_bearing :
    ¬ (∀ row, ShiftsImmHoldsWithoutSignLowerBound row → ShiftsImmHolds row) :=
  sraiReleasedSign.strictly_weaker ShiftsImmHolds srai_retires_arithmetic_shift

/-- The same counterexample, read at the shared layer: no strengthening of the
weakened `shift_common.zig` predicate recovers `ShiftHolds`, which is what makes
this control certify the `SRA` sign path as well as `SRAI`. -/
theorem shift_sign_lower_bound_is_load_bearing :
    ¬ (∀ row, ShiftHoldsWithoutSignLowerBound row → ShiftHolds row) := by
  intro implies
  exact srai_sign_lower_bound_is_load_bearing fun row weakened =>
    { core := implies row.semantic weakened.core
      clockPositive := weakened.clockPositive
      sourceClock := weakened.sourceClock
      destinationClock := weakened.destinationClock
      immediateBinds := weakened.immediateBinds
      nextPcResult := weakened.nextPcResult }

/-! ## Control 2: the free shift amount (`SLLI`, `SRLI`, `SRAI`)

Constraint 65 of `shifts_imm` is
`imm_truncated - (8 * limb_shift + bit_shift) = 0`: the committed shift amount
is exactly the `shamt` field the program-access lookup published. Delete it and
the hot markers may select any amount at all while the instruction word claims
another. -/

/-- `ShiftsImmHolds` with constraint 65 deleted, and nothing else changed. -/
structure ShiftsImmHoldsWithoutImmediateBinds (row : ShiftsImmRow) : Prop where
  core : ShiftHolds row.semantic
  clockPositive : 0 < row.clock
  sourceClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 2)
  -- immediateBinds is deliberately absent: this is the mutation. It is
  -- constraint 65, `imm_truncated - shift_amount = 0`.
  nextPcResult : row.claimedNextPc = nextPc row.pc

theorem shiftsImmHolds_weakens_immediateBinds
    (row : ShiftsImmRow)
    (holds : ShiftsImmHolds row) :
    ShiftsImmHoldsWithoutImmediateBinds row where
  core := holds.core
  clockPositive := holds.clockPositive
  sourceClock := holds.sourceClock
  destinationClock := holds.destinationClock
  nextPcResult := holds.nextPcResult

/-- The architectural claim `slli_refines` reaches: the retired value is
`X(rs1)` shifted left by the `shamt` field carried on the program-access bus,
not by whatever the marker columns happen to select. -/
def SlliRetiresShamtShift (row : ShiftsImmRow) : Prop :=
  row.semantic.kind = ShiftKind.sll →
    shiftsImmRetirement row =
      executeSlli row.pc row.semantic.rs1Previous.word row.semantic.rd
        (shiftsImmShamt row)

theorem slli_retires_shamt_shift
    (row : ShiftsImmRow)
    (holds : ShiftsImmHolds row) :
    SlliRetiresShamtShift row := by
  intro kind
  have amount := shifts_imm_shamt_toNat row holds
  have result :
      row.semantic.result.word =
        executeSllValue row.semantic.rs1Previous.word (shiftsImmShamt row) := by
    rw [← holds.core.sourceReadOnly]
    simp only [executeSllValue, amount]
    exact shift_left_word row.semantic holds.core kind
  have write :
      architecturalWrite row.semantic.rd row.semantic.rdNext.word =
        architecturalWrite row.semantic.rd
          (executeSllValue row.semantic.rs1Previous.word
            (shiftsImmShamt row)) := by
    rw [shift_destination_value row.semantic holds.core,
      architecturalWrite_value, result]
  simp only [shiftsImmRetirement, executeSlli, holds.nextPcResult, write]

/-- `SLLI x7, x5, 1` on the operand `1`, but with the marker columns selecting
`bit_shift = 4`. The movement block is internally honest at the *selected*
amount -- `result_0 = 16 * rs1_next_0` with every carry zero and in range below
`bit_multiplier = 16` -- so the row shifts by four while the instruction word
says one. -/
def slliFreeAmountSemantic : ShiftRow where
  rs1Previous := mutationBytes 1 0 0 0
  rs1Next := mutationBytes 1 0 0 0
  rs1Sign := false
  kind := ShiftKind.sll
  limbIndex := 0
  bitIndex := 4
  carry0 := 0
  carry1 := 0
  carry2 := 0
  carry3 := 0
  result := mutationBytes 0x10 0 0 0
  rd := BitVec.ofNat 5 7
  rdPrevious := WordBytes.zero
  rdNext := mutationBytes 0x10 0 0 0
  rdNonzero := true

def slliFreeAmountRow : ShiftsImmRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rdPreviousClock := 0
  immTruncated := 1
  semantic := slliFreeAmountSemantic
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem slliFreeAmountRow_satisfies :
    ShiftsImmHoldsWithoutImmediateBinds slliFreeAmountRow := by
  refine {
    core := ?_
    clockPositive := by decide
    sourceClock := ?_
    destinationClock := ?_
    nextPcResult := rfl
  }
  · refine {
      limbIndexRange := by decide
      bitIndexRange := by decide
      signIsLogicalZero := fun _ => rfl
      signLowerBound := fun h => absurd h (by decide)
      signUpperBound := fun h => absurd h (by decide)
      carry0Range := by decide
      carry1Range := by decide
      carry2Range := by decide
      carry3Range := by decide
      sourceReadOnly := rfl
      leftMovement := ?_
      rightMovement := fun h => absurd rfl h
      destinationFlag := by decide
      destinationLimb0 := by decide
      destinationLimb1 := by decide
      destinationLimb2 := by decide
      destinationLimb3 := by decide
    }
    intro _
    refine ⟨?_, ?_, ?_, ?_⟩ <;> decide
  · simp [validPreviousClock, accessClock, slliFreeAmountRow]
  · simp [validPreviousClock, accessClock, slliFreeAmountRow]

/-- The row retires `0x10` where `SLLI` by the published `shamt = 1` gives
`0x2`. -/
theorem slliFreeAmountRow_refutes :
    ¬ SlliRetiresShamtShift slliFreeAmountRow := by
  unfold SlliRetiresShamtShift
  decide

/-- The failure mode, spelled out: the instruction word says shift by one, the
markers shift by four. -/
theorem slliFreeAmountRow_shifts_by_the_wrong_amount :
    (shiftsImmShamt slliFreeAmountRow).toNat = 1 ∧
      slliFreeAmountRow.semantic.shiftAmount = 4 ∧
      slliFreeAmountRow.semantic.result.word = BitVec.ofNat 32 0x10 ∧
      executeSllValue slliFreeAmountRow.semantic.rs1Previous.word
          (shiftsImmShamt slliFreeAmountRow) =
        BitVec.ofNat 32 0x2 :=
  ⟨by decide, by decide, by decide, by decide⟩

/-- The published control. -/
def slliFreeShiftAmount :
    MutationControl ShiftsImmHoldsWithoutImmediateBinds
      SlliRetiresShamtShift where
  name := "slli-free-shift-amount"
  witness := slliFreeAmountRow
  satisfies := slliFreeAmountRow_satisfies
  refutes := slliFreeAmountRow_refutes

/-- The witness is genuinely outside the honest system. -/
theorem slliFreeAmountRow_not_sound : ¬ ShiftsImmHolds slliFreeAmountRow :=
  slliFreeShiftAmount.witness_not_sound ShiftsImmHolds slli_retires_shamt_shift

/-- The deletion is not free: nothing else in the immediate family ties the hot
markers to the published `shamt`, so constraint 65 is what makes the shift
amount an *instruction* operand for all three of `SLLI`, `SRLI` and `SRAI`. -/
theorem shifts_imm_immediate_binds_is_load_bearing :
    ¬ (∀ row, ShiftsImmHoldsWithoutImmediateBinds row → ShiftsImmHolds row) :=
  slliFreeShiftAmount.strictly_weaker ShiftsImmHolds slli_retires_shamt_shift

/-! ## Control 3: the logical-versus-arithmetic confusion (`SRLI`, `SRL`)

Constraint 5 is `(1 - is_sra) * rs1_sign = 0`: a sign witness is available only
to an arithmetic right shift. It is the single constraint separating the two
right-shift fills, since the movement equations themselves are shared and read
`rs1_sign` unconditionally. Delete it and an `SRLI` row sign-fills. -/

/-- `ShiftHolds` with constraint 5 deleted, and nothing else changed. -/
structure ShiftHoldsWithoutSignIsLogicalZero (row : ShiftRow) : Prop where
  /-- `limb_markers_hot`. -/
  limbIndexRange : row.limbIndex < 4
  /-- `bit_markers_hot`. -/
  bitIndexRange : row.bitIndex < 8
  -- signIsLogicalZero is deliberately absent: this is the mutation. It is
  -- constraint 5, `(1 - is_sra) * rs1_sign = 0`.
  /-- Lookup 15 / 19, `range_check_m31 (0, rs1_next_3 - 128 * rs1_sign)`: the
  residue is a seven-bit value, so `rs1_sign` is exactly bit 31 of the operand.
  Requested only on `is_sra` rows. -/
  signLowerBound :
    row.kind = ShiftKind.sra → 128 * row.signNat ≤ row.rs1Next.limb3.toNat
  signUpperBound :
    row.kind = ShiftKind.sra →
      row.rs1Next.limb3.toNat < 128 * row.signNat + 128
  /-- `carryRangePairs`: `range_check_8_8 (carry_k, bit_multiplier - carry_k -
  1)` makes both components bytes, which on an active row is exactly
  `carry_k < bit_multiplier`. -/
  carry0Range : row.carry0 < row.multiplier
  carry1Range : row.carry1 < row.multiplier
  carry2Range : row.carry2 < row.multiplier
  carry3Range : row.carry3 < row.multiplier
  /-- Constraints 61-64, `readOnlyAccessConstraints(rs1, enabler)`. -/
  sourceReadOnly : row.rs1Next = row.rs1Previous
  /-- Constraints 22-37. -/
  leftMovement :
    row.kind = ShiftKind.sll →
      shiftLeftEquations row.limbIndex row.multiplier row.rs1Next row.result
        row.carry0 row.carry1 row.carry2 row.carry3
  /-- Constraints 38-53. -/
  rightMovement :
    row.kind ≠ ShiftKind.sll →
      shiftRightEquations row.limbIndex row.multiplier row.signNat
        row.rs1Next row.result row.carry0 row.carry1 row.carry2 row.carry3
  /-- Constraints 54-56, `destinationConstraints`. -/
  destinationFlag : row.rdNonzero = decide (row.rd ≠ zeroRegister)
  /-- Constraints 57-60, `destinationResultConstraints`. -/
  destinationLimb0 :
    row.rdNext.limb0 =
      if row.rdNonzero then row.result.limb0 else WordBytes.zero.limb0
  destinationLimb1 :
    row.rdNext.limb1 =
      if row.rdNonzero then row.result.limb1 else WordBytes.zero.limb1
  destinationLimb2 :
    row.rdNext.limb2 =
      if row.rdNonzero then row.result.limb2 else WordBytes.zero.limb2
  destinationLimb3 :
    row.rdNext.limb3 =
      if row.rdNonzero then row.result.limb3 else WordBytes.zero.limb3

theorem shiftHolds_weakens_signIsLogicalZero
    (row : ShiftRow)
    (holds : ShiftHolds row) :
    ShiftHoldsWithoutSignIsLogicalZero row where
  limbIndexRange := holds.limbIndexRange
  bitIndexRange := holds.bitIndexRange
  signLowerBound := holds.signLowerBound
  signUpperBound := holds.signUpperBound
  carry0Range := holds.carry0Range
  carry1Range := holds.carry1Range
  carry2Range := holds.carry2Range
  carry3Range := holds.carry3Range
  sourceReadOnly := holds.sourceReadOnly
  leftMovement := holds.leftMovement
  rightMovement := holds.rightMovement
  destinationFlag := holds.destinationFlag
  destinationLimb0 := holds.destinationLimb0
  destinationLimb1 := holds.destinationLimb1
  destinationLimb2 := holds.destinationLimb2
  destinationLimb3 := holds.destinationLimb3

/-- `ShiftsImmHolds` with the shared layer weakened by exactly that one
deletion. -/
structure ShiftsImmHoldsWithoutSignIsLogicalZero (row : ShiftsImmRow) :
    Prop where
  core : ShiftHoldsWithoutSignIsLogicalZero row.semantic
  clockPositive : 0 < row.clock
  sourceClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 2)
  /-- Constraint 65: `imm_truncated - shift_amount = 0`. -/
  immediateBinds : row.immTruncated = row.semantic.shiftAmount
  nextPcResult : row.claimedNextPc = nextPc row.pc

theorem shiftsImmHolds_weakens_signIsLogicalZero
    (row : ShiftsImmRow)
    (holds : ShiftsImmHolds row) :
    ShiftsImmHoldsWithoutSignIsLogicalZero row where
  core := shiftHolds_weakens_signIsLogicalZero row.semantic holds.core
  clockPositive := holds.clockPositive
  sourceClock := holds.sourceClock
  destinationClock := holds.destinationClock
  immediateBinds := holds.immediateBinds
  nextPcResult := holds.nextPcResult

/-- The architectural claim `srli_refines` reaches: an `SRLI` row retires the
*zero-filled* right shift of `X(rs1)`. -/
def SrliRetiresLogicalShift (row : ShiftsImmRow) : Prop :=
  row.semantic.kind = ShiftKind.srl →
    shiftsImmRetirement row =
      executeSrli row.pc row.semantic.rs1Previous.word row.semantic.rd
        (shiftsImmShamt row)

theorem srli_retires_logical_shift
    (row : ShiftsImmRow)
    (holds : ShiftsImmHolds row) :
    SrliRetiresLogicalShift row := by
  intro kind
  have amount := shifts_imm_shamt_toNat row holds
  have notLeft : row.semantic.kind ≠ ShiftKind.sll := by rw [kind]; decide
  have sign : row.semantic.rs1Sign = false :=
    holds.core.signIsLogicalZero (by rw [kind]; decide)
  have result :
      row.semantic.result.word =
        executeSrlValue row.semantic.rs1Previous.word (shiftsImmShamt row) := by
    rw [← holds.core.sourceReadOnly]
    simp only [executeSrlValue, amount]
    exact shift_right_logical_word row.semantic holds.core notLeft sign
  have write :
      architecturalWrite row.semantic.rd row.semantic.rdNext.word =
        architecturalWrite row.semantic.rd
          (executeSrlValue row.semantic.rs1Previous.word
            (shiftsImmShamt row)) := by
    rw [shift_destination_value row.semantic holds.core,
      architecturalWrite_value, result]
  simp only [shiftsImmRetirement, executeSrli, holds.nextPcResult, write]

/-- `SRLI x7, x5, 8` on `0x80000000` with the sign witness set. Every surviving
constraint holds: the two halves of the sign range check are gated on `is_sra`
and are vacuous on this row, and the shared movement equations are satisfied
with `rs1_sign = 1`, because they never ask which selector is hot. -/
def srliSignFillSemantic : ShiftRow where
  rs1Previous := mutationBytes 0 0 0 0x80
  rs1Next := mutationBytes 0 0 0 0x80
  rs1Sign := true
  kind := ShiftKind.srl
  limbIndex := 1
  bitIndex := 0
  carry0 := 0
  carry1 := 0
  carry2 := 0
  carry3 := 0
  result := mutationBytes 0 0 0x80 0xff
  rd := BitVec.ofNat 5 7
  rdPrevious := WordBytes.zero
  rdNext := mutationBytes 0 0 0x80 0xff
  rdNonzero := true

def srliSignFillRow : ShiftsImmRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rdPreviousClock := 0
  immTruncated := 8
  semantic := srliSignFillSemantic
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem srliSignFillRow_satisfies :
    ShiftsImmHoldsWithoutSignIsLogicalZero srliSignFillRow := by
  refine {
    core := ?_
    clockPositive := by decide
    sourceClock := ?_
    destinationClock := ?_
    immediateBinds := rfl
    nextPcResult := rfl
  }
  · refine {
      limbIndexRange := by decide
      bitIndexRange := by decide
      signLowerBound := fun h => absurd h (by decide)
      signUpperBound := fun h => absurd h (by decide)
      carry0Range := by decide
      carry1Range := by decide
      carry2Range := by decide
      carry3Range := by decide
      sourceReadOnly := rfl
      leftMovement := fun h => absurd h (by decide)
      rightMovement := ?_
      destinationFlag := by decide
      destinationLimb0 := by decide
      destinationLimb1 := by decide
      destinationLimb2 := by decide
      destinationLimb3 := by decide
    }
    intro _
    refine ⟨?_, ?_, ?_, ?_⟩ <;> decide
  · simp [validPreviousClock, accessClock, srliSignFillRow]
  · simp [validPreviousClock, accessClock, srliSignFillRow]

/-- The row retires `0xff800000` where `SRLI` of `0x80000000` by eight is
`0x00800000`: the arithmetic fill on a logical shift. -/
theorem srliSignFillRow_refutes :
    ¬ SrliRetiresLogicalShift srliSignFillRow := by
  unfold SrliRetiresLogicalShift
  decide

/-- The failure mode, spelled out: this is exactly the `SRAI` answer retired by
an `SRLI` row, so the deleted constraint is the whole of the fill separation. -/
theorem srliSignFillRow_is_an_arithmetic_fill :
    srliSignFillRow.semantic.kind = ShiftKind.srl ∧
      srliSignFillRow.semantic.result.word = BitVec.ofNat 32 0xff800000 ∧
      executeSrlValue srliSignFillRow.semantic.rs1Previous.word
          (shiftsImmShamt srliSignFillRow) =
        BitVec.ofNat 32 0x00800000 ∧
      executeSraValue srliSignFillRow.semantic.rs1Previous.word
          (shiftsImmShamt srliSignFillRow) =
        BitVec.ofNat 32 0xff800000 :=
  ⟨rfl, by decide, by decide, by decide⟩

/-- The published control. -/
def srliLogicalArithmeticConfusion :
    MutationControl ShiftsImmHoldsWithoutSignIsLogicalZero
      SrliRetiresLogicalShift where
  name := "srli-logical-arithmetic-confusion"
  witness := srliSignFillRow
  satisfies := srliSignFillRow_satisfies
  refutes := srliSignFillRow_refutes

/-- The witness is genuinely outside the honest system. -/
theorem srliSignFillRow_not_sound : ¬ ShiftsImmHolds srliSignFillRow :=
  srliLogicalArithmeticConfusion.witness_not_sound ShiftsImmHolds
    srli_retires_logical_shift

/-- The deletion is not free: constraint 5 is the whole of the separation
between the two right-shift fills. -/
theorem srli_sign_is_logical_zero_is_load_bearing :
    ¬ (∀ row,
        ShiftsImmHoldsWithoutSignIsLogicalZero row → ShiftsImmHolds row) :=
  srliLogicalArithmeticConfusion.strictly_weaker ShiftsImmHolds
    srli_retires_logical_shift

/-- The same counterexample at the shared layer, which is what makes this
control certify `SRL` as well as `SRLI`. -/
theorem shift_sign_is_logical_zero_is_load_bearing :
    ¬ (∀ row, ShiftHoldsWithoutSignIsLogicalZero row → ShiftHolds row) := by
  intro implies
  exact srli_sign_is_logical_zero_is_load_bearing fun row weakened =>
    { core := implies row.semantic weakened.core
      clockPositive := weakened.clockPositive
      sourceClock := weakened.sourceClock
      destinationClock := weakened.destinationClock
      immediateBinds := weakened.immediateBinds
      nextPcResult := weakened.nextPcResult }

/-! ## Control 4: the free result limb (`SLL`, `SLLI`)

Constraint 22 is
`is_sll * limb_markers_0 * (result_0 + 256 * carries_0)
  = limb_markers_0 * rs1_next_0 * bit_multiplier_left`,
the output-byte-0 equation of the left-shift block on the hot-limb-0 branch.
`shiftLeftEquationsWithoutLowByte` is `shiftLeftEquations` with exactly that one
conjunct deleted; the `limb_markers_1..3` branches -- constraints 26-37 -- are
copied verbatim, so the counterexample is unambiguous about which of the sixteen
left-block constraints let it through.

This control is carried on the *register* family, so the four controls in this
file together cover `SLLI`, `SRLI`, `SRAI` and `SLL`. -/

/-- `shiftLeftEquations` with the hot-limb-0 output-byte-0 equation, production
constraint 22, deleted. -/
def shiftLeftEquationsWithoutLowByte
    (limbIndex mult : Nat)
    (source result : WordBytes)
    (carry0 carry1 carry2 carry3 : Nat) : Prop :=
  match limbIndex with
  | 0 =>
      -- the `result_0 + 256 * carries_0 = bit_multiplier_left * rs1_next_0`
      -- equation is deliberately absent: this is the mutation.
      result.limb1.toNat + 256 * carry1 = mult * source.limb1.toNat + carry0 ∧
      result.limb2.toNat + 256 * carry2 = mult * source.limb2.toNat + carry1 ∧
      result.limb3.toNat + 256 * carry3 = mult * source.limb3.toNat + carry2
  | 1 =>
      result.limb0.toNat = 0 ∧
      result.limb1.toNat + 256 * carry0 = mult * source.limb0.toNat ∧
      result.limb2.toNat + 256 * carry1 = mult * source.limb1.toNat + carry0 ∧
      result.limb3.toNat + 256 * carry2 = mult * source.limb2.toNat + carry1
  | 2 =>
      result.limb0.toNat = 0 ∧
      result.limb1.toNat = 0 ∧
      result.limb2.toNat + 256 * carry0 = mult * source.limb0.toNat ∧
      result.limb3.toNat + 256 * carry1 = mult * source.limb1.toNat + carry0
  | _ =>
      result.limb0.toNat = 0 ∧
      result.limb1.toNat = 0 ∧
      result.limb2.toNat = 0 ∧
      result.limb3.toNat + 256 * carry0 = mult * source.limb0.toNat

theorem shiftLeftEquations_weakens_lowByte
    (limbIndex mult : Nat)
    (source result : WordBytes)
    (carry0 carry1 carry2 carry3 : Nat)
    (equations :
      shiftLeftEquations limbIndex mult source result carry0 carry1 carry2
        carry3) :
    shiftLeftEquationsWithoutLowByte limbIndex mult source result carry0 carry1
      carry2 carry3 := by
  cases limbIndex with
  | zero =>
    simp only [shiftLeftEquations] at equations
    exact ⟨equations.2.1, equations.2.2.1, equations.2.2.2⟩
  | succ first =>
    cases first with
    | zero => exact equations
    | succ second =>
      cases second with
      | zero => exact equations
      | succ third => exact equations

/-- `ShiftHolds` with constraint 22 deleted from the left-shift block, and
nothing else changed. -/
structure ShiftHoldsWithoutLeftLowByte (row : ShiftRow) : Prop where
  /-- `limb_markers_hot`. -/
  limbIndexRange : row.limbIndex < 4
  /-- `bit_markers_hot`. -/
  bitIndexRange : row.bitIndex < 8
  /-- Constraint 5, `(1 - is_sra) * rs1_sign = 0`: only an arithmetic right
  shift may carry a sign witness, so every other kind zero-fills. -/
  signIsLogicalZero : row.kind ≠ ShiftKind.sra → row.rs1Sign = false
  /-- Lookup 15 / 19, `range_check_m31 (0, rs1_next_3 - 128 * rs1_sign)`: the
  residue is a seven-bit value, so `rs1_sign` is exactly bit 31 of the operand.
  Requested only on `is_sra` rows. -/
  signLowerBound :
    row.kind = ShiftKind.sra → 128 * row.signNat ≤ row.rs1Next.limb3.toNat
  signUpperBound :
    row.kind = ShiftKind.sra →
      row.rs1Next.limb3.toNat < 128 * row.signNat + 128
  /-- `carryRangePairs`: `range_check_8_8 (carry_k, bit_multiplier - carry_k -
  1)` makes both components bytes, which on an active row is exactly
  `carry_k < bit_multiplier`. -/
  carry0Range : row.carry0 < row.multiplier
  carry1Range : row.carry1 < row.multiplier
  carry2Range : row.carry2 < row.multiplier
  carry3Range : row.carry3 < row.multiplier
  /-- Constraints 61-64, `readOnlyAccessConstraints(rs1, enabler)`. -/
  sourceReadOnly : row.rs1Next = row.rs1Previous
  /-- Constraints 23-37: constraint 22 is deliberately absent. -/
  leftMovement :
    row.kind = ShiftKind.sll →
      shiftLeftEquationsWithoutLowByte row.limbIndex row.multiplier row.rs1Next
        row.result row.carry0 row.carry1 row.carry2 row.carry3
  /-- Constraints 38-53. -/
  rightMovement :
    row.kind ≠ ShiftKind.sll →
      shiftRightEquations row.limbIndex row.multiplier row.signNat
        row.rs1Next row.result row.carry0 row.carry1 row.carry2 row.carry3
  /-- Constraints 54-56, `destinationConstraints`. -/
  destinationFlag : row.rdNonzero = decide (row.rd ≠ zeroRegister)
  /-- Constraints 57-60, `destinationResultConstraints`. -/
  destinationLimb0 :
    row.rdNext.limb0 =
      if row.rdNonzero then row.result.limb0 else WordBytes.zero.limb0
  destinationLimb1 :
    row.rdNext.limb1 =
      if row.rdNonzero then row.result.limb1 else WordBytes.zero.limb1
  destinationLimb2 :
    row.rdNext.limb2 =
      if row.rdNonzero then row.result.limb2 else WordBytes.zero.limb2
  destinationLimb3 :
    row.rdNext.limb3 =
      if row.rdNonzero then row.result.limb3 else WordBytes.zero.limb3

theorem shiftHolds_weakens_leftLowByte
    (row : ShiftRow)
    (holds : ShiftHolds row) :
    ShiftHoldsWithoutLeftLowByte row where
  limbIndexRange := holds.limbIndexRange
  bitIndexRange := holds.bitIndexRange
  signIsLogicalZero := holds.signIsLogicalZero
  signLowerBound := holds.signLowerBound
  signUpperBound := holds.signUpperBound
  carry0Range := holds.carry0Range
  carry1Range := holds.carry1Range
  carry2Range := holds.carry2Range
  carry3Range := holds.carry3Range
  sourceReadOnly := holds.sourceReadOnly
  leftMovement := fun kind =>
    shiftLeftEquations_weakens_lowByte row.limbIndex row.multiplier row.rs1Next
      row.result row.carry0 row.carry1 row.carry2 row.carry3
      (holds.leftMovement kind)
  rightMovement := holds.rightMovement
  destinationFlag := holds.destinationFlag
  destinationLimb0 := holds.destinationLimb0
  destinationLimb1 := holds.destinationLimb1
  destinationLimb2 := holds.destinationLimb2
  destinationLimb3 := holds.destinationLimb3

/-- `ShiftsRegHolds` with the shared layer weakened by exactly that one
deletion; the six register-family constraints are copied verbatim. -/
structure ShiftsRegHoldsWithoutLeftLowByte (row : ShiftsRegRow) : Prop where
  core : ShiftHoldsWithoutLeftLowByte row.semantic
  clockPositive : 0 < row.clock
  sourceClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  secondSourceClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  /-- Constraints 65-68, `readOnlyAccessConstraints(rs2, enabler)`. -/
  secondSourceReadOnly : row.rs2Next = row.rs2Previous
  /-- Lookup 9, `range_check_20 (7 - (rs2_next_0 - shift_amount) * 32⁻¹)`: the
  requested value is a non-negative integer only when `rs2_next_0` exceeds
  `shift_amount` by a multiple of 32, and the `range_check_20` domain caps the
  quotient at 7 because `rs2_next_0` is a byte. That is exactly the RISC-V
  five-bit mask on the register shift amount. -/
  shiftAmountBinds :
    ∃ high,
      high ≤ 7 ∧
        row.rs2Next.limb0.toNat = 32 * high + row.semantic.shiftAmount
  nextPcResult : row.claimedNextPc = nextPc row.pc

theorem shiftsRegHolds_weakens_leftLowByte
    (row : ShiftsRegRow)
    (holds : ShiftsRegHolds row) :
    ShiftsRegHoldsWithoutLeftLowByte row where
  core := shiftHolds_weakens_leftLowByte row.semantic holds.core
  clockPositive := holds.clockPositive
  sourceClock := holds.sourceClock
  secondSourceClock := holds.secondSourceClock
  destinationClock := holds.destinationClock
  secondSourceReadOnly := holds.secondSourceReadOnly
  shiftAmountBinds := holds.shiftAmountBinds
  nextPcResult := holds.nextPcResult

/-- The architectural claim `sll_refines` reaches: an `SLL` row retires
`X(rs1) << X(rs2)[4..0]`. -/
def SllRetiresLeftShift (row : ShiftsRegRow) : Prop :=
  row.semantic.kind = ShiftKind.sll →
    shiftsRegRetirement row =
      executeSll row.pc row.semantic.rs1Previous.word row.rs2Previous.word
        row.semantic.rd

theorem sll_retires_left_shift
    (row : ShiftsRegRow)
    (holds : ShiftsRegHolds row) :
    SllRetiresLeftShift row := by
  intro kind
  have amount :
      (registerShiftAmount row.rs2Previous.word).toNat =
        row.semantic.shiftAmount := by
    rw [registerShiftAmount_toNat, ← holds.secondSourceReadOnly,
      ← shifts_reg_amount_is_masked row holds]
  have result :
      row.semantic.result.word =
        executeSllValue row.semantic.rs1Previous.word
          (registerShiftAmount row.rs2Previous.word) := by
    rw [← holds.core.sourceReadOnly]
    simp only [executeSllValue, amount]
    exact shift_left_word row.semantic holds.core kind
  have write :
      architecturalWrite row.semantic.rd row.semantic.rdNext.word =
        architecturalWrite row.semantic.rd
          (executeSllValue row.semantic.rs1Previous.word
            (registerShiftAmount row.rs2Previous.word)) := by
    rw [shift_destination_value row.semantic holds.core,
      architecturalWrite_value, result]
  simp only [shiftsRegRetirement, executeSll, holds.nextPcResult, write]

/-- `SLL x7, x5, x6` with `X(rs1) = 0x11` and `X(rs2) = 1`, claiming `0x23` in
the low byte instead of `0x22`. The three surviving left-block equations still
hold -- the upper source bytes are zero and every carry is zero, in range below
`bit_multiplier = 2` -- and the five-bit mask lookup still binds
`shift_amount = 1`. -/
def sllFreeLowByteSemantic : ShiftRow where
  rs1Previous := mutationBytes 0x11 0 0 0
  rs1Next := mutationBytes 0x11 0 0 0
  rs1Sign := false
  kind := ShiftKind.sll
  limbIndex := 0
  bitIndex := 1
  carry0 := 0
  carry1 := 0
  carry2 := 0
  carry3 := 0
  result := mutationBytes 0x23 0 0 0
  rd := BitVec.ofNat 5 7
  rdPrevious := WordBytes.zero
  rdNext := mutationBytes 0x23 0 0 0
  rdNonzero := true

def sllFreeLowByteRow : ShiftsRegRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rs2 := BitVec.ofNat 5 6
  rs2PreviousClock := 0
  rs2Previous := mutationBytes 1 0 0 0
  rs2Next := mutationBytes 1 0 0 0
  rdPreviousClock := 0
  semantic := sllFreeLowByteSemantic
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem sllFreeLowByteRow_satisfies :
    ShiftsRegHoldsWithoutLeftLowByte sllFreeLowByteRow := by
  refine {
    core := ?_
    clockPositive := by decide
    sourceClock := ?_
    secondSourceClock := ?_
    destinationClock := ?_
    secondSourceReadOnly := rfl
    shiftAmountBinds := ⟨0, by decide, by decide⟩
    nextPcResult := rfl
  }
  · refine {
      limbIndexRange := by decide
      bitIndexRange := by decide
      signIsLogicalZero := fun _ => rfl
      signLowerBound := fun h => absurd h (by decide)
      signUpperBound := fun h => absurd h (by decide)
      carry0Range := by decide
      carry1Range := by decide
      carry2Range := by decide
      carry3Range := by decide
      sourceReadOnly := rfl
      leftMovement := ?_
      rightMovement := fun h => absurd rfl h
      destinationFlag := by decide
      destinationLimb0 := by decide
      destinationLimb1 := by decide
      destinationLimb2 := by decide
      destinationLimb3 := by decide
    }
    intro _
    refine ⟨?_, ?_, ?_⟩ <;> decide
  · simp [validPreviousClock, accessClock, sllFreeLowByteRow]
  · simp [validPreviousClock, accessClock, sllFreeLowByteRow]
  · simp [validPreviousClock, accessClock, sllFreeLowByteRow]

/-- The row retires `0x23` where `SLL` of `0x11` by one is `0x22`. -/
theorem sllFreeLowByteRow_refutes :
    ¬ SllRetiresLeftShift sllFreeLowByteRow := by
  unfold SllRetiresLeftShift
  decide

/-- The failure mode, spelled out: the shift amount is still the honest masked
one, and only the freed output byte is wrong. -/
theorem sllFreeLowByteRow_has_one_wrong_byte :
    (registerShiftAmount sllFreeLowByteRow.rs2Previous.word).toNat = 1 ∧
      sllFreeLowByteRow.semantic.result.word = BitVec.ofNat 32 0x23 ∧
      executeSllValue sllFreeLowByteRow.semantic.rs1Previous.word
          (registerShiftAmount sllFreeLowByteRow.rs2Previous.word) =
        BitVec.ofNat 32 0x22 :=
  ⟨by decide, by decide, by decide⟩

/-- The published control. -/
def sllFreeResultLowByte :
    MutationControl ShiftsRegHoldsWithoutLeftLowByte SllRetiresLeftShift where
  name := "sll-free-result-low-byte"
  witness := sllFreeLowByteRow
  satisfies := sllFreeLowByteRow_satisfies
  refutes := sllFreeLowByteRow_refutes

/-- The witness is genuinely outside the honest system. -/
theorem sllFreeLowByteRow_not_sound : ¬ ShiftsRegHolds sllFreeLowByteRow :=
  sllFreeResultLowByte.witness_not_sound ShiftsRegHolds sll_retires_left_shift

/-- The deletion is not free: the carry chain does not reconstruct the low
output byte on its own, so each individual byte equation of the left-shift block
is doing work. -/
theorem shifts_reg_left_low_byte_is_load_bearing :
    ¬ (∀ row, ShiftsRegHoldsWithoutLeftLowByte row → ShiftsRegHolds row) :=
  sllFreeResultLowByte.strictly_weaker ShiftsRegHolds sll_retires_left_shift

/-- The same counterexample at the shared layer, which is what makes this
control certify the `SLLI` left block as well as `SLL`. -/
theorem shift_left_low_byte_is_load_bearing :
    ¬ (∀ row, ShiftHoldsWithoutLeftLowByte row → ShiftHolds row) := by
  intro implies
  exact shifts_reg_left_low_byte_is_load_bearing fun row weakened =>
    { core := implies row.semantic weakened.core
      clockPositive := weakened.clockPositive
      sourceClock := weakened.sourceClock
      secondSourceClock := weakened.secondSourceClock
      destinationClock := weakened.destinationClock
      secondSourceReadOnly := weakened.secondSourceReadOnly
      shiftAmountBinds := weakened.shiftAmountBinds
      nextPcResult := weakened.nextPcResult }

/-! ## Index of the four published controls -/

/-- The four controls of this file, in the order Issue #137 names them. Each
`name` is the stable identity recorded in the Team B certificate index. -/
theorem shift_mutation_control_names :
    sraiReleasedSign.name = "srai-released-sign" ∧
      slliFreeShiftAmount.name = "slli-free-shift-amount" ∧
      srliLogicalArithmeticConfusion.name =
        "srli-logical-arithmetic-confusion" ∧
      sllFreeResultLowByte.name = "sll-free-result-low-byte" :=
  ⟨rfl, rfl, rfl, rfl⟩

end RiscvRefinement.Opcodes
