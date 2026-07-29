import RiscvRefinement.Air.Family.Shifts
import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.Shifts

/-!
# Load-bearing mutation controls for the register shifts `SLL` / `SRL` / `SRA`

`Opcodes/ShiftsMutation.lean` carries four controls weighted towards the
immediate selectors: three of them delete a constraint of the shared
`shift_common.zig` layer and are stated on a `ShiftsImmRow`, and the fourth is
the left-shift low output byte. None of them touches the two constraints that
exist *only* in `shifts_reg`, and none of them refutes the register-sourced
shift amount.

This file is the register-family complement. Four more controls, each a
`MutationControl`: a concrete `ShiftsRegRow` that satisfies the row predicate
with exactly one constraint removed and still retires the wrong architectural
value.

| control | deleted constraint | opcodes certified |
| --- | --- | --- |
| `sllFreeShiftAmountMask` | lookup 9, the five-bit mask | `SLL`, `SRL`, `SRA` |
| `sllReleasedSecondSource` | constraints 65-68, `rs2` read-only | `SLL`, `SRL`, `SRA` |
| `sraReleasedSignWitness` | lookup 19, upper half | `SRA`, `SRAI` |
| `srlFreeResultLowByte` | constraint 38 | `SRL`, `SRA`, `SRLI`, `SRAI` |

The first two delete constraints that live in `ShiftsRegHolds` itself, so they
certify the register family only -- but all three of its opcodes, because
neither constraint is gated on a shift selector. The last two delete a
constraint of the shared layer, so each also lifts to the immediate family:
`ShiftHolds` is embedded verbatim by both `ShiftsImmHolds` and `ShiftsRegHolds`,
and a counterexample to the shared layer lifts to either. Those two lifts are
`shift_sign_upper_bound_is_load_bearing` and
`shift_right_low_byte_is_load_bearing`.

## Every corollary here is unconditional

`MutationControl.strictly_weaker` takes the soundness of the *unweakened*
predicate as a hypothesis, and a control is worth exactly as much as that
hypothesis is true. All three conclusions below are stated purely in terms of
the row -- the source operand is read off `rs1_previous` and the shift amount
off `rs2_previous`, which `sourceReadOnly` / `secondSourceReadOnly` and the
register lookups pin to the architectural `X(rs1)` and `X(rs2)` -- so soundness
is *proved* in this file (`sll_retires_register_shift`,
`srl_retires_register_logical_shift`,
`sra_retires_register_arithmetic_shift`) rather than assumed.

## Non-circularity

Every conclusion is a retirement equality against the reviewed architectural
capsule `RiscvRefinement/Sail/Reviewed/Shifts.lean`, i.e. the claim the
`sll_refines` / `srl_refines` / `sra_refines` theorems reach. Each is guarded on
the selector its opcode owns, and each is parameterised by the row rather than
naming a constant, so no soundness hypothesis is false-by-construction and no
corollary is vacuous. None of them restates the deleted constraint.

## A note on "shifting by an amount ≥ 32"

The committed shift amount cannot literally exceed 31 in this representation:
`limb_markers_hot` and `bit_markers_hot` cap `shift_amount = 8 * limb_shift +
bit_shift` at 31 before any of these controls apply. The way a row freed from
the five-bit mask shifts by an unmasked amount is therefore observational: it
retires exactly the value the *unmasked* shift by the whole of `X(rs2)` would
produce, where the architecture demands the masked one. That is what
`sllUnmaskedAmountRow_shifts_by_an_unmasked_amount` states, with the unmasked
shift written out as `X(rs1) <<< 32`.
-/

namespace RiscvRefinement.Opcodes

open RiscvRefinement
open RiscvRefinement.Air.Family
open RiscvRefinement.Mutation
open RiscvRefinement.Sail.Reviewed

/-- Little-endian byte literal helper, local to these controls so the witnesses
do not depend on the layout of any other witness block. -/
def shiftsRegMutationBytes (b0 b1 b2 b3 : Nat) : WordBytes where
  limb0 := BitVec.ofNat 8 b0
  limb1 := BitVec.ofNat 8 b1
  limb2 := BitVec.ofNat 8 b2
  limb3 := BitVec.ofNat 8 b3

/-! ## The three architectural conclusions

One per register-shift selector, each stated against the reviewed capsule and
guarded on its own selector so that an honest row of a *different* opcode never
refutes it. -/

/-- The architectural claim `sll_refines` reaches: an `SLL` row retires
`X(rs1) << X(rs2)[4..0]`, with `X(rs2)` read from the register file *before* the
instruction, i.e. `rs2_previous`. -/
def SllRetiresRegisterShift (row : ShiftsRegRow) : Prop :=
  row.semantic.kind = ShiftKind.sll →
    shiftsRegRetirement row =
      executeSll row.pc row.semantic.rs1Previous.word row.rs2Previous.word
        row.semantic.rd

/-- The architectural claim `srl_refines` reaches: an `SRL` row retires the
zero-filled `X(rs1) >> X(rs2)[4..0]`. -/
def SrlRetiresRegisterLogicalShift (row : ShiftsRegRow) : Prop :=
  row.semantic.kind = ShiftKind.srl →
    shiftsRegRetirement row =
      executeSrl row.pc row.semantic.rs1Previous.word row.rs2Previous.word
        row.semantic.rd

/-- The architectural claim `sra_refines` reaches: an `SRA` row retires the
sign-filled `X(rs1) >> X(rs2)[4..0]`. -/
def SraRetiresRegisterArithmeticShift (row : ShiftsRegRow) : Prop :=
  row.semantic.kind = ShiftKind.sra →
    shiftsRegRetirement row =
      executeSra row.pc row.semantic.rs1Previous.word row.rs2Previous.word
        row.semantic.rd

/-- The committed shift amount is the architectural `X(rs2)[4..0]`. This is the
one step every soundness proof below shares, and it is exactly what the two
register-only constraints buy: `secondSourceReadOnly` moves `rs2_next` back to
`rs2_previous`, and `shiftAmountBinds` -- lookup 9 -- is the five-bit mask. -/
theorem shifts_reg_previous_amount_toNat
    (row : ShiftsRegRow)
    (holds : ShiftsRegHolds row) :
    (registerShiftAmount row.rs2Previous.word).toNat =
      row.semantic.shiftAmount := by
  rw [registerShiftAmount_toNat, ← holds.secondSourceReadOnly,
    ← shifts_reg_amount_is_masked row holds]

theorem sll_retires_register_shift
    (row : ShiftsRegRow)
    (holds : ShiftsRegHolds row) :
    SllRetiresRegisterShift row := by
  intro kind
  have amount := shifts_reg_previous_amount_toNat row holds
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

theorem srl_retires_register_logical_shift
    (row : ShiftsRegRow)
    (holds : ShiftsRegHolds row) :
    SrlRetiresRegisterLogicalShift row := by
  intro kind
  have amount := shifts_reg_previous_amount_toNat row holds
  have notLeft : row.semantic.kind ≠ ShiftKind.sll := by rw [kind]; decide
  have sign : row.semantic.rs1Sign = false :=
    holds.core.signIsLogicalZero (by rw [kind]; decide)
  have result :
      row.semantic.result.word =
        executeSrlValue row.semantic.rs1Previous.word
          (registerShiftAmount row.rs2Previous.word) := by
    rw [← holds.core.sourceReadOnly]
    simp only [executeSrlValue, amount]
    exact shift_right_logical_word row.semantic holds.core notLeft sign
  have write :
      architecturalWrite row.semantic.rd row.semantic.rdNext.word =
        architecturalWrite row.semantic.rd
          (executeSrlValue row.semantic.rs1Previous.word
            (registerShiftAmount row.rs2Previous.word)) := by
    rw [shift_destination_value row.semantic holds.core,
      architecturalWrite_value, result]
  simp only [shiftsRegRetirement, executeSrl, holds.nextPcResult, write]

theorem sra_retires_register_arithmetic_shift
    (row : ShiftsRegRow)
    (holds : ShiftsRegHolds row) :
    SraRetiresRegisterArithmeticShift row := by
  intro kind
  have amount := shifts_reg_previous_amount_toNat row holds
  have result :
      row.semantic.result.word =
        executeSraValue row.semantic.rs1Previous.word
          (registerShiftAmount row.rs2Previous.word) := by
    rw [← holds.core.sourceReadOnly]
    simp only [executeSraValue, amount]
    exact shift_right_arithmetic_word row.semantic holds.core kind
  have write :
      architecturalWrite row.semantic.rd row.semantic.rdNext.word =
        architecturalWrite row.semantic.rd
          (executeSraValue row.semantic.rs1Previous.word
            (registerShiftAmount row.rs2Previous.word)) := by
    rw [shift_destination_value row.semantic holds.core,
      architecturalWrite_value, result]
  simp only [shiftsRegRetirement, executeSra, holds.nextPcResult, write]

/-! ## Control 1: the free shift-amount mask (`SLL`, `SRL`, `SRA`)

Lookup 9 of `shifts_reg` is
`range_check_20 (7 - (rs2_next_0 - shift_amount) * 32⁻¹)`. It passes only when
`rs2_next_0 - shift_amount` is a non-negative multiple of 32 with quotient at
most 7, which -- since `rs2_next_0` is a byte and `shift_amount < 32` -- is
exactly the RISC-V five-bit mask `X(rs2)[4..0]`. It is the *only* constraint in
the whole family tying the hot marker columns to the second source register, and
it is the one thing that distinguishes the register shifts from the immediate
ones.

Delete it and the marker columns float free of `rs2` entirely. -/

/-- `ShiftsRegHolds` with lookup 9 deleted, and nothing else changed. -/
structure ShiftsRegHoldsWithoutShiftAmountBinds (row : ShiftsRegRow) : Prop where
  core : ShiftHolds row.semantic
  clockPositive : 0 < row.clock
  sourceClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  secondSourceClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  /-- Constraints 65-68, `readOnlyAccessConstraints(rs2, enabler)`. -/
  secondSourceReadOnly : row.rs2Next = row.rs2Previous
  -- shiftAmountBinds is deliberately absent: this is the mutation. It is
  -- lookup 9, `range_check_20 (7 - (rs2_next_0 - shift_amount) * 32⁻¹)`.
  nextPcResult : row.claimedNextPc = nextPc row.pc

/-- The deletion is a real weakening: every honest register-shift row still
satisfies it. Without this the control could be about a predicate nothing
satisfies. -/
theorem shiftsRegHolds_weakens_shiftAmountBinds
    (row : ShiftsRegRow)
    (holds : ShiftsRegHolds row) :
    ShiftsRegHoldsWithoutShiftAmountBinds row where
  core := holds.core
  clockPositive := holds.clockPositive
  sourceClock := holds.sourceClock
  secondSourceClock := holds.secondSourceClock
  destinationClock := holds.destinationClock
  secondSourceReadOnly := holds.secondSourceReadOnly
  nextPcResult := holds.nextPcResult

/-- `SLL x7, x5, x6` with `X(rs1) = 2` and `X(rs2) = 32`. The five-bit mask sends
32 to 0, so the architecture retires `2` unchanged; this row instead selects
`limb_shift = 3`, `bit_shift = 7`, i.e. `shift_amount = 31`, and shifts the
operand clean off the top.

Every surviving constraint is repaired. `bit_multiplier = 128`, so `carry_0 = 1`
is in range, and the hot-limb-3 branch of the left block is
`result_3 + 256 * carry_0 = 128 * rs1_next_0`, i.e. `0 + 256 = 256`, with the
three lower output bytes forced to zero. `rs2_next = rs2_previous` still holds:
the row does not touch the register, it merely ignores it. -/
def sllUnmaskedAmountSemantic : ShiftRow where
  rs1Previous := shiftsRegMutationBytes 2 0 0 0
  rs1Next := shiftsRegMutationBytes 2 0 0 0
  rs1Sign := false
  kind := ShiftKind.sll
  limbIndex := 3
  bitIndex := 7
  carry0 := 1
  carry1 := 0
  carry2 := 0
  carry3 := 0
  result := shiftsRegMutationBytes 0 0 0 0
  rd := BitVec.ofNat 5 7
  rdPrevious := WordBytes.zero
  rdNext := shiftsRegMutationBytes 0 0 0 0
  rdNonzero := true

def sllUnmaskedAmountRow : ShiftsRegRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rs2 := BitVec.ofNat 5 6
  rs2PreviousClock := 0
  rs2Previous := shiftsRegMutationBytes 32 0 0 0
  rs2Next := shiftsRegMutationBytes 32 0 0 0
  rdPreviousClock := 0
  semantic := sllUnmaskedAmountSemantic
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem sllUnmaskedAmountRow_satisfies :
    ShiftsRegHoldsWithoutShiftAmountBinds sllUnmaskedAmountRow := by
  refine {
    core := ?_
    clockPositive := by decide
    sourceClock := ?_
    secondSourceClock := ?_
    destinationClock := ?_
    secondSourceReadOnly := rfl
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
  · simp [validPreviousClock, accessClock, sllUnmaskedAmountRow]
  · simp [validPreviousClock, accessClock, sllUnmaskedAmountRow]
  · simp [validPreviousClock, accessClock, sllUnmaskedAmountRow]

/-- The row retires `0` where `SLL` by `X(rs2)[4..0] = 0` retires `2`. -/
theorem sllUnmaskedAmountRow_refutes :
    ¬ SllRetiresRegisterShift sllUnmaskedAmountRow := by
  unfold SllRetiresRegisterShift
  decide

/-- The failure mode, spelled out. `X(rs2) = 32`, whose five-bit mask is zero, so
the architecture retires the operand unchanged. The freed row retires zero --
which is precisely `X(rs1) <<< 32`, the result of using the register value
*unmasked*. This is the classic missing-mask bug, and lookup 9 is the only thing
standing in its way. -/
theorem sllUnmaskedAmountRow_shifts_by_an_unmasked_amount :
    sllUnmaskedAmountRow.rs2Previous.word.toNat = 32 ∧
      (registerShiftAmount sllUnmaskedAmountRow.rs2Previous.word).toNat = 0 ∧
      sllUnmaskedAmountRow.semantic.shiftAmount = 31 ∧
      sllUnmaskedAmountRow.semantic.result.word = BitVec.ofNat 32 0 ∧
      executeSllValue sllUnmaskedAmountRow.semantic.rs1Previous.word
          (registerShiftAmount sllUnmaskedAmountRow.rs2Previous.word) =
        BitVec.ofNat 32 2 ∧
      sllUnmaskedAmountRow.semantic.rs1Previous.word <<< (32 : Nat) =
        BitVec.ofNat 32 0 :=
  ⟨by decide, by decide, by decide, by decide, by decide, by decide⟩

/-- The published control. -/
def sllFreeShiftAmountMask :
    MutationControl ShiftsRegHoldsWithoutShiftAmountBinds
      SllRetiresRegisterShift where
  name := "sll-free-shift-amount-mask"
  witness := sllUnmaskedAmountRow
  satisfies := sllUnmaskedAmountRow_satisfies
  refutes := sllUnmaskedAmountRow_refutes

/-- The witness is genuinely outside the honest system, which is what stops a
control from being manufactured by deleting a constraint that never mattered. -/
theorem sllUnmaskedAmountRow_not_sound : ¬ ShiftsRegHolds sllUnmaskedAmountRow :=
  sllFreeShiftAmountMask.witness_not_sound ShiftsRegHolds
    sll_retires_register_shift

/-- The deletion is not free: nothing else in the register family relates the
marker columns to `rs2`, so lookup 9 is the whole of the RV32 five-bit mask. It
is ungated by selector, so it is load-bearing for `SLL`, `SRL` and `SRA`
alike. -/
theorem shifts_reg_shift_amount_binds_is_load_bearing :
    ¬ (∀ row, ShiftsRegHoldsWithoutShiftAmountBinds row → ShiftsRegHolds row) :=
  sllFreeShiftAmountMask.strictly_weaker ShiftsRegHolds
    sll_retires_register_shift

/-! ## Control 2: the released `rs2` preservation (`SLL`, `SRL`, `SRA`)

Constraints 65-68 are `readOnlyAccessConstraints(rs2, enabler)`: the value the
row emits on the register bus at `rs2` must equal the value it consumed. A
register shift reads `rs2`, it does not write it.

The deletion has two effects at once, and both are architectural. The row may
publish a *new* value into its own shift-amount register, which no shift is
allowed to do; and because lookup 9 binds `shift_amount` to `rs2_next` rather
than `rs2_previous`, the shift is then taken by a value that was never in the
register file. The witness below does exactly that. -/

/-- `ShiftsRegHolds` with constraints 65-68 deleted, and nothing else changed.
Lookup 9 is kept verbatim, so the row's shift amount is still tied to
`rs2_next` -- it is only the tie between `rs2_next` and the architectural
register content that is gone. -/
structure ShiftsRegHoldsWithoutSecondSourceReadOnly (row : ShiftsRegRow) :
    Prop where
  core : ShiftHolds row.semantic
  clockPositive : 0 < row.clock
  sourceClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  secondSourceClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  -- secondSourceReadOnly is deliberately absent: this is the mutation. It is
  -- constraints 65-68, `readOnlyAccessConstraints(rs2, enabler)`.
  /-- Lookup 9, the five-bit mask, kept verbatim. -/
  shiftAmountBinds :
    ∃ high,
      high ≤ 7 ∧
        row.rs2Next.limb0.toNat = 32 * high + row.semantic.shiftAmount
  nextPcResult : row.claimedNextPc = nextPc row.pc

theorem shiftsRegHolds_weakens_secondSourceReadOnly
    (row : ShiftsRegRow)
    (holds : ShiftsRegHolds row) :
    ShiftsRegHoldsWithoutSecondSourceReadOnly row where
  core := holds.core
  clockPositive := holds.clockPositive
  sourceClock := holds.sourceClock
  secondSourceClock := holds.secondSourceClock
  destinationClock := holds.destinationClock
  shiftAmountBinds := holds.shiftAmountBinds
  nextPcResult := holds.nextPcResult

/-- `SLL x7, x5, x6` with `X(rs1) = 0x11` and `X(rs2) = 0`. The architecture
therefore retires `0x11` unchanged. This row emits `1` at `x6` instead of the
`0` it consumed -- an unauthorised write to a register the instruction may only
read -- and lookup 9 then binds `shift_amount = 1` to that fabricated value, so
the row shifts by one and retires `0x22`.

The left block is internally honest at the fabricated amount:
`bit_multiplier = 2`, `result_0 + 256 * carry_0 = 2 * rs1_next_0` is
`0x22 = 34`, and every carry is zero and below the multiplier. -/
def sllMutatedRs2Semantic : ShiftRow where
  rs1Previous := shiftsRegMutationBytes 0x11 0 0 0
  rs1Next := shiftsRegMutationBytes 0x11 0 0 0
  rs1Sign := false
  kind := ShiftKind.sll
  limbIndex := 0
  bitIndex := 1
  carry0 := 0
  carry1 := 0
  carry2 := 0
  carry3 := 0
  result := shiftsRegMutationBytes 0x22 0 0 0
  rd := BitVec.ofNat 5 7
  rdPrevious := WordBytes.zero
  rdNext := shiftsRegMutationBytes 0x22 0 0 0
  rdNonzero := true

def sllMutatedRs2Row : ShiftsRegRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rs2 := BitVec.ofNat 5 6
  rs2PreviousClock := 0
  rs2Previous := shiftsRegMutationBytes 0 0 0 0
  rs2Next := shiftsRegMutationBytes 1 0 0 0
  rdPreviousClock := 0
  semantic := sllMutatedRs2Semantic
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem sllMutatedRs2Row_satisfies :
    ShiftsRegHoldsWithoutSecondSourceReadOnly sllMutatedRs2Row := by
  refine {
    core := ?_
    clockPositive := by decide
    sourceClock := ?_
    secondSourceClock := ?_
    destinationClock := ?_
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
    refine ⟨?_, ?_, ?_, ?_⟩ <;> decide
  · simp [validPreviousClock, accessClock, sllMutatedRs2Row]
  · simp [validPreviousClock, accessClock, sllMutatedRs2Row]
  · simp [validPreviousClock, accessClock, sllMutatedRs2Row]

/-- The row retires `0x22` where `SLL` by `X(rs2)[4..0] = 0` retires `0x11`. -/
theorem sllMutatedRs2Row_refutes :
    ¬ SllRetiresRegisterShift sllMutatedRs2Row := by
  unfold SllRetiresRegisterShift
  decide

/-- The failure mode, spelled out: the row overwrites its own shift-amount
register and then shifts by the value it just invented. `rs2 = x6` is neither
the destination `rd = x7` nor the source `rs1 = x5`, so this is a register write
that the instruction has no architectural licence to perform. -/
theorem sllMutatedRs2Row_overwrites_its_shift_amount_register :
    sllMutatedRs2Row.rs2Previous.word = BitVec.ofNat 32 0 ∧
      sllMutatedRs2Row.rs2Next.word = BitVec.ofNat 32 1 ∧
      sllMutatedRs2Row.rs2Next ≠ sllMutatedRs2Row.rs2Previous ∧
      sllMutatedRs2Row.rs2 ≠ sllMutatedRs2Row.semantic.rd ∧
      sllMutatedRs2Row.semantic.shiftAmount = 1 ∧
      sllMutatedRs2Row.semantic.result.word = BitVec.ofNat 32 0x22 ∧
      executeSllValue sllMutatedRs2Row.semantic.rs1Previous.word
          (registerShiftAmount sllMutatedRs2Row.rs2Previous.word) =
        BitVec.ofNat 32 0x11 :=
  ⟨by decide, by decide, by decide, by decide, by decide, by decide, by decide⟩

/-- The published control. -/
def sllReleasedSecondSource :
    MutationControl ShiftsRegHoldsWithoutSecondSourceReadOnly
      SllRetiresRegisterShift where
  name := "sll-released-second-source"
  witness := sllMutatedRs2Row
  satisfies := sllMutatedRs2Row_satisfies
  refutes := sllMutatedRs2Row_refutes

/-- The witness is genuinely outside the honest system. -/
theorem sllMutatedRs2Row_not_sound : ¬ ShiftsRegHolds sllMutatedRs2Row :=
  sllReleasedSecondSource.witness_not_sound ShiftsRegHolds
    sll_retires_register_shift

/-- The deletion is not free: the five-bit mask is stated against `rs2_next`, so
without the read-only constraints it binds nothing about the architectural
register. The `rs2` preservation constraints are ungated by selector, so this is
load-bearing for `SLL`, `SRL` and `SRA` alike. -/
theorem shifts_reg_second_source_read_only_is_load_bearing :
    ¬ (∀ row,
        ShiftsRegHoldsWithoutSecondSourceReadOnly row → ShiftsRegHolds row) :=
  sllReleasedSecondSource.strictly_weaker ShiftsRegHolds
    sll_retires_register_shift

/-! ## Control 3: the released sign witness on `SRA` (`SRA`, `SRAI`)

Lookup 19 of `shifts_reg` requests
`range_check_m31 (0, rs1_next_3 - 128 * rs1_sign)` on an `is_sra` row. The `m31`
range check carries two halves, which the capsule transcribes as `signLowerBound`
and `signUpperBound`: the residue is non-negative, `128 * rs1_sign ≤ rs1_next_3`,
and it is a seven-bit value, `rs1_next_3 < 128 * rs1_sign + 128`. Together they
say `rs1_sign` is exactly bit 31 of the operand.

`signUpperBound` is the half that forbids claiming *no* sign fill on a
**negative** operand. Delete it and an `SRA` row can set `rs1_sign = 0` with
`rs1_next_3 = 0x80`, which zeroes the `255 * rs1_sign` fill of the discarded
limbs and drops the `256 * rs1_sign * (bit_multiplier - 1)` term of the
top-input equation: a negative operand gets the logical, zero-filled answer.

This is the mirror image of `sraiReleasedSign` in `Opcodes/ShiftsMutation.lean`,
which deletes the *other* half and sign-fills a positive operand. Both halves of
lookup 19 are therefore now separately certified. -/

/-- `ShiftHolds` with the upper half of the sign range check deleted, and nothing
else changed. -/
structure ShiftHoldsWithoutSignUpperBound (row : ShiftRow) : Prop where
  /-- `limb_markers_hot`. -/
  limbIndexRange : row.limbIndex < 4
  /-- `bit_markers_hot`. -/
  bitIndexRange : row.bitIndex < 8
  /-- Constraint 5, `(1 - is_sra) * rs1_sign = 0`. -/
  signIsLogicalZero : row.kind ≠ ShiftKind.sra → row.rs1Sign = false
  /-- Lookup 19, `range_check_m31 (0, rs1_next_3 - 128 * rs1_sign)`: the residue
  is non-negative. Requested only on `is_sra` rows. -/
  signLowerBound :
    row.kind = ShiftKind.sra → 128 * row.signNat ≤ row.rs1Next.limb3.toNat
  -- signUpperBound is deliberately absent: this is the mutation. It is the
  -- seven-bit half of lookup 19,
  -- `range_check_m31 (0, rs1_next_3 - 128 * rs1_sign)`.
  /-- `carryRangePairs`. -/
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

theorem shiftHolds_weakens_signUpperBound
    (row : ShiftRow)
    (holds : ShiftHolds row) :
    ShiftHoldsWithoutSignUpperBound row where
  limbIndexRange := holds.limbIndexRange
  bitIndexRange := holds.bitIndexRange
  signIsLogicalZero := holds.signIsLogicalZero
  signLowerBound := holds.signLowerBound
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

/-- `ShiftsRegHolds` with the shared layer weakened by exactly that one deletion;
the six register-family constraints are copied verbatim. -/
structure ShiftsRegHoldsWithoutSignUpperBound (row : ShiftsRegRow) : Prop where
  core : ShiftHoldsWithoutSignUpperBound row.semantic
  clockPositive : 0 < row.clock
  sourceClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  secondSourceClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  secondSourceReadOnly : row.rs2Next = row.rs2Previous
  shiftAmountBinds :
    ∃ high,
      high ≤ 7 ∧
        row.rs2Next.limb0.toNat = 32 * high + row.semantic.shiftAmount
  nextPcResult : row.claimedNextPc = nextPc row.pc

theorem shiftsRegHolds_weakens_signUpperBound
    (row : ShiftsRegRow)
    (holds : ShiftsRegHolds row) :
    ShiftsRegHoldsWithoutSignUpperBound row where
  core := shiftHolds_weakens_signUpperBound row.semantic holds.core
  clockPositive := holds.clockPositive
  sourceClock := holds.sourceClock
  secondSourceClock := holds.secondSourceClock
  destinationClock := holds.destinationClock
  secondSourceReadOnly := holds.secondSourceReadOnly
  shiftAmountBinds := holds.shiftAmountBinds
  nextPcResult := holds.nextPcResult

/-- `SRA x7, x5, x6` on the negative operand `0x80000000` with `X(rs2) = 8`, and
the sign witness released to zero.

Every surviving constraint is repaired. `bit_multiplier = 1`, so all four
carries are zero and in range; the non-negativity half of lookup 19 still passes
(`0 ≤ 0x80`); and the hot-limb-1 branch of the right block holds with
`rs1_sign = 0`, which makes its top-input equation `result_2 = rs1_next_3` and
its fill equation `result_3 = 255 * 0 = 0`. -/
def sraZeroFillSemantic : ShiftRow where
  rs1Previous := shiftsRegMutationBytes 0 0 0 0x80
  rs1Next := shiftsRegMutationBytes 0 0 0 0x80
  rs1Sign := false
  kind := ShiftKind.sra
  limbIndex := 1
  bitIndex := 0
  carry0 := 0
  carry1 := 0
  carry2 := 0
  carry3 := 0
  result := shiftsRegMutationBytes 0 0 0x80 0
  rd := BitVec.ofNat 5 7
  rdPrevious := WordBytes.zero
  rdNext := shiftsRegMutationBytes 0 0 0x80 0
  rdNonzero := true

def sraZeroFillRow : ShiftsRegRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rs2 := BitVec.ofNat 5 6
  rs2PreviousClock := 0
  rs2Previous := shiftsRegMutationBytes 8 0 0 0
  rs2Next := shiftsRegMutationBytes 8 0 0 0
  rdPreviousClock := 0
  semantic := sraZeroFillSemantic
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem sraZeroFillRow_satisfies :
    ShiftsRegHoldsWithoutSignUpperBound sraZeroFillRow := by
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
      signIsLogicalZero := fun h => absurd rfl h
      signLowerBound := fun _ => by decide
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
  · simp [validPreviousClock, accessClock, sraZeroFillRow]
  · simp [validPreviousClock, accessClock, sraZeroFillRow]
  · simp [validPreviousClock, accessClock, sraZeroFillRow]

/-- The row retires `0x00800000` where `SRA` of `0x80000000` by eight is
`0xff800000`: a zero fill on a negative operand. -/
theorem sraZeroFillRow_refutes :
    ¬ SraRetiresRegisterArithmeticShift sraZeroFillRow := by
  unfold SraRetiresRegisterArithmeticShift
  decide

/-- The failure mode, spelled out: the operand's bit 31 is set, so the
architecture fills with ones, and the row fills with zeroes instead -- retiring
exactly the `SRL` answer from an `SRA` row. -/
theorem sraZeroFillRow_is_a_zero_fill_on_a_negative_operand :
    sraZeroFillRow.semantic.rs1Next.word.msb = true ∧
      sraZeroFillRow.semantic.rs1Sign = false ∧
      sraZeroFillRow.semantic.result.word = BitVec.ofNat 32 0x00800000 ∧
      executeSraValue sraZeroFillRow.semantic.rs1Previous.word
          (registerShiftAmount sraZeroFillRow.rs2Previous.word) =
        BitVec.ofNat 32 0xff800000 ∧
      executeSrlValue sraZeroFillRow.semantic.rs1Previous.word
          (registerShiftAmount sraZeroFillRow.rs2Previous.word) =
        BitVec.ofNat 32 0x00800000 :=
  ⟨by decide, rfl, by decide, by decide, by decide⟩

/-- The published control. -/
def sraReleasedSignWitness :
    MutationControl ShiftsRegHoldsWithoutSignUpperBound
      SraRetiresRegisterArithmeticShift where
  name := "sra-released-sign-witness"
  witness := sraZeroFillRow
  satisfies := sraZeroFillRow_satisfies
  refutes := sraZeroFillRow_refutes

/-- The witness is genuinely outside the honest system. -/
theorem sraZeroFillRow_not_sound : ¬ ShiftsRegHolds sraZeroFillRow :=
  sraReleasedSignWitness.witness_not_sound ShiftsRegHolds
    sra_retires_register_arithmetic_shift

/-- The deletion is not free: the sign witness cannot be recovered from the
remaining constraints, so the seven-bit half of lookup 19 is genuinely what ties
`rs1_sign` up to bit 31 of the operand. -/
theorem shifts_reg_sign_upper_bound_is_load_bearing :
    ¬ (∀ row, ShiftsRegHoldsWithoutSignUpperBound row → ShiftsRegHolds row) :=
  sraReleasedSignWitness.strictly_weaker ShiftsRegHolds
    sra_retires_register_arithmetic_shift

/-- The same counterexample, read at the shared layer: no strengthening of the
weakened `shift_common.zig` predicate recovers `ShiftHolds`, which is what makes
this control certify the `SRAI` sign path as well as `SRA`. -/
theorem shift_sign_upper_bound_is_load_bearing :
    ¬ (∀ row, ShiftHoldsWithoutSignUpperBound row → ShiftHolds row) := by
  intro implies
  exact shifts_reg_sign_upper_bound_is_load_bearing fun row weakened =>
    { core := implies row.semantic weakened.core
      clockPositive := weakened.clockPositive
      sourceClock := weakened.sourceClock
      secondSourceClock := weakened.secondSourceClock
      destinationClock := weakened.destinationClock
      secondSourceReadOnly := weakened.secondSourceReadOnly
      shiftAmountBinds := weakened.shiftAmountBinds
      nextPcResult := weakened.nextPcResult }

/-! ## Control 4: the free result limb of the right block (`SRL`, `SRA`, and the
immediate siblings)

Constraint 38 is
`bit_multiplier_right * result_0 + carries_0
  = limb_markers_0 * rs1_next_0 + 256 * carries_1`,
the output-byte-0 equation of the right-shift block on the hot-limb-0 branch.
`shiftRightEquationsWithoutLowByte` is `shiftRightEquations` with exactly that
one conjunct deleted; the other three equations of the `limb_markers_0` branch --
constraints 39-41 -- and all twelve equations of the `limb_markers_1..3`
branches are copied verbatim, so the counterexample is unambiguous about which
of the sixteen right-block constraints let it through.

`Opcodes/ShiftsMutation.lean` certifies the corresponding *left*-block byte, so
between the two files both movement blocks now have a certified output byte. -/

/-- `shiftRightEquations` with the hot-limb-0 output-byte-0 equation, production
constraint 38, deleted.

The `carry_0` parameter is kept in the signature so the two definitions have the
same shape and the weakening lemma below is a position-for-position comparison,
but it is written `_carry0`: constraint 38 was the only equation in any branch
that mentioned it, which is itself a reading of how narrow this deletion is. -/
def shiftRightEquationsWithoutLowByte
    (limbIndex mult sign : Nat)
    (source result : WordBytes)
    (_carry0 carry1 carry2 carry3 : Nat) : Prop :=
  match limbIndex with
  | 0 =>
      -- the `mult * result_0 + carry_0 = rs1_next_0 + 256 * carry_1` equation is
      -- deliberately absent: this is the mutation.
      mult * result.limb1.toNat + carry1 = source.limb1.toNat + 256 * carry2 ∧
      mult * result.limb2.toNat + carry2 = source.limb2.toNat + 256 * carry3 ∧
      mult * result.limb3.toNat + carry3 + 256 * sign =
        source.limb3.toNat + 256 * sign * mult
  | 1 =>
      mult * result.limb0.toNat + carry1 = source.limb1.toNat + 256 * carry2 ∧
      mult * result.limb1.toNat + carry2 = source.limb2.toNat + 256 * carry3 ∧
      mult * result.limb2.toNat + carry3 + 256 * sign =
        source.limb3.toNat + 256 * sign * mult ∧
      result.limb3.toNat = 255 * sign
  | 2 =>
      mult * result.limb0.toNat + carry2 = source.limb2.toNat + 256 * carry3 ∧
      mult * result.limb1.toNat + carry3 + 256 * sign =
        source.limb3.toNat + 256 * sign * mult ∧
      result.limb2.toNat = 255 * sign ∧
      result.limb3.toNat = 255 * sign
  | _ =>
      mult * result.limb0.toNat + carry3 + 256 * sign =
        source.limb3.toNat + 256 * sign * mult ∧
      result.limb1.toNat = 255 * sign ∧
      result.limb2.toNat = 255 * sign ∧
      result.limb3.toNat = 255 * sign

theorem shiftRightEquations_weakens_lowByte
    (limbIndex mult sign : Nat)
    (source result : WordBytes)
    (carry0 carry1 carry2 carry3 : Nat)
    (equations :
      shiftRightEquations limbIndex mult sign source result carry0 carry1 carry2
        carry3) :
    shiftRightEquationsWithoutLowByte limbIndex mult sign source result carry0
      carry1 carry2 carry3 := by
  cases limbIndex with
  | zero =>
    simp only [shiftRightEquations] at equations
    exact ⟨equations.2.1, equations.2.2.1, equations.2.2.2⟩
  | succ first =>
    cases first with
    | zero => exact equations
    | succ second =>
      cases second with
      | zero => exact equations
      | succ third => exact equations

/-- `ShiftHolds` with constraint 38 deleted from the right-shift block, and
nothing else changed. -/
structure ShiftHoldsWithoutRightLowByte (row : ShiftRow) : Prop where
  /-- `limb_markers_hot`. -/
  limbIndexRange : row.limbIndex < 4
  /-- `bit_markers_hot`. -/
  bitIndexRange : row.bitIndex < 8
  /-- Constraint 5, `(1 - is_sra) * rs1_sign = 0`. -/
  signIsLogicalZero : row.kind ≠ ShiftKind.sra → row.rs1Sign = false
  /-- Lookup 19, both halves, kept verbatim. -/
  signLowerBound :
    row.kind = ShiftKind.sra → 128 * row.signNat ≤ row.rs1Next.limb3.toNat
  signUpperBound :
    row.kind = ShiftKind.sra →
      row.rs1Next.limb3.toNat < 128 * row.signNat + 128
  /-- `carryRangePairs`. -/
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
  /-- Constraints 39-53: constraint 38 is deliberately absent. -/
  rightMovement :
    row.kind ≠ ShiftKind.sll →
      shiftRightEquationsWithoutLowByte row.limbIndex row.multiplier row.signNat
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

theorem shiftHolds_weakens_rightLowByte
    (row : ShiftRow)
    (holds : ShiftHolds row) :
    ShiftHoldsWithoutRightLowByte row where
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
  leftMovement := holds.leftMovement
  rightMovement := fun kind =>
    shiftRightEquations_weakens_lowByte row.limbIndex row.multiplier row.signNat
      row.rs1Next row.result row.carry0 row.carry1 row.carry2 row.carry3
      (holds.rightMovement kind)
  destinationFlag := holds.destinationFlag
  destinationLimb0 := holds.destinationLimb0
  destinationLimb1 := holds.destinationLimb1
  destinationLimb2 := holds.destinationLimb2
  destinationLimb3 := holds.destinationLimb3

/-- `ShiftsRegHolds` with the shared layer weakened by exactly that one
deletion. -/
structure ShiftsRegHoldsWithoutRightLowByte (row : ShiftsRegRow) : Prop where
  core : ShiftHoldsWithoutRightLowByte row.semantic
  clockPositive : 0 < row.clock
  sourceClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  secondSourceClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  secondSourceReadOnly : row.rs2Next = row.rs2Previous
  shiftAmountBinds :
    ∃ high,
      high ≤ 7 ∧
        row.rs2Next.limb0.toNat = 32 * high + row.semantic.shiftAmount
  nextPcResult : row.claimedNextPc = nextPc row.pc

theorem shiftsRegHolds_weakens_rightLowByte
    (row : ShiftsRegRow)
    (holds : ShiftsRegHolds row) :
    ShiftsRegHoldsWithoutRightLowByte row where
  core := shiftHolds_weakens_rightLowByte row.semantic holds.core
  clockPositive := holds.clockPositive
  sourceClock := holds.sourceClock
  secondSourceClock := holds.secondSourceClock
  destinationClock := holds.destinationClock
  secondSourceReadOnly := holds.secondSourceReadOnly
  shiftAmountBinds := holds.shiftAmountBinds
  nextPcResult := holds.nextPcResult

/-- `SRL x7, x5, x6` with `X(rs1) = 0x10` and `X(rs2) = 1`, claiming `0x09` in
the low output byte instead of `0x08`.

The three surviving equations of the hot-limb-0 branch still hold: the three
upper source bytes are zero, every carry is zero and in range below
`bit_multiplier = 2`, and `rs1_sign = 0` makes the top-input equation
`2 * result_3 + carry_3 = rs1_next_3`, i.e. `0 = 0`. The five-bit mask still
binds `shift_amount = 1`, so the shift amount is the honest one and the *only*
thing wrong with this row is the freed byte. -/
def srlFreeLowByteSemantic : ShiftRow where
  rs1Previous := shiftsRegMutationBytes 0x10 0 0 0
  rs1Next := shiftsRegMutationBytes 0x10 0 0 0
  rs1Sign := false
  kind := ShiftKind.srl
  limbIndex := 0
  bitIndex := 1
  carry0 := 0
  carry1 := 0
  carry2 := 0
  carry3 := 0
  result := shiftsRegMutationBytes 0x09 0 0 0
  rd := BitVec.ofNat 5 7
  rdPrevious := WordBytes.zero
  rdNext := shiftsRegMutationBytes 0x09 0 0 0
  rdNonzero := true

def srlFreeLowByteRow : ShiftsRegRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rs2 := BitVec.ofNat 5 6
  rs2PreviousClock := 0
  rs2Previous := shiftsRegMutationBytes 1 0 0 0
  rs2Next := shiftsRegMutationBytes 1 0 0 0
  rdPreviousClock := 0
  semantic := srlFreeLowByteSemantic
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem srlFreeLowByteRow_satisfies :
    ShiftsRegHoldsWithoutRightLowByte srlFreeLowByteRow := by
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
      leftMovement := fun h => absurd h (by decide)
      rightMovement := ?_
      destinationFlag := by decide
      destinationLimb0 := by decide
      destinationLimb1 := by decide
      destinationLimb2 := by decide
      destinationLimb3 := by decide
    }
    intro _
    refine ⟨?_, ?_, ?_⟩ <;> decide
  · simp [validPreviousClock, accessClock, srlFreeLowByteRow]
  · simp [validPreviousClock, accessClock, srlFreeLowByteRow]
  · simp [validPreviousClock, accessClock, srlFreeLowByteRow]

/-- The row retires `0x09` where `SRL` of `0x10` by one is `0x08`. -/
theorem srlFreeLowByteRow_refutes :
    ¬ SrlRetiresRegisterLogicalShift srlFreeLowByteRow := by
  unfold SrlRetiresRegisterLogicalShift
  decide

/-- The failure mode, spelled out: the shift amount is still the honest masked
one and the three upper output bytes are still correct; only the freed byte is
wrong, and it is wrong by one. -/
theorem srlFreeLowByteRow_has_one_wrong_byte :
    (registerShiftAmount srlFreeLowByteRow.rs2Previous.word).toNat = 1 ∧
      srlFreeLowByteRow.semantic.shiftAmount = 1 ∧
      srlFreeLowByteRow.semantic.result.word = BitVec.ofNat 32 0x09 ∧
      executeSrlValue srlFreeLowByteRow.semantic.rs1Previous.word
          (registerShiftAmount srlFreeLowByteRow.rs2Previous.word) =
        BitVec.ofNat 32 0x08 :=
  ⟨by decide, by decide, by decide, by decide⟩

/-- The published control. -/
def srlFreeResultLowByte :
    MutationControl ShiftsRegHoldsWithoutRightLowByte
      SrlRetiresRegisterLogicalShift where
  name := "srl-free-result-low-byte"
  witness := srlFreeLowByteRow
  satisfies := srlFreeLowByteRow_satisfies
  refutes := srlFreeLowByteRow_refutes

/-- The witness is genuinely outside the honest system. -/
theorem srlFreeLowByteRow_not_sound : ¬ ShiftsRegHolds srlFreeLowByteRow :=
  srlFreeResultLowByte.witness_not_sound ShiftsRegHolds
    srl_retires_register_logical_shift

/-- The deletion is not free: the carry chain does not reconstruct the low output
byte on its own, so each individual byte equation of the right-shift block is
doing work. -/
theorem shifts_reg_right_low_byte_is_load_bearing :
    ¬ (∀ row, ShiftsRegHoldsWithoutRightLowByte row → ShiftsRegHolds row) :=
  srlFreeResultLowByte.strictly_weaker ShiftsRegHolds
    srl_retires_register_logical_shift

/-- The same counterexample at the shared layer, which is what makes this control
certify the `SRLI` and `SRAI` right blocks as well as `SRL` and `SRA`. -/
theorem shift_right_low_byte_is_load_bearing :
    ¬ (∀ row, ShiftHoldsWithoutRightLowByte row → ShiftHolds row) := by
  intro implies
  exact shifts_reg_right_low_byte_is_load_bearing fun row weakened =>
    { core := implies row.semantic weakened.core
      clockPositive := weakened.clockPositive
      sourceClock := weakened.sourceClock
      secondSourceClock := weakened.secondSourceClock
      destinationClock := weakened.destinationClock
      secondSourceReadOnly := weakened.secondSourceReadOnly
      shiftAmountBinds := weakened.shiftAmountBinds
      nextPcResult := weakened.nextPcResult }

/-! ## The three conclusions are reachable

Each conclusion is guarded on the selector its opcode owns, so it would be
worthless if no row could activate the guard: a guarded implication with an
unsatisfiable antecedent is true of every row, and a control refuting it would
certify nothing. The three honest witnesses of `Opcodes/Shifts.lean` activate
the three guards, and each satisfies its conclusion through the in-file
soundness theorem. -/

/-- Non-vacuity of the three conclusions: each is satisfied by the honest witness
of its opcode, whose selector is hot. -/
theorem shifts_reg_conclusions_are_reachable :
    sllWitnessRow.semantic.kind = ShiftKind.sll ∧
      srlWitnessRow.semantic.kind = ShiftKind.srl ∧
      sraWitnessRow.semantic.kind = ShiftKind.sra ∧
      SllRetiresRegisterShift sllWitnessRow ∧
      SrlRetiresRegisterLogicalShift srlWitnessRow ∧
      SraRetiresRegisterArithmeticShift sraWitnessRow :=
  ⟨rfl, rfl, rfl,
    sll_retires_register_shift sllWitnessRow sll_witness_holds,
    srl_retires_register_logical_shift srlWitnessRow srl_witness_holds,
    sra_retires_register_arithmetic_shift sraWitnessRow sra_witness_holds⟩

/-- And each conclusion is genuinely *refutable*, i.e. it is not a tautology: the
four witnesses of this file all fail one of them. Taken with the reachability
result above, each conclusion is pinned strictly between "always true" and
"never true", which is the shape a mutation control's conclusion has to have. -/
theorem shifts_reg_conclusions_are_refutable :
    ¬ SllRetiresRegisterShift sllUnmaskedAmountRow ∧
      ¬ SllRetiresRegisterShift sllMutatedRs2Row ∧
      ¬ SraRetiresRegisterArithmeticShift sraZeroFillRow ∧
      ¬ SrlRetiresRegisterLogicalShift srlFreeLowByteRow :=
  ⟨sllUnmaskedAmountRow_refutes, sllMutatedRs2Row_refutes,
    sraZeroFillRow_refutes, srlFreeLowByteRow_refutes⟩

/-! ## Index of the four published controls -/

/-- The four controls of this file. Each `name` is the stable identity recorded
in the Team B certificate index, and each is distinct from the four names
published by `Opcodes/ShiftsMutation.lean`. -/
theorem shifts_reg_mutation_control_names :
    sllFreeShiftAmountMask.name = "sll-free-shift-amount-mask" ∧
      sllReleasedSecondSource.name = "sll-released-second-source" ∧
      sraReleasedSignWitness.name = "sra-released-sign-witness" ∧
      srlFreeResultLowByte.name = "srl-free-result-low-byte" :=
  ⟨rfl, rfl, rfl, rfl⟩

end RiscvRefinement.Opcodes
