-- The AIR-interpreter bridge for the `mulh` / `mulhsu` / `mulhu` family.
--
-- This is the second family bridged this way; `Air/Bridge/MulBridge.lean` is
-- the first and the template. Issue #137 forbids Team B from restating
-- production constraints in a private Lean predicate, and
-- `RiscvRefinement/Air/Family/Multiply.lean` currently does exactly that:
-- `MulhHolds` is a hand transcription of `/tmp/tb-ir/mulh.json`. This file maps
-- a typed `MulhRow` onto the 53 columns of the shipped AIR and proves, by
-- *evaluating the encoded production node table*, that whenever `MulhHolds row`
-- holds
--
--   * every one of the 30 constraint roots evaluates to zero,
--   * every live fixed-table request lands inside its table, and
--   * every one of the 22 lookup tuples is the transcribed relation tuple.
--
-- So the hand transcription is not weaker than the shipped AIR: nothing the AIR
-- asks for on an active row is missing from it.
--
-- Two things differ from `mul` and both are load-bearing.
--
-- 1. `mul` has a committed `enabler` column pinned to one, so it has no case
--    split. `mulh` is three opcodes sharing one AIR, and its "enabler" is the
--    sum `is_mulh + is_mulhsu + is_mulhu`, pinned to one by constraint 23. The
--    column assignment therefore synthesises the three selector columns from
--    `MulhRow.selector`, and eight of the thirty constraints are discharged by
--    a three-way case split on it.
--
-- 2. Lookups 17 and 18 -- the `range_check_m31` sign witnesses -- carry
--    numerators `-(is_mulh + is_mulhsu)` and `-is_mulh`, which vanish on
--    `mulhu` (and, for 18, `mulhsu`) rows. A LogUp term with a zero numerator
--    is not a request, and on such a row the tuple genuinely is outside the
--    table: `MulhProgram.lean` carries a satisfying `mulhu` witness whose
--    lookup-17 tuple is `(0, 255)`. The fixed-request theorem is therefore
--    stated over live requests only. That is not a weakening of convenience;
--    the ungated statement is false, and the generated file `#guard`s it false
--    on that row so the gate cannot be quietly widened later.
--
-- The pc-wrap side condition `MulhRowFits` is carried forward from the `mul`
-- bridge for the same reason (see the docstring on it): `MulhRow.pc` is a
-- `BitVec 32` whose `nextPc` wraps, and the AIR's `pc` is a field element whose
-- next-pc node is `pc + 4`. `MulhHolds` does not imply the two agree.
--
-- What is NOT proved here is the same list as for `mul`, in
-- /tmp/o1-bridge-report.md section 3, plus the two `mulh`-specific items in
-- /tmp/o2-mulh-bridge-report.md.

import RiscvRefinement.Air.Bridge.MulhProgram
import RiscvRefinement.Air.Bridge.MulBridge

namespace RiscvRefinement.Air.Bridge

open RiscvRefinement
open RiscvRefinement.Air.Family

set_option maxRecDepth 8000

-- The encoded node table and the hand transcription in
-- `Air/Family/Multiply.lean` are pinned to the same export.
-- `mulhProgramIrDigest` is written by the generator from the sha256 of the
-- bytes it read; `mulhIrDigest` is the constant the transcription carries.
#guard mulhProgramIrDigest == mulhIrDigest

/-! ## The `M31` arithmetic this family adds

Everything else comes from `MulBridge.lean`, whose `M31` layer is
family-independent. -/

namespace M31

/-- The shape every one of the eight `range_check_8_11` carry requests has:
the AIR spells a carry as `(partial_sum - output) * 8388608`, and `8388608` is
the inverse of `256` in `M31`. -/
theorem carryStep (total output carry : Nat)
    (equation : total = output + 256 * carry) :
    (M31.reduce total - M31.reduce output) * M31.reduce 8388608 =
      M31.reduce carry := by
  rw [M31.reduce_sub _ _ (by omega),
    show total - output = 256 * carry from by omega, M31.reduce_mul]
  exact M31.reduce_shift _

end M31

private theorem reduceToNat_lt {value bound : Nat} (small : value < bound) :
    (M31.reduce value).toNat < bound := by
  simp only [M31.toNat, M31.val_reduce]
  exact Nat.lt_of_le_of_lt (Nat.mod_le _ _) small

/-- A selector-gated constraint whose gate is off: the row-dependent factor is
never inspected. -/
private theorem mulLeftZero {left right : M31} (zero : left = 0) :
    left * right = 0 := by
  rw [zero, M31.zero_mul]

/-! ## The selector columns

`MulhRow.selector` is the fact that exactly one of `is_mulh`, `is_mulhsu`,
`is_mulhu` is set; the AIR spends three columns on it. -/

def mulhBit : MulhSelector → Nat
  | .mulh => 1
  | .mulhsu => 0
  | .mulhu => 0

def mulhsuBit : MulhSelector → Nat
  | .mulh => 0
  | .mulhsu => 1
  | .mulhu => 0

def mulhuBit : MulhSelector → Nat
  | .mulh => 0
  | .mulhsu => 0
  | .mulhu => 1

/-- Constraint 23: the family selector is pinned to one. -/
theorem selectorSum (selector : MulhSelector) :
    M31.reduce (mulhBit selector) + M31.reduce (mulhsuBit selector) +
        M31.reduce (mulhuBit selector) = M31.reduce 1 := by
  cases selector <;> rfl

/-- Constraint 24 and lookup 0: the program-bus opcode identifier. -/
theorem selectorOpcode (selector : MulhSelector) :
    M31.reduce (mulhBit selector) * M31.reduce 38 +
        M31.reduce (mulhsuBit selector) * M31.reduce 39 +
        M31.reduce (mulhuBit selector) * M31.reduce 40 =
      M31.reduce selector.opcodeId := by
  cases selector <;> rfl

/-- The AIR extends each operand to eight limbs by repeating `sign * 255`. -/
theorem signFillImage (sign : Bool) :
    M31.reduce (multiplySignBit sign) * M31.reduce 255 =
      M31.reduce (multiplySignFill sign) := by
  cases sign <;> rfl

/-! ## The column assignment

`MulhRow` is not a complete AIR row: `destination_inverse`, the three selector
columns and the six `bus_value_*` columns have no counterpart in the
transcription, so the assignment has to synthesise them from the fields
`MulhRow` does carry. That gap is real and is called out in the report. -/

/-- The typed row, laid out as the 53 columns of `mulh.json`. -/
def mulhColumns (row : MulhRow) : List M31 :=
  [ M31.reduce row.clock,                          -- 0  clock
    M31.reduce row.pc.toNat,                       -- 1  pc
    M31.reduce row.rd.toNat,                       -- 2  rd_addr
    M31.reduce row.rdPrevious.limb0.toNat,         -- 3  rd_previous_0
    M31.reduce row.rdPrevious.limb1.toNat,         -- 4  rd_previous_1
    M31.reduce row.rdPrevious.limb2.toNat,         -- 5  rd_previous_2
    M31.reduce row.rdPrevious.limb3.toNat,         -- 6  rd_previous_3
    M31.reduce row.rdPreviousClock,                -- 7  rd_previous_clock
    M31.reduce row.rdNext.limb0.toNat,             -- 8  rd_next_0
    M31.reduce row.rdNext.limb1.toNat,             -- 9  rd_next_1
    M31.reduce row.rdNext.limb2.toNat,             -- 10 rd_next_2
    M31.reduce row.rdNext.limb3.toNat,             -- 11 rd_next_3
    M31.reduce row.rs1.toNat,                      -- 12 rs1_addr
    M31.reduce row.rs1Previous.limb0.toNat,        -- 13 rs1_previous_0
    M31.reduce row.rs1Previous.limb1.toNat,        -- 14 rs1_previous_1
    M31.reduce row.rs1Previous.limb2.toNat,        -- 15 rs1_previous_2
    M31.reduce row.rs1Previous.limb3.toNat,        -- 16 rs1_previous_3
    M31.reduce row.rs1PreviousClock,               -- 17 rs1_previous_clock
    M31.reduce row.rs1Next.limb0.toNat,            -- 18 rs1_next_0
    M31.reduce row.rs1Next.limb1.toNat,            -- 19 rs1_next_1
    M31.reduce row.rs1Next.limb2.toNat,            -- 20 rs1_next_2
    M31.reduce row.rs1Next.limb3.toNat,            -- 21 rs1_next_3
    M31.reduce row.rs2.toNat,                      -- 22 rs2_addr
    M31.reduce row.rs2Previous.limb0.toNat,        -- 23 rs2_previous_0
    M31.reduce row.rs2Previous.limb1.toNat,        -- 24 rs2_previous_1
    M31.reduce row.rs2Previous.limb2.toNat,        -- 25 rs2_previous_2
    M31.reduce row.rs2Previous.limb3.toNat,        -- 26 rs2_previous_3
    M31.reduce row.rs2PreviousClock,               -- 27 rs2_previous_clock
    M31.reduce row.rs2Next.limb0.toNat,            -- 28 rs2_next_0
    M31.reduce row.rs2Next.limb1.toNat,            -- 29 rs2_next_1
    M31.reduce row.rs2Next.limb2.toNat,            -- 30 rs2_next_2
    M31.reduce row.rs2Next.limb3.toNat,            -- 31 rs2_next_3
    M31.reduce row.rdHigh.limb0.toNat,             -- 32 rd_high_0
    M31.reduce row.rdHigh.limb1.toNat,             -- 33 rd_high_1
    M31.reduce row.rdHigh.limb2.toNat,             -- 34 rd_high_2
    M31.reduce row.rdHigh.limb3.toNat,             -- 35 rd_high_3
    M31.reduce (multiplySignBit row.rs1Sign),      -- 36 rs1_sign
    M31.reduce (multiplySignBit row.rs2Sign),      -- 37 rs2_sign
    M31.reduce (mulhBit row.selector),             -- 38 is_mulh
    M31.reduce (mulhsuBit row.selector),           -- 39 is_mulhsu
    M31.reduce (mulhuBit row.selector),            -- 40 is_mulhu
    M31.reduce row.result.limb0.toNat,             -- 41 result_0
    M31.reduce row.result.limb1.toNat,             -- 42 result_1
    M31.reduce row.result.limb2.toNat,             -- 43 result_2
    M31.reduce row.result.limb3.toNat,             -- 44 result_3
    M31.reduce (flagValue row.rdNonzero),          -- 45 destination_nonzero
    registerInverse row.rd,                        -- 46 destination_inverse
    M31.reduce row.selector.opcodeId,              -- 47 bus_value_47
    M31.reduce row.claimedNextPc.toNat,            -- 48 bus_value_48
    M31.reduce (row.clock + 1),                    -- 49 bus_value_49
    M31.reduce (accessClock row.clock 1),          -- 50 bus_value_50
    M31.reduce (accessClock row.clock 2),          -- 51 bus_value_51
    M31.reduce (accessClock row.clock 3) ]         -- 52 bus_value_52

/-- The side condition the transcription does not carry.

`MulhRow.pc` is a `BitVec 32` and `nextPc` wraps at `2 ^ 32`; the AIR's `pc` is
a single field element and its next-pc node is `pc + 4` in `M31`. The two agree
only when the program counter does not wrap, which is a hypothesis about the
row, not a consequence of `MulhHolds`. Identical to `MulRowFits`; the two should
merge into a shared row invariant when the row types absorb it. -/
structure MulhRowFits (row : MulhRow) : Prop where
  programCounter : row.pc.toNat + 4 < 4294967296

/-! ## Facts about the row that the constraint proofs consume -/

private theorem nextPcImage (row : MulhRow) (holds : MulhHolds row)
    (fits : MulhRowFits row) :
    row.claimedNextPc.toNat = row.pc.toNat + 4 := by
  have wrap := fits.programCounter
  simp only [holds.nextPcResult, RiscvRefinement.nextPc, BitVec.toNat_add,
    BitVec.toNat_ofNat, Nat.reducePow]
  omega

private theorem rdNonzeroImage (row : MulhRow) (holds : MulhHolds row) :
    row.rdNonzero = decide (row.rd.toNat ≠ 0) := by
  have index : (row.rd = zeroRegister) ↔ (row.rd.toNat = 0) := by
    constructor
    · intro equal
      rw [equal]
      rfl
    · intro equal
      apply BitVec.eq_of_toNat_eq
      rw [equal]
      rfl
  rw [holds.destinationFlag]
  simp only [ne_eq, index]

private theorem destinationSelectorVanishes (row : MulhRow) (holds : MulhHolds row) :
    M31.reduce row.rd.toNat *
        (M31.reduce 1 - M31.reduce (flagValue row.rdNonzero)) = 0 := by
  cases flag : row.rdNonzero with
  | false =>
      have image := rdNonzeroImage row holds
      rw [flag] at image
      have zero : row.rd.toNat = 0 := by simpa using image.symm
      rw [zero]
      simp only [flagValue, M31.reduce_zero, M31.zero_mul]
  | true =>
      simp only [flagValue]
      rw [M31.sub_self, M31.mul_zero]

private theorem destinationLimbVanishes
    (flagBit : Bool) (limbNext limbResult zeroLimb : Byte)
    (zeroValue : zeroLimb.toNat = 0)
    (equation : limbNext = if flagBit then limbResult else zeroLimb) :
    M31.reduce limbNext.toNat -
        M31.reduce (flagValue flagBit) * M31.reduce limbResult.toNat = 0 := by
  cases flagBit with
  | false =>
      simp only [Bool.false_eq_true, if_false] at equation
      rw [equation, zeroValue]
      simp only [flagValue, M31.reduce_zero, M31.zero_mul]
      exact M31.sub_self 0
  | true =>
      simp only [if_true] at equation
      rw [equation]
      simp only [flagValue, M31.reduce_mul, Nat.one_mul]
      exact M31.sub_self _

/-! ## The bridge for the constraint roots -/

/-- Every constraint root of the encoded production `mulh` AIR evaluates to
zero under `mulhColumns row`, for every row the transcription accepts. -/
theorem mulhConstraintValues (row : MulhRow) (holds : MulhHolds row)
    (fits : MulhRowFits row) :
    mulhProgramCompiled.constraintValues (mulhColumns row) = List.replicate 30 0 := by
  have nextPcValue := nextPcImage row holds fits
  have clockPositive := holds.clockPositive
  simp only [MulhCircuit.constraintValues, MulhCircuit.values, MulhCircuit.value,
    MulhCircuit.nodeValuesRev, mulhProgramCompiled, mulhProgram, evalLoop,
    Node.evalLocal, nth, List.map_cons, List.map_nil, mulhColumns, List.replicate,
    List.cons.injEq, and_true]
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  -- constraint 0: active * (1 - active), active = is_mulh + is_mulhsu + is_mulhu
  · rw [selectorSum, M31.sub_self, M31.mul_zero]
  -- constraints 1-3: booleanity of the three opcode selectors
  · cases row.selector <;> decide
  · cases row.selector <;> decide
  · cases row.selector <;> decide
  -- constraints 4-5: booleanity of the two sign witnesses
  · cases row.rs1Sign <;> decide
  · cases row.rs2Sign <;> decide
  -- constraint 6: (1 - is_mulh - is_mulhsu) * rs1_sign
  · cases selector : row.selector with
    | mulh => exact mulLeftZero (by decide)
    | mulhsu => exact mulLeftZero (by decide)
    | mulhu =>
        rw [holds.unsignedSourceOne (by rw [selector]; rfl)]
        decide
  -- constraint 7: (1 - is_mulh) * rs2_sign
  · cases selector : row.selector with
    | mulh => exact mulLeftZero (by decide)
    | mulhsu =>
        rw [holds.unsignedSourceTwo (by rw [selector]; rfl)]
        decide
    | mulhu =>
        rw [holds.unsignedSourceTwo (by rw [selector]; rfl)]
        decide
  -- constraint 8: destination_nonzero * (destination_nonzero - 1)
  · cases row.rdNonzero <;> decide
  -- constraint 9: rd_addr * (1 - destination_nonzero)
  · exact destinationSelectorVanishes row holds
  -- constraint 10: rd_addr * destination_inverse - destination_nonzero
  · have bound : row.rd.toNat < 32 := by simpa using row.rd.isLt
    rw [registerInverse, M31.reduce_mul, rdNonzeroImage row holds]
    exact M31.reduce_sub_eq_zero _ _ (registerInverseTable_spec row.rd.toNat bound)
  -- constraints 11-14: rd_next_i = destination_nonzero * result_i
  · exact destinationLimbVanishes row.rdNonzero _ _ _ rfl holds.destinationLimb0
  · exact destinationLimbVanishes row.rdNonzero _ _ _ rfl holds.destinationLimb1
  · exact destinationLimbVanishes row.rdNonzero _ _ _ rfl holds.destinationLimb2
  · exact destinationLimbVanishes row.rdNonzero _ _ _ rfl holds.destinationLimb3
  -- constraints 15-18: rs1 is read-only on the register bus
  · rw [holds.sourceOneLimb0, M31.sub_self, M31.mul_zero]
  · rw [holds.sourceOneLimb1, M31.sub_self, M31.mul_zero]
  · rw [holds.sourceOneLimb2, M31.sub_self, M31.mul_zero]
  · rw [holds.sourceOneLimb3, M31.sub_self, M31.mul_zero]
  -- constraints 19-22: rs2 is read-only on the register bus
  · rw [holds.sourceTwoLimb0, M31.sub_self, M31.mul_zero]
  · rw [holds.sourceTwoLimb1, M31.sub_self, M31.mul_zero]
  · rw [holds.sourceTwoLimb2, M31.sub_self, M31.mul_zero]
  · rw [holds.sourceTwoLimb3, M31.sub_self, M31.mul_zero]
  -- constraint 23: the family selector is pinned to one
  · rw [selectorSum]
    exact M31.sub_self 1
  -- constraint 24: bus_value_47 is the program-bus opcode identifier
  · rw [selectorOpcode]
    exact M31.sub_self _
  -- constraint 25: bus_value_48 = pc + 4
  · rw [nextPcValue, M31.reduce_add]
    exact M31.sub_self _
  -- constraint 26: bus_value_49 = clock + 1
  · rw [M31.reduce_add]
    exact M31.sub_self _
  -- constraints 27-29: bus_value_5x = (clock - 1) * 4 + x
  · rw [M31.reduce_sub _ _ clockPositive, M31.reduce_mul, M31.reduce_add]
    exact M31.sub_self _
  · rw [M31.reduce_sub _ _ clockPositive, M31.reduce_mul, M31.reduce_add]
    exact M31.sub_self _
  · rw [M31.reduce_sub _ _ clockPositive, M31.reduce_mul, M31.reduce_add]
    exact M31.sub_self _

/-! ## The eight-limb carry chain

Section 4.1 of the `mul` report applies verbatim here: the `mulh` AIR has *no*
constraint root for the multiplication. The complete 64-bit product identity is
carried entirely by the eight `range_check_8_11` requests, whose second
component is the running carry spelled `(partial_sum - output) * 8388608` with
`8388608 = 256⁻¹ mod (2 ^ 31 - 1)`. These eight lemmas are therefore the
load-bearing content of the bridge, not `mulhConstraintValues`. -/

private theorem carryImage0 (row : MulhRow) (holds : MulhHolds row) :
    (M31.reduce 0 +
          M31.reduce row.rs1Next.limb0.toNat * M31.reduce row.rs2Next.limb0.toNat -
        M31.reduce row.rdHigh.limb0.toNat) * M31.reduce 8388608 =
      M31.reduce row.carry0.toNat := by
  have equation := holds.productLimb0
  simp only [M31.reduce_mul, M31.reduce_add]
  exact M31.carryStep _ _ _ (by omega)

private theorem carryImage1 (row : MulhRow) (holds : MulhHolds row) :
    (M31.reduce row.carry0.toNat +
          M31.reduce row.rs1Next.limb0.toNat * M31.reduce row.rs2Next.limb1.toNat +
          M31.reduce row.rs1Next.limb1.toNat * M31.reduce row.rs2Next.limb0.toNat -
        M31.reduce row.rdHigh.limb1.toNat) * M31.reduce 8388608 =
      M31.reduce row.carry1.toNat := by
  have equation := holds.productLimb1
  simp only [M31.reduce_mul, M31.reduce_add]
  exact M31.carryStep _ _ _ (by omega)

private theorem carryImage2 (row : MulhRow) (holds : MulhHolds row) :
    (M31.reduce row.carry1.toNat +
          M31.reduce row.rs1Next.limb0.toNat * M31.reduce row.rs2Next.limb2.toNat +
          M31.reduce row.rs1Next.limb1.toNat * M31.reduce row.rs2Next.limb1.toNat +
          M31.reduce row.rs1Next.limb2.toNat * M31.reduce row.rs2Next.limb0.toNat -
        M31.reduce row.rdHigh.limb2.toNat) * M31.reduce 8388608 =
      M31.reduce row.carry2.toNat := by
  have equation := holds.productLimb2
  simp only [M31.reduce_mul, M31.reduce_add]
  exact M31.carryStep _ _ _ (by omega)

private theorem carryImage3 (row : MulhRow) (holds : MulhHolds row) :
    (M31.reduce row.carry2.toNat +
          M31.reduce row.rs1Next.limb0.toNat * M31.reduce row.rs2Next.limb3.toNat +
          M31.reduce row.rs1Next.limb1.toNat * M31.reduce row.rs2Next.limb2.toNat +
          M31.reduce row.rs1Next.limb2.toNat * M31.reduce row.rs2Next.limb1.toNat +
          M31.reduce row.rs1Next.limb3.toNat * M31.reduce row.rs2Next.limb0.toNat -
        M31.reduce row.rdHigh.limb3.toNat) * M31.reduce 8388608 =
      M31.reduce row.carry3.toNat := by
  have equation := holds.productLimb3
  simp only [M31.reduce_mul, M31.reduce_add]
  exact M31.carryStep _ _ _ (by omega)

private theorem carryImage4 (row : MulhRow) (holds : MulhHolds row) :
    (M31.reduce row.carry3.toNat +
          M31.reduce row.rs1Next.limb0.toNat *
            M31.reduce (multiplySignFill row.rs2Sign) +
          M31.reduce row.rs1Next.limb1.toNat * M31.reduce row.rs2Next.limb3.toNat +
          M31.reduce row.rs1Next.limb2.toNat * M31.reduce row.rs2Next.limb2.toNat +
          M31.reduce row.rs1Next.limb3.toNat * M31.reduce row.rs2Next.limb1.toNat +
          M31.reduce (multiplySignFill row.rs1Sign) *
            M31.reduce row.rs2Next.limb0.toNat -
        M31.reduce row.result.limb0.toNat) * M31.reduce 8388608 =
      M31.reduce row.carry4.toNat := by
  have equation := holds.productLimb4
  simp only [M31.reduce_mul, M31.reduce_add]
  exact M31.carryStep _ _ _ (by omega)

private theorem carryImage5 (row : MulhRow) (holds : MulhHolds row) :
    (M31.reduce row.carry4.toNat +
          M31.reduce row.rs1Next.limb0.toNat *
            M31.reduce (multiplySignFill row.rs2Sign) +
          M31.reduce row.rs1Next.limb1.toNat *
            M31.reduce (multiplySignFill row.rs2Sign) +
          M31.reduce row.rs1Next.limb2.toNat * M31.reduce row.rs2Next.limb3.toNat +
          M31.reduce row.rs1Next.limb3.toNat * M31.reduce row.rs2Next.limb2.toNat +
          M31.reduce (multiplySignFill row.rs1Sign) *
            M31.reduce row.rs2Next.limb1.toNat +
          M31.reduce (multiplySignFill row.rs1Sign) *
            M31.reduce row.rs2Next.limb0.toNat -
        M31.reduce row.result.limb1.toNat) * M31.reduce 8388608 =
      M31.reduce row.carry5.toNat := by
  have equation := holds.productLimb5
  simp only [M31.reduce_mul, M31.reduce_add]
  exact M31.carryStep _ _ _ (by omega)

private theorem carryImage6 (row : MulhRow) (holds : MulhHolds row) :
    (M31.reduce row.carry5.toNat +
          M31.reduce row.rs1Next.limb0.toNat *
            M31.reduce (multiplySignFill row.rs2Sign) +
          M31.reduce row.rs1Next.limb1.toNat *
            M31.reduce (multiplySignFill row.rs2Sign) +
          M31.reduce row.rs1Next.limb2.toNat *
            M31.reduce (multiplySignFill row.rs2Sign) +
          M31.reduce row.rs1Next.limb3.toNat * M31.reduce row.rs2Next.limb3.toNat +
          M31.reduce (multiplySignFill row.rs1Sign) *
            M31.reduce row.rs2Next.limb2.toNat +
          M31.reduce (multiplySignFill row.rs1Sign) *
            M31.reduce row.rs2Next.limb1.toNat +
          M31.reduce (multiplySignFill row.rs1Sign) *
            M31.reduce row.rs2Next.limb0.toNat -
        M31.reduce row.result.limb2.toNat) * M31.reduce 8388608 =
      M31.reduce row.carry6.toNat := by
  have equation := holds.productLimb6
  simp only [M31.reduce_mul, M31.reduce_add]
  exact M31.carryStep _ _ _ (by omega)

private theorem carryImage7 (row : MulhRow) (holds : MulhHolds row) :
    (M31.reduce row.carry6.toNat +
          M31.reduce row.rs1Next.limb0.toNat *
            M31.reduce (multiplySignFill row.rs2Sign) +
          M31.reduce row.rs1Next.limb1.toNat *
            M31.reduce (multiplySignFill row.rs2Sign) +
          M31.reduce row.rs1Next.limb2.toNat *
            M31.reduce (multiplySignFill row.rs2Sign) +
          M31.reduce row.rs1Next.limb3.toNat *
            M31.reduce (multiplySignFill row.rs2Sign) +
          M31.reduce (multiplySignFill row.rs1Sign) *
            M31.reduce row.rs2Next.limb3.toNat +
          M31.reduce (multiplySignFill row.rs1Sign) *
            M31.reduce row.rs2Next.limb2.toNat +
          M31.reduce (multiplySignFill row.rs1Sign) *
            M31.reduce row.rs2Next.limb1.toNat +
          M31.reduce (multiplySignFill row.rs1Sign) *
            M31.reduce row.rs2Next.limb0.toNat -
        M31.reduce row.result.limb3.toNat) * M31.reduce 8388608 =
      M31.reduce row.carry7.toNat := by
  have equation := holds.productLimb7
  simp only [M31.reduce_mul, M31.reduce_add]
  exact M31.carryStep _ _ _ (by omega)

/-! ## The sign witnesses

Lookups 17 and 18 are `range_check_m31 (0, X_next_3 - 128 * X_sign)`. The
second coordinate is the low seven bits of the operand's top byte, so the
request says exactly "the sign witness is bit 31". -/

private theorem sourceOneSignActive (row : MulhRow) (holds : MulhHolds row)
    (sign : row.rs1Sign = true) : row.selector.signedSourceOne = true := by
  cases active : row.selector.signedSourceOne with
  | false => exact absurd (holds.unsignedSourceOne active) (by rw [sign]; simp)
  | true => rfl

private theorem sourceTwoSignActive (row : MulhRow) (holds : MulhHolds row)
    (sign : row.rs2Sign = true) : row.selector.signedSourceTwo = true := by
  cases active : row.selector.signedSourceTwo with
  | false => exact absurd (holds.unsignedSourceTwo active) (by rw [sign]; simp)
  | true => rfl

private theorem sourceOneSignShift (row : MulhRow) (holds : MulhHolds row) :
    128 * multiplySignBit row.rs1Sign ≤ row.rs1Next.limb3.toNat := by
  cases sign : row.rs1Sign with
  | false => simp [multiplySignBit]
  | true =>
      obtain ⟨rest, witness⟩ :=
        holds.signedSourceOne (sourceOneSignActive row holds sign)
      rw [sign] at witness
      simp only [multiplySignBit] at witness ⊢
      omega

private theorem sourceTwoSignShift (row : MulhRow) (holds : MulhHolds row) :
    128 * multiplySignBit row.rs2Sign ≤ row.rs2Next.limb3.toNat := by
  cases sign : row.rs2Sign with
  | false => simp [multiplySignBit]
  | true =>
      obtain ⟨rest, witness⟩ :=
        holds.signedSourceTwo (sourceTwoSignActive row holds sign)
      rw [sign] at witness
      simp only [multiplySignBit] at witness ⊢
      omega

private theorem sourceOneSignResidue (row : MulhRow) (holds : MulhHolds row) :
    M31.reduce row.rs1Next.limb3.toNat -
        M31.reduce (multiplySignBit row.rs1Sign) * M31.reduce 128 =
      M31.reduce (row.rs1Next.limb3.toNat - 128 * multiplySignBit row.rs1Sign) := by
  rw [M31.reduce_mul, Nat.mul_comm (multiplySignBit row.rs1Sign) 128,
    M31.reduce_sub _ _ (sourceOneSignShift row holds)]

private theorem sourceTwoSignResidue (row : MulhRow) (holds : MulhHolds row) :
    M31.reduce row.rs2Next.limb3.toNat -
        M31.reduce (multiplySignBit row.rs2Sign) * M31.reduce 128 =
      M31.reduce (row.rs2Next.limb3.toNat - 128 * multiplySignBit row.rs2Sign) := by
  rw [M31.reduce_mul, Nat.mul_comm (multiplySignBit row.rs2Sign) 128,
    M31.reduce_sub _ _ (sourceTwoSignShift row holds)]

/-- When lookup 17 is live, its second coordinate is a seven-bit value: that is
what makes the request land in the `range_check_m31` table. -/
private theorem sourceOneSignRange (row : MulhRow) (holds : MulhHolds row)
    (active : row.selector.signedSourceOne = true) :
    row.rs1Next.limb3.toNat - 128 * multiplySignBit row.rs1Sign < 128 := by
  obtain ⟨rest, witness⟩ := holds.signedSourceOne active
  have bound := rest.isLt
  simp only [Nat.reducePow] at bound
  omega

private theorem sourceTwoSignRange (row : MulhRow) (holds : MulhHolds row)
    (active : row.selector.signedSourceTwo = true) :
    row.rs2Next.limb3.toNat - 128 * multiplySignBit row.rs2Sign < 128 := by
  obtain ⟨rest, witness⟩ := holds.signedSourceTwo active
  have bound := rest.isLt
  simp only [Nat.reducePow] at bound
  omega

/-! ## The access-clock images, shared with the `mul` bridge -/

private theorem gapImage (row : MulhRow) (holds : MulhHolds row)
    (ordinal previous : Nat) (order : previous < accessClock row.clock ordinal) :
    (M31.reduce row.clock - M31.reduce 1) * M31.reduce 4 + M31.reduce ordinal -
          M31.reduce previous - M31.reduce 1 =
      M31.reduce (accessClock row.clock ordinal - previous - 1) := by
  have positive := holds.clockPositive
  rw [M31.reduce_sub _ _ positive, M31.reduce_mul, M31.reduce_add]
  rw [show (row.clock - 1) * 4 + ordinal = accessClock row.clock ordinal from rfl]
  rw [M31.reduce_sub _ _ (by omega), M31.reduce_sub _ _ (by omega)]

private theorem accessClockImage (row : MulhRow) (holds : MulhHolds row)
    (ordinal : Nat) :
    (M31.reduce row.clock - M31.reduce 1) * M31.reduce 4 + M31.reduce ordinal =
      M31.reduce (accessClock row.clock ordinal) := by
  have positive := holds.clockPositive
  rw [M31.reduce_sub _ _ positive, M31.reduce_mul, M31.reduce_add]
  congr 1

/-- The one reserved row of the `range_check_m31` table is `(255, 127)`; both
`mulh` requests have first coordinate `0`, so the exclusion never bites. -/
private theorem zeroNotReserved (value : M31) :
    (decide ((M31.reduce 0).toNat = 255) && decide (value.toNat = 127)) = false := by
  rw [show (decide ((M31.reduce 0).toNat = 255)) = false from by decide, Bool.false_and]

/-! ## The bridge for the fixed-table requests

This is the theorem that carries the multiplication. The eight
`range_check_8_11` requests bound each output byte to eight bits and each carry
to eleven bits, and it is the eleven-bit carry bound that forces every division
by `256` in the schoolbook chain to be exact. -/

/-- Every live fixed-table request the shipped `mulh` AIR makes lands inside its
table, for every row the transcription accepts.

"Live" means non-zero numerator, which is the LogUp reading: a term with a zero
numerator contributes nothing to the bus sum and is therefore not a request.
Only lookups 17 and 18 are ever dead, and only on rows whose selector makes the
corresponding operand unsigned. See the file header, and the counterexample
`#guard` in `MulhProgram.lean`, for why this cannot be strengthened. -/
theorem mulhFixedRequestsHold (row : MulhRow) (holds : MulhHolds row) :
    mulhProgramCompiled.fixedRequestsHold (mulhColumns row) = true := by
  have sourceOne := holds.sourceOneClock
  have sourceTwo := holds.sourceTwoClock
  have destination := holds.destinationClock
  simp only [MulhCircuit.fixedRequestsHold, MulhCircuit.fixedRequestHolds,
    MulhCircuit.lookupTuple, MulhCircuit.lookupNumerator, MulhCircuit.values,
    MulhCircuit.value, MulhCircuit.nodeValuesRev, mulhProgramCompiled, mulhProgram,
    evalLoop, Node.evalLocal, nth, List.map_cons, List.map_nil, List.all_cons,
    List.all_nil, mulhColumns, rangeCheck20Contains, rangeCheck811Contains,
    rangeCheckM31Contains, Bool.or_true, Bool.and_true]
  rw [signFillImage row.rs1Sign, signFillImage row.rs2Sign,
    carryImage0 row holds, carryImage1 row holds, carryImage2 row holds,
    carryImage3 row holds, carryImage4 row holds, carryImage5 row holds,
    carryImage6 row holds, carryImage7 row holds,
    sourceOneSignResidue row holds, sourceTwoSignResidue row holds,
    gapImage row holds 1 row.rs1PreviousClock sourceOne.1,
    gapImage row holds 2 row.rs2PreviousClock sourceTwo.1,
    gapImage row holds 3 row.rdPreviousClock destination.1]
  simp only [Bool.and_eq_true, Bool.or_eq_true, Bool.true_and,
    Bool.not_eq_eq_eq_not, Bool.not_true, decide_eq_true_eq]
  refine ⟨Or.inr (reduceToNat_lt sourceOne.2),
    Or.inr (reduceToNat_lt sourceTwo.2),
    Or.inr ⟨reduceToNat_lt row.rdHigh.limb0.isLt, reduceToNat_lt row.carry0.isLt⟩,
    Or.inr ⟨reduceToNat_lt row.rdHigh.limb1.isLt, reduceToNat_lt row.carry1.isLt⟩,
    Or.inr ⟨reduceToNat_lt row.rdHigh.limb2.isLt, reduceToNat_lt row.carry2.isLt⟩,
    Or.inr ⟨reduceToNat_lt row.rdHigh.limb3.isLt, reduceToNat_lt row.carry3.isLt⟩,
    Or.inr ⟨reduceToNat_lt row.result.limb0.isLt, reduceToNat_lt row.carry4.isLt⟩,
    Or.inr ⟨reduceToNat_lt row.result.limb1.isLt, reduceToNat_lt row.carry5.isLt⟩,
    Or.inr ⟨reduceToNat_lt row.result.limb2.isLt, reduceToNat_lt row.carry6.isLt⟩,
    Or.inr ⟨reduceToNat_lt row.result.limb3.isLt, reduceToNat_lt row.carry7.isLt⟩,
    ?_, ?_, Or.inr (reduceToNat_lt destination.2)⟩
  -- lookup 17: the rs1 sign request, live exactly when the operand is signed
  · cases active : row.selector.signedSourceOne with
    | false =>
        refine Or.inl ?_
        cases selector : row.selector with
        | mulh => rw [selector] at active; exact absurd active (by decide)
        | mulhsu => rw [selector] at active; exact absurd active (by decide)
        | mulhu => decide
    | true =>
        exact Or.inr ⟨⟨by decide, reduceToNat_lt (sourceOneSignRange row holds active)⟩,
          zeroNotReserved _⟩
  -- lookup 18: the rs2 sign request
  · cases active : row.selector.signedSourceTwo with
    | false =>
        refine Or.inl ?_
        cases selector : row.selector with
        | mulh => rw [selector] at active; exact absurd active (by decide)
        | mulhsu => decide
        | mulhu => decide
    | true =>
        exact Or.inr ⟨⟨by decide, reduceToNat_lt (sourceTwoSignRange row holds active)⟩,
          zeroNotReserved _⟩

/-! ## The bridge for the relation arguments -/

/-- The twenty-two lookup tuples the shipped AIR emits, evaluated under the same
column assignment. This is the statement that the relation arguments Team B
writes down in `mulhRelations` are the tuples the production AIR actually puts
on the bus, rather than a parallel description of them. -/
theorem mulhLookupTuples (row : MulhRow) (holds : MulhHolds row)
    (fits : MulhRowFits row) :
    mulhProgramCompiled.lookups.map (mulhProgramCompiled.lookupTuple (mulhColumns row)) =
      [ -- 0  program_access request
        [M31.reduce row.pc.toNat, M31.reduce row.selector.opcodeId,
          M31.reduce row.rd.toNat, M31.reduce row.rs1.toNat, M31.reduce row.rs2.toNat],
        -- 1  registers_state consume
        [M31.reduce row.pc.toNat, M31.reduce row.clock],
        -- 2  registers_state emit
        [M31.reduce row.claimedNextPc.toNat, M31.reduce (row.clock + 1)],
        -- 3  rs1 memory consume
        [M31.reduce 0, M31.reduce row.rs1.toNat, M31.reduce row.rs1PreviousClock,
          M31.reduce row.rs1Previous.limb0.toNat,
          M31.reduce row.rs1Previous.limb1.toNat,
          M31.reduce row.rs1Previous.limb2.toNat,
          M31.reduce row.rs1Previous.limb3.toNat],
        -- 4  rs1 memory emit
        [M31.reduce 0, M31.reduce row.rs1.toNat,
          M31.reduce (accessClock row.clock 1),
          M31.reduce row.rs1Next.limb0.toNat,
          M31.reduce row.rs1Next.limb1.toNat,
          M31.reduce row.rs1Next.limb2.toNat,
          M31.reduce row.rs1Next.limb3.toNat],
        -- 5  rs1 access-clock gap
        [M31.reduce (accessClock row.clock 1 - row.rs1PreviousClock - 1)],
        -- 6  rs2 memory consume
        [M31.reduce 0, M31.reduce row.rs2.toNat, M31.reduce row.rs2PreviousClock,
          M31.reduce row.rs2Previous.limb0.toNat,
          M31.reduce row.rs2Previous.limb1.toNat,
          M31.reduce row.rs2Previous.limb2.toNat,
          M31.reduce row.rs2Previous.limb3.toNat],
        -- 7  rs2 memory emit
        [M31.reduce 0, M31.reduce row.rs2.toNat,
          M31.reduce (accessClock row.clock 2),
          M31.reduce row.rs2Next.limb0.toNat,
          M31.reduce row.rs2Next.limb1.toNat,
          M31.reduce row.rs2Next.limb2.toNat,
          M31.reduce row.rs2Next.limb3.toNat],
        -- 8  rs2 access-clock gap
        [M31.reduce (accessClock row.clock 2 - row.rs2PreviousClock - 1)],
        -- 9-12  the low four product range checks: rd_high is the LOW word
        [M31.reduce row.rdHigh.limb0.toNat, M31.reduce row.carry0.toNat],
        [M31.reduce row.rdHigh.limb1.toNat, M31.reduce row.carry1.toNat],
        [M31.reduce row.rdHigh.limb2.toNat, M31.reduce row.carry2.toNat],
        [M31.reduce row.rdHigh.limb3.toNat, M31.reduce row.carry3.toNat],
        -- 13-16  the high four: result is the HIGH word, the one written to rd
        [M31.reduce row.result.limb0.toNat, M31.reduce row.carry4.toNat],
        [M31.reduce row.result.limb1.toNat, M31.reduce row.carry5.toNat],
        [M31.reduce row.result.limb2.toNat, M31.reduce row.carry6.toNat],
        [M31.reduce row.result.limb3.toNat, M31.reduce row.carry7.toNat],
        -- 17  rs1 sign witness
        [M31.reduce 0,
          M31.reduce (row.rs1Next.limb3.toNat - 128 * multiplySignBit row.rs1Sign)],
        -- 18  rs2 sign witness
        [M31.reduce 0,
          M31.reduce (row.rs2Next.limb3.toNat - 128 * multiplySignBit row.rs2Sign)],
        -- 19  rd memory consume
        [M31.reduce 0, M31.reduce row.rd.toNat, M31.reduce row.rdPreviousClock,
          M31.reduce row.rdPrevious.limb0.toNat,
          M31.reduce row.rdPrevious.limb1.toNat,
          M31.reduce row.rdPrevious.limb2.toNat,
          M31.reduce row.rdPrevious.limb3.toNat],
        -- 20  rd memory emit
        [M31.reduce 0, M31.reduce row.rd.toNat,
          M31.reduce (accessClock row.clock 3),
          M31.reduce row.rdNext.limb0.toNat,
          M31.reduce row.rdNext.limb1.toNat,
          M31.reduce row.rdNext.limb2.toNat,
          M31.reduce row.rdNext.limb3.toNat],
        -- 21  rd access-clock gap
        [M31.reduce (accessClock row.clock 3 - row.rdPreviousClock - 1)] ] := by
  have sourceOne := holds.sourceOneClock
  have sourceTwo := holds.sourceTwoClock
  have destination := holds.destinationClock
  have nextPcValue := nextPcImage row holds fits
  simp only [MulhCircuit.lookupTuple, MulhCircuit.values, MulhCircuit.value,
    MulhCircuit.nodeValuesRev, mulhProgramCompiled, mulhProgram, evalLoop,
    Node.evalLocal, nth, List.map_cons, List.map_nil, mulhColumns]
  rw [signFillImage row.rs1Sign, signFillImage row.rs2Sign,
    carryImage0 row holds, carryImage1 row holds, carryImage2 row holds,
    carryImage3 row holds, carryImage4 row holds, carryImage5 row holds,
    carryImage6 row holds, carryImage7 row holds,
    sourceOneSignResidue row holds, sourceTwoSignResidue row holds,
    selectorOpcode row.selector,
    gapImage row holds 1 row.rs1PreviousClock sourceOne.1,
    gapImage row holds 2 row.rs2PreviousClock sourceTwo.1,
    gapImage row holds 3 row.rdPreviousClock destination.1,
    accessClockImage row holds 1, accessClockImage row holds 2,
    accessClockImage row holds 3]
  simp only [M31.reduce_add, nextPcValue]

/-! ## From bus limbs back to the relation records

`mulhLookupTuples` states the six `memory_access` tuples as four separate limb
columns, because that is what the AIR puts on the bus. `MulhRelations` carries
each register value as a single `Word`. This lemma is the (only) step between
the two readings; without it, "the AIR's tuples are `mulhRelations`'s tuples"
would be an eyeball claim about the limb decomposition. -/

theorem wordBytesImage (bytes : WordBytes) :
    bytes.word.toNat =
      (M31.reduce bytes.limb0.toNat).toNat +
        256 * (M31.reduce bytes.limb1.toNat).toNat +
        65536 * (M31.reduce bytes.limb2.toNat).toNat +
        16777216 * (M31.reduce bytes.limb3.toNat).toNat := by
  have bound0 := bytes.limb0.isLt
  have bound1 := bytes.limb1.isLt
  have bound2 := bytes.limb2.isLt
  have bound3 := bytes.limb3.isLt
  simp only [Nat.reducePow] at bound0 bound1 bound2 bound3
  rw [WordBytes.word_toNat, WordBytes.value,
    M31.toNat_reduce_of_lt (by simp only [M31.modulus, m31Modulus]; omega),
    M31.toNat_reduce_of_lt (by simp only [M31.modulus, m31Modulus]; omega),
    M31.toNat_reduce_of_lt (by simp only [M31.modulus, m31Modulus]; omega),
    M31.toNat_reduce_of_lt (by simp only [M31.modulus, m31Modulus]; omega)]

/-- The value the register file actually receives, read off the four limbs the
AIR emits in lookup 20. -/
theorem mulhDestinationEmitValue (row : MulhRow) :
    (mulhRelations row).destinationEmit.value.toNat =
      (M31.reduce row.rdNext.limb0.toNat).toNat +
        256 * (M31.reduce row.rdNext.limb1.toNat).toNat +
        65536 * (M31.reduce row.rdNext.limb2.toNat).toNat +
        16777216 * (M31.reduce row.rdNext.limb3.toNat).toNat :=
  wordBytesImage row.rdNext

/-! ## Non-vacuity, and a check on the column assignment itself

`mulhColumns` is hand-written, so it is exactly the kind of transcription this
work exists to remove. It is checked here against `mulhWitnessColumns`, which
the generator computed independently from `mulh.json` (and which the generated
file already checks satisfies every constraint and every table request). If a
column were mis-ordered or mis-populated, this `#guard` fails. -/

/-- `MULH` of `-1` and `2`. Both sign witnesses are exercised: `rs1_sign = 1`
and `rs2_sign = 0`. The 64-bit product is `0xffffffff_fffffffe`, so the *low*
word `rd_high` is `0xfffffffe` and the *high* word `result`, the one written to
`rd`, is `0xffffffff`. -/
def mulhWitnessRow : MulhRow where
  pc := 100#32
  clock := 5
  rd := 7#5
  rdPreviousClock := 3
  rdPrevious := { limb0 := 0#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  rdNext := { limb0 := 255#8, limb1 := 255#8, limb2 := 255#8, limb3 := 255#8 }
  rs1 := 1#5
  rs1PreviousClock := 3
  rs1Previous := { limb0 := 255#8, limb1 := 255#8, limb2 := 255#8, limb3 := 255#8 }
  rs1Next := { limb0 := 255#8, limb1 := 255#8, limb2 := 255#8, limb3 := 255#8 }
  rs2 := 2#5
  rs2PreviousClock := 3
  rs2Previous := { limb0 := 2#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  rs2Next := { limb0 := 2#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  rdHigh := { limb0 := 254#8, limb1 := 255#8, limb2 := 255#8, limb3 := 255#8 }
  rs1Sign := true
  rs2Sign := false
  selector := .mulh
  result := { limb0 := 255#8, limb1 := 255#8, limb2 := 255#8, limb3 := 255#8 }
  carry0 := 1#11
  carry1 := 1#11
  carry2 := 1#11
  carry3 := 1#11
  carry4 := 1#11
  carry5 := 1#11
  carry6 := 1#11
  carry7 := 1#11
  rdNonzero := true
  claimedNextPc := 104#32

#guard mulhColumns mulhWitnessRow == mulhWitnessColumns

theorem mulhWitnessHolds : MulhHolds mulhWitnessRow := by
  refine { clockPositive := by decide
           sourceOneClock := ⟨by decide, by decide⟩
           sourceTwoClock := ⟨by decide, by decide⟩
           destinationClock := ⟨by decide, by decide⟩
           sourceOneLimb0 := by decide
           sourceOneLimb1 := by decide
           sourceOneLimb2 := by decide
           sourceOneLimb3 := by decide
           sourceTwoLimb0 := by decide
           sourceTwoLimb1 := by decide
           sourceTwoLimb2 := by decide
           sourceTwoLimb3 := by decide
           unsignedSourceOne := by intro contra; exact absurd contra (by decide)
           unsignedSourceTwo := by intro contra; exact absurd contra (by decide)
           signedSourceOne := fun _ => ⟨127#7, by decide⟩
           signedSourceTwo := fun _ => ⟨0#7, by decide⟩
           productLimb0 := by decide
           productLimb1 := by decide
           productLimb2 := by decide
           productLimb3 := by decide
           productLimb4 := by decide
           productLimb5 := by decide
           productLimb6 := by decide
           productLimb7 := by decide
           destinationFlag := by decide
           destinationLimb0 := by decide
           destinationLimb1 := by decide
           destinationLimb2 := by decide
           destinationLimb3 := by decide
           nextPcResult := by decide }

theorem mulhWitnessFits : MulhRowFits mulhWitnessRow := by
  constructor
  decide

-- The bridge is therefore not vacuous: this row satisfies every hypothesis.
theorem mulhWitnessConstraintValues :
    mulhProgramCompiled.constraintValues (mulhColumns mulhWitnessRow) =
      List.replicate 30 0 :=
  mulhConstraintValues mulhWitnessRow mulhWitnessHolds mulhWitnessFits

theorem mulhWitnessFixedRequestsHold :
    mulhProgramCompiled.fixedRequestsHold (mulhColumns mulhWitnessRow) = true :=
  mulhFixedRequestsHold mulhWitnessRow mulhWitnessHolds

/-- The `mulhu` companion of the witness above: `0xff000000 * 2`, whose top
source byte is `255`. Its lookup-17 tuple is `(0, 255)`, which is *outside* the
`range_check_m31` table -- and the row is still accepted, because lookup 17's
numerator `-(is_mulh + is_mulhsu)` is zero here. This row is what makes the
numerator gate in `MulhCircuit.fixedRequestsHold` load-bearing rather than
decorative; `MulhProgram.lean` `#guard`s the ungated reading false on it. -/
def mulhUnsignedWitnessRow : MulhRow where
  pc := 100#32
  clock := 5
  rd := 7#5
  rdPreviousClock := 3
  rdPrevious := { limb0 := 0#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  rdNext := { limb0 := 1#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  rs1 := 1#5
  rs1PreviousClock := 3
  rs1Previous := { limb0 := 0#8, limb1 := 0#8, limb2 := 0#8, limb3 := 255#8 }
  rs1Next := { limb0 := 0#8, limb1 := 0#8, limb2 := 0#8, limb3 := 255#8 }
  rs2 := 2#5
  rs2PreviousClock := 3
  rs2Previous := { limb0 := 2#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  rs2Next := { limb0 := 2#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  rdHigh := { limb0 := 0#8, limb1 := 0#8, limb2 := 0#8, limb3 := 254#8 }
  rs1Sign := false
  rs2Sign := false
  selector := .mulhu
  result := { limb0 := 1#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  carry0 := 0#11
  carry1 := 0#11
  carry2 := 0#11
  carry3 := 1#11
  carry4 := 0#11
  carry5 := 0#11
  carry6 := 0#11
  carry7 := 0#11
  rdNonzero := true
  claimedNextPc := 104#32

#guard mulhColumns mulhUnsignedWitnessRow == mulhUnsignedWitnessColumns

theorem mulhUnsignedWitnessHolds : MulhHolds mulhUnsignedWitnessRow := by
  refine { clockPositive := by decide
           sourceOneClock := ⟨by decide, by decide⟩
           sourceTwoClock := ⟨by decide, by decide⟩
           destinationClock := ⟨by decide, by decide⟩
           sourceOneLimb0 := by decide
           sourceOneLimb1 := by decide
           sourceOneLimb2 := by decide
           sourceOneLimb3 := by decide
           sourceTwoLimb0 := by decide
           sourceTwoLimb1 := by decide
           sourceTwoLimb2 := by decide
           sourceTwoLimb3 := by decide
           unsignedSourceOne := fun _ => rfl
           unsignedSourceTwo := fun _ => rfl
           signedSourceOne := by intro contra; exact absurd contra (by decide)
           signedSourceTwo := by intro contra; exact absurd contra (by decide)
           productLimb0 := by decide
           productLimb1 := by decide
           productLimb2 := by decide
           productLimb3 := by decide
           productLimb4 := by decide
           productLimb5 := by decide
           productLimb6 := by decide
           productLimb7 := by decide
           destinationFlag := by decide
           destinationLimb0 := by decide
           destinationLimb1 := by decide
           destinationLimb2 := by decide
           destinationLimb3 := by decide
           nextPcResult := by decide }

theorem mulhUnsignedWitnessFits : MulhRowFits mulhUnsignedWitnessRow := by
  constructor
  decide

-- The gated theorem covers the unsigned row too.
theorem mulhUnsignedWitnessFixedRequestsHold :
    mulhProgramCompiled.fixedRequestsHold (mulhColumns mulhUnsignedWitnessRow) = true :=
  mulhFixedRequestsHold mulhUnsignedWitnessRow mulhUnsignedWitnessHolds

/-! ### The numerator gate is load-bearing

These two are kernel-checked, not `#guard`ed, because they are the reason
`mulhFixedRequestsHold` reads the way it does. Together with
`mulhUnsignedWitnessHolds` they say: there is a row that `MulhHolds` accepts and
that the production AIR accepts, on which the ungated "every fixed-table request
lands in its table" reading is FALSE. Anyone tempted to strengthen
`MulhCircuit.fixedRequestsHold` to the ungated form has to delete a theorem to
do it. -/

theorem mulhUnsignedWitnessUngatedFails :
    mulhProgramCompiled.fixedRequestsHoldUnconditional
        (mulhColumns mulhUnsignedWitnessRow) = false := by
  decide

/-- The failure above is specific to the dead sign requests: on a `MULH` row,
where all twenty-two requests are live, the ungated reading does hold. -/
theorem mulhWitnessUngatedHolds :
    mulhProgramCompiled.fixedRequestsHoldUnconditional
        (mulhColumns mulhWitnessRow) = true := by
  decide

end RiscvRefinement.Air.Bridge
