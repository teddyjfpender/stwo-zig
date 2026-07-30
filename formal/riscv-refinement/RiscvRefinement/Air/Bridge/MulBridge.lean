-- The AIR-interpreter bridge for the smallest Team B family, `mul`.
--
-- Issue #137 forbids Team B from restating production constraints in a private
-- Lean predicate. `RiscvRefinement/Air/Family/Multiply.lean` currently does
-- exactly that: `MulHolds` is a hand transcription of `/tmp/tb-ir/mul.json`.
-- This file closes the loop in the direction that matters. It maps a typed
-- `MulRow` onto the 44 columns of the shipped AIR and proves, by *evaluating
-- the encoded production node table*, that
--
--   * every one of the 22 constraint roots evaluates to zero, and
--   * every fixed-table request lands inside its table,
--
-- whenever `MulHolds row` holds. So the hand transcription is not weaker than
-- the shipped AIR: nothing the AIR asks for on an active row is missing from
-- it.
--
-- What is NOT proved here, and why, is written up in /tmp/o1-bridge-report.md.
-- The short version: the converse (roots vanish -> `MulHolds`) is not even
-- statable in this shape, because it needs an inverse of `mulColumns`, and
-- reconstructing a `Byte` from a column value is exactly what the range-check
-- lookups buy -- so the converse is a statement about tables, not about
-- constraint roots.

import RiscvRefinement.Air.Bridge.MulProgram
import RiscvRefinement.Air.Family.Multiply

namespace RiscvRefinement.Air.Bridge

open RiscvRefinement
open RiscvRefinement.Air.Family

set_option maxRecDepth 4000

/-! ## The `M31` arithmetic the bridge needs

Every column of `mulColumns` below is the image `M31.reduce n` of a `Nat`, so
the whole bridge is congruence arithmetic modulo `m31Modulus` plus the four
identities `reduce` distributes over. -/

namespace M31

theorem eq_of_val {left right : M31} (equal : left.val = right.val) :
    left = right := by
  cases left
  cases right
  simp_all

@[simp] theorem val_reduce (value : Nat) :
    (M31.reduce value).val = value % modulus := rfl

@[simp] theorem val_zero : (0 : M31).val = 0 := rfl

@[simp] theorem reduce_zero : M31.reduce 0 = 0 := rfl

theorem val_add (left right : M31) :
    (left + right).val = (left.val + right.val) % modulus := rfl

theorem val_sub (left right : M31) :
    (left - right).val = (left.val + modulus - right.val) % modulus := rfl

theorem val_mul (left right : M31) :
    (left * right).val = (left.val * right.val) % modulus := rfl

theorem reduce_add (left right : Nat) :
    M31.reduce left + M31.reduce right = M31.reduce (left + right) := by
  apply eq_of_val
  simp only [val_add, val_reduce]
  exact (Nat.add_mod left right modulus).symm

theorem reduce_mul (left right : Nat) :
    M31.reduce left * M31.reduce right = M31.reduce (left * right) := by
  apply eq_of_val
  simp only [val_mul, val_reduce]
  exact (Nat.mul_mod left right modulus).symm

theorem reduce_sub (left right : Nat) (order : right ≤ left) :
    M31.reduce left - M31.reduce right = M31.reduce (left - right) := by
  apply eq_of_val
  simp only [val_sub, val_reduce, modulus, m31Modulus]
  omega

/-- The workhorse: a difference of two images vanishes exactly when the two
`Nat`s agree modulo the prime. -/
theorem reduce_sub_eq_zero (left right : Nat)
    (congruent : left % modulus = right % modulus) :
    M31.reduce left - M31.reduce right = 0 := by
  apply eq_of_val
  simp only [val_sub, val_reduce, val_zero]
  rw [congruent]
  simp only [modulus, m31Modulus]
  omega

theorem sub_self (value : Nat) : M31.reduce value - M31.reduce value = 0 :=
  reduce_sub_eq_zero value value rfl

theorem zero_mul (value : M31) : 0 * value = 0 := by
  apply eq_of_val
  simp only [val_mul, val_zero, Nat.zero_mul, Nat.zero_mod]

theorem mul_zero (value : M31) : value * 0 = 0 := by
  apply eq_of_val
  simp only [val_mul, val_zero, Nat.mul_zero, Nat.zero_mod]

/-- `256 * 8388608 = 2 ^ 31 = modulus + 1`, so the AIR's multiplication by
`8388608` really is division by `256` on the image of a carry. -/
theorem reduce_shift (value : Nat) :
    M31.reduce (256 * value * 8388608) = M31.reduce value := by
  apply eq_of_val
  simp only [val_reduce]
  have expand : 256 * value * 8388608 = value + modulus * value := by
    simp only [modulus, m31Modulus]
    omega
  rw [expand, Nat.add_mul_mod_self_left]

theorem toNat_reduce_of_lt {value : Nat} (bound : value < modulus) :
    (M31.reduce value).toNat = value := by
  simp [toNat, Nat.mod_eq_of_lt bound]

end M31

/-! ## The column assignment

`MulRow` does not carry a complete AIR row: `destination_inverse` and the four
`bus_value_*` columns are witness/output columns the transcription dropped, so
the assignment has to synthesise them. That is a real gap in the capsule and it
is called out in the report; here it just means those five entries are
functions of the fields `MulRow` does carry. -/

/-- `destination_nonzero` as the `Nat` the AIR column holds. -/
def flagValue : Bool → Nat
  | true => 1
  | false => 0

/-- Inverses of `1 .. 31` in `M31`, the values the prover puts in
`destination_inverse`. Entry `0` is unconstrained and is taken to be zero. -/
def registerInverseTable : List Nat :=
  [ 0, 1, 1073741824, 1431655765,
    536870912, 858993459, 1789569706, 1840700269,
    268435456, 1908874353, 1503238553, 1952257861,
    894784853, 1486719448, 1994091958, 286331153,
    134217728, 252645135, 2028179000, 1017229096,
    1825361100, 2045222521, 2049870754, 840319688,
    1521134250, 1460288880, 743359724, 636291451,
    997045979, 296204641, 1216907400, 2078209981 ]

def registerInverse (rd : RegisterIndex) : M31 :=
  M31.reduce (registerInverseTable.getD rd.toNat 0)

/-- The one fact about the table, checked by evaluation over all 32 register
indices rather than asserted. -/
theorem registerInverseTable_spec :
    ∀ index, index < 32 →
      (index * registerInverseTable.getD index 0) % m31Modulus =
        flagValue (decide (index ≠ 0)) % m31Modulus := by
  decide

/-- The typed row, laid out as the 44 columns of `mul.json`. -/
def mulColumns (row : MulRow) : List M31 :=
  [ M31.reduce 1,                                 -- 0  enabler
    M31.reduce row.clock,                         -- 1  clock
    M31.reduce row.pc.toNat,                      -- 2  pc
    M31.reduce row.rd.toNat,                      -- 3  rd_addr
    M31.reduce row.rdPrevious.limb0.toNat,        -- 4  rd_previous_0
    M31.reduce row.rdPrevious.limb1.toNat,        -- 5  rd_previous_1
    M31.reduce row.rdPrevious.limb2.toNat,        -- 6  rd_previous_2
    M31.reduce row.rdPrevious.limb3.toNat,        -- 7  rd_previous_3
    M31.reduce row.rdPreviousClock,               -- 8  rd_previous_clock
    M31.reduce row.rdNext.limb0.toNat,            -- 9  rd_next_0
    M31.reduce row.rdNext.limb1.toNat,            -- 10 rd_next_1
    M31.reduce row.rdNext.limb2.toNat,            -- 11 rd_next_2
    M31.reduce row.rdNext.limb3.toNat,            -- 12 rd_next_3
    M31.reduce row.rs1.toNat,                     -- 13 rs1_addr
    M31.reduce row.rs1Previous.limb0.toNat,       -- 14 rs1_previous_0
    M31.reduce row.rs1Previous.limb1.toNat,       -- 15 rs1_previous_1
    M31.reduce row.rs1Previous.limb2.toNat,       -- 16 rs1_previous_2
    M31.reduce row.rs1Previous.limb3.toNat,       -- 17 rs1_previous_3
    M31.reduce row.rs1PreviousClock,              -- 18 rs1_previous_clock
    M31.reduce row.rs1Next.limb0.toNat,           -- 19 rs1_next_0
    M31.reduce row.rs1Next.limb1.toNat,           -- 20 rs1_next_1
    M31.reduce row.rs1Next.limb2.toNat,           -- 21 rs1_next_2
    M31.reduce row.rs1Next.limb3.toNat,           -- 22 rs1_next_3
    M31.reduce row.rs2.toNat,                     -- 23 rs2_addr
    M31.reduce row.rs2Previous.limb0.toNat,       -- 24 rs2_previous_0
    M31.reduce row.rs2Previous.limb1.toNat,       -- 25 rs2_previous_1
    M31.reduce row.rs2Previous.limb2.toNat,       -- 26 rs2_previous_2
    M31.reduce row.rs2Previous.limb3.toNat,       -- 27 rs2_previous_3
    M31.reduce row.rs2PreviousClock,              -- 28 rs2_previous_clock
    M31.reduce row.rs2Next.limb0.toNat,           -- 29 rs2_next_0
    M31.reduce row.rs2Next.limb1.toNat,           -- 30 rs2_next_1
    M31.reduce row.rs2Next.limb2.toNat,           -- 31 rs2_next_2
    M31.reduce row.rs2Next.limb3.toNat,           -- 32 rs2_next_3
    M31.reduce row.result.limb0.toNat,            -- 33 result_0
    M31.reduce row.result.limb1.toNat,            -- 34 result_1
    M31.reduce row.result.limb2.toNat,            -- 35 result_2
    M31.reduce row.result.limb3.toNat,            -- 36 result_3
    M31.reduce (flagValue row.rdNonzero),         -- 37 destination_nonzero
    registerInverse row.rd,                       -- 38 destination_inverse
    M31.reduce row.claimedNextPc.toNat,           -- 39 bus_value_39
    M31.reduce (row.clock + 1),                   -- 40 bus_value_40
    M31.reduce (accessClock row.clock 1),         -- 41 bus_value_41
    M31.reduce (accessClock row.clock 2),         -- 42 bus_value_42
    M31.reduce (accessClock row.clock 3) ]        -- 43 bus_value_43

/-- The side condition the transcription does not carry.

`MulRow.pc` is a `BitVec 32` and `nextPc` wraps at `2 ^ 32`; the AIR's `pc` is
a single field element and its next-pc node is `pc + 4` in `M31`. The two agree
only when the program counter does not wrap, which is a hypothesis about the
row, not a consequence of `MulHolds`. -/
structure MulRowFits (row : MulRow) : Prop where
  programCounter : row.pc.toNat + 4 < 4294967296

/-! ## Facts about the row that the constraint proofs consume -/

private theorem nextPcImage (row : MulRow) (holds : MulHolds row)
    (fits : MulRowFits row) :
    row.claimedNextPc.toNat = row.pc.toNat + 4 := by
  have wrap := fits.programCounter
  simp only [holds.nextPcResult, RiscvRefinement.nextPc, BitVec.toNat_add,
    BitVec.toNat_ofNat, Nat.reducePow]
  omega

private theorem rdNonzeroImage (row : MulRow) (holds : MulHolds row) :
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

private theorem flagBooleanVanishes (flagBit : Bool) :
    M31.reduce (flagValue flagBit) *
        (M31.reduce (flagValue flagBit) - M31.reduce 1) = 0 := by
  cases flagBit with
  | false => simp only [flagValue, M31.reduce_zero, M31.zero_mul]
  | true =>
      simp only [flagValue]
      rw [M31.sub_self, M31.mul_zero]

private theorem destinationSelectorVanishes (row : MulRow) (holds : MulHolds row) :
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

/-! ## The bridge for the constraint roots

The proof has one shape: unfold the encoded node table under the column
assignment -- this *is* the evaluation of the production AIR -- and discharge
the 22 resulting `M31` identities from `MulHolds`. -/

/-- Every constraint root of the encoded production `mul` AIR evaluates to zero
under `mulColumns row`, for every row the transcription accepts. -/
theorem mulConstraintValues (row : MulRow) (holds : MulHolds row)
    (fits : MulRowFits row) :
    mulProgramCompiled.constraintValues (mulColumns row) = List.replicate 22 0 := by
  have nextPcValue := nextPcImage row holds fits
  have clockPositive := holds.clockPositive
  simp only [Program.constraintValues, Program.values, Program.value,
    Program.nodeValuesRev, mulProgramCompiled, mulProgram, evalLoop,
    Node.evalLocal, nth, List.map_cons, List.map_nil, mulColumns, List.replicate,
    List.cons.injEq, and_true]
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_, ?_, ?_, ?_⟩
  -- constraint 0: enabler * (1 - enabler)
  · rw [M31.sub_self, M31.mul_zero]
  -- constraint 1: destination_nonzero * (destination_nonzero - 1)
  · exact flagBooleanVanishes row.rdNonzero
  -- constraint 2: rd_addr * (1 - destination_nonzero)
  · exact destinationSelectorVanishes row holds
  -- constraint 3: rd_addr * destination_inverse - destination_nonzero
  · have bound : row.rd.toNat < 32 := by simpa using row.rd.isLt
    rw [registerInverse, M31.reduce_mul, rdNonzeroImage row holds]
    exact M31.reduce_sub_eq_zero _ _ (registerInverseTable_spec row.rd.toNat bound)
  -- constraints 4-7: rd_next_i = destination_nonzero * result_i
  · exact destinationLimbVanishes row.rdNonzero _ _ _ rfl holds.destinationLimb0
  · exact destinationLimbVanishes row.rdNonzero _ _ _ rfl holds.destinationLimb1
  · exact destinationLimbVanishes row.rdNonzero _ _ _ rfl holds.destinationLimb2
  · exact destinationLimbVanishes row.rdNonzero _ _ _ rfl holds.destinationLimb3
  -- constraints 8-11: rs1 is read-only on the register bus
  · rw [holds.sourceOneLimb0, M31.sub_self, M31.mul_zero]
  · rw [holds.sourceOneLimb1, M31.sub_self, M31.mul_zero]
  · rw [holds.sourceOneLimb2, M31.sub_self, M31.mul_zero]
  · rw [holds.sourceOneLimb3, M31.sub_self, M31.mul_zero]
  -- constraints 12-15: rs2 is read-only on the register bus
  · rw [holds.sourceTwoLimb0, M31.sub_self, M31.mul_zero]
  · rw [holds.sourceTwoLimb1, M31.sub_self, M31.mul_zero]
  · rw [holds.sourceTwoLimb2, M31.sub_self, M31.mul_zero]
  · rw [holds.sourceTwoLimb3, M31.sub_self, M31.mul_zero]
  -- constraint 16: the family selector is pinned to one
  · exact M31.sub_self 1
  -- constraint 17: bus_value_39 = pc + 4
  · rw [nextPcValue, M31.reduce_add]
    exact M31.sub_self _
  -- constraint 18: bus_value_40 = clock + 1
  · rw [M31.reduce_add]
    exact M31.sub_self _
  -- constraints 19-21: bus_value_4x = (clock - 1) * 4 + x
  · rw [M31.reduce_sub _ _ clockPositive, M31.reduce_mul, M31.reduce_add]
    exact M31.sub_self _
  · rw [M31.reduce_sub _ _ clockPositive, M31.reduce_mul, M31.reduce_add]
    exact M31.sub_self _
  · rw [M31.reduce_sub _ _ clockPositive, M31.reduce_mul, M31.reduce_add]
    exact M31.sub_self _

/-! ## The bridge for the lookup arguments

The four `range_check_8_11` requests are where the multiplication actually
lives: the `mul` AIR has no constraint root for the product at all, it pins the
carry chain by asking the preprocessed table to certify that each
`(result_i, carry_i)` pair is (8, 11)-bit. The AIR spells the carry as
`(partial_sum - result_i) * 8388608`, and `8388608` is the inverse of `256` in
`M31`, so the content of these lemmas is that the transcribed `Nat` carry chain
really is that field expression. -/

private theorem carryImage0 (row : MulRow) (holds : MulHolds row) :
    (M31.reduce row.rs1Next.limb0.toNat * M31.reduce row.rs2Next.limb0.toNat -
          M31.reduce row.result.limb0.toNat) * M31.reduce 8388608 =
      M31.reduce row.carry0.toNat := by
  have equation := holds.productLimb0
  rw [M31.reduce_mul, M31.reduce_sub _ _ (by omega), M31.reduce_mul,
    show row.rs1Next.limb0.toNat * row.rs2Next.limb0.toNat -
        row.result.limb0.toNat = 256 * row.carry0.toNat from by omega]
  exact M31.reduce_shift _

private theorem carryImage1 (row : MulRow) (holds : MulHolds row) :
    (M31.reduce row.carry0.toNat +
            M31.reduce row.rs1Next.limb1.toNat * M31.reduce row.rs2Next.limb0.toNat +
            M31.reduce row.rs1Next.limb0.toNat * M31.reduce row.rs2Next.limb1.toNat -
          M31.reduce row.result.limb1.toNat) * M31.reduce 8388608 =
      M31.reduce row.carry1.toNat := by
  have equation := holds.productLimb1
  rw [M31.reduce_mul, M31.reduce_mul, M31.reduce_add, M31.reduce_add,
    M31.reduce_sub _ _ (by omega), M31.reduce_mul,
    show row.carry0.toNat +
          row.rs1Next.limb1.toNat * row.rs2Next.limb0.toNat +
          row.rs1Next.limb0.toNat * row.rs2Next.limb1.toNat -
        row.result.limb1.toNat = 256 * row.carry1.toNat from by omega]
  exact M31.reduce_shift _

private theorem carryImage2 (row : MulRow) (holds : MulHolds row) :
    (M31.reduce row.carry1.toNat +
            M31.reduce row.rs1Next.limb2.toNat * M31.reduce row.rs2Next.limb0.toNat +
            M31.reduce row.rs1Next.limb1.toNat * M31.reduce row.rs2Next.limb1.toNat +
            M31.reduce row.rs1Next.limb0.toNat * M31.reduce row.rs2Next.limb2.toNat -
          M31.reduce row.result.limb2.toNat) * M31.reduce 8388608 =
      M31.reduce row.carry2.toNat := by
  have equation := holds.productLimb2
  rw [M31.reduce_mul, M31.reduce_mul, M31.reduce_mul, M31.reduce_add, M31.reduce_add,
    M31.reduce_add, M31.reduce_sub _ _ (by omega), M31.reduce_mul,
    show row.carry1.toNat +
          row.rs1Next.limb2.toNat * row.rs2Next.limb0.toNat +
          row.rs1Next.limb1.toNat * row.rs2Next.limb1.toNat +
          row.rs1Next.limb0.toNat * row.rs2Next.limb2.toNat -
        row.result.limb2.toNat = 256 * row.carry2.toNat from by omega]
  exact M31.reduce_shift _

private theorem carryImage3 (row : MulRow) (holds : MulHolds row) :
    (M31.reduce row.carry2.toNat +
            M31.reduce row.rs1Next.limb3.toNat * M31.reduce row.rs2Next.limb0.toNat +
            M31.reduce row.rs1Next.limb2.toNat * M31.reduce row.rs2Next.limb1.toNat +
            M31.reduce row.rs1Next.limb1.toNat * M31.reduce row.rs2Next.limb2.toNat +
            M31.reduce row.rs1Next.limb0.toNat * M31.reduce row.rs2Next.limb3.toNat -
          M31.reduce row.result.limb3.toNat) * M31.reduce 8388608 =
      M31.reduce row.carry3.toNat := by
  have equation := holds.productLimb3
  rw [M31.reduce_mul, M31.reduce_mul, M31.reduce_mul, M31.reduce_mul, M31.reduce_add,
    M31.reduce_add, M31.reduce_add, M31.reduce_add, M31.reduce_sub _ _ (by omega),
    M31.reduce_mul,
    show row.carry2.toNat +
          row.rs1Next.limb3.toNat * row.rs2Next.limb0.toNat +
          row.rs1Next.limb2.toNat * row.rs2Next.limb1.toNat +
          row.rs1Next.limb1.toNat * row.rs2Next.limb2.toNat +
          row.rs1Next.limb0.toNat * row.rs2Next.limb3.toNat -
        row.result.limb3.toNat = 256 * row.carry3.toNat from by omega]
  exact M31.reduce_shift _

/-- The `range_check_20` requests carry the access-clock gap, which is what
`validPreviousClock` bounds. -/
private theorem gapImage (row : MulRow) (holds : MulHolds row)
    (ordinal previous : Nat) (order : previous < accessClock row.clock ordinal) :
    (M31.reduce row.clock - M31.reduce 1) * M31.reduce 4 + M31.reduce ordinal -
          M31.reduce previous - M31.reduce 1 =
      M31.reduce (accessClock row.clock ordinal - previous - 1) := by
  have positive := holds.clockPositive
  rw [M31.reduce_sub _ _ positive, M31.reduce_mul, M31.reduce_add]
  rw [show (row.clock - 1) * 4 + ordinal = accessClock row.clock ordinal from rfl]
  rw [M31.reduce_sub _ _ (by omega), M31.reduce_sub _ _ (by omega)]

private theorem accessClockImage (row : MulRow) (holds : MulHolds row)
    (ordinal : Nat) :
    (M31.reduce row.clock - M31.reduce 1) * M31.reduce 4 + M31.reduce ordinal =
      M31.reduce (accessClock row.clock ordinal) := by
  have positive := holds.clockPositive
  rw [M31.reduce_sub _ _ positive, M31.reduce_mul, M31.reduce_add]
  congr 1

private theorem reduceToNat_lt {value bound : Nat} (small : value < bound) :
    (M31.reduce value).toNat < bound := by
  simp only [M31.toNat, M31.val_reduce]
  exact Nat.lt_of_le_of_lt (Nat.mod_le _ _) small

/-- Every fixed-table request the shipped `mul` AIR makes lands inside its
table, for every row the transcription accepts.

For the three `range_check_20` requests this is `validPreviousClock`; for the
four `range_check_8_11` requests it is the carry chain plus the fact that
`WordBytes` limbs are `BitVec 8` and the carries are `BitVec 11`, which is the
"discharged by typing" claim in the header of `Air/Family/Multiply.lean` --
here discharged against the shipped table meaning instead of asserted. -/
theorem mulFixedRequestsHold (row : MulRow) (holds : MulHolds row) :
    mulProgramCompiled.fixedRequestsHold (mulColumns row) = true := by
  have sourceOne := holds.sourceOneClock
  have sourceTwo := holds.sourceTwoClock
  have destination := holds.destinationClock
  simp only [Program.fixedRequestsHold, Program.lookupTuple, Program.values,
    Program.value, Program.nodeValuesRev, mulProgramCompiled, mulProgram, evalLoop,
    Node.evalLocal, nth, List.map_cons, List.map_nil, List.all_cons, List.all_nil,
    mulColumns, rangeCheck20Contains, rangeCheck811Contains]
  rw [carryImage0 row holds, carryImage1 row holds, carryImage2 row holds,
    carryImage3 row holds,
    gapImage row holds 1 row.rs1PreviousClock sourceOne.1,
    gapImage row holds 2 row.rs2PreviousClock sourceTwo.1,
    gapImage row holds 3 row.rdPreviousClock destination.1]
  simp only [Bool.and_eq_true, Bool.true_and, Bool.and_true, decide_eq_true_eq]
  exact ⟨reduceToNat_lt sourceOne.2, reduceToNat_lt sourceTwo.2,
    ⟨reduceToNat_lt row.result.limb0.isLt, reduceToNat_lt row.carry0.isLt⟩,
    ⟨reduceToNat_lt row.result.limb1.isLt, reduceToNat_lt row.carry1.isLt⟩,
    ⟨reduceToNat_lt row.result.limb2.isLt, reduceToNat_lt row.carry2.isLt⟩,
    ⟨reduceToNat_lt row.result.limb3.isLt, reduceToNat_lt row.carry3.isLt⟩,
    reduceToNat_lt destination.2⟩

/-! ## The bridge for the relation arguments

The sixteen lookup tuples the shipped AIR emits, evaluated under the same
column assignment. This is the statement that the relation arguments Team B
writes down in `mulRelations` -- the program tuple, the two state tuples, the
six register-file memory tuples -- are the tuples the production AIR actually
puts on the bus, rather than a parallel description of them. -/

theorem mulLookupTuples (row : MulRow) (holds : MulHolds row) (fits : MulRowFits row) :
    mulProgramCompiled.lookups.map (mulProgramCompiled.lookupTuple (mulColumns row)) =
      [ -- 0  program_access request
        [M31.reduce row.pc.toNat, M31.reduce 37, M31.reduce row.rd.toNat,
          M31.reduce row.rs1.toNat, M31.reduce row.rs2.toNat],
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
        -- 9-12  the four product range checks
        [M31.reduce row.result.limb0.toNat, M31.reduce row.carry0.toNat],
        [M31.reduce row.result.limb1.toNat, M31.reduce row.carry1.toNat],
        [M31.reduce row.result.limb2.toNat, M31.reduce row.carry2.toNat],
        [M31.reduce row.result.limb3.toNat, M31.reduce row.carry3.toNat],
        -- 13  rd memory consume
        [M31.reduce 0, M31.reduce row.rd.toNat, M31.reduce row.rdPreviousClock,
          M31.reduce row.rdPrevious.limb0.toNat,
          M31.reduce row.rdPrevious.limb1.toNat,
          M31.reduce row.rdPrevious.limb2.toNat,
          M31.reduce row.rdPrevious.limb3.toNat],
        -- 14  rd memory emit
        [M31.reduce 0, M31.reduce row.rd.toNat,
          M31.reduce (accessClock row.clock 3),
          M31.reduce row.rdNext.limb0.toNat,
          M31.reduce row.rdNext.limb1.toNat,
          M31.reduce row.rdNext.limb2.toNat,
          M31.reduce row.rdNext.limb3.toNat],
        -- 15  rd access-clock gap
        [M31.reduce (accessClock row.clock 3 - row.rdPreviousClock - 1)] ] := by
  have sourceOne := holds.sourceOneClock
  have sourceTwo := holds.sourceTwoClock
  have destination := holds.destinationClock
  have nextPcValue := nextPcImage row holds fits
  simp only [Program.lookupTuple, Program.values, Program.value,
    Program.nodeValuesRev, mulProgramCompiled, mulProgram, evalLoop,
    Node.evalLocal, nth, List.map_cons, List.map_nil, mulColumns]
  rw [carryImage0 row holds, carryImage1 row holds, carryImage2 row holds,
    carryImage3 row holds,
    gapImage row holds 1 row.rs1PreviousClock sourceOne.1,
    gapImage row holds 2 row.rs2PreviousClock sourceTwo.1,
    gapImage row holds 3 row.rdPreviousClock destination.1,
    accessClockImage row holds 1, accessClockImage row holds 2,
    accessClockImage row holds 3]
  simp only [M31.reduce_add, nextPcValue]

/-! ## Non-vacuity, and a check on the column assignment itself

`mulColumns` is hand-written, so it is exactly the kind of transcription this
work exists to remove. It is checked here against `mulWitnessColumns`, which
the generator computed independently from `mul.json` (and which the generated
file already checks satisfies every constraint and every table request). If a
column were mis-ordered or mis-populated, this `#guard` fails. -/

def mulWitnessRow : MulRow where
  pc := 100#32
  clock := 5
  rd := 7#5
  rdPreviousClock := 3
  rdPrevious := { limb0 := 0#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  rdNext := { limb0 := 20#8, limb1 := 15#8, limb2 := 10#8, limb3 := 5#8 }
  rs1 := 1#5
  rs1PreviousClock := 3
  rs1Previous := { limb0 := 4#8, limb1 := 3#8, limb2 := 2#8, limb3 := 1#8 }
  rs1Next := { limb0 := 4#8, limb1 := 3#8, limb2 := 2#8, limb3 := 1#8 }
  rs2 := 2#5
  rs2PreviousClock := 3
  rs2Previous := { limb0 := 5#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  rs2Next := { limb0 := 5#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  result := { limb0 := 20#8, limb1 := 15#8, limb2 := 10#8, limb3 := 5#8 }
  carry0 := 0#11
  carry1 := 0#11
  carry2 := 0#11
  carry3 := 0#11
  rdNonzero := true
  claimedNextPc := 104#32

#guard mulColumns mulWitnessRow == mulWitnessColumns

theorem mulWitnessHolds : MulHolds mulWitnessRow := by
  constructor <;> first
    | decide
    | exact ⟨by decide, by decide⟩

theorem mulWitnessFits : MulRowFits mulWitnessRow := by
  constructor
  decide

-- The bridge is therefore not vacuous: this row satisfies every hypothesis.
theorem mulWitnessConstraintValues :
    mulProgramCompiled.constraintValues (mulColumns mulWitnessRow) =
      List.replicate 22 0 :=
  mulConstraintValues mulWitnessRow mulWitnessHolds mulWitnessFits

end RiscvRefinement.Air.Bridge
