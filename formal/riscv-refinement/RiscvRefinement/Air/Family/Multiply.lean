-- REVIEWED TRANSCRIPTION. Not a generated file.
--
-- Source of truth: the fresh export of the production symbolic AIR,
--   /tmp/tb-ir/mul.json   (44 columns, 130 nodes, 22 constraints, 16 lookups)
--   /tmp/tb-ir/mulh.json  (53 columns, 221 nodes, 30 constraints, 22 lookups)
-- cross-checked constraint by constraint against the Zig semantics in
--   src/frontends/riscv/air/semantics/mul.zig
--   src/frontends/riscv/air/semantics/mulh.zig
--
-- Transcription conventions, all of which are exact:
--   * the AIR's `enabler` / `is_mulh + is_mulhsu + is_mulhu` selector column is
--     pinned to one by constraint 16 (mul) and constraint 23 (mulh), so every
--     row modelled here is an active row and the selector factor is dropped;
--   * `range_check_8_11` requests bound an output limb to eight bits and its
--     carry to eleven bits: limbs are `BitVec 8` inside `WordBytes` and carries
--     are `BitVec 11`, so both range tables are discharged by typing;
--   * `range_check_m31` sign requests carry `(0, top_byte - 128 * sign)` whose
--     second component is a seven-bit value, transcribed as the existential
--     `∃ rest : BitVec 7, limb3.toNat = 128 * sign + rest.toNat`;
--   * `destination_nonzero` is pinned to `decide (rd ≠ x0)` by the three
--     destination constraints, and `rd_next = destination_nonzero * result`;
--   * register access ordinals 1/2/3 are `rs1`/`rs2`/`rd`, matching the
--     `(clock - 1) * 4 + ordinal` bus clocks in the export.
--
-- Nine bus requests per family are declared unmodelled by the export
-- (`unmodelled_bus_requests = 9`); they are the range-table side of the
-- lookups, which this capsule discharges by the typing rules above.

import RiscvRefinement.Common

namespace RiscvRefinement.Air.Family

open RiscvRefinement

/-- sha256 of `/tmp/tb-ir/mul.json`, the exported production AIR for `MUL`. -/
def mulIrDigest : String :=
  "20036f269882cc1ca77d9a83f9b8863763e3b4b9e4fd3d28c6b1d78bfb931146"

/-- sha256 of `/tmp/tb-ir/mulh.json`, the exported production AIR for the
`MULH` / `MULHSU` / `MULHU` family. -/
def mulhIrDigest : String :=
  "461461c9adcf8b65f3c5a8d14f9336ddb65b3fea28c1ca9bbe530156ad88f28b"

/-! ## Limb arithmetic shared by both families -/

/-- Distribute one factor over a little-endian four-limb value. -/
theorem multiplyRowExpand (a b0 b1 b2 b3 : Nat) :
    a * (b0 + 256 * b1 + 65536 * b2 + 16777216 * b3) =
      a * b0 + 256 * (a * b1) + 65536 * (a * b2) + 16777216 * (a * b3) := by
  rw [Nat.mul_add, Nat.mul_add, Nat.mul_add,
    Nat.mul_left_comm a 256 b1, Nat.mul_left_comm a 65536 b2,
    Nat.mul_left_comm a 16777216 b3]

/-- The schoolbook expansion of a 32 x 32 limb product. This is the only
ring identity the multiply proofs need; everything downstream of it is linear
in the sixteen limb products. -/
theorem multiplyValueMul (x y : WordBytes) :
    x.value * y.value =
      x.limb0.toNat * y.limb0.toNat +
      256 * (x.limb0.toNat * y.limb1.toNat + x.limb1.toNat * y.limb0.toNat) +
      65536 * (x.limb0.toNat * y.limb2.toNat + x.limb1.toNat * y.limb1.toNat +
        x.limb2.toNat * y.limb0.toNat) +
      16777216 * (x.limb0.toNat * y.limb3.toNat + x.limb1.toNat * y.limb2.toNat +
        x.limb2.toNat * y.limb1.toNat + x.limb3.toNat * y.limb0.toNat) +
      4294967296 * (x.limb1.toNat * y.limb3.toNat + x.limb2.toNat * y.limb2.toNat +
        x.limb3.toNat * y.limb1.toNat) +
      1099511627776 * (x.limb2.toNat * y.limb3.toNat +
        x.limb3.toNat * y.limb2.toNat) +
      281474976710656 * (x.limb3.toNat * y.limb3.toNat) := by
  simp only [WordBytes.value, Nat.add_mul, Nat.mul_assoc, multiplyRowExpand]
  omega

/-! ## MUL: the low word of the product

`mul.json` columns 0-43, constraints 0-21, lookups 0-15. -/

structure MulRow where
  pc : Word
  clock : Nat
  rd : RegisterIndex
  rdPreviousClock : Nat
  rdPrevious : WordBytes
  rdNext : WordBytes
  rs1 : RegisterIndex
  rs1PreviousClock : Nat
  rs1Previous : WordBytes
  rs1Next : WordBytes
  rs2 : RegisterIndex
  rs2PreviousClock : Nat
  rs2Previous : WordBytes
  rs2Next : WordBytes
  result : WordBytes
  carry0 : BitVec 11
  carry1 : BitVec 11
  carry2 : BitVec 11
  carry3 : BitVec 11
  rdNonzero : Bool
  claimedNextPc : Word
deriving DecidableEq, Repr

/-- Every `mul.json` constraint and lookup argument, transcribed. -/
structure MulHolds (row : MulRow) : Prop where
  clockPositive : 0 < row.clock
  sourceOneClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  sourceTwoClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  -- constraints 8-11: `rs1` is read-only on the register bus.
  sourceOneLimb0 : row.rs1Next.limb0 = row.rs1Previous.limb0
  sourceOneLimb1 : row.rs1Next.limb1 = row.rs1Previous.limb1
  sourceOneLimb2 : row.rs1Next.limb2 = row.rs1Previous.limb2
  sourceOneLimb3 : row.rs1Next.limb3 = row.rs1Previous.limb3
  -- constraints 12-15: `rs2` is read-only on the register bus.
  sourceTwoLimb0 : row.rs2Next.limb0 = row.rs2Previous.limb0
  sourceTwoLimb1 : row.rs2Next.limb1 = row.rs2Previous.limb1
  sourceTwoLimb2 : row.rs2Next.limb2 = row.rs2Previous.limb2
  sourceTwoLimb3 : row.rs2Next.limb3 = row.rs2Previous.limb3
  -- lookups 9-12: the four `range_check_8_11` product requests.
  productLimb0 :
    row.rs1Next.limb0.toNat * row.rs2Next.limb0.toNat =
      row.result.limb0.toNat + 256 * row.carry0.toNat
  productLimb1 :
    row.carry0.toNat +
        row.rs1Next.limb1.toNat * row.rs2Next.limb0.toNat +
        row.rs1Next.limb0.toNat * row.rs2Next.limb1.toNat =
      row.result.limb1.toNat + 256 * row.carry1.toNat
  productLimb2 :
    row.carry1.toNat +
        row.rs1Next.limb2.toNat * row.rs2Next.limb0.toNat +
        row.rs1Next.limb1.toNat * row.rs2Next.limb1.toNat +
        row.rs1Next.limb0.toNat * row.rs2Next.limb2.toNat =
      row.result.limb2.toNat + 256 * row.carry2.toNat
  productLimb3 :
    row.carry2.toNat +
        row.rs1Next.limb3.toNat * row.rs2Next.limb0.toNat +
        row.rs1Next.limb2.toNat * row.rs2Next.limb1.toNat +
        row.rs1Next.limb1.toNat * row.rs2Next.limb2.toNat +
        row.rs1Next.limb0.toNat * row.rs2Next.limb3.toNat =
      row.result.limb3.toNat + 256 * row.carry3.toNat
  -- constraints 1-3.
  destinationFlag : row.rdNonzero = decide (row.rd ≠ zeroRegister)
  -- constraints 4-7.
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
  -- constraint 17 / state lookup 2.
  nextPcResult : row.claimedNextPc = nextPc row.pc

def mulRetirement (row : MulRow) : Retirement where
  nextPc := row.claimedNextPc
  write := architecturalWrite row.rd row.rdNext.word

def mulProgramTuple (row : MulRow) : ProgramTuple where
  pc := row.pc
  opcodeId := 37
  rd := row.rd.toNat
  rs1 := row.rs1.toNat
  operand := row.rs2.toNat

structure MulRelations where
  program : ProgramTuple
  stateConsume : StateTuple
  stateEmit : StateTuple
  sourceOneConsume : RegisterTuple
  sourceOneEmit : RegisterTuple
  sourceTwoConsume : RegisterTuple
  sourceTwoEmit : RegisterTuple
  destinationConsume : RegisterTuple
  destinationEmit : RegisterTuple
deriving DecidableEq, Repr

def mulRelations (row : MulRow) : MulRelations where
  program := mulProgramTuple row
  stateConsume := { pc := row.pc, clock := row.clock }
  stateEmit := { pc := nextPc row.pc, clock := row.clock + 1 }
  sourceOneConsume := {
    addr := row.rs1
    clock := row.rs1PreviousClock
    value := row.rs1Previous.word
  }
  sourceOneEmit := {
    addr := row.rs1
    clock := accessClock row.clock 1
    value := row.rs1Next.word
  }
  sourceTwoConsume := {
    addr := row.rs2
    clock := row.rs2PreviousClock
    value := row.rs2Previous.word
  }
  sourceTwoEmit := {
    addr := row.rs2
    clock := accessClock row.clock 2
    value := row.rs2Next.word
  }
  destinationConsume := {
    addr := row.rd
    clock := row.rdPreviousClock
    value := row.rdPrevious.word
  }
  destinationEmit := {
    addr := row.rd
    clock := accessClock row.clock 3
    value := row.rdNext.word
  }

theorem mulSourceOneStable (row : MulRow) (holds : MulHolds row) :
    row.rs1Next.word = row.rs1Previous.word :=
  congrArg WordBytes.word <|
    WordBytes.eq_of_limbs row.rs1Next row.rs1Previous
      holds.sourceOneLimb0 holds.sourceOneLimb1
      holds.sourceOneLimb2 holds.sourceOneLimb3

theorem mulSourceTwoStable (row : MulRow) (holds : MulHolds row) :
    row.rs2Next.word = row.rs2Previous.word :=
  congrArg WordBytes.word <|
    WordBytes.eq_of_limbs row.rs2Next row.rs2Previous
      holds.sourceTwoLimb0 holds.sourceTwoLimb1
      holds.sourceTwoLimb2 holds.sourceTwoLimb3

/-- The `MUL` carry chain forces the witnessed result to be the low 32 bits of
the complete integer product of the two operands. -/
theorem mulLowProduct (row : MulRow) (holds : MulHolds row) :
    row.rs1Next.value * row.rs2Next.value % 4294967296 = row.result.value := by
  have expand := multiplyValueMul row.rs1Next row.rs2Next
  have limb0 := holds.productLimb0
  have limb1 := holds.productLimb1
  have limb2 := holds.productLimb2
  have limb3 := holds.productLimb3
  have bound0 := row.result.limb0.isLt
  have bound1 := row.result.limb1.isLt
  have bound2 := row.result.limb2.isLt
  have bound3 := row.result.limb3.isLt
  simp only [Nat.reducePow] at bound0 bound1 bound2 bound3
  simp only [WordBytes.value] at expand ⊢
  omega

theorem mulResultWord (row : MulRow) (holds : MulHolds row) :
    row.result.word = row.rs1Next.word * row.rs2Next.word := by
  apply BitVec.eq_of_toNat_eq
  simp only [WordBytes.word_toNat, BitVec.toNat_mul, Nat.reducePow]
  exact (mulLowProduct row holds).symm

theorem mulDestinationValue (row : MulRow) (holds : MulHolds row) :
    row.rdNext.word = architecturalValue row.rd row.result.word := by
  by_cases isZero : row.rd = zeroRegister
  · have flag : row.rdNonzero = false := by
      rw [holds.destinationFlag]; simp [isZero]
    rw [isZero, architecturalValue_zero]
    apply BitVec.eq_of_toNat_eq
    simp only [WordBytes.word_toNat]
    simp [WordBytes.value, holds.destinationLimb0, holds.destinationLimb1,
      holds.destinationLimb2, holds.destinationLimb3, flag, WordBytes.zero,
      zeroWord]
  · have flag : row.rdNonzero = true := by
      rw [holds.destinationFlag]; simp [isZero]
    rw [architecturalValue]
    simp only [isZero, ↓reduceIte]
    apply BitVec.eq_of_toNat_eq
    simp only [WordBytes.word_toNat]
    simp [WordBytes.value, holds.destinationLimb0, holds.destinationLimb1,
      holds.destinationLimb2, holds.destinationLimb3, flag]

/-! ## MULH / MULHSU / MULHU: the complete 64-bit product

`mulh.json` columns 0-52, constraints 0-29, lookups 0-21. -/

/-- Constraints 0-3 and 23 pin exactly one of `is_mulh`, `is_mulhsu`,
`is_mulhu` to one; the inductive selector is that fact. -/
inductive MulhSelector where
  | mulh
  | mulhsu
  | mulhu
deriving DecidableEq, Repr

/-- Program-bus opcode identifiers, from constraint 24. -/
def MulhSelector.opcodeId : MulhSelector → Nat
  | .mulh => 38
  | .mulhsu => 39
  | .mulhu => 40

/-- Lookup 17 requests the `rs1` sign range check with numerator
`is_mulh + is_mulhsu`. -/
def MulhSelector.signedSourceOne : MulhSelector → Bool
  | .mulh => true
  | .mulhsu => true
  | .mulhu => false

/-- Lookup 18 requests the `rs2` sign range check with numerator `is_mulh`. -/
def MulhSelector.signedSourceTwo : MulhSelector → Bool
  | .mulh => true
  | .mulhsu => false
  | .mulhu => false

/-- The AIR extends each operand to eight limbs by repeating `255 * sign`. -/
def multiplySignFill : Bool → Nat
  | true => 255
  | false => 0

/-- The sign witness as the numeral the `range_check_m31` request uses. -/
def multiplySignBit : Bool → Nat
  | true => 1
  | false => 0

/-- The 64-bit value of the sign-extended operand the AIR multiplies:
`value + sign * (2 ^ 64 - 2 ^ 32)`, which is exactly the eight-limb operand
`a0..a3, 255 * sign, 255 * sign, 255 * sign, 255 * sign`. -/
def multiplyExtendedValue (bytes : WordBytes) : Bool → Nat
  | true => bytes.value + 18446744069414584320
  | false => bytes.value

structure MulhRow where
  pc : Word
  clock : Nat
  rd : RegisterIndex
  rdPreviousClock : Nat
  rdPrevious : WordBytes
  rdNext : WordBytes
  rs1 : RegisterIndex
  rs1PreviousClock : Nat
  rs1Previous : WordBytes
  rs1Next : WordBytes
  rs2 : RegisterIndex
  rs2PreviousClock : Nat
  rs2Previous : WordBytes
  rs2Next : WordBytes
  /-- AIR columns `rd_high_0..3`: the *low* 32 bits of the 64-bit product,
  witnessed but never written to the register file. -/
  rdHigh : WordBytes
  rs1Sign : Bool
  rs2Sign : Bool
  selector : MulhSelector
  /-- AIR columns `result_0..3`: the high 32 bits, which are written. -/
  result : WordBytes
  carry0 : BitVec 11
  carry1 : BitVec 11
  carry2 : BitVec 11
  carry3 : BitVec 11
  carry4 : BitVec 11
  carry5 : BitVec 11
  carry6 : BitVec 11
  carry7 : BitVec 11
  rdNonzero : Bool
  claimedNextPc : Word
deriving DecidableEq, Repr

/-- Every `mulh.json` constraint and lookup argument, transcribed. -/
structure MulhHolds (row : MulhRow) : Prop where
  clockPositive : 0 < row.clock
  sourceOneClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  sourceTwoClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  -- constraints 15-18: `rs1` is read-only on the register bus.
  sourceOneLimb0 : row.rs1Next.limb0 = row.rs1Previous.limb0
  sourceOneLimb1 : row.rs1Next.limb1 = row.rs1Previous.limb1
  sourceOneLimb2 : row.rs1Next.limb2 = row.rs1Previous.limb2
  sourceOneLimb3 : row.rs1Next.limb3 = row.rs1Previous.limb3
  -- constraints 19-22: `rs2` is read-only on the register bus.
  sourceTwoLimb0 : row.rs2Next.limb0 = row.rs2Previous.limb0
  sourceTwoLimb1 : row.rs2Next.limb1 = row.rs2Previous.limb1
  sourceTwoLimb2 : row.rs2Next.limb2 = row.rs2Previous.limb2
  sourceTwoLimb3 : row.rs2Next.limb3 = row.rs2Previous.limb3
  -- constraint 6: `(1 - is_mulh - is_mulhsu) * rs1_sign = 0`.
  unsignedSourceOne : row.selector.signedSourceOne = false → row.rs1Sign = false
  -- constraint 7: `(1 - is_mulh) * rs2_sign = 0`.
  unsignedSourceTwo : row.selector.signedSourceTwo = false → row.rs2Sign = false
  -- lookup 17: `range_check_m31 (0, rs1_next_3 - 128 * rs1_sign)`.
  signedSourceOne :
    row.selector.signedSourceOne = true →
      ∃ rest : BitVec 7,
        row.rs1Next.limb3.toNat =
          128 * multiplySignBit row.rs1Sign + rest.toNat
  -- lookup 18: `range_check_m31 (0, rs2_next_3 - 128 * rs2_sign)`.
  signedSourceTwo :
    row.selector.signedSourceTwo = true →
      ∃ rest : BitVec 7,
        row.rs2Next.limb3.toNat =
          128 * multiplySignBit row.rs2Sign + rest.toNat
  -- lookups 9-12: the low four `range_check_8_11` product requests.
  productLimb0 :
    row.rs1Next.limb0.toNat * row.rs2Next.limb0.toNat =
      row.rdHigh.limb0.toNat + 256 * row.carry0.toNat
  productLimb1 :
    row.carry0.toNat +
        row.rs1Next.limb0.toNat * row.rs2Next.limb1.toNat +
        row.rs1Next.limb1.toNat * row.rs2Next.limb0.toNat =
      row.rdHigh.limb1.toNat + 256 * row.carry1.toNat
  productLimb2 :
    row.carry1.toNat +
        row.rs1Next.limb0.toNat * row.rs2Next.limb2.toNat +
        row.rs1Next.limb1.toNat * row.rs2Next.limb1.toNat +
        row.rs1Next.limb2.toNat * row.rs2Next.limb0.toNat =
      row.rdHigh.limb2.toNat + 256 * row.carry2.toNat
  productLimb3 :
    row.carry2.toNat +
        row.rs1Next.limb0.toNat * row.rs2Next.limb3.toNat +
        row.rs1Next.limb1.toNat * row.rs2Next.limb2.toNat +
        row.rs1Next.limb2.toNat * row.rs2Next.limb1.toNat +
        row.rs1Next.limb3.toNat * row.rs2Next.limb0.toNat =
      row.rdHigh.limb3.toNat + 256 * row.carry3.toNat
  -- lookups 13-16: the high four `range_check_8_11` product requests, whose
  -- operand limbs 4..7 are the repeated sign fills.
  productLimb4 :
    row.carry3.toNat +
        row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign +
        row.rs1Next.limb1.toNat * row.rs2Next.limb3.toNat +
        row.rs1Next.limb2.toNat * row.rs2Next.limb2.toNat +
        row.rs1Next.limb3.toNat * row.rs2Next.limb1.toNat +
        multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat =
      row.result.limb0.toNat + 256 * row.carry4.toNat
  productLimb5 :
    row.carry4.toNat +
        row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign +
        row.rs1Next.limb1.toNat * multiplySignFill row.rs2Sign +
        row.rs1Next.limb2.toNat * row.rs2Next.limb3.toNat +
        row.rs1Next.limb3.toNat * row.rs2Next.limb2.toNat +
        multiplySignFill row.rs1Sign * row.rs2Next.limb1.toNat +
        multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat =
      row.result.limb1.toNat + 256 * row.carry5.toNat
  productLimb6 :
    row.carry5.toNat +
        row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign +
        row.rs1Next.limb1.toNat * multiplySignFill row.rs2Sign +
        row.rs1Next.limb2.toNat * multiplySignFill row.rs2Sign +
        row.rs1Next.limb3.toNat * row.rs2Next.limb3.toNat +
        multiplySignFill row.rs1Sign * row.rs2Next.limb2.toNat +
        multiplySignFill row.rs1Sign * row.rs2Next.limb1.toNat +
        multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat =
      row.result.limb2.toNat + 256 * row.carry6.toNat
  productLimb7 :
    row.carry6.toNat +
        row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign +
        row.rs1Next.limb1.toNat * multiplySignFill row.rs2Sign +
        row.rs1Next.limb2.toNat * multiplySignFill row.rs2Sign +
        row.rs1Next.limb3.toNat * multiplySignFill row.rs2Sign +
        multiplySignFill row.rs1Sign * row.rs2Next.limb3.toNat +
        multiplySignFill row.rs1Sign * row.rs2Next.limb2.toNat +
        multiplySignFill row.rs1Sign * row.rs2Next.limb1.toNat +
        multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat =
      row.result.limb3.toNat + 256 * row.carry7.toNat
  -- constraints 8-10.
  destinationFlag : row.rdNonzero = decide (row.rd ≠ zeroRegister)
  -- constraints 11-14.
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
  -- constraint 25 / state lookup 2.
  nextPcResult : row.claimedNextPc = nextPc row.pc

def mulhRetirement (row : MulhRow) : Retirement where
  nextPc := row.claimedNextPc
  write := architecturalWrite row.rd row.rdNext.word

def mulhProgramTuple (row : MulhRow) : ProgramTuple where
  pc := row.pc
  opcodeId := row.selector.opcodeId
  rd := row.rd.toNat
  rs1 := row.rs1.toNat
  operand := row.rs2.toNat

structure MulhRelations where
  program : ProgramTuple
  stateConsume : StateTuple
  stateEmit : StateTuple
  sourceOneConsume : RegisterTuple
  sourceOneEmit : RegisterTuple
  sourceTwoConsume : RegisterTuple
  sourceTwoEmit : RegisterTuple
  destinationConsume : RegisterTuple
  destinationEmit : RegisterTuple
deriving DecidableEq, Repr

def mulhRelations (row : MulhRow) : MulhRelations where
  program := mulhProgramTuple row
  stateConsume := { pc := row.pc, clock := row.clock }
  stateEmit := { pc := nextPc row.pc, clock := row.clock + 1 }
  sourceOneConsume := {
    addr := row.rs1
    clock := row.rs1PreviousClock
    value := row.rs1Previous.word
  }
  sourceOneEmit := {
    addr := row.rs1
    clock := accessClock row.clock 1
    value := row.rs1Next.word
  }
  sourceTwoConsume := {
    addr := row.rs2
    clock := row.rs2PreviousClock
    value := row.rs2Previous.word
  }
  sourceTwoEmit := {
    addr := row.rs2
    clock := accessClock row.clock 2
    value := row.rs2Next.word
  }
  destinationConsume := {
    addr := row.rd
    clock := row.rdPreviousClock
    value := row.rdPrevious.word
  }
  destinationEmit := {
    addr := row.rd
    clock := accessClock row.clock 3
    value := row.rdNext.word
  }

theorem mulhSourceOneStable (row : MulhRow) (holds : MulhHolds row) :
    row.rs1Next.word = row.rs1Previous.word :=
  congrArg WordBytes.word <|
    WordBytes.eq_of_limbs row.rs1Next row.rs1Previous
      holds.sourceOneLimb0 holds.sourceOneLimb1
      holds.sourceOneLimb2 holds.sourceOneLimb3

theorem mulhSourceTwoStable (row : MulhRow) (holds : MulhHolds row) :
    row.rs2Next.word = row.rs2Previous.word :=
  congrArg WordBytes.word <|
    WordBytes.eq_of_limbs row.rs2Next row.rs2Previous
      holds.sourceTwoLimb0 holds.sourceTwoLimb1
      holds.sourceTwoLimb2 holds.sourceTwoLimb3

theorem mulhDestinationValue (row : MulhRow) (holds : MulhHolds row) :
    row.rdNext.word = architecturalValue row.rd row.result.word := by
  by_cases isZero : row.rd = zeroRegister
  · have flag : row.rdNonzero = false := by
      rw [holds.destinationFlag]; simp [isZero]
    rw [isZero, architecturalValue_zero]
    apply BitVec.eq_of_toNat_eq
    simp only [WordBytes.word_toNat]
    simp [WordBytes.value, holds.destinationLimb0, holds.destinationLimb1,
      holds.destinationLimb2, holds.destinationLimb3, flag, WordBytes.zero,
      zeroWord]
  · have flag : row.rdNonzero = true := by
      rw [holds.destinationFlag]; simp [isZero]
    rw [architecturalValue]
    simp only [isZero, ↓reduceIte]
    apply BitVec.eq_of_toNat_eq
    simp only [WordBytes.word_toNat]
    simp [WordBytes.value, holds.destinationLimb0, holds.destinationLimb1,
      holds.destinationLimb2, holds.destinationLimb3, flag]

/-! ### The complete 64-bit product recurrence

This is the shared lemma the three high-word selectors are all proved from:
the eight-limb carry chain forces the concatenation of the witnessed low word
`rd_high` and the witnessed high word `result` to be the complete 64-bit
product of the two sign-extended operands, up to a multiple of `2 ^ 64`. -/

theorem mulhProductRecurrence (row : MulhRow) (holds : MulhHolds row) :
    ∃ overflow : Nat,
      multiplyExtendedValue row.rs1Next row.rs1Sign *
          multiplyExtendedValue row.rs2Next row.rs2Sign =
        row.rdHigh.value + 4294967296 * row.result.value +
          18446744073709551616 * overflow := by
  have expand := multiplyValueMul row.rs1Next row.rs2Next
  have limb0 := holds.productLimb0
  have limb1 := holds.productLimb1
  have limb2 := holds.productLimb2
  have limb3 := holds.productLimb3
  have limb4 := holds.productLimb4
  have limb5 := holds.productLimb5
  have limb6 := holds.productLimb6
  have limb7 := holds.productLimb7
  cases signOne : row.rs1Sign <;> cases signTwo : row.rs2Sign <;>
    simp only [signOne, signTwo, multiplySignFill, multiplyExtendedValue,
      Nat.mul_zero, Nat.zero_mul, Nat.add_zero] at limb4 limb5 limb6 limb7 ⊢
  · refine ⟨row.carry7.toNat, ?_⟩
    simp only [WordBytes.value] at expand ⊢
    omega
  · refine ⟨row.carry7.toNat +
      (255 * row.rs1Next.limb1.toNat + 65535 * row.rs1Next.limb2.toNat +
        16777215 * row.rs1Next.limb3.toNat), ?_⟩
    rw [Nat.mul_add]
    simp only [WordBytes.value] at expand ⊢
    omega
  · refine ⟨row.carry7.toNat +
      (255 * row.rs2Next.limb1.toNat + 65535 * row.rs2Next.limb2.toNat +
        16777215 * row.rs2Next.limb3.toNat), ?_⟩
    rw [Nat.add_mul]
    simp only [WordBytes.value] at expand ⊢
    omega
  · refine ⟨row.carry7.toNat +
      (255 * row.rs1Next.limb1.toNat + 65535 * row.rs1Next.limb2.toNat +
        16777215 * row.rs1Next.limb3.toNat) +
      (255 * row.rs2Next.limb1.toNat + 65535 * row.rs2Next.limb2.toNat +
        16777215 * row.rs2Next.limb3.toNat) +
      18446744065119617025, ?_⟩
    rw [Nat.add_mul, Nat.mul_add, Nat.mul_add]
    simp only [WordBytes.value] at expand ⊢
    omega

/-- The `range_check_m31` sign request binds the witness to bit 31 of the
operand: the AIR equation `limb3 = 128 * sign + rest` with `rest` a seven-bit
value is exactly `sign = msb`. Nothing here assumes the binding. -/
theorem multiplySignIsMsb
    (bytes : WordBytes)
    (sign : Bool)
    (rest : BitVec 7)
    (witness : bytes.limb3.toNat = 128 * multiplySignBit sign + rest.toNat) :
    bytes.word.msb = sign := by
  have restBound := rest.isLt
  have bound0 := bytes.limb0.isLt
  have bound1 := bytes.limb1.isLt
  have bound2 := bytes.limb2.isLt
  simp only [Nat.reducePow] at restBound bound0 bound1 bound2
  rw [BitVec.msb_eq_decide]
  simp only [WordBytes.word_toNat, WordBytes.value, Nat.reduceSub,
    Nat.reducePow]
  cases sign
  · simp only [multiplySignBit] at witness
    simp only [decide_eq_false_iff_not, Nat.not_le]
    omega
  · simp only [multiplySignBit] at witness
    simp only [decide_eq_true_eq]
    omega

/-- The high-word projection the three high multiply selectors share: the
witnessed `result` word is bits 63..32 of the complete 64-bit product of the
sign-extended operands. -/
theorem mulhHighWord (row : MulhRow) (holds : MulhHolds row) :
    multiplyExtendedValue row.rs1Next row.rs1Sign *
          multiplyExtendedValue row.rs2Next row.rs2Sign %
        18446744073709551616 / 4294967296 % 4294967296 =
      row.result.value := by
  obtain ⟨overflow, product⟩ := mulhProductRecurrence row holds
  have lowBound := row.rdHigh.value_lt
  have highBound := row.result.value_lt
  simp only [Nat.reducePow] at lowBound highBound
  omega

/-- The low-word projection: the witnessed `rd_high` word is bits 31..0 of the
same complete 64-bit product. This is what makes the recurrence a statement
about the whole product rather than about the high half alone. -/
theorem mulhLowWord (row : MulhRow) (holds : MulhHolds row) :
    multiplyExtendedValue row.rs1Next row.rs1Sign *
          multiplyExtendedValue row.rs2Next row.rs2Sign %
        4294967296 =
      row.rdHigh.value := by
  obtain ⟨overflow, product⟩ := mulhProductRecurrence row holds
  have lowBound := row.rdHigh.value_lt
  have highBound := row.result.value_lt
  simp only [Nat.reducePow] at lowBound highBound
  omega

end RiscvRefinement.Air.Family
