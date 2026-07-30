import RiscvRefinement.Air.Family.Multiply
import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.Multiply
import RiscvRefinement.Sail.Reviewed.Multiply

/-!
# Load-bearing mutation controls for `MULH`, `MULHSU` and `MULHU`

`Opcodes/MultiplyMutation.lean` carries one control for `MUL`
(`mul-free-low-limb`). The three *high* multiply selectors share a single
capsule -- `MulhRow` / `MulhHolds` in `Air/Family/Multiply.lean`, transcribed
from the 53-column, 30-constraint production AIR `mulh.json` -- and had none.
This file is that matrix, in the `MutationControl` form of
`RiscvRefinement/Mutation.lean`: for each named deletion, a copy of `MulhHolds`
with exactly *one* field removed, a proof that the deletion really is a
weakening (so no control is a statement about an empty predicate), a concrete
row that satisfies everything left, and a proof that the row retires the wrong
architectural word.

## The naming trap

The production AIR's column group `rd_high_0..3` carries the **low** 32 bits of
the 64-bit product, and the column group `result_0..3` -- the value actually
written to `rd` -- carries the **high** 32 bits. `MulhRow.rdHigh` and
`MulhRow.result` preserve that production naming, so every conclusion below is
stated against `MulhRow.rdNext`, the register-bus write-back, and never against
`rdHigh`. Inverting the two would silently invert every control here: a witness
that perturbs `rdHigh` changes a value nothing architectural depends on, and the
resulting "control" would refute nothing.

## Discipline

Following `Opcodes/DivMutation.lean` rather than `Opcodes/MultiplyMutation.lean`,
the soundness side is *discharged here* rather than assumed:
`mulh_conclusion_sound`, `mulhsu_conclusion_sound` and `mulhu_conclusion_sound`
prove each conclusion from the unweakened `MulhHolds`, so every
`..._is_load_bearing` corollary below is unconditional.

Each conclusion is row-parameterised (never a literal constant), guarded on the
row's own selector, and stated purely in terms of the reviewed architectural
capsule `Sail/Reviewed/Multiply.lean` (`executeMulhValue`, `executeMulhsuValue`,
`executeMulhuValue`) applied to the words the row consumed on the source
register buses. None of them restates a deleted constraint, so none is circular.
-/

namespace RiscvRefinement.Opcodes

open RiscvRefinement
open RiscvRefinement.Air.Family
open RiscvRefinement.Mutation
open RiscvRefinement.Sail.Reviewed

/-! ## The architectural conclusions -/

/-- The architectural claim `mulh_refines` reaches on a `MULH` row: the word
emitted on the destination register bus is bits 63..32 of the 64-bit product of
the two *signed* words consumed on the source register buses. -/
def MulhRetiresHighWord (row : MulhRow) : Prop :=
  row.selector = MulhSelector.mulh →
    row.rdNext.word =
      architecturalValue row.rd
        (executeMulhValue row.rs1Previous.word row.rs2Previous.word)

/-- The same claim on a `MULHSU` row: signed `rs1`, unsigned `rs2`. -/
def MulhsuRetiresHighWord (row : MulhRow) : Prop :=
  row.selector = MulhSelector.mulhsu →
    row.rdNext.word =
      architecturalValue row.rd
        (executeMulhsuValue row.rs1Previous.word row.rs2Previous.word)

/-- The same claim on a `MULHU` row: both operands unsigned. -/
def MulhuRetiresHighWord (row : MulhRow) : Prop :=
  row.selector = MulhSelector.mulhu →
    row.rdNext.word =
      architecturalValue row.rd
        (executeMulhuValue row.rs1Previous.word row.rs2Previous.word)

/-- Soundness of the `MULH` conclusion, from the unweakened row predicate.
`mulhDestinationValue` carries the witnessed high word to the destination bus
and `mulhValueRefines` identifies it with the reviewed architectural value. -/
theorem mulh_conclusion_sound (row : MulhRow) (holds : MulhHolds row) :
    MulhRetiresHighWord row := by
  intro selector
  rw [mulhDestinationValue row holds, mulhValueRefines row holds selector]

/-- Soundness of the `MULHSU` conclusion. -/
theorem mulhsu_conclusion_sound (row : MulhRow) (holds : MulhHolds row) :
    MulhsuRetiresHighWord row := by
  intro selector
  rw [mulhDestinationValue row holds, mulhsuValueRefines row holds selector]

/-- Soundness of the `MULHU` conclusion. -/
theorem mulhu_conclusion_sound (row : MulhRow) (holds : MulhHolds row) :
    MulhuRetiresHighWord row := by
  intro selector
  rw [mulhDestinationValue row holds, mulhuValueRefines row holds selector]

/-! ## Witness plumbing

Every witness below places the instruction at `pc = 0x1000` on clock `9`, reads
`rs1` from `x5` and `rs2` from `x6`, writes `rd = x7`, leaves both sources
untouched on the register bus (so the read-only residuals are `rfl`), and
advances the program counter by four. Only the arithmetic payload varies. -/

/-- Little-endian four-limb literal. -/
def mulhBytes (b0 b1 b2 b3 : Nat) : WordBytes where
  limb0 := BitVec.ofNat 8 b0
  limb1 := BitVec.ofNat 8 b1
  limb2 := BitVec.ofNat 8 b2
  limb3 := BitVec.ofNat 8 b3

/-- The shared witness skeleton. `source1` and `source2` are installed as both
the consumed and the emitted source limbs, which is what makes the eight
read-only residuals hold definitionally. -/
def mulhWitnessRow
    (selector : MulhSelector)
    (source1 source2 : WordBytes)
    (sign1 sign2 : Bool)
    (low high written : WordBytes)
    (c0 c1 c2 c3 c4 c5 c6 c7 : Nat) :
    MulhRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 9
  rd := BitVec.ofNat 5 7
  rdPreviousClock := 0
  rdPrevious := WordBytes.zero
  rdNext := written
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rs1Previous := source1
  rs1Next := source1
  rs2 := BitVec.ofNat 5 6
  rs2PreviousClock := 0
  rs2Previous := source2
  rs2Next := source2
  -- `rd_high_0..3`: the LOW 32 bits of the product. Never written to `rd`.
  rdHigh := low
  rs1Sign := sign1
  rs2Sign := sign2
  selector := selector
  -- `result_0..3`: the HIGH 32 bits. This is what `rd` receives.
  result := high
  carry0 := BitVec.ofNat 11 c0
  carry1 := BitVec.ofNat 11 c1
  carry2 := BitVec.ofNat 11 c2
  carry3 := BitVec.ofNat 11 c3
  carry4 := BitVec.ofNat 11 c4
  carry5 := BitVec.ofNat 11 c5
  carry6 := BitVec.ofNat 11 c6
  carry7 := BitVec.ofNat 11 c7
  rdNonzero := true
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

/-- The three register-bus access clocks of a witness row are valid. -/
theorem mulhWitness_validClock
    (ordinal : Nat)
    (positive : 0 < ordinal)
    (bound : ordinal < 4) :
    validPreviousClock 0 (accessClock 9 ordinal) := by
  refine ⟨?_, ?_⟩ <;> simp only [accessClock] <;> omega

/-! ## Control 1 — free high-word limb (`productLimb4`)

*Delete one product-limb equation from the eight-limb recurrence; exhibit a row
whose retired high word is wrong.*

Lookups 13-16 are the four `range_check_8_11` requests that carry limbs 4..7 of
the schoolbook product, and limbs 4..7 are exactly the high 32 bits -- the word
written to `rd`. `productLimb4` is the limb-4 member. It is the only residual
mentioning `result_0`, so deleting it frees the low byte of the *retired* word
while the other seven limb equations, the carry chain above it, and the four
destination residuals all still hold.

Certifies: the deleted residual is shared by all three high selectors, and two
witnesses are given below, one on `MULH` and one on `MULHU`. -/

structure MulhHoldsWithoutProductLimb4 (row : MulhRow) : Prop where
  clockPositive : 0 < row.clock
  sourceOneClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  sourceTwoClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  sourceOneLimb0 : row.rs1Next.limb0 = row.rs1Previous.limb0
  sourceOneLimb1 : row.rs1Next.limb1 = row.rs1Previous.limb1
  sourceOneLimb2 : row.rs1Next.limb2 = row.rs1Previous.limb2
  sourceOneLimb3 : row.rs1Next.limb3 = row.rs1Previous.limb3
  sourceTwoLimb0 : row.rs2Next.limb0 = row.rs2Previous.limb0
  sourceTwoLimb1 : row.rs2Next.limb1 = row.rs2Previous.limb1
  sourceTwoLimb2 : row.rs2Next.limb2 = row.rs2Previous.limb2
  sourceTwoLimb3 : row.rs2Next.limb3 = row.rs2Previous.limb3
  unsignedSourceOne : row.selector.signedSourceOne = false → row.rs1Sign = false
  unsignedSourceTwo : row.selector.signedSourceTwo = false → row.rs2Sign = false
  signedSourceOne :
    row.selector.signedSourceOne = true →
      ∃ rest : BitVec 7,
        row.rs1Next.limb3.toNat =
          128 * multiplySignBit row.rs1Sign + rest.toNat
  signedSourceTwo :
    row.selector.signedSourceTwo = true →
      ∃ rest : BitVec 7,
        row.rs2Next.limb3.toNat =
          128 * multiplySignBit row.rs2Sign + rest.toNat
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
  -- productLimb4 is deliberately absent.
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
  destinationFlag : row.rdNonzero = decide (row.rd ≠ zeroRegister)
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
  nextPcResult : row.claimedNextPc = nextPc row.pc

/-- Deleting the constraint really is a deletion: every honest row still
satisfies the weakened predicate, so the controls below are not statements
about a predicate nothing satisfies. -/
theorem mulhHolds_weakens_productLimb4
    (row : MulhRow)
    (holds : MulhHolds row) :
    MulhHoldsWithoutProductLimb4 row where
  clockPositive := holds.clockPositive
  sourceOneClock := holds.sourceOneClock
  sourceTwoClock := holds.sourceTwoClock
  destinationClock := holds.destinationClock
  sourceOneLimb0 := holds.sourceOneLimb0
  sourceOneLimb1 := holds.sourceOneLimb1
  sourceOneLimb2 := holds.sourceOneLimb2
  sourceOneLimb3 := holds.sourceOneLimb3
  sourceTwoLimb0 := holds.sourceTwoLimb0
  sourceTwoLimb1 := holds.sourceTwoLimb1
  sourceTwoLimb2 := holds.sourceTwoLimb2
  sourceTwoLimb3 := holds.sourceTwoLimb3
  unsignedSourceOne := holds.unsignedSourceOne
  unsignedSourceTwo := holds.unsignedSourceTwo
  signedSourceOne := holds.signedSourceOne
  signedSourceTwo := holds.signedSourceTwo
  productLimb0 := holds.productLimb0
  productLimb1 := holds.productLimb1
  productLimb2 := holds.productLimb2
  productLimb3 := holds.productLimb3
  productLimb5 := holds.productLimb5
  productLimb6 := holds.productLimb6
  productLimb7 := holds.productLimb7
  destinationFlag := holds.destinationFlag
  destinationLimb0 := holds.destinationLimb0
  destinationLimb1 := holds.destinationLimb1
  destinationLimb2 := holds.destinationLimb2
  destinationLimb3 := holds.destinationLimb3
  nextPcResult := holds.nextPcResult

/-- `MULH x7, x5, x6` on `-2 ^ 31 * -2 ^ 31`. The honest row is
`honestMulhRow`: the 64-bit product is `2 ^ 62`, so `rd_high = 0` and
`result = 0x40000000`. Here the freed limb-4 equation lets `result_0` -- the low
byte of the *retired* word -- be `1` instead of `0`, and the destination
residuals faithfully copy the lie to `rd`. Retired: `0x40000001`. -/
def mulhFreeHighLimbRow : MulhRow :=
  mulhWitnessRow MulhSelector.mulh
    (mulhBytes 0 0 0 128) (mulhBytes 0 0 0 128) true true
    (mulhBytes 0 0 0 0) (mulhBytes 1 0 0 64) (mulhBytes 1 0 0 64)
    0 0 0 0 0 0 64 255

theorem mulhFreeHighLimbRow_satisfies :
    MulhHoldsWithoutProductLimb4 mulhFreeHighLimbRow where
  clockPositive := by decide
  sourceOneClock := mulhWitness_validClock 1 (by decide) (by decide)
  sourceTwoClock := mulhWitness_validClock 2 (by decide) (by decide)
  destinationClock := mulhWitness_validClock 3 (by decide) (by decide)
  sourceOneLimb0 := rfl
  sourceOneLimb1 := rfl
  sourceOneLimb2 := rfl
  sourceOneLimb3 := rfl
  sourceTwoLimb0 := rfl
  sourceTwoLimb1 := rfl
  sourceTwoLimb2 := rfl
  sourceTwoLimb3 := rfl
  unsignedSourceOne := by decide
  unsignedSourceTwo := by decide
  signedSourceOne := fun _ => ⟨BitVec.ofNat 7 0, by decide⟩
  signedSourceTwo := fun _ => ⟨BitVec.ofNat 7 0, by decide⟩
  productLimb0 := by decide
  productLimb1 := by decide
  productLimb2 := by decide
  productLimb3 := by decide
  productLimb5 := by decide
  productLimb6 := by decide
  productLimb7 := by decide
  destinationFlag := by decide
  destinationLimb0 := by decide
  destinationLimb1 := by decide
  destinationLimb2 := by decide
  destinationLimb3 := by decide
  nextPcResult := rfl

theorem mulhFreeHighLimbRow_refutes :
    ¬ MulhRetiresHighWord mulhFreeHighLimbRow := by
  intro claim
  exact absurd (claim rfl) (by decide)

/-- The published control, certifying `MULH`. -/
def mulhFreeHighLimb :
    MutationControl MulhHoldsWithoutProductLimb4 MulhRetiresHighWord where
  name := "mulh-free-high-limb"
  witness := mulhFreeHighLimbRow
  satisfies := mulhFreeHighLimbRow_satisfies
  refutes := mulhFreeHighLimbRow_refutes

/-- The deletion is not free: no strengthening of the weakened predicate back to
`MulhHolds` exists, because `MulhHolds` implies the architectural claim and the
witness does not satisfy it. Unconditional: the soundness argument is
`mulh_conclusion_sound`, proved above. -/
theorem mulh_product_limb4_is_load_bearing :
    ¬ (∀ row, MulhHoldsWithoutProductLimb4 row → MulhHolds row) :=
  mulhFreeHighLimb.strictly_weaker MulhHolds mulh_conclusion_sound

/-- `MULHU x7, x5, x6` on `0xffffffff * 0xffffffff`. The honest row is
`honestMulhuRow`: the product is `0xfffffffe00000001`, so `rd_high = 1` and
`result = 0xfffffffe`. The freed limb-4 equation lets `result_0` be `253`
instead of `254`. Retired: `0xfffffffd`. -/
def mulhuFreeHighLimbRow : MulhRow :=
  mulhWitnessRow MulhSelector.mulhu
    (mulhBytes 255 255 255 255) (mulhBytes 255 255 255 255) false false
    (mulhBytes 1 0 0 0) (mulhBytes 253 255 255 255) (mulhBytes 253 255 255 255)
    254 509 764 1019 765 510 255 0

theorem mulhuFreeHighLimbRow_satisfies :
    MulhHoldsWithoutProductLimb4 mulhuFreeHighLimbRow where
  clockPositive := by decide
  sourceOneClock := mulhWitness_validClock 1 (by decide) (by decide)
  sourceTwoClock := mulhWitness_validClock 2 (by decide) (by decide)
  destinationClock := mulhWitness_validClock 3 (by decide) (by decide)
  sourceOneLimb0 := rfl
  sourceOneLimb1 := rfl
  sourceOneLimb2 := rfl
  sourceOneLimb3 := rfl
  sourceTwoLimb0 := rfl
  sourceTwoLimb1 := rfl
  sourceTwoLimb2 := rfl
  sourceTwoLimb3 := rfl
  unsignedSourceOne := by decide
  unsignedSourceTwo := by decide
  signedSourceOne := by intro request; exact absurd request (by decide)
  signedSourceTwo := by intro request; exact absurd request (by decide)
  productLimb0 := by decide
  productLimb1 := by decide
  productLimb2 := by decide
  productLimb3 := by decide
  productLimb5 := by decide
  productLimb6 := by decide
  productLimb7 := by decide
  destinationFlag := by decide
  destinationLimb0 := by decide
  destinationLimb1 := by decide
  destinationLimb2 := by decide
  destinationLimb3 := by decide
  nextPcResult := rfl

theorem mulhuFreeHighLimbRow_refutes :
    ¬ MulhuRetiresHighWord mulhuFreeHighLimbRow := by
  intro claim
  exact absurd (claim rfl) (by decide)

/-- The published control, certifying `MULHU`. -/
def mulhuFreeHighLimb :
    MutationControl MulhHoldsWithoutProductLimb4 MulhuRetiresHighWord where
  name := "mulhu-free-high-limb"
  witness := mulhuFreeHighLimbRow
  satisfies := mulhuFreeHighLimbRow_satisfies
  refutes := mulhuFreeHighLimbRow_refutes

theorem mulhu_product_limb4_is_load_bearing :
    ¬ (∀ row, MulhHoldsWithoutProductLimb4 row → MulhHolds row) :=
  mulhuFreeHighLimb.strictly_weaker MulhHolds mulhu_conclusion_sound

/-! ## Control 2 — unbound `rs1` sign (`signedSourceOne`)

*Delete the constraint tying `rs1_sign` to bit 31 of `rs1`; exhibit a `MULH` row
treating a negative operand as positive.*

This is the most load-bearing deletion in the family, because it is exactly what
separates `MULH` from `MULHU`. The AIR never multiplies `rs1` directly: it
multiplies the eight-limb operand `rs1_0..3, 255 * rs1_sign x4`, so `rs1_sign`
*is* the interpretation of the operand. Lookup 17,
`range_check_m31 (0, rs1_next_3 - 128 * rs1_sign)`, is the only residual that
ties that witness to bit 31 of the value on the register bus; constraint 6,
`(1 - is_mulh - is_mulhsu) * rs1_sign = 0`, only forces it *down* on `MULHU`.
Delete lookup 17 and a signed selector may declare any negative operand
positive.

Certifies `MULH` and `MULHSU`, the two selectors that request lookup 17
(numerator `is_mulh + is_mulhsu`); a witness is given for each. -/

structure MulhHoldsWithoutSourceOneSignBinding (row : MulhRow) : Prop where
  clockPositive : 0 < row.clock
  sourceOneClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  sourceTwoClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  sourceOneLimb0 : row.rs1Next.limb0 = row.rs1Previous.limb0
  sourceOneLimb1 : row.rs1Next.limb1 = row.rs1Previous.limb1
  sourceOneLimb2 : row.rs1Next.limb2 = row.rs1Previous.limb2
  sourceOneLimb3 : row.rs1Next.limb3 = row.rs1Previous.limb3
  sourceTwoLimb0 : row.rs2Next.limb0 = row.rs2Previous.limb0
  sourceTwoLimb1 : row.rs2Next.limb1 = row.rs2Previous.limb1
  sourceTwoLimb2 : row.rs2Next.limb2 = row.rs2Previous.limb2
  sourceTwoLimb3 : row.rs2Next.limb3 = row.rs2Previous.limb3
  unsignedSourceOne : row.selector.signedSourceOne = false → row.rs1Sign = false
  unsignedSourceTwo : row.selector.signedSourceTwo = false → row.rs2Sign = false
  -- signedSourceOne (lookup 17) is deliberately absent.
  signedSourceTwo :
    row.selector.signedSourceTwo = true →
      ∃ rest : BitVec 7,
        row.rs2Next.limb3.toNat =
          128 * multiplySignBit row.rs2Sign + rest.toNat
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
  destinationFlag : row.rdNonzero = decide (row.rd ≠ zeroRegister)
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
  nextPcResult : row.claimedNextPc = nextPc row.pc

theorem mulhHolds_weakens_sourceOneSignBinding
    (row : MulhRow)
    (holds : MulhHolds row) :
    MulhHoldsWithoutSourceOneSignBinding row where
  clockPositive := holds.clockPositive
  sourceOneClock := holds.sourceOneClock
  sourceTwoClock := holds.sourceTwoClock
  destinationClock := holds.destinationClock
  sourceOneLimb0 := holds.sourceOneLimb0
  sourceOneLimb1 := holds.sourceOneLimb1
  sourceOneLimb2 := holds.sourceOneLimb2
  sourceOneLimb3 := holds.sourceOneLimb3
  sourceTwoLimb0 := holds.sourceTwoLimb0
  sourceTwoLimb1 := holds.sourceTwoLimb1
  sourceTwoLimb2 := holds.sourceTwoLimb2
  sourceTwoLimb3 := holds.sourceTwoLimb3
  unsignedSourceOne := holds.unsignedSourceOne
  unsignedSourceTwo := holds.unsignedSourceTwo
  signedSourceTwo := holds.signedSourceTwo
  productLimb0 := holds.productLimb0
  productLimb1 := holds.productLimb1
  productLimb2 := holds.productLimb2
  productLimb3 := holds.productLimb3
  productLimb4 := holds.productLimb4
  productLimb5 := holds.productLimb5
  productLimb6 := holds.productLimb6
  productLimb7 := holds.productLimb7
  destinationFlag := holds.destinationFlag
  destinationLimb0 := holds.destinationLimb0
  destinationLimb1 := holds.destinationLimb1
  destinationLimb2 := holds.destinationLimb2
  destinationLimb3 := holds.destinationLimb3
  nextPcResult := holds.nextPcResult

/-- `MULH x7, x5, x6` with `rs1 = 0x80000000` and `rs2 = 2`. The freed
`rs1_sign` is declared `false`, so the AIR's eight-limb operand is the *zero*
extension `0x0000000080000000` and the whole recurrence is honest for the
unsigned product `0x0000000100000000`: `rd_high = 0`, `result = 1`. The
architectural `MULH` answer is `(-2 ^ 31) * 2 = -2 ^ 32`, whose high word is
`0xffffffff`. Retired: `0x00000001`. Every other residual holds, including
lookup 18 binding the honest `rs2_sign = false`. -/
def mulhUnboundSourceOneSignRow : MulhRow :=
  mulhWitnessRow MulhSelector.mulh
    (mulhBytes 0 0 0 128) (mulhBytes 2 0 0 0) false false
    (mulhBytes 0 0 0 0) (mulhBytes 1 0 0 0) (mulhBytes 1 0 0 0)
    0 0 0 1 0 0 0 0

theorem mulhUnboundSourceOneSignRow_satisfies :
    MulhHoldsWithoutSourceOneSignBinding mulhUnboundSourceOneSignRow where
  clockPositive := by decide
  sourceOneClock := mulhWitness_validClock 1 (by decide) (by decide)
  sourceTwoClock := mulhWitness_validClock 2 (by decide) (by decide)
  destinationClock := mulhWitness_validClock 3 (by decide) (by decide)
  sourceOneLimb0 := rfl
  sourceOneLimb1 := rfl
  sourceOneLimb2 := rfl
  sourceOneLimb3 := rfl
  sourceTwoLimb0 := rfl
  sourceTwoLimb1 := rfl
  sourceTwoLimb2 := rfl
  sourceTwoLimb3 := rfl
  unsignedSourceOne := by decide
  unsignedSourceTwo := by decide
  signedSourceTwo := fun _ => ⟨BitVec.ofNat 7 0, by decide⟩
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
  nextPcResult := rfl

theorem mulhUnboundSourceOneSignRow_refutes :
    ¬ MulhRetiresHighWord mulhUnboundSourceOneSignRow := by
  intro claim
  exact absurd (claim rfl) (by decide)

/-- The published control, certifying `MULH`: without lookup 17 the prover may
run `MULH` as `MULHU`. -/
def mulhUnboundSourceOneSign :
    MutationControl MulhHoldsWithoutSourceOneSignBinding MulhRetiresHighWord where
  name := "mulh-unbound-rs1-sign"
  witness := mulhUnboundSourceOneSignRow
  satisfies := mulhUnboundSourceOneSignRow_satisfies
  refutes := mulhUnboundSourceOneSignRow_refutes

theorem mulh_source_one_sign_is_load_bearing :
    ¬ (∀ row, MulhHoldsWithoutSourceOneSignBinding row → MulhHolds row) :=
  mulhUnboundSourceOneSign.strictly_weaker MulhHolds mulh_conclusion_sound

/-- The same deletion on the other selector that requests lookup 17.
`MULHSU x7, x5, x6` with `rs1 = 0x80000000` and `rs2 = 2`: the architectural
answer is the high word of `(-2 ^ 31) * 2`, again `0xffffffff`, and the row
retires `0x00000001`. Constraint 7 still holds honestly here -- `rs2_sign` is
`false`, as `MULHSU` requires -- so the counterexample is unambiguously the
`rs1` binding. -/
def mulhsuUnboundSourceOneSignRow : MulhRow :=
  mulhWitnessRow MulhSelector.mulhsu
    (mulhBytes 0 0 0 128) (mulhBytes 2 0 0 0) false false
    (mulhBytes 0 0 0 0) (mulhBytes 1 0 0 0) (mulhBytes 1 0 0 0)
    0 0 0 1 0 0 0 0

theorem mulhsuUnboundSourceOneSignRow_satisfies :
    MulhHoldsWithoutSourceOneSignBinding mulhsuUnboundSourceOneSignRow where
  clockPositive := by decide
  sourceOneClock := mulhWitness_validClock 1 (by decide) (by decide)
  sourceTwoClock := mulhWitness_validClock 2 (by decide) (by decide)
  destinationClock := mulhWitness_validClock 3 (by decide) (by decide)
  sourceOneLimb0 := rfl
  sourceOneLimb1 := rfl
  sourceOneLimb2 := rfl
  sourceOneLimb3 := rfl
  sourceTwoLimb0 := rfl
  sourceTwoLimb1 := rfl
  sourceTwoLimb2 := rfl
  sourceTwoLimb3 := rfl
  unsignedSourceOne := by decide
  unsignedSourceTwo := by decide
  signedSourceTwo := by intro request; exact absurd request (by decide)
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
  nextPcResult := rfl

theorem mulhsuUnboundSourceOneSignRow_refutes :
    ¬ MulhsuRetiresHighWord mulhsuUnboundSourceOneSignRow := by
  intro claim
  exact absurd (claim rfl) (by decide)

/-- The published control, certifying `MULHSU`. -/
def mulhsuUnboundSourceOneSign :
    MutationControl MulhHoldsWithoutSourceOneSignBinding
      MulhsuRetiresHighWord where
  name := "mulhsu-unbound-rs1-sign"
  witness := mulhsuUnboundSourceOneSignRow
  satisfies := mulhsuUnboundSourceOneSignRow_satisfies
  refutes := mulhsuUnboundSourceOneSignRow_refutes

theorem mulhsu_source_one_sign_is_load_bearing :
    ¬ (∀ row, MulhHoldsWithoutSourceOneSignBinding row → MulhHolds row) :=
  mulhsuUnboundSourceOneSign.strictly_weaker MulhHolds mulhsu_conclusion_sound

/-! ## Control 3 — unbound `rs2` sign (`signedSourceTwo`)

*Delete the constraint tying `rs2_sign` to bit 31 of `rs2`; exhibit a `MULH` row
treating a negative operand as positive.*

Lookup 18, `range_check_m31 (0, rs2_next_3 - 128 * rs2_sign)`, is requested with
numerator `is_mulh` alone: it is what separates `MULH` from `MULHSU`. Delete it
and `MULH` may read its second operand unsigned, which is precisely `MULHSU`
behaviour on a `MULH` opcode identifier.

Certifies `MULH`, the only selector that requests lookup 18. -/

structure MulhHoldsWithoutSourceTwoSignBinding (row : MulhRow) : Prop where
  clockPositive : 0 < row.clock
  sourceOneClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  sourceTwoClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  sourceOneLimb0 : row.rs1Next.limb0 = row.rs1Previous.limb0
  sourceOneLimb1 : row.rs1Next.limb1 = row.rs1Previous.limb1
  sourceOneLimb2 : row.rs1Next.limb2 = row.rs1Previous.limb2
  sourceOneLimb3 : row.rs1Next.limb3 = row.rs1Previous.limb3
  sourceTwoLimb0 : row.rs2Next.limb0 = row.rs2Previous.limb0
  sourceTwoLimb1 : row.rs2Next.limb1 = row.rs2Previous.limb1
  sourceTwoLimb2 : row.rs2Next.limb2 = row.rs2Previous.limb2
  sourceTwoLimb3 : row.rs2Next.limb3 = row.rs2Previous.limb3
  unsignedSourceOne : row.selector.signedSourceOne = false → row.rs1Sign = false
  unsignedSourceTwo : row.selector.signedSourceTwo = false → row.rs2Sign = false
  signedSourceOne :
    row.selector.signedSourceOne = true →
      ∃ rest : BitVec 7,
        row.rs1Next.limb3.toNat =
          128 * multiplySignBit row.rs1Sign + rest.toNat
  -- signedSourceTwo (lookup 18) is deliberately absent.
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
  destinationFlag : row.rdNonzero = decide (row.rd ≠ zeroRegister)
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
  nextPcResult : row.claimedNextPc = nextPc row.pc

theorem mulhHolds_weakens_sourceTwoSignBinding
    (row : MulhRow)
    (holds : MulhHolds row) :
    MulhHoldsWithoutSourceTwoSignBinding row where
  clockPositive := holds.clockPositive
  sourceOneClock := holds.sourceOneClock
  sourceTwoClock := holds.sourceTwoClock
  destinationClock := holds.destinationClock
  sourceOneLimb0 := holds.sourceOneLimb0
  sourceOneLimb1 := holds.sourceOneLimb1
  sourceOneLimb2 := holds.sourceOneLimb2
  sourceOneLimb3 := holds.sourceOneLimb3
  sourceTwoLimb0 := holds.sourceTwoLimb0
  sourceTwoLimb1 := holds.sourceTwoLimb1
  sourceTwoLimb2 := holds.sourceTwoLimb2
  sourceTwoLimb3 := holds.sourceTwoLimb3
  unsignedSourceOne := holds.unsignedSourceOne
  unsignedSourceTwo := holds.unsignedSourceTwo
  signedSourceOne := holds.signedSourceOne
  productLimb0 := holds.productLimb0
  productLimb1 := holds.productLimb1
  productLimb2 := holds.productLimb2
  productLimb3 := holds.productLimb3
  productLimb4 := holds.productLimb4
  productLimb5 := holds.productLimb5
  productLimb6 := holds.productLimb6
  productLimb7 := holds.productLimb7
  destinationFlag := holds.destinationFlag
  destinationLimb0 := holds.destinationLimb0
  destinationLimb1 := holds.destinationLimb1
  destinationLimb2 := holds.destinationLimb2
  destinationLimb3 := holds.destinationLimb3
  nextPcResult := holds.nextPcResult

/-- `MULH x7, x5, x6` with `rs1 = 2` and `rs2 = 0x80000000`. The freed
`rs2_sign` is declared `false`, so the recurrence honestly computes the
*unsigned* product `2 * 2 ^ 31 = 0x0000000100000000`: `rd_high = 0`,
`result = 1`. The architectural `MULH` answer is the high word of
`2 * (-2 ^ 31) = -2 ^ 32`, namely `0xffffffff`. Retired: `0x00000001`. Lookup 17
still holds honestly (`rs1_sign = false` really is bit 31 of `2`), so the
counterexample is unambiguously the `rs2` binding. -/
def mulhUnboundSourceTwoSignRow : MulhRow :=
  mulhWitnessRow MulhSelector.mulh
    (mulhBytes 2 0 0 0) (mulhBytes 0 0 0 128) false false
    (mulhBytes 0 0 0 0) (mulhBytes 1 0 0 0) (mulhBytes 1 0 0 0)
    0 0 0 1 0 0 0 0

theorem mulhUnboundSourceTwoSignRow_satisfies :
    MulhHoldsWithoutSourceTwoSignBinding mulhUnboundSourceTwoSignRow where
  clockPositive := by decide
  sourceOneClock := mulhWitness_validClock 1 (by decide) (by decide)
  sourceTwoClock := mulhWitness_validClock 2 (by decide) (by decide)
  destinationClock := mulhWitness_validClock 3 (by decide) (by decide)
  sourceOneLimb0 := rfl
  sourceOneLimb1 := rfl
  sourceOneLimb2 := rfl
  sourceOneLimb3 := rfl
  sourceTwoLimb0 := rfl
  sourceTwoLimb1 := rfl
  sourceTwoLimb2 := rfl
  sourceTwoLimb3 := rfl
  unsignedSourceOne := by decide
  unsignedSourceTwo := by decide
  signedSourceOne := fun _ => ⟨BitVec.ofNat 7 0, by decide⟩
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
  nextPcResult := rfl

theorem mulhUnboundSourceTwoSignRow_refutes :
    ¬ MulhRetiresHighWord mulhUnboundSourceTwoSignRow := by
  intro claim
  exact absurd (claim rfl) (by decide)

/-- The published control, certifying `MULH`: without lookup 18 the prover may
run `MULH` as `MULHSU`. -/
def mulhUnboundSourceTwoSign :
    MutationControl MulhHoldsWithoutSourceTwoSignBinding
      MulhRetiresHighWord where
  name := "mulh-unbound-rs2-sign"
  witness := mulhUnboundSourceTwoSignRow
  satisfies := mulhUnboundSourceTwoSignRow_satisfies
  refutes := mulhUnboundSourceTwoSignRow_refutes

theorem mulh_source_two_sign_is_load_bearing :
    ¬ (∀ row, MulhHoldsWithoutSourceTwoSignBinding row → MulhHolds row) :=
  mulhUnboundSourceTwoSign.strictly_weaker MulhHolds mulh_conclusion_sound

/-! ## Control 4 — selector sign confusion (`unsignedSourceTwo`)

*Delete `(1 - is_mulh) * rs2_sign = 0`; exhibit a `MULHSU` row claiming a signed
`rs2`.*

This deletion is the mirror image of Control 3, and it is why the two residuals
are not redundant with one another. On a `MULHSU` or `MULHU` row lookup 18 is
*not* requested -- its numerator is `is_mulh` -- so constraint 7 is the only
thing forcing `rs2_sign` to zero there. Delete it and the sign witness on those
two selectors becomes entirely free, letting the AIR sign-extend an operand the
ISA defines as unsigned.

Certifies `MULHSU`, and by the same argument `MULHU` (constraint 7 covers both
selectors with `is_mulh = 0`). -/

structure MulhHoldsWithoutSelectorSourceTwoSign (row : MulhRow) : Prop where
  clockPositive : 0 < row.clock
  sourceOneClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  sourceTwoClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  sourceOneLimb0 : row.rs1Next.limb0 = row.rs1Previous.limb0
  sourceOneLimb1 : row.rs1Next.limb1 = row.rs1Previous.limb1
  sourceOneLimb2 : row.rs1Next.limb2 = row.rs1Previous.limb2
  sourceOneLimb3 : row.rs1Next.limb3 = row.rs1Previous.limb3
  sourceTwoLimb0 : row.rs2Next.limb0 = row.rs2Previous.limb0
  sourceTwoLimb1 : row.rs2Next.limb1 = row.rs2Previous.limb1
  sourceTwoLimb2 : row.rs2Next.limb2 = row.rs2Previous.limb2
  sourceTwoLimb3 : row.rs2Next.limb3 = row.rs2Previous.limb3
  unsignedSourceOne : row.selector.signedSourceOne = false → row.rs1Sign = false
  -- unsignedSourceTwo (constraint 7) is deliberately absent.
  signedSourceOne :
    row.selector.signedSourceOne = true →
      ∃ rest : BitVec 7,
        row.rs1Next.limb3.toNat =
          128 * multiplySignBit row.rs1Sign + rest.toNat
  signedSourceTwo :
    row.selector.signedSourceTwo = true →
      ∃ rest : BitVec 7,
        row.rs2Next.limb3.toNat =
          128 * multiplySignBit row.rs2Sign + rest.toNat
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
  destinationFlag : row.rdNonzero = decide (row.rd ≠ zeroRegister)
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
  nextPcResult : row.claimedNextPc = nextPc row.pc

theorem mulhHolds_weakens_selectorSourceTwoSign
    (row : MulhRow)
    (holds : MulhHolds row) :
    MulhHoldsWithoutSelectorSourceTwoSign row where
  clockPositive := holds.clockPositive
  sourceOneClock := holds.sourceOneClock
  sourceTwoClock := holds.sourceTwoClock
  destinationClock := holds.destinationClock
  sourceOneLimb0 := holds.sourceOneLimb0
  sourceOneLimb1 := holds.sourceOneLimb1
  sourceOneLimb2 := holds.sourceOneLimb2
  sourceOneLimb3 := holds.sourceOneLimb3
  sourceTwoLimb0 := holds.sourceTwoLimb0
  sourceTwoLimb1 := holds.sourceTwoLimb1
  sourceTwoLimb2 := holds.sourceTwoLimb2
  sourceTwoLimb3 := holds.sourceTwoLimb3
  unsignedSourceOne := holds.unsignedSourceOne
  signedSourceOne := holds.signedSourceOne
  signedSourceTwo := holds.signedSourceTwo
  productLimb0 := holds.productLimb0
  productLimb1 := holds.productLimb1
  productLimb2 := holds.productLimb2
  productLimb3 := holds.productLimb3
  productLimb4 := holds.productLimb4
  productLimb5 := holds.productLimb5
  productLimb6 := holds.productLimb6
  productLimb7 := holds.productLimb7
  destinationFlag := holds.destinationFlag
  destinationLimb0 := holds.destinationLimb0
  destinationLimb1 := holds.destinationLimb1
  destinationLimb2 := holds.destinationLimb2
  destinationLimb3 := holds.destinationLimb3
  nextPcResult := holds.nextPcResult

/-- `MULHSU x7, x5, x6` with `rs1 = 2` and `rs2 = 0xffffffff`, claiming
`rs2_sign = true`. With constraint 7 gone nothing contradicts the claim -- lookup
18 is not requested on this selector -- so the eight-limb recurrence honestly
computes `2 * (2 ^ 64 - 1) = 0xfffffffffffffffe`: `rd_high = 0xfffffffe`,
`result = 0xffffffff`. The architectural `MULHSU` answer is the high word of
`2 * 0xffffffff = 0x00000001fffffffe`, namely `0x00000001`. Retired:
`0xffffffff`. -/
def mulhsuSignedSourceTwoRow : MulhRow :=
  mulhWitnessRow MulhSelector.mulhsu
    (mulhBytes 2 0 0 0) (mulhBytes 255 255 255 255) false true
    (mulhBytes 254 255 255 255) (mulhBytes 255 255 255 255)
    (mulhBytes 255 255 255 255)
    1 1 1 1 1 1 1 1

theorem mulhsuSignedSourceTwoRow_satisfies :
    MulhHoldsWithoutSelectorSourceTwoSign mulhsuSignedSourceTwoRow where
  clockPositive := by decide
  sourceOneClock := mulhWitness_validClock 1 (by decide) (by decide)
  sourceTwoClock := mulhWitness_validClock 2 (by decide) (by decide)
  destinationClock := mulhWitness_validClock 3 (by decide) (by decide)
  sourceOneLimb0 := rfl
  sourceOneLimb1 := rfl
  sourceOneLimb2 := rfl
  sourceOneLimb3 := rfl
  sourceTwoLimb0 := rfl
  sourceTwoLimb1 := rfl
  sourceTwoLimb2 := rfl
  sourceTwoLimb3 := rfl
  unsignedSourceOne := by decide
  signedSourceOne := fun _ => ⟨BitVec.ofNat 7 0, by decide⟩
  signedSourceTwo := by intro request; exact absurd request (by decide)
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
  nextPcResult := rfl

theorem mulhsuSignedSourceTwoRow_refutes :
    ¬ MulhsuRetiresHighWord mulhsuSignedSourceTwoRow := by
  intro claim
  exact absurd (claim rfl) (by decide)

/-- The published control, certifying `MULHSU`. -/
def mulhsuSelectorSignConfusion :
    MutationControl MulhHoldsWithoutSelectorSourceTwoSign
      MulhsuRetiresHighWord where
  name := "mulhsu-selector-sign-confusion"
  witness := mulhsuSignedSourceTwoRow
  satisfies := mulhsuSignedSourceTwoRow_satisfies
  refutes := mulhsuSignedSourceTwoRow_refutes

theorem mulhsu_selector_source_two_sign_is_load_bearing :
    ¬ (∀ row, MulhHoldsWithoutSelectorSourceTwoSign row → MulhHolds row) :=
  mulhsuSelectorSignConfusion.strictly_weaker MulhHolds mulhsu_conclusion_sound

/-! ## Audit

Two facts guard the whole file against the failure modes the project has hit.

First, non-vacuity of every weakened predicate: `honestMulhRow`,
`honestMulhsuRow` and `honestMulhuRow` are honest production rows, and the four
`mulhHolds_weakens_*` theorems carry them into each weakened predicate. A
weakened predicate nothing satisfies could not do that.

Second, the architectural answers, recomputed independently of every row. Each
disjunct below is the reviewed-capsule value for the operand pair of one
witness, and each differs from what that witness retires. This is what catches
the `rd_high` / `result` naming inversion: if the conclusions had been stated
against the low word instead of the high word, these constants would be the
product's *low* halves and would no longer separate the witnesses from the
honest rows. -/

/-- Non-vacuity, spelled out. Each weakened predicate above is satisfied by an
honest production row of `Opcodes/Multiply.lean`, so none of the four is a
predicate nothing satisfies and no control below is vacuously true. -/
theorem mulhMutationExtra_weakened_nonvacuous :
    MulhHoldsWithoutProductLimb4 honestMulhRow ∧
      MulhHoldsWithoutSourceOneSignBinding honestMulhsuRow ∧
      MulhHoldsWithoutSourceTwoSignBinding honestMulhRow ∧
      MulhHoldsWithoutSelectorSourceTwoSign honestMulhuRow :=
  ⟨mulhHolds_weakens_productLimb4 _ honestMulhRow_holds,
    mulhHolds_weakens_sourceOneSignBinding _ honestMulhsuRow_holds,
    mulhHolds_weakens_sourceTwoSignBinding _ honestMulhRow_holds,
    mulhHolds_weakens_selectorSourceTwoSign _ honestMulhuRow_holds⟩

theorem mulhMutationExtra_architectural_answers :
    -- Control 1, `MULH`: high word of `(-2 ^ 31) * (-2 ^ 31)`.
    executeMulhValue (BitVec.ofNat 32 0x80000000) (BitVec.ofNat 32 0x80000000) =
        BitVec.ofNat 32 0x40000000 ∧
      -- Control 1, `MULHU`: high word of `0xffffffff * 0xffffffff`.
      executeMulhuValue (BitVec.ofNat 32 0xffffffff)
          (BitVec.ofNat 32 0xffffffff) =
        BitVec.ofNat 32 0xfffffffe ∧
      -- Control 2, `MULH`: high word of `(-2 ^ 31) * 2`.
      executeMulhValue (BitVec.ofNat 32 0x80000000) (BitVec.ofNat 32 2) =
        BitVec.ofNat 32 0xffffffff ∧
      -- Control 2, `MULHSU`: high word of `(-2 ^ 31) * 2`, `rs2` unsigned.
      executeMulhsuValue (BitVec.ofNat 32 0x80000000) (BitVec.ofNat 32 2) =
        BitVec.ofNat 32 0xffffffff ∧
      -- Control 3, `MULH`: high word of `2 * (-2 ^ 31)`.
      executeMulhValue (BitVec.ofNat 32 2) (BitVec.ofNat 32 0x80000000) =
        BitVec.ofNat 32 0xffffffff ∧
      -- Control 4, `MULHSU`: high word of `2 * 0xffffffff`, `rs2` unsigned.
      executeMulhsuValue (BitVec.ofNat 32 2) (BitVec.ofNat 32 0xffffffff) =
        BitVec.ofNat 32 1 := by
  refine ⟨by decide, by decide, by decide, by decide, by decide, by decide⟩

/-- The other half of the audit: every witness really is outside the unweakened
production system. Each conjunct is `MutationControl.witness_not_sound` against
the matching in-file soundness proof, so this is unconditional. -/
theorem mulhMutationExtra_witnesses_not_sound :
    ¬ MulhHolds mulhFreeHighLimbRow ∧
      ¬ MulhHolds mulhuFreeHighLimbRow ∧
      ¬ MulhHolds mulhUnboundSourceOneSignRow ∧
      ¬ MulhHolds mulhsuUnboundSourceOneSignRow ∧
      ¬ MulhHolds mulhUnboundSourceTwoSignRow ∧
      ¬ MulhHolds mulhsuSignedSourceTwoRow :=
  ⟨mulhFreeHighLimb.witness_not_sound MulhHolds mulh_conclusion_sound,
    mulhuFreeHighLimb.witness_not_sound MulhHolds mulhu_conclusion_sound,
    mulhUnboundSourceOneSign.witness_not_sound MulhHolds mulh_conclusion_sound,
    mulhsuUnboundSourceOneSign.witness_not_sound MulhHolds
      mulhsu_conclusion_sound,
    mulhUnboundSourceTwoSign.witness_not_sound MulhHolds mulh_conclusion_sound,
    mulhsuSelectorSignConfusion.witness_not_sound MulhHolds
      mulhsu_conclusion_sound⟩

/-- The six witnesses, recorded as a list so the certificate index can name
them without reconstructing the rows. -/
def mulhMutationExtraNames : List String :=
  [ mulhFreeHighLimb.name
  , mulhuFreeHighLimb.name
  , mulhUnboundSourceOneSign.name
  , mulhsuUnboundSourceOneSign.name
  , mulhUnboundSourceTwoSign.name
  , mulhsuSelectorSignConfusion.name ]

end RiscvRefinement.Opcodes
