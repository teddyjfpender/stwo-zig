-- REVIEWED-CAPSULE BOUNDARY. Hand-written file; not generated, and not a
-- generated-Sail theorem. The architectural conclusion this mutation control
-- certifies is stated against the reviewed normalized capsule
-- RiscvRefinement/Sail/Reviewed/Multiply.lean, which is hand-written with no
-- generator, no digest, and no derivation from any Sail artifact (see its
-- header). Nothing in this file is publication-level for the architectural
-- side.

import RiscvRefinement.Air.Family.Multiply
import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.Multiply
import RiscvRefinement.Sail.Reviewed.Multiply

/-!
# Load-bearing mutation control for `MUL`

`mul_refines` derives the destination word from the AIR's four product-limb
equations. This file proves that the first of those equations is load-bearing:
delete it, and a row survives everything that is left while computing the wrong
architectural product.

The pattern generalises. `MulHoldsWithoutProductLimb0` is `MulHolds` with
exactly one field removed -- removing more than one would leave the
counterexample ambiguous about which deletion caused it -- and the conclusion is
the architectural claim `mul_refines` reaches, not a restatement of the deleted
equation. If the conclusion restated the deleted constraint the control would be
circular, proving only that deleting a constraint makes that constraint false.
-/

namespace RiscvRefinement.Opcodes

open RiscvRefinement
open RiscvRefinement.Air.Family
open RiscvRefinement.Mutation
open RiscvRefinement.Sail.Reviewed

/-- `MulHolds` with the limb-0 product equation deleted, and nothing else
changed. -/
structure MulHoldsWithoutProductLimb0 (row : MulRow) : Prop where
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
  -- productLimb0 is deliberately absent.
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
satisfies the weakened predicate. Without this the control could be vacuous,
proving something about a predicate nothing satisfies. -/
theorem mulHolds_weakens
    (row : MulRow)
    (holds : MulHolds row) :
    MulHoldsWithoutProductLimb0 row where
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
  productLimb1 := holds.productLimb1
  productLimb2 := holds.productLimb2
  productLimb3 := holds.productLimb3
  destinationFlag := holds.destinationFlag
  destinationLimb0 := holds.destinationLimb0
  destinationLimb1 := holds.destinationLimb1
  destinationLimb2 := holds.destinationLimb2
  destinationLimb3 := holds.destinationLimb3
  nextPcResult := holds.nextPcResult

/-- The architectural claim: the retired destination word is the low word of the
product of the two source words. This is what `mul_refines` establishes, stated
independently of the AIR so the control cannot be circular. -/
def MulComputesProduct (row : MulRow) : Prop :=
  mulRetirement row =
    executeMul row.pc row.rs1Previous.word row.rs2Previous.word row.rd

/-- A row multiplying `3 * 5`, but with the free limb-0 product equation used to
claim `16` in the low byte instead of `15`. Everything else is honest: the
sources are preserved, the three surviving product equations hold with all
carries zero, the destination mirrors `result`, and the next PC is `pc + 4`. -/
def freeLowLimbRow : MulRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rd := BitVec.ofNat 5 7
  rdPreviousClock := 0
  rdPrevious := WordBytes.zero
  rdNext := { WordBytes.zero with limb0 := BitVec.ofNat 8 16 }
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rs1Previous := { WordBytes.zero with limb0 := BitVec.ofNat 8 3 }
  rs1Next := { WordBytes.zero with limb0 := BitVec.ofNat 8 3 }
  rs2 := BitVec.ofNat 5 6
  rs2PreviousClock := 0
  rs2Previous := { WordBytes.zero with limb0 := BitVec.ofNat 8 5 }
  rs2Next := { WordBytes.zero with limb0 := BitVec.ofNat 8 5 }
  result := { WordBytes.zero with limb0 := BitVec.ofNat 8 16 }
  carry0 := BitVec.ofNat 11 0
  carry1 := BitVec.ofNat 11 0
  carry2 := BitVec.ofNat 11 0
  carry3 := BitVec.ofNat 11 0
  rdNonzero := true
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem freeLowLimbRow_satisfies :
    MulHoldsWithoutProductLimb0 freeLowLimbRow := by
  refine {
    clockPositive := by decide
    sourceOneClock := ?_
    sourceTwoClock := ?_
    destinationClock := ?_
    sourceOneLimb0 := rfl
    sourceOneLimb1 := rfl
    sourceOneLimb2 := rfl
    sourceOneLimb3 := rfl
    sourceTwoLimb0 := rfl
    sourceTwoLimb1 := rfl
    sourceTwoLimb2 := rfl
    sourceTwoLimb3 := rfl
    productLimb1 := by decide
    productLimb2 := by decide
    productLimb3 := by decide
    destinationFlag := by decide
    destinationLimb0 := rfl
    destinationLimb1 := rfl
    destinationLimb2 := rfl
    destinationLimb3 := rfl
    nextPcResult := rfl
  } <;> simp [validPreviousClock, accessClock, freeLowLimbRow]

theorem freeLowLimbRow_refutes : ¬ MulComputesProduct freeLowLimbRow := by
  intro claim
  have limb : (BitVec.ofNat 8 16 : Byte) = BitVec.ofNat 8 15 := by
    have := congrArg Retirement.write claim
    simp only [
      MulComputesProduct,
      mulRetirement,
      executeMul,
      freeLowLimbRow,
      architecturalWrite,
    ] at this
    revert this
    decide
  exact absurd limb (by decide)

/-- The published control: deleting the limb-0 product equation admits a row
that computes `3 * 5 = 16`. -/
def mulFreeLowLimb :
    MutationControl MulHoldsWithoutProductLimb0 MulComputesProduct where
  name := "mul-free-low-limb"
  witness := freeLowLimbRow
  satisfies := freeLowLimbRow_satisfies
  refutes := freeLowLimbRow_refutes

/-- The architectural claim really is what the unweakened row predicate
delivers, so the corollary below needs no hypothesis.

Proving this rather than assuming it is the standard the rest of the
development holds to: a corollary conditional on a soundness hypothesis is only
worth as much as that hypothesis is true, and three such corollaries elsewhere
in this development were found to be vacuous before being repaired. -/
theorem mulHolds_computes_product
    (row : MulRow)
    (holds : MulHolds row) :
    MulComputesProduct row := by
  unfold MulComputesProduct mulRetirement executeMul
  rw [holds.nextPcResult, mulDestinationValue row holds,
    architecturalWrite_value, mulValueRefines row holds]

/-- The deletion is not free: no strengthening of the weakened predicate back to
`MulHolds` is possible, because `MulHolds` implies the architectural claim and
the witness does not satisfy it. Unconditional. -/
theorem mul_product_limb0_is_load_bearing :
    ¬ (∀ row, MulHoldsWithoutProductLimb0 row → MulHolds row) :=
  mulFreeLowLimb.strictly_weaker MulHolds mulHolds_computes_product

end RiscvRefinement.Opcodes
