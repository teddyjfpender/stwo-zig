-- Synthetic fixture: a CONDITIONAL mutation control. The corollary takes a
-- `sound` hypothesis instead of using the in-file soundness theorem, which is
-- exactly the state that shipped three vacuous corollaries before being
-- caught. Never compiled; shaped like Opcodes/MultiplyMutation.lean.
import RiscvRefinement.Mutation

namespace RiscvRefinement.Opcodes

/-- The architectural claim. Deliberately UNGUARDED: `MulRow` is the
single-opcode `mul` family, so family granularity coincides with the opcode. -/
def MulComputesProduct (row : MulRow) : Prop :=
  mulRetirement row =
    executeMul row.pc row.rs1Previous.word row.rs2Previous.word row.rd

theorem mul_refines (row : MulRow) (holds : MulHolds row) :
    mulRetirement row = executeMul row.pc row.a row.b row.rd :=
  mulRetirement_eq row holds

theorem mul_exists : ∃ row : MulRow, MulHolds row :=
  ⟨mulWitnessRowFixture, mulWitnessRowFixture_holds⟩

/-- An in-file soundness proof DOES exist -- but the corollary below does not
use it, so the corollary is still conditional. -/
theorem mul_conclusion_sound (row : MulRow) (holds : MulHolds row) :
    MulComputesProduct row := by
  exact mul_retirement_product row holds

structure MulHoldsWithoutProductLimb0 (row : MulRow) : Prop where
  -- productLimb0 is deliberately absent.
  productLimb1 : mulCarry row 1 = row.result.limb1.toNat

def freeLowLimbRow : MulRow :=
  mulWitnessRowFixture

theorem freeLowLimbRow_satisfies :
    MulHoldsWithoutProductLimb0 freeLowLimbRow := by
  constructor <;> decide

theorem freeLowLimbRow_refutes : ¬ MulComputesProduct freeLowLimbRow := by
  intro claim
  exact absurd claim (by decide)

/-- The published control. -/
def mulFreeLowLimb :
    MutationControl MulHoldsWithoutProductLimb0 MulComputesProduct where
  name := "mul-free-low-limb"
  witness := freeLowLimbRow
  satisfies := freeLowLimbRow_satisfies
  refutes := freeLowLimbRow_refutes

/-- CONDITIONAL: rests on an assumed soundness hypothesis. -/
theorem mul_product_limb0_is_load_bearing
    (sound : ∀ row, MulHolds row → MulComputesProduct row) :
    ¬ (∀ row, MulHoldsWithoutProductLimb0 row → MulHolds row) :=
  mulFreeLowLimb.strictly_weaker MulHolds sound

end RiscvRefinement.Opcodes
