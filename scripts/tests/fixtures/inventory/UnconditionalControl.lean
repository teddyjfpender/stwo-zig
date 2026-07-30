-- Synthetic fixture: an UNCONDITIONAL mutation control with its soundness
-- hypothesis discharged in this file. Never compiled; shaped like
-- Opcodes/DivMutation.lean.
import RiscvRefinement.Mutation

namespace RiscvRefinement.Opcodes

/-- The architectural claim, guarded on the row's own `DIVU` selector. -/
def DivuRetiresQuotient (row : DivRow) : Prop :=
  row.isDivu = true →
    row.rdNext.word =
      architecturalValue row.rd
        (Arith.divideUnsigned row.rs1Previous.word row.rs2Previous.word)

/-- The refinement theorem for the summary table. -/
theorem divu_refines (row : DivRow) (holds : DivHolds row) :
    divRetirement row = executeDivu row.pc row.a row.b row.rd :=
  divRetirement_eq row holds

/-- The non-vacuity witness for the summary table. -/
theorem divu_exists : ∃ row : DivRow, DivHolds row :=
  ⟨divWitnessRowFixture, divWitnessRowFixture_holds⟩

/-- Soundness of the conclusion, proved from the unweakened predicate. -/
theorem divu_conclusion_sound (row : DivRow) (holds : DivHolds row) :
    DivuRetiresQuotient row := by
  intro selector
  exact divu_retirement_word row holds selector

structure DivHoldsWithoutScanTotal (row : DivRow) : Prop where
  selectorUnique : row.selectorSum = 1
  -- scanTotal is deliberately absent: this is the mutation.
  productRecurrence : divProduct row = row.dividend

def divSlackScanRow : DivRow :=
  divWitnessRowFixture

theorem divSlackScanRow_satisfies :
    DivHoldsWithoutScanTotal divSlackScanRow := by
  constructor <;> decide

theorem divSlackScanRow_refutes :
    ¬ DivuRetiresQuotient divSlackScanRow := by
  intro claim
  exact absurd (claim (by decide)) (by decide)

/-- The published control. -/
def divReleasedComparison :
    MutationControl DivHoldsWithoutScanTotal
      DivuRetiresQuotient where
  name := "div-released-comparison-witness"
  witness := divSlackScanRow
  satisfies := divSlackScanRow_satisfies
  refutes := divSlackScanRow_refutes

/-- Unconditional: the soundness hypothesis is discharged by
`divu_conclusion_sound` rather than assumed. -/
theorem div_scan_total_is_load_bearing :
    ¬ (∀ row, DivHoldsWithoutScanTotal row → DivHolds row) :=
  divReleasedComparison.strictly_weaker DivHolds divu_conclusion_sound

end RiscvRefinement.Opcodes
