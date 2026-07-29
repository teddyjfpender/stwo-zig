-- Synthetic fixture: a file with refinement and non-vacuity evidence but no
-- MutationControl at all. Also carries decoy controls inside comments, which
-- the scanner must ignore. Never compiled.
import RiscvRefinement.Common

/-
A decoy inside a block comment must not be counted:

def commentedOutControl :
    MutationControl SllHoldsWithoutNothing SllRetiresLeftShift where
  name := "decoy-in-block-comment"
-/

namespace RiscvRefinement.Opcodes

-- def lineCommentControl : MutationControl A B where
--   name := "decoy-in-line-comment"

theorem sll_refines (row : ShiftsRegRow) (holds : ShiftsRegHolds row) :
    shiftsRegRetirement row = executeSll row.pc row.a row.b row.rd :=
  shiftsRegRetirement_eq row holds

theorem sll_exists : ∃ row : ShiftsRegRow, ShiftsRegHolds row :=
  ⟨shiftsRegWitnessRowFixture, shiftsRegWitnessRowFixture_holds⟩

end RiscvRefinement.Opcodes
