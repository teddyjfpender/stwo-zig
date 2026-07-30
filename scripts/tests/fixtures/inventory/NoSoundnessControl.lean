-- Synthetic fixture: a conditional control with NO soundness proof anywhere
-- in the file. The corollary is one false hypothesis away from vacuous and
-- nothing in this file rules that out. Never compiled.
import RiscvRefinement.Mutation

namespace RiscvRefinement.Opcodes

/-- The architectural claim, guarded on the `LH` selector. -/
def LhRetiresHighHalf (row : LoadStoreRow) : Prop :=
  row.isLh = true → row.shiftId = 5 →
    row.result.word = Memory.signExtendHalf row.srcNext.highHalf

structure LoadStoreHoldsWithoutHalfLoadHigh (row : LoadStoreRow) : Prop where
  -- halfLoadHigh is deliberately absent: this is the mutation.
  halfLoadExtension : row.isHalfLoad = true → row.result.limb2 = row.signMask

def lhWrongHalfRow : LoadStoreRow :=
  loadStoreWitnessRowFixture

theorem lhWrongHalfRow_satisfies :
    LoadStoreHoldsWithoutHalfLoadHigh lhWrongHalfRow := by
  constructor <;> decide

theorem lhWrongHalfRow_refutes : ¬ LhRetiresHighHalf lhWrongHalfRow := by
  intro claim
  exact absurd (claim rfl (by decide)) (by decide)

/-- The published control. -/
def lhWrongHighHalf :
    MutationControl LoadStoreHoldsWithoutHalfLoadHigh LhRetiresHighHalf where
  name := "lh-wrong-high-half"
  witness := lhWrongHalfRow
  satisfies := lhWrongHalfRow_satisfies
  refutes := lhWrongHalfRow_refutes

/-- CONDITIONAL, and no `LoadStoreHolds → LhRetiresHighHalf` theorem exists in
this file to discharge the hypothesis. -/
theorem lh_high_half_selection_is_load_bearing
    (sound : ∀ row, LoadStoreHolds row → LhRetiresHighHalf row) :
    ¬ (∀ row, LoadStoreHoldsWithoutHalfLoadHigh row → LoadStoreHolds row) :=
  lhWrongHighHalf.strictly_weaker LoadStoreHolds sound

end RiscvRefinement.Opcodes
