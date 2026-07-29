import RiscvRefinement.Common

/-!
# Load-bearing mutation controls

A `MutationControl` exhibits a concrete row that satisfies a predicate with
exactly one check removed while refuting the architectural conclusion.  This
makes the deleted check demonstrably load-bearing rather than merely
schema-sensitive.
-/

namespace RiscvRefinement.Mutation

/-- Constructive evidence that a one-check weakening admits an
architecturally incorrect witness. -/
structure MutationControl
    {Row : Type}
    (weakened : Row → Prop)
    (conclusion : Row → Prop) where
  name : String
  witness : Row
  satisfies : weakened witness
  refutes : ¬ conclusion witness

/-- A mutation witness cannot satisfy an original predicate whose soundness
theorem establishes the refuted conclusion. -/
theorem MutationControl.witness_not_sound
    {Row : Type}
    {weakened conclusion : Row → Prop}
    (control : MutationControl weakened conclusion)
    (original : Row → Prop)
    (sound : ∀ row, original row → conclusion row) :
    ¬ original control.witness := fun holds =>
  control.refutes (sound control.witness holds)

/-- A checked mutation control proves that the weakened predicate is strictly
weaker than the sound original predicate. -/
theorem MutationControl.strictly_weaker
    {Row : Type}
    {weakened conclusion : Row → Prop}
    (control : MutationControl weakened conclusion)
    (original : Row → Prop)
    (sound : ∀ row, original row → conclusion row) :
    ¬ (∀ row, weakened row → original row) := fun implies =>
  control.witness_not_sound original sound
    (implies control.witness control.satisfies)

/-- Fallback for representation checks whose architectural condition is
already enforced by the typed row: a concrete witness still proves that
deleting the check strictly weakens interpreted acceptance. -/
theorem strictly_weaker_of_not_original
    {Row : Type}
    {weakened original : Row → Prop}
    (witness : Row)
    (satisfies : weakened witness)
    (refutes : ¬ original witness) :
    ¬ (∀ row, weakened row → original row) :=
  fun implies => refutes (implies witness satisfies)

end RiscvRefinement.Mutation
