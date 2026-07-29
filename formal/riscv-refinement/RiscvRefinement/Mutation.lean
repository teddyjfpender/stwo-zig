import RiscvRefinement.Common

/-!
# Load-bearing mutation controls

A refinement theorem is only as strong as the constraints it actually consumes.
A theorem that quietly ignores a constraint would still typecheck, and the row
predicate would still look complete, so "the proof compiles" is not evidence
that every constraint is load-bearing.

A `MutationControl` is the evidence. It exhibits a concrete row that satisfies
the *weakened* predicate — the row predicate with one constraint deleted — and
proves the architectural conclusion is false for that row. That is a
constructive proof that the deleted constraint cannot be dropped: with it, the
conclusion follows; without it, here is the counterexample.

This is stronger than the Level-1 validator-sensitivity controls in
`scripts/riscv_refinement_lib/negative.py`, which only prove the AIR *schema
validator* rejects a mutated payload. Those check the tooling. These check the
theorem.

## Using it

For a family with row type `R`, row predicate `Holds : R → Prop`, and
architectural conclusion `Correct : R → Prop`:

1. Define `HoldsWithout<Field> : R → Prop` as `Holds` with exactly one field
   removed. Removing more than one field weakens the control, because the
   counterexample may then be blamed on the wrong deletion.
2. Exhibit a row satisfying it whose `Correct` fails.
3. Package both as a `MutationControl`.

The `Correct` predicate must be the architectural claim the refinement theorem
concludes, not a restatement of the deleted constraint. Otherwise the control is
circular: it would only prove that deleting a constraint makes that constraint
false.
-/

namespace RiscvRefinement.Mutation

open RiscvRefinement

/-- A load-bearing-constraint control.

`weakened` is the row predicate with one constraint deleted and `conclusion` is
the architectural claim. The fields prove that the deletion is not free: some
row passes the weakened predicate and still gets the wrong answer. -/
structure MutationControl
    {Row : Type}
    (weakened : Row → Prop)
    (conclusion : Row → Prop) where
  /-- Short stable identity, recorded in the Team B certificate index. -/
  name : String
  /-- The row that survives the weakened predicate. -/
  witness : Row
  /-- It really does satisfy everything that is left. -/
  satisfies : weakened witness
  /-- And it really does get the architectural answer wrong. -/
  refutes : ¬ conclusion witness

/-- A control's witness cannot satisfy any predicate that implies the
conclusion. In particular it cannot satisfy the unweakened row predicate, so a
control can never be manufactured by deleting a constraint that was vacuous.

This is the sanity check that makes the device honest: if someone weakens a
predicate that never mattered, they will not be able to produce a `refutes`
field, and if they weaken a predicate that did matter, this lemma confirms the
witness is genuinely outside the original system. -/
theorem MutationControl.witness_not_sound
    {Row : Type}
    {weakened conclusion : Row → Prop}
    (control : MutationControl weakened conclusion)
    (original : Row → Prop)
    (sound : ∀ row, original row → conclusion row) :
    ¬ original control.witness := fun holds =>
  control.refutes (sound control.witness holds)

/-- Deleting a constraint strictly weakens the system: the original predicate is
not implied by the weakened one, witnessed by the control. -/
theorem MutationControl.strictly_weaker
    {Row : Type}
    {weakened conclusion : Row → Prop}
    (control : MutationControl weakened conclusion)
    (original : Row → Prop)
    (sound : ∀ row, original row → conclusion row) :
    ¬ (∀ row, weakened row → original row) := fun implies =>
  control.witness_not_sound original sound
    (implies control.witness control.satisfies)

end RiscvRefinement.Mutation
