import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.Jal

/-!
# JAL state-target mutation control

The generated JAL constraints do not constrain the registers-state emission
event itself.  This negative control replaces only its jump target with
`pc + 4`.  Generic selector, constraint, and fixed-table checks still accept,
while the exact architectural jump claim is refuted.
-/

namespace RiscvRefinement.Opcodes.JalMutation

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Mutation

def wrongStateEmitLookup : EvaluatedLookup where
  ordinal := 12
  domain := .registersState
  numerator := 1
  tuple := #[
    Air.Bridge.Jal.bitVecM31 Air.Bridge.Jal.exampleRow.pc +
      M31.reduce 4,
    M31.reduce Air.Bridge.Jal.exampleRow.clock + 1
  ]
  role := .emit
  tableId := none
  accessOrdinal := none

def wrongStateEmitEvaluation : SymbolicEvaluation :=
  let original :=
    Air.Bridge.Jal.evaluation
      Air.Bridge.Jal.exampleRow
      Air.Bridge.Jal.exampleWitness
  { original with
    events :=
      original.events.setIfInBounds
        12 (.lookup wrongStateEmitLookup)
  }

def genericallyAccepted (evaluation : SymbolicEvaluation) : Prop :=
  evaluation.activeSelectorsAccepted = true ∧
    evaluation.constraintsHold = true ∧
    evaluation.fixedLookupsHold = true

def withoutStateEmitProjection
    (evaluation : SymbolicEvaluation) : Prop :=
  genericallyAccepted evaluation ∧
    evaluation.lookup? 10 =
      some
        (Air.Bridge.Jal.programLookup
          Air.Bridge.Jal.exampleRow) ∧
    evaluation.lookup? 11 =
      some
        (Air.Bridge.Jal.stateConsumeLookup
          Air.Bridge.Jal.exampleRow)

def architecturalJumpTarget
    (evaluation : SymbolicEvaluation) : Prop :=
  (evaluation.lookup? 12).bind
      (fun lookup => lookup.tuple[0]?) =
    some
      (Air.Bridge.Jal.bitVecM31
        (Air.Bridge.Jal.jumpTarget
          Air.Bridge.Jal.exampleRow.pc
          Air.Bridge.Jal.exampleRow.immediateEncoded))

def originalAcceptance
    (evaluation : SymbolicEvaluation) : Prop :=
  withoutStateEmitProjection evaluation ∧
    evaluation.lookup? 12 =
      some
        (Air.Bridge.Jal.stateEmitLookup
          Air.Bridge.Jal.exampleRow)

private theorem all_setIfInBounds_of_all
    {α : Type}
    (values : Array α)
    (predicate : α → Bool)
    (index : Nat)
    (replacement : α)
    (accepted : values.all predicate = true)
    (replacementAccepted : predicate replacement = true) :
    (values.setIfInBounds index replacement).all predicate = true := by
  rw [Array.all_eq_true] at accepted ⊢
  intro selected bound
  rw [Array.getElem_setIfInBounds]
  split
  · exact replacementAccepted
  · exact accepted selected (by simpa using bound)

theorem originalSound
    (evaluation : SymbolicEvaluation)
    (accepted : originalAcceptance evaluation) :
    architecturalJumpTarget evaluation := by
  unfold architecturalJumpTarget
  rw [accepted.2]
  simp [
    Air.Bridge.Jal.stateEmitLookup,
    Air.Bridge.Jal.targetField
      Air.Bridge.Jal.exampleRow
      Air.Bridge.Jal.exampleAdmission,
  ]

set_option maxRecDepth 20000 in
theorem wrongStateEmit_satisfies :
    withoutStateEmitProjection wrongStateEmitEvaluation := by
  have projection :=
    Air.Bridge.Jal.lookupProjection
      Air.Bridge.Jal.exampleRow
      Air.Bridge.Jal.exampleWitness
  refine ⟨⟨?_, ?_, ?_⟩, ?_, ?_⟩
  · simpa [wrongStateEmitEvaluation] using
      Air.Bridge.Jal.exampleAcceptance.selectors
  · rw [
      wrongStateEmitEvaluation,
      SymbolicEvaluation.constraintsHold,
    ]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.constraintsHold] using
        Air.Bridge.Jal.exampleAcceptance.constraints
    · rfl
  · rw [
      wrongStateEmitEvaluation,
      SymbolicEvaluation.fixedLookupsHold,
    ]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.fixedLookupsHold] using
        Air.Bridge.Jal.exampleAcceptance.fixedLookups
    · simp [
        wrongStateEmitLookup,
        EvaluatedLookup.fixedRequestHolds,
        EvaluatedLookup.fixedMembership,
      ]
  · simpa [
      wrongStateEmitEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
    ] using projection.1
  · simpa [
      wrongStateEmitEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
    ] using projection.2.1

set_option maxRecDepth 20000 in
theorem wrongStateEmit_refutes :
    ¬ architecturalJumpTarget wrongStateEmitEvaluation := by
  unfold architecturalJumpTarget
  have eventBound :
      12 <
        (Air.Bridge.Jal.evaluation
          Air.Bridge.Jal.exampleRow
          Air.Bridge.Jal.exampleWitness).events.size := by
    simp [
      Air.Bridge.Jal.evaluation,
      LocalProgram.evalSymbolic,
      Air.Generated.Programs.jal,
      Air.Generated.Programs.jalSource,
    ]
  have mutatedAt :
      wrongStateEmitEvaluation.lookup? 12 =
        some wrongStateEmitLookup := by
    rw [
      wrongStateEmitEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
      if_pos eventBound,
    ]
    rfl
  rw [mutatedAt]
  simp [
    wrongStateEmitLookup,
    Air.Bridge.Jal.exampleRow,
    Air.Bridge.Jal.jumpTarget,
    Air.Bridge.Jal.immediate,
    Decode.jalImmediate,
    Air.Bridge.Jal.bitVecM31,
    Air.Bridge.TeamACommon.bitVecM31,
    Air.Bridge.Lui.bitVecM31,
  ]
  intro equality
  have values := congrArg M31.val equality
  simp [M31.modulus_eq] at values

def wrongStateEmitControl :
    MutationControl
      withoutStateEmitProjection
      architecturalJumpTarget where
  name := "jal-wrong-jump-state-emit"
  witness := wrongStateEmitEvaluation
  satisfies := wrongStateEmit_satisfies
  refutes := wrongStateEmit_refutes

theorem wrongStateEmit_strictly_weaker :
    ¬ (∀ evaluation,
      withoutStateEmitProjection evaluation →
        originalAcceptance evaluation) :=
  wrongStateEmitControl.strictly_weaker
    originalAcceptance originalSound

end RiscvRefinement.Opcodes.JalMutation
