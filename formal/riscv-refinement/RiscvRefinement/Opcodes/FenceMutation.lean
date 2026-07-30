import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.Fence

/-!
# FENCE state-emission mutation control

The generated FENCE constraints do not inspect the state-emission tuple.  Its
architectural `pc + 4` meaning therefore depends on retaining the exact ordered
production lookup projection.  This control replaces only that lookup with a
`pc + 8` emission and proves that generic selector/constraint/table acceptance
still succeeds while the architectural next-PC claim fails.
-/

namespace RiscvRefinement.Opcodes.FenceMutation

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Mutation

def wrongStateEmitLookup : EvaluatedLookup where
  ordinal := 4
  domain := .registersState
  numerator := 1
  tuple := #[
    Air.Bridge.Fence.bitVecM31 Air.Bridge.Fence.exampleRow.pc + M31.reduce 8,
    M31.reduce Air.Bridge.Fence.exampleRow.clock + 1
  ]
  role := .emit
  tableId := none
  accessOrdinal := none

def wrongStateEmitEvaluation : SymbolicEvaluation :=
  let original :=
    Air.Bridge.Fence.evaluation Air.Bridge.Fence.exampleRow
  { original with
    events :=
      original.events.setIfInBounds 4 (.lookup wrongStateEmitLookup)
  }

def genericallyAccepted (evaluation : SymbolicEvaluation) : Prop :=
  evaluation.activeSelectorsAccepted = true ∧
    evaluation.constraintsHold = true ∧
    evaluation.fixedLookupsHold = true

def withoutStateEmitProjection (evaluation : SymbolicEvaluation) : Prop :=
  genericallyAccepted evaluation ∧
    evaluation.lookup? 2 =
      some
        (Air.Bridge.Fence.programLookup
          Air.Bridge.Fence.exampleRow) ∧
    evaluation.lookup? 3 =
      some
        (Air.Bridge.Fence.stateConsumeLookup
          Air.Bridge.Fence.exampleRow)

def architecturalNextPc (evaluation : SymbolicEvaluation) : Prop :=
  (evaluation.lookup? 4).bind (fun lookup => lookup.tuple[0]?) =
    some
      (Air.Bridge.Fence.bitVecM31
        (RiscvRefinement.nextPc Air.Bridge.Fence.exampleRow.pc))

def originalAcceptance (evaluation : SymbolicEvaluation) : Prop :=
  withoutStateEmitProjection evaluation ∧
    evaluation.lookup? 4 =
      some
        (Air.Bridge.Fence.stateEmitLookup
          Air.Bridge.Fence.exampleRow)

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

theorem original_sound
    (evaluation : SymbolicEvaluation)
    (accepted : originalAcceptance evaluation) :
    architecturalNextPc evaluation := by
  unfold architecturalNextPc
  rw [accepted.2]
  simp [
    Air.Bridge.Fence.stateEmitLookup,
    Air.Bridge.Fence.nextPcField
      Air.Bridge.Fence.exampleRow
      Air.Bridge.Fence.exampleAdmission,
  ]

set_option maxRecDepth 20000 in
theorem wrongStateEmit_satisfies :
    withoutStateEmitProjection wrongStateEmitEvaluation := by
  have lookupProjection :=
    Air.Bridge.Fence.lookupProjection Air.Bridge.Fence.exampleRow
  refine ⟨⟨?_, ?_, ?_⟩, ?_, ?_⟩
  · simpa [wrongStateEmitEvaluation] using
      Air.Bridge.Fence.selectorAccepted Air.Bridge.Fence.exampleRow
  · rw [
      wrongStateEmitEvaluation,
      SymbolicEvaluation.constraintsHold,
    ]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.constraintsHold] using
        Air.Bridge.Fence.constraintsHold Air.Bridge.Fence.exampleRow
    · rfl
  · rw [
      wrongStateEmitEvaluation,
      SymbolicEvaluation.fixedLookupsHold,
    ]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.fixedLookupsHold] using
        Air.Bridge.Fence.fixedLookupsHold Air.Bridge.Fence.exampleRow
    · simp [
        wrongStateEmitLookup,
        EvaluatedLookup.fixedRequestHolds,
        EvaluatedLookup.fixedMembership,
      ]
  · simpa [
      wrongStateEmitEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
    ] using lookupProjection.1
  · simpa [
      wrongStateEmitEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
    ] using lookupProjection.2.1

set_option maxRecDepth 20000 in
theorem wrongStateEmit_refutes :
    ¬ architecturalNextPc wrongStateEmitEvaluation := by
  unfold architecturalNextPc
  have eventBound :
      4 <
        (Air.Bridge.Fence.evaluation
          Air.Bridge.Fence.exampleRow).events.size := by
    simp [
      Air.Bridge.Fence.evaluation,
      LocalProgram.evalSymbolic,
      Air.Generated.Programs.fence,
      Air.Generated.Programs.fenceSource,
    ]
  have mutatedAt :
      wrongStateEmitEvaluation.lookup? 4 =
        some wrongStateEmitLookup := by
    rw [
      wrongStateEmitEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
      if_pos eventBound,
    ]
    rfl
  rw [mutatedAt]
  simp [wrongStateEmitLookup]
  rw [
    ← Air.Bridge.Fence.nextPcField
      Air.Bridge.Fence.exampleRow
      Air.Bridge.Fence.exampleAdmission,
  ]
  intro equality
  have pcBound :
      Air.Bridge.Fence.exampleRow.pc.toNat < M31.modulus := by
    decide
  have leftBound :
      (Air.Bridge.Fence.bitVecM31
          Air.Bridge.Fence.exampleRow.pc).val +
          (M31.reduce 8).val <
        M31.modulus := by
    rw [
      Air.Bridge.Lui.bitVecM31_val _ pcBound,
      M31.reduce_val_of_lt 8 (by decide),
    ]
    decide
  have rightBound :
      (Air.Bridge.Fence.bitVecM31
          Air.Bridge.Fence.exampleRow.pc).val +
          (M31.reduce 4).val <
        M31.modulus := by
    rw [
      Air.Bridge.Lui.bitVecM31_val _ pcBound,
      M31.reduce_val_of_lt 4 (by decide),
    ]
    decide
  have values := congrArg M31.val equality
  rw [
    M31.add_val_of_lt _ _ leftBound,
    M31.add_val_of_lt _ _ rightBound,
    Air.Bridge.Lui.bitVecM31_val _ pcBound,
    M31.reduce_val_of_lt 8 (by decide),
    M31.reduce_val_of_lt 4 (by decide),
  ] at values
  omega

def wrongStateEmitControl :
    MutationControl withoutStateEmitProjection architecturalNextPc where
  name := "fence-wrong-next-pc-state-emit"
  witness := wrongStateEmitEvaluation
  satisfies := wrongStateEmit_satisfies
  refutes := wrongStateEmit_refutes

theorem wrongStateEmit_strictly_weaker :
    ¬ (∀ evaluation,
      withoutStateEmitProjection evaluation →
        originalAcceptance evaluation) :=
  wrongStateEmitControl.strictly_weaker
    originalAcceptance original_sound

end RiscvRefinement.Opcodes.FenceMutation
