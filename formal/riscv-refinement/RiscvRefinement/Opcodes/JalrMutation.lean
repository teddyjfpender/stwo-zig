import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.Jalr

/-!
# JALR state-target mutation control

This control replaces only the accepted state-emission target (`104` in the
canonical odd-sum example) with `pc + 4`. Selectors, every constraint, every
fixed-table request, and the exact program tuple still pass. The architectural
JALR target therefore depends on retaining the exact ordered state projection.
-/

namespace RiscvRefinement.Opcodes.JalrMutation

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Mutation

private abbrev row := Air.Bridge.Jalr.exampleRow
private abbrev witness := Air.Bridge.Jalr.exampleWitness

def wrongStateEmitLookup : EvaluatedLookup where
  ordinal := 35
  domain := .registersState
  numerator := 1
  tuple := #[
    Air.Bridge.Jalr.bitVecM31 (RiscvRefinement.nextPc row.pc),
    M31.reduce row.clock + 1
  ]
  role := .emit
  tableId := none
  accessOrdinal := none

def wrongStateEmitEvaluation : SymbolicEvaluation :=
  let original := Air.Bridge.Jalr.evaluation row witness
  { original with
    events :=
      original.events.setIfInBounds 35 (.lookup wrongStateEmitLookup)
  }

def genericallyAccepted (evaluation : SymbolicEvaluation) : Prop :=
  evaluation.activeSelectorsAccepted = true ∧
    evaluation.constraintsHold = true ∧
    evaluation.fixedLookupsHold = true

def withoutStateEmitProjection (evaluation : SymbolicEvaluation) : Prop :=
  genericallyAccepted evaluation ∧
    evaluation.lookup? 23 =
      some (Air.Bridge.Jalr.programLookup row)

def architecturalNextPc (evaluation : SymbolicEvaluation) : Prop :=
  (evaluation.lookup? 35).bind (fun lookup => lookup.tuple[0]?) =
    some
      (Air.Bridge.Jalr.bitVecM31
        (Air.Bridge.Jalr.jumpTarget row.rs1Value.word row.immediate))

def originalAcceptance (evaluation : SymbolicEvaluation) : Prop :=
  withoutStateEmitProjection evaluation ∧
    evaluation.lookup? 35 =
      some (Air.Bridge.Jalr.stateEmitLookup row)

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
    Air.Bridge.Jalr.stateEmitLookup,
    Air.Bridge.Jalr.stateTargetField_eq
      row Air.Bridge.Jalr.exampleAdmission,
  ]

set_option maxRecDepth 50000 in
theorem wrongStateEmit_satisfies :
    withoutStateEmitProjection wrongStateEmitEvaluation := by
  have projection := Air.Bridge.Jalr.lookupProjection row witness
  have accepted := Air.Bridge.Jalr.exampleAcceptance
  refine ⟨⟨?_, ?_, ?_⟩, ?_⟩
  · simpa [wrongStateEmitEvaluation] using
      Air.Bridge.Jalr.selectorAccepted row witness
  · rw [wrongStateEmitEvaluation, SymbolicEvaluation.constraintsHold]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.constraintsHold] using accepted.constraints
    · rfl
  · rw [wrongStateEmitEvaluation, SymbolicEvaluation.fixedLookupsHold]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.fixedLookupsHold] using accepted.fixedLookups
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

set_option maxRecDepth 50000 in
theorem wrongStateEmit_refutes :
    ¬ architecturalNextPc wrongStateEmitEvaluation := by
  unfold architecturalNextPc
  have eventBound :
      35 < (Air.Bridge.Jalr.evaluation row witness).events.size := by
    simp [
      Air.Bridge.Jalr.evaluation,
      LocalProgram.evalSymbolic,
      Air.Generated.Programs.jalr,
      Air.Generated.Programs.jalrSource,
    ]
  have mutatedAt :
      wrongStateEmitEvaluation.lookup? 35 =
        some wrongStateEmitLookup := by
    rw [
      wrongStateEmitEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
      if_pos eventBound,
    ]
    rfl
  rw [mutatedAt]
  intro equality
  have fieldEquality :
      Air.Bridge.Jalr.bitVecM31 (RiscvRefinement.nextPc row.pc) =
        Air.Bridge.Jalr.bitVecM31
          (Air.Bridge.Jalr.jumpTarget
            row.rs1Value.word row.immediate) := by
    simpa [wrongStateEmitLookup] using equality
  have values := congrArg M31.val fieldEquality
  simp [
    row,
    Air.Bridge.Jalr.exampleRow,
    Air.Bridge.Jalr.wordBytes,
    WordBytes.value,
    Air.Bridge.Jalr.jumpTarget,
    Air.Bridge.Jalr.unalignedTarget,
    Air.Bridge.Jalr.bitVecM31,
    Air.Bridge.TeamACommon.bitVecM31,
    Air.Bridge.Lui.bitVecM31,
    RiscvRefinement.nextPc,
    M31.reduce_val,
    M31.modulus_eq,
  ] at values

def wrongStateEmitControl :
    MutationControl withoutStateEmitProjection architecturalNextPc where
  name := "jalr-target-replaced-by-link-pc"
  witness := wrongStateEmitEvaluation
  satisfies := wrongStateEmit_satisfies
  refutes := wrongStateEmit_refutes

theorem wrongStateEmit_strictly_weaker :
    ¬ (∀ evaluation,
      withoutStateEmitProjection evaluation →
        originalAcceptance evaluation) :=
  wrongStateEmitControl.strictly_weaker
    originalAcceptance original_sound

end RiscvRefinement.Opcodes.JalrMutation
