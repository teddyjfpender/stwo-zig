import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.Branches

/-!
# Branch state-emission mutation control

The generated constraints and fixed-table checks are unchanged if a
post-evaluation attacker replaces the state-emission event.  This control
replaces BEQ's taken `pc + 16` target with the fallthrough `pc + 4`.  Generic
acceptance and every earlier event remain valid; the exact ordered state
projection is therefore load-bearing for architectural retirement.
-/

namespace RiscvRefinement.Opcodes.BranchesMutation

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Mutation

private abbrev row :=
  Air.Bridge.Branches.Eq.exampleRow
    Air.Bridge.Branches.Eq.Kind.beq true

private abbrev witness :=
  Air.Bridge.Branches.Eq.exampleWitness
    Air.Bridge.Branches.Eq.Kind.beq true

def wrongStateEmitLookup : EvaluatedLookup where
  ordinal := 26
  domain := .registersState
  numerator := 1
  tuple := #[
    Air.Bridge.Branches.bitVecM31
      (RiscvRefinement.nextPc row.pc),
    M31.reduce row.clock + 1
  ]
  role := .emit
  tableId := none
  accessOrdinal := none

def wrongStateEmitEvaluation : SymbolicEvaluation :=
  let original := Air.Bridge.Branches.Eq.evaluation row witness
  { original with
    events :=
      original.events.setIfInBounds 26 (.lookup wrongStateEmitLookup)
  }

def genericallyAccepted (evaluation : SymbolicEvaluation) : Prop :=
  evaluation.activeSelectorsAccepted = true ∧
    evaluation.constraintsHold = true ∧
    evaluation.fixedLookupsHold = true

def withoutStateEmitProjection (evaluation : SymbolicEvaluation) : Prop :=
  genericallyAccepted evaluation ∧
    evaluation.lookup? 18 =
      some (Air.Bridge.Branches.Eq.programLookup row) ∧
    evaluation.lookup? 25 =
      some (Air.Bridge.Branches.Eq.stateConsumeLookup row)

def architecturalNextPc (evaluation : SymbolicEvaluation) : Prop :=
  (evaluation.lookup? 26).bind (fun lookup => lookup.tuple[0]?) =
    some
      (Air.Bridge.Branches.bitVecM31
        (Air.Bridge.Branches.selectedPc
          row.pc row.immediateEncoded
          (Air.Bridge.Branches.Eq.taken row)))

def originalAcceptance (evaluation : SymbolicEvaluation) : Prop :=
  withoutStateEmitProjection evaluation ∧
    evaluation.lookup? 26 =
      some (Air.Bridge.Branches.Eq.stateEmitLookup row)

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
    Air.Bridge.Branches.Eq.stateEmitLookup,
    Air.Bridge.Branches.selectedPcField
      row.clock row.rs1PreviousClock row.rs2PreviousClock
      row.pc row.immediateEncoded
      (Air.Bridge.Branches.Eq.taken row)
      (Air.Bridge.Branches.Eq.exampleAdmission
        Air.Bridge.Branches.Eq.Kind.beq true),
  ]

set_option maxRecDepth 30000 in
theorem wrongStateEmit_satisfies :
    withoutStateEmitProjection wrongStateEmitEvaluation := by
  have projection :=
    Air.Bridge.Branches.Eq.lookupProjection row witness
  have accepted :=
    Air.Bridge.Branches.Eq.exampleAcceptance
      Air.Bridge.Branches.Eq.Kind.beq true
  refine ⟨⟨?_, ?_, ?_⟩, ?_, ?_⟩
  · simpa [wrongStateEmitEvaluation] using
      Air.Bridge.Branches.Eq.selectorAccepted row witness
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
  · simpa [
      wrongStateEmitEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
    ] using projection.2.2.2.2.2.2.2.1

set_option maxRecDepth 30000 in
theorem wrongStateEmit_refutes :
    ¬ architecturalNextPc wrongStateEmitEvaluation := by
  unfold architecturalNextPc
  have eventBound :
      26 <
        (Air.Bridge.Branches.Eq.evaluation row witness).events.size := by
    simp [
      Air.Bridge.Branches.Eq.evaluation,
      Air.Bridge.Branches.Eq.Kind.program,
      row,
      Air.Bridge.Branches.Eq.exampleRow,
      LocalProgram.evalSymbolic,
      Air.Generated.Programs.beq,
      Air.Generated.Programs.beqSource,
    ]
  have mutatedAt :
      wrongStateEmitEvaluation.lookup? 26 =
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
      Air.Bridge.Branches.bitVecM31
          (RiscvRefinement.nextPc row.pc) =
        Air.Bridge.Branches.bitVecM31
          (Air.Bridge.Branches.selectedPc
            row.pc row.immediateEncoded
            (Air.Bridge.Branches.Eq.taken row)) := by
    simpa [wrongStateEmitLookup] using equality
  have values := congrArg M31.val fieldEquality
  simp [
    row,
    Air.Bridge.Branches.Eq.exampleRow,
    Air.Bridge.Branches.Eq.exampleValue,
    Air.Bridge.Branches.Eq.taken,
    Air.Bridge.Branches.Eq.equal,
    Air.Bridge.Branches.selectedPc,
    Air.Bridge.Branches.branchTarget,
    Air.Bridge.Branches.immediate,
    Decode.branchImmediate,
    Air.Bridge.Branches.bitVecM31,
    Air.Bridge.TeamACommon.bitVecM31,
    Air.Bridge.Lui.bitVecM31,
    RiscvRefinement.nextPc,
    M31.reduce_val,
    M31.modulus_eq,
  ] at values
  have sign :
      (BitVec.ofNat 13 16).msb = false := by decide
  simp [sign] at values

def wrongStateEmitControl :
    MutationControl withoutStateEmitProjection architecturalNextPc where
  name := "beq-taken-replaced-by-fallthrough"
  witness := wrongStateEmitEvaluation
  satisfies := wrongStateEmit_satisfies
  refutes := wrongStateEmit_refutes

theorem wrongStateEmit_strictly_weaker :
    ¬ (∀ evaluation,
      withoutStateEmitProjection evaluation →
        originalAcceptance evaluation) :=
  wrongStateEmitControl.strictly_weaker
    originalAcceptance original_sound

end RiscvRefinement.Opcodes.BranchesMutation
