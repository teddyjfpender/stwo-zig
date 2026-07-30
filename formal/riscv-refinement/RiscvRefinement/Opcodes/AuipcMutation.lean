import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.Auipc

/-!
# AUIPC destination-value mutation control

This control replaces only the low byte of AUIPC's destination-emission
lookup.  Selectors, every algebraic constraint, every fixed-table request,
and the exact program projection still pass.  The architectural destination
therefore depends on retaining the exact ordered memory-access projection.
-/

namespace RiscvRefinement.Opcodes.AuipcMutation

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Mutation

private abbrev row := Air.Bridge.Auipc.exampleRow
private abbrev witness := Air.Bridge.Auipc.exampleWitness

def wrongDestinationEmitLookup : EvaluatedLookup where
  ordinal := 27
  domain := .memoryAccess
  numerator := 1
  tuple := #[
    0,
    Air.Bridge.Auipc.bitVecM31 row.rd,
    Air.Bridge.Auipc.accessClockField row,
    Air.Bridge.Auipc.bitVecM31 (BitVec.ofNat 8 4),
    Air.Bridge.Auipc.bitVecM31 (BitVec.ofNat 8 48),
    0,
    0
  ]
  role := .emit
  tableId := none
  accessOrdinal := some 1

def wrongDestinationEvaluation : SymbolicEvaluation :=
  let original := Air.Bridge.Auipc.evaluation row witness
  { original with
    events :=
      original.events.setIfInBounds
        27 (.lookup wrongDestinationEmitLookup)
  }

def genericallyAccepted (evaluation : SymbolicEvaluation) : Prop :=
  evaluation.activeSelectorsAccepted = true ∧
    evaluation.constraintsHold = true ∧
    evaluation.fixedLookupsHold = true

def withoutDestinationEmitProjection
    (evaluation : SymbolicEvaluation) : Prop :=
  genericallyAccepted evaluation ∧
    evaluation.lookup? 17 =
      some (Air.Bridge.Auipc.programLookup row) ∧
    evaluation.lookup? 19 =
      some (Air.Bridge.Auipc.stateEmitLookup row)

def architecturalDestinationLow
    (evaluation : SymbolicEvaluation) : Prop :=
  (evaluation.lookup? 27).bind
      (fun lookup => lookup.tuple[3]?) =
    some
      (Air.Bridge.Auipc.bitVecM31
        (Air.Bridge.Auipc.wordBytes
          (Air.Bridge.Auipc.pcRelativeValue
            row.pc row.immediateEncoded)).limb0)

def originalAcceptance
    (evaluation : SymbolicEvaluation) : Prop :=
  withoutDestinationEmitProjection evaluation ∧
    evaluation.lookup? 27 =
      some (Air.Bridge.Auipc.destinationEmitLookup row)

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
    architecturalDestinationLow evaluation := by
  unfold architecturalDestinationLow
  rw [accepted.2]
  simp [
    Air.Bridge.Auipc.destinationEmitLookup,
    row,
    Air.Bridge.Auipc.exampleRow,
    Air.Bridge.Auipc.wordBytes,
    Air.Bridge.Auipc.pcRelativeValue,
    Air.Bridge.Auipc.immediateWord,
    Decode.auipcImmediate,
  ]

set_option maxRecDepth 50000 in
theorem wrongDestination_satisfies :
    withoutDestinationEmitProjection
      wrongDestinationEvaluation := by
  have accepted := Air.Bridge.Auipc.exampleAcceptance
  refine ⟨⟨?_, ?_, ?_⟩, ?_, ?_⟩
  · simpa [wrongDestinationEvaluation] using
      accepted.selectors
  · rw [
      wrongDestinationEvaluation,
      SymbolicEvaluation.constraintsHold,
    ]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.constraintsHold] using
        accepted.constraints
    · rfl
  · rw [
      wrongDestinationEvaluation,
      SymbolicEvaluation.fixedLookupsHold,
    ]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.fixedLookupsHold] using
        accepted.fixedLookups
    · simp [
        wrongDestinationEmitLookup,
        EvaluatedLookup.fixedRequestHolds,
        EvaluatedLookup.fixedMembership,
      ]
  · simpa [
      wrongDestinationEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
    ] using
      Air.Bridge.Auipc.lookupProjection
        row witness 17 (by decide) (by decide)
  · simpa [
      wrongDestinationEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
    ] using
      Air.Bridge.Auipc.lookupProjection
        row witness 19 (by decide) (by decide)

set_option maxRecDepth 50000 in
theorem wrongDestination_refutes :
    ¬ architecturalDestinationLow
      wrongDestinationEvaluation := by
  unfold architecturalDestinationLow
  have eventBound :
      27 <
        (Air.Bridge.Auipc.evaluation row witness).events.size := by
    simp [
      Air.Bridge.Auipc.evaluation,
      LocalProgram.evalSymbolic,
      Air.Generated.Programs.auipc,
      Air.Generated.Programs.auipcSource,
    ]
  have mutatedAt :
      wrongDestinationEvaluation.lookup? 27 =
        some wrongDestinationEmitLookup := by
    rw [
      wrongDestinationEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
      if_pos eventBound,
    ]
    simp [EvaluatedEvent.lookup?]
  rw [mutatedAt]
  intro equality
  have fieldEquality :
      Air.Bridge.Auipc.bitVecM31
          (BitVec.ofNat 8 4) =
        Air.Bridge.Auipc.bitVecM31
          (Air.Bridge.Auipc.wordBytes
            (Air.Bridge.Auipc.pcRelativeValue
              row.pc row.immediateEncoded)).limb0 := by
    simpa [wrongDestinationEmitLookup] using equality
  have values := congrArg M31.val fieldEquality
  simp [
    row,
    Air.Bridge.Auipc.exampleRow,
    Air.Bridge.Auipc.wordBytes,
    Air.Bridge.Auipc.pcRelativeValue,
    Air.Bridge.Auipc.immediateWord,
    Decode.auipcImmediate,
    Air.Bridge.Auipc.bitVecM31,
    Air.Bridge.TeamACommon.bitVecM31,
    Air.Bridge.Lui.bitVecM31,
  ] at values
  change 4 = 0 at values
  omega

def wrongDestinationControl :
    MutationControl
      withoutDestinationEmitProjection
      architecturalDestinationLow where
  name := "auipc-destination-low-byte-plus-four"
  witness := wrongDestinationEvaluation
  satisfies := wrongDestination_satisfies
  refutes := wrongDestination_refutes

theorem wrongDestination_strictly_weaker :
    ¬ (∀ evaluation,
      withoutDestinationEmitProjection evaluation →
        originalAcceptance evaluation) :=
  wrongDestinationControl.strictly_weaker
    originalAcceptance originalSound

theorem auipcDestinationProjectionLoadBearing :
    ∃ evaluation,
      withoutDestinationEmitProjection evaluation ∧
        ¬ architecturalDestinationLow evaluation :=
  ⟨wrongDestinationEvaluation,
    wrongDestination_satisfies,
    wrongDestination_refutes⟩

end RiscvRefinement.Opcodes.AuipcMutation
