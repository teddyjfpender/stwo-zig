import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.Lt

/-!
# Comparison-selector manifest mutation controls

For each of SLT, SLTU, SLTI, and SLTIU, this file changes only the emitted
program-access manifest id to its signed/unsigned sibling.  The generated
selector checks, every polynomial constraint, every fixed-table request, and
the state-emission tuple still pass.  The exact program lookup is therefore
load-bearing for binding an accepted comparison row to the decoded mnemonic.
-/

namespace RiscvRefinement.Opcodes.LtMutation

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Mutation

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

namespace Reg

abbrev Kind := Air.Bridge.LtReg.Kind
private abbrev row (kind : Kind) := Air.Bridge.LtReg.highBitRow kind
private abbrev witness (kind : Kind) := Air.Bridge.LtReg.highBitWitness kind

def siblingManifestId : Kind → Nat
  | .signed => 4
  | .unsigned => 3

def wrongProgramLookup (kind : Kind) : EvaluatedLookup :=
  { Air.Bridge.LtReg.programLookup (row kind) with
    tuple := #[
      Air.Bridge.LtReg.bitVecM31 (row kind).pc,
      M31.reduce (siblingManifestId kind),
      Air.Bridge.LtReg.bitVecM31 (row kind).rd,
      Air.Bridge.LtReg.bitVecM31 (row kind).rs1,
      Air.Bridge.LtReg.bitVecM31 (row kind).rs2
    ]
  }

def wrongProgramEvaluation (kind : Kind) : SymbolicEvaluation :=
  let original := Air.Bridge.LtReg.evaluation (row kind) (witness kind)
  { original with
    events :=
      original.events.setIfInBounds 36 (.lookup (wrongProgramLookup kind))
  }

def genericallyAccepted (evaluation : SymbolicEvaluation) : Prop :=
  evaluation.activeSelectorsAccepted = true ∧
    evaluation.constraintsHold = true ∧
    evaluation.fixedLookupsHold = true

def withoutProgramProjection
    (kind : Kind)
    (evaluation : SymbolicEvaluation) :
    Prop :=
  genericallyAccepted evaluation ∧
    evaluation.lookup? 38 =
      some (Air.Bridge.LtReg.stateEmitLookup (row kind))

def architecturalProgram
    (kind : Kind)
    (evaluation : SymbolicEvaluation) :
    Prop :=
  evaluation.lookup? 36 =
    some (Air.Bridge.LtReg.programLookup (row kind))

def originalAcceptance
    (kind : Kind)
    (evaluation : SymbolicEvaluation) :
    Prop :=
  withoutProgramProjection kind evaluation ∧
    architecturalProgram kind evaluation

theorem original_sound
    (kind : Kind)
    (evaluation : SymbolicEvaluation)
    (accepted : originalAcceptance kind evaluation) :
    architecturalProgram kind evaluation :=
  accepted.2

set_option maxRecDepth 50000 in
theorem wrongProgram_satisfies (kind : Kind) :
    withoutProgramProjection kind (wrongProgramEvaluation kind) := by
  have projection :=
    Air.Bridge.LtReg.lookupProjection (row kind) (witness kind)
  have accepted := Air.Bridge.LtReg.highBitAcceptance kind
  refine ⟨⟨?_, ?_, ?_⟩, ?_⟩
  · simpa [wrongProgramEvaluation] using
      Air.Bridge.LtReg.selectorAccepted (row kind) (witness kind)
  · rw [wrongProgramEvaluation, SymbolicEvaluation.constraintsHold]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.constraintsHold] using accepted.constraints
    · rfl
  · rw [wrongProgramEvaluation, SymbolicEvaluation.fixedLookupsHold]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.fixedLookupsHold] using accepted.fixedLookups
    · simp [
        wrongProgramLookup,
        Air.Bridge.LtReg.programLookup,
        EvaluatedLookup.fixedRequestHolds,
        EvaluatedLookup.fixedMembership,
      ]
  · simpa [
      wrongProgramEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
    ] using projection.2.2.1

set_option maxRecDepth 50000 in
theorem wrongProgram_refutes (kind : Kind) :
    ¬ architecturalProgram kind (wrongProgramEvaluation kind) := by
  have eventBound :
      36 <
        (Air.Bridge.LtReg.evaluation
          (row kind) (witness kind)).events.size := by
    cases kind <;>
      simp [
        Air.Bridge.LtReg.evaluation,
        Air.Bridge.LtReg.program,
        row,
        Air.Bridge.LtReg.highBitRow,
        LocalProgram.evalSymbolic,
        Air.Generated.Programs.slt,
        Air.Generated.Programs.sltSource,
        Air.Generated.Programs.sltu,
        Air.Generated.Programs.sltuSource,
      ]
  have mutatedAt :
      (wrongProgramEvaluation kind).lookup? 36 =
        some (wrongProgramLookup kind) := by
    rw [
      wrongProgramEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
      if_pos eventBound,
    ]
    rfl
  unfold architecturalProgram
  rw [mutatedAt]
  intro equality
  have lookupEquality :
      wrongProgramLookup kind =
        Air.Bridge.LtReg.programLookup (row kind) :=
    Option.some.inj equality
  have manifestEquality :=
    congrArg (fun lookup : EvaluatedLookup => lookup.tuple[1]?)
      lookupEquality
  cases kind <;>
    simp [
      wrongProgramLookup,
      siblingManifestId,
      row,
      Air.Bridge.LtReg.highBitRow,
      Air.Bridge.LtReg.programLookup,
      Air.Bridge.LtReg.manifestId,
    ] at manifestEquality
  all_goals
    have valueEquality := congrArg M31.val manifestEquality
    simp [M31.reduce_val, M31.modulus_eq] at valueEquality

def wrongProgramControl (kind : Kind) :
    MutationControl
      (withoutProgramProjection kind)
      (architecturalProgram kind) where
  name := match kind with
    | .signed => "slt-manifest-replaced-by-sltu"
    | .unsigned => "sltu-manifest-replaced-by-slt"
  witness := wrongProgramEvaluation kind
  satisfies := wrongProgram_satisfies kind
  refutes := wrongProgram_refutes kind

theorem wrongProgram_strictly_weaker (kind : Kind) :
    ¬ (∀ evaluation,
      withoutProgramProjection kind evaluation →
        originalAcceptance kind evaluation) :=
  (wrongProgramControl kind).strictly_weaker
    (originalAcceptance kind) (original_sound kind)

theorem slt_wrongManifest_satisfies :
    withoutProgramProjection .signed
      (wrongProgramEvaluation .signed) :=
  wrongProgram_satisfies .signed

theorem slt_wrongManifest_refutes :
    ¬ architecturalProgram .signed
      (wrongProgramEvaluation .signed) :=
  wrongProgram_refutes .signed

def slt_wrongManifestControl :=
  wrongProgramControl .signed

theorem slt_wrongManifest_strictly_weaker :
    ¬ (∀ evaluation,
      withoutProgramProjection .signed evaluation →
        originalAcceptance .signed evaluation) :=
  wrongProgram_strictly_weaker .signed

theorem sltu_wrongManifest_satisfies :
    withoutProgramProjection .unsigned
      (wrongProgramEvaluation .unsigned) :=
  wrongProgram_satisfies .unsigned

theorem sltu_wrongManifest_refutes :
    ¬ architecturalProgram .unsigned
      (wrongProgramEvaluation .unsigned) :=
  wrongProgram_refutes .unsigned

def sltu_wrongManifestControl :=
  wrongProgramControl .unsigned

theorem sltu_wrongManifest_strictly_weaker :
    ¬ (∀ evaluation,
      withoutProgramProjection .unsigned evaluation →
        originalAcceptance .unsigned evaluation) :=
  wrongProgram_strictly_weaker .unsigned

end Reg

namespace Imm

abbrev Kind := Air.Bridge.LtImm.Kind
private abbrev row (kind : Kind) := Air.Bridge.LtImm.highBitRow kind
private abbrev witness (kind : Kind) := Air.Bridge.LtImm.highBitWitness kind

def siblingManifestId : Kind → Nat
  | .signed => 12
  | .unsigned => 11

def wrongProgramLookup (kind : Kind) : EvaluatedLookup :=
  { Air.Bridge.LtImm.programLookup (row kind) with
    tuple := #[
      Air.Bridge.LtImm.bitVecM31 (row kind).pc,
      M31.reduce (siblingManifestId kind),
      Air.Bridge.LtImm.bitVecM31 (row kind).rd,
      Air.Bridge.LtImm.bitVecM31 (row kind).rs1,
      Air.Bridge.LtImm.immediateField (row kind)
    ]
  }

def wrongProgramEvaluation (kind : Kind) : SymbolicEvaluation :=
  let original := Air.Bridge.LtImm.evaluation (row kind) (witness kind)
  { original with
    events :=
      original.events.setIfInBounds 33 (.lookup (wrongProgramLookup kind))
  }

def genericallyAccepted (evaluation : SymbolicEvaluation) : Prop :=
  evaluation.activeSelectorsAccepted = true ∧
    evaluation.constraintsHold = true ∧
    evaluation.fixedLookupsHold = true

def withoutProgramProjection
    (kind : Kind)
    (evaluation : SymbolicEvaluation) :
    Prop :=
  genericallyAccepted evaluation ∧
    evaluation.lookup? 36 =
      some (Air.Bridge.LtImm.stateEmitLookup (row kind))

def architecturalProgram
    (kind : Kind)
    (evaluation : SymbolicEvaluation) :
    Prop :=
  evaluation.lookup? 33 =
    some (Air.Bridge.LtImm.programLookup (row kind))

def originalAcceptance
    (kind : Kind)
    (evaluation : SymbolicEvaluation) :
    Prop :=
  withoutProgramProjection kind evaluation ∧
    architecturalProgram kind evaluation

theorem original_sound
    (kind : Kind)
    (evaluation : SymbolicEvaluation)
    (accepted : originalAcceptance kind evaluation) :
    architecturalProgram kind evaluation :=
  accepted.2

set_option maxRecDepth 50000 in
theorem wrongProgram_satisfies (kind : Kind) :
    withoutProgramProjection kind (wrongProgramEvaluation kind) := by
  have stateProjection :=
    Air.Bridge.LtImm.lookupProjection
      (row kind) (witness kind) 36 (by omega) (by omega)
  have accepted := Air.Bridge.LtImm.highBitAcceptance kind
  refine ⟨⟨?_, ?_, ?_⟩, ?_⟩
  · simpa [wrongProgramEvaluation] using
      Air.Bridge.LtImm.selectorAccepted (row kind) (witness kind)
  · rw [wrongProgramEvaluation, SymbolicEvaluation.constraintsHold]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.constraintsHold] using accepted.constraints
    · rfl
  · rw [wrongProgramEvaluation, SymbolicEvaluation.fixedLookupsHold]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.fixedLookupsHold] using accepted.fixedLookups
    · simp [
        wrongProgramLookup,
        Air.Bridge.LtImm.programLookup,
        EvaluatedLookup.fixedRequestHolds,
        EvaluatedLookup.fixedMembership,
      ]
  · simpa [
      wrongProgramEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
    ] using stateProjection

set_option maxRecDepth 50000 in
theorem wrongProgram_refutes (kind : Kind) :
    ¬ architecturalProgram kind (wrongProgramEvaluation kind) := by
  have eventBound :
      33 <
        (Air.Bridge.LtImm.evaluation
          (row kind) (witness kind)).events.size := by
    cases kind <;>
      simp [
        Air.Bridge.LtImm.evaluation,
        Air.Bridge.LtImm.program,
        row,
        Air.Bridge.LtImm.highBitRow,
        LocalProgram.evalSymbolic,
        Air.Generated.Programs.slti,
        Air.Generated.Programs.sltiSource,
        Air.Generated.Programs.sltiu,
        Air.Generated.Programs.sltiuSource,
      ]
  have mutatedAt :
      (wrongProgramEvaluation kind).lookup? 33 =
        some (wrongProgramLookup kind) := by
    rw [
      wrongProgramEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
      if_pos eventBound,
    ]
    rfl
  unfold architecturalProgram
  rw [mutatedAt]
  intro equality
  have lookupEquality :
      wrongProgramLookup kind =
        Air.Bridge.LtImm.programLookup (row kind) :=
    Option.some.inj equality
  have manifestEquality :=
    congrArg (fun lookup : EvaluatedLookup => lookup.tuple[1]?)
      lookupEquality
  cases kind <;>
    simp [
      wrongProgramLookup,
      siblingManifestId,
      row,
      Air.Bridge.LtImm.highBitRow,
      Air.Bridge.LtImm.programLookup,
      Air.Bridge.LtImm.manifestId,
    ] at manifestEquality
  all_goals
    have valueEquality := congrArg M31.val manifestEquality
    simp [M31.reduce_val, M31.modulus_eq] at valueEquality

def wrongProgramControl (kind : Kind) :
    MutationControl
      (withoutProgramProjection kind)
      (architecturalProgram kind) where
  name := match kind with
    | .signed => "slti-manifest-replaced-by-sltiu"
    | .unsigned => "sltiu-manifest-replaced-by-slti"
  witness := wrongProgramEvaluation kind
  satisfies := wrongProgram_satisfies kind
  refutes := wrongProgram_refutes kind

theorem wrongProgram_strictly_weaker (kind : Kind) :
    ¬ (∀ evaluation,
      withoutProgramProjection kind evaluation →
        originalAcceptance kind evaluation) :=
  (wrongProgramControl kind).strictly_weaker
    (originalAcceptance kind) (original_sound kind)

theorem slti_wrongManifest_satisfies :
    withoutProgramProjection .signed
      (wrongProgramEvaluation .signed) :=
  wrongProgram_satisfies .signed

theorem slti_wrongManifest_refutes :
    ¬ architecturalProgram .signed
      (wrongProgramEvaluation .signed) :=
  wrongProgram_refutes .signed

def slti_wrongManifestControl :=
  wrongProgramControl .signed

theorem slti_wrongManifest_strictly_weaker :
    ¬ (∀ evaluation,
      withoutProgramProjection .signed evaluation →
        originalAcceptance .signed evaluation) :=
  wrongProgram_strictly_weaker .signed

theorem sltiu_wrongManifest_satisfies :
    withoutProgramProjection .unsigned
      (wrongProgramEvaluation .unsigned) :=
  wrongProgram_satisfies .unsigned

theorem sltiu_wrongManifest_refutes :
    ¬ architecturalProgram .unsigned
      (wrongProgramEvaluation .unsigned) :=
  wrongProgram_refutes .unsigned

def sltiu_wrongManifestControl :=
  wrongProgramControl .unsigned

theorem sltiu_wrongManifest_strictly_weaker :
    ¬ (∀ evaluation,
      withoutProgramProjection .unsigned evaluation →
        originalAcceptance .unsigned evaluation) :=
  wrongProgram_strictly_weaker .unsigned

end Imm

end RiscvRefinement.Opcodes.LtMutation
