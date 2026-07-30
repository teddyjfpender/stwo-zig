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

/-!
The selector-specific controls below instantiate the same post-evaluation
attack for every branch program.  Each witness is a taken canonical row for
that exact selector, and each mutation replaces only its projected state emit.
-/

private abbrev eqRow (kind : Air.Bridge.Branches.Eq.Kind) :=
  Air.Bridge.Branches.Eq.exampleRow kind true

private abbrev eqWitness (kind : Air.Bridge.Branches.Eq.Kind) :=
  Air.Bridge.Branches.Eq.exampleWitness kind true

def eqWrongStateEmitLookup
    (kind : Air.Bridge.Branches.Eq.Kind) : EvaluatedLookup where
  ordinal := 26
  domain := .registersState
  numerator := 1
  tuple := #[
    Air.Bridge.Branches.bitVecM31
      (RiscvRefinement.nextPc (eqRow kind).pc),
    M31.reduce (eqRow kind).clock + 1
  ]
  role := .emit
  tableId := none
  accessOrdinal := none

def eqWrongStateEmitEvaluation
    (kind : Air.Bridge.Branches.Eq.Kind) : SymbolicEvaluation :=
  let original :=
    Air.Bridge.Branches.Eq.evaluation (eqRow kind) (eqWitness kind)
  { original with
    events :=
      original.events.setIfInBounds 26
        (.lookup (eqWrongStateEmitLookup kind))
  }

def eqWithoutStateEmitProjection
    (kind : Air.Bridge.Branches.Eq.Kind)
    (evaluation : SymbolicEvaluation) : Prop :=
  genericallyAccepted evaluation ∧
    evaluation.lookup? 18 =
      some (Air.Bridge.Branches.Eq.programLookup (eqRow kind)) ∧
    evaluation.lookup? 25 =
      some (Air.Bridge.Branches.Eq.stateConsumeLookup (eqRow kind))

def eqArchitecturalNextPc
    (kind : Air.Bridge.Branches.Eq.Kind)
    (evaluation : SymbolicEvaluation) : Prop :=
  (evaluation.lookup? 26).bind (fun lookup => lookup.tuple[0]?) =
    some
      (Air.Bridge.Branches.bitVecM31
        (Air.Bridge.Branches.selectedPc
          (eqRow kind).pc (eqRow kind).immediateEncoded
          (Air.Bridge.Branches.Eq.taken (eqRow kind))))

def eqOriginalAcceptance
    (kind : Air.Bridge.Branches.Eq.Kind)
    (evaluation : SymbolicEvaluation) : Prop :=
  eqWithoutStateEmitProjection kind evaluation ∧
    evaluation.lookup? 26 =
      some (Air.Bridge.Branches.Eq.stateEmitLookup (eqRow kind))

theorem eqOriginal_sound
    (kind : Air.Bridge.Branches.Eq.Kind)
    (evaluation : SymbolicEvaluation)
    (accepted : eqOriginalAcceptance kind evaluation) :
    eqArchitecturalNextPc kind evaluation := by
  unfold eqArchitecturalNextPc
  rw [accepted.2]
  simp [
    Air.Bridge.Branches.Eq.stateEmitLookup,
    Air.Bridge.Branches.selectedPcField
      (eqRow kind).clock
      (eqRow kind).rs1PreviousClock
      (eqRow kind).rs2PreviousClock
      (eqRow kind).pc
      (eqRow kind).immediateEncoded
      (Air.Bridge.Branches.Eq.taken (eqRow kind))
      (Air.Bridge.Branches.Eq.exampleAdmission kind true),
  ]

set_option maxRecDepth 30000 in
theorem eqWrongStateEmit_satisfies
    (kind : Air.Bridge.Branches.Eq.Kind) :
    eqWithoutStateEmitProjection kind
      (eqWrongStateEmitEvaluation kind) := by
  have projection :=
    Air.Bridge.Branches.Eq.lookupProjection (eqRow kind) (eqWitness kind)
  have accepted :=
    Air.Bridge.Branches.Eq.exampleAcceptance kind true
  refine ⟨⟨?_, ?_, ?_⟩, ?_, ?_⟩
  · simpa [eqWrongStateEmitEvaluation] using
      Air.Bridge.Branches.Eq.selectorAccepted
        (eqRow kind) (eqWitness kind)
  · rw [
      eqWrongStateEmitEvaluation,
      SymbolicEvaluation.constraintsHold,
    ]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.constraintsHold] using accepted.constraints
    · rfl
  · rw [
      eqWrongStateEmitEvaluation,
      SymbolicEvaluation.fixedLookupsHold,
    ]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.fixedLookupsHold] using
        accepted.fixedLookups
    · simp [
        eqWrongStateEmitLookup,
        EvaluatedLookup.fixedRequestHolds,
        EvaluatedLookup.fixedMembership,
      ]
  · simpa [
      eqWrongStateEmitEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
    ] using projection.1
  · simpa [
      eqWrongStateEmitEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
    ] using projection.2.2.2.2.2.2.2.1

set_option maxRecDepth 30000 in
theorem eqWrongStateEmit_refutes
    (kind : Air.Bridge.Branches.Eq.Kind) :
    ¬ eqArchitecturalNextPc kind
      (eqWrongStateEmitEvaluation kind) := by
  unfold eqArchitecturalNextPc
  have eventBound :
      26 <
        (Air.Bridge.Branches.Eq.evaluation
          (eqRow kind) (eqWitness kind)).events.size := by
    cases kind <;>
      simp [
        Air.Bridge.Branches.Eq.evaluation,
        Air.Bridge.Branches.Eq.Kind.program,
        eqRow,
        eqWitness,
        Air.Bridge.Branches.Eq.exampleRow,
        Air.Bridge.Branches.Eq.exampleWitness,
        LocalProgram.evalSymbolic,
        Air.Generated.Programs.beq,
        Air.Generated.Programs.beqSource,
        Air.Generated.Programs.bne,
        Air.Generated.Programs.bneSource,
      ]
  have mutatedAt :
      (eqWrongStateEmitEvaluation kind).lookup? 26 =
        some (eqWrongStateEmitLookup kind) := by
    rw [
      eqWrongStateEmitEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
      if_pos eventBound,
    ]
    rfl
  rw [mutatedAt]
  intro equality
  have fieldEquality :
      Air.Bridge.Branches.bitVecM31
          (RiscvRefinement.nextPc (eqRow kind).pc) =
        Air.Bridge.Branches.bitVecM31
          (Air.Bridge.Branches.selectedPc
            (eqRow kind).pc (eqRow kind).immediateEncoded
            (Air.Bridge.Branches.Eq.taken (eqRow kind))) := by
    simpa [eqWrongStateEmitLookup] using equality
  rw [Air.Bridge.Branches.Eq.exampleTaken kind true] at fieldEquality
  have values := congrArg M31.val fieldEquality
  simp [
    eqRow,
    Air.Bridge.Branches.Eq.exampleRow,
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

def eqWrongStateEmitControl
    (kind : Air.Bridge.Branches.Eq.Kind) :
    MutationControl
      (eqWithoutStateEmitProjection kind)
      (eqArchitecturalNextPc kind) where
  name := match kind with
    | .beq => "beq-state-projection-load-bearing"
    | .bne => "bne-state-projection-load-bearing"
  witness := eqWrongStateEmitEvaluation kind
  satisfies := eqWrongStateEmit_satisfies kind
  refutes := eqWrongStateEmit_refutes kind

def beqStateProjectionMutation :=
  eqWrongStateEmitControl Air.Bridge.Branches.Eq.Kind.beq

def bneStateProjectionMutation :=
  eqWrongStateEmitControl Air.Bridge.Branches.Eq.Kind.bne

private abbrev ltRow (kind : Air.Bridge.Branches.Lt.Kind) :=
  Air.Bridge.Branches.Lt.exampleRow kind true

private abbrev ltWitness (kind : Air.Bridge.Branches.Lt.Kind) :=
  Air.Bridge.Branches.Lt.exampleWitness kind true

def ltWrongStateEmitLookup
    (kind : Air.Bridge.Branches.Lt.Kind) : EvaluatedLookup where
  ordinal := 35
  domain := .registersState
  numerator := 1
  tuple := #[
    Air.Bridge.Branches.bitVecM31
      (RiscvRefinement.nextPc (ltRow kind).pc),
    M31.reduce (ltRow kind).clock + 1
  ]
  role := .emit
  tableId := none
  accessOrdinal := none

def ltWrongStateEmitEvaluation
    (kind : Air.Bridge.Branches.Lt.Kind) : SymbolicEvaluation :=
  let original :=
    Air.Bridge.Branches.Lt.evaluation (ltRow kind) (ltWitness kind)
  { original with
    events :=
      original.events.setIfInBounds 35
        (.lookup (ltWrongStateEmitLookup kind))
  }

def ltWithoutStateEmitProjection
    (kind : Air.Bridge.Branches.Lt.Kind)
    (evaluation : SymbolicEvaluation) : Prop :=
  genericallyAccepted evaluation ∧
    evaluation.lookup? 33 =
      some (Air.Bridge.Branches.Lt.programLookup (ltRow kind)) ∧
    evaluation.lookup? 34 =
      some (Air.Bridge.Branches.Lt.stateConsumeLookup (ltRow kind))

def ltArchitecturalNextPc
    (kind : Air.Bridge.Branches.Lt.Kind)
    (evaluation : SymbolicEvaluation) : Prop :=
  (evaluation.lookup? 35).bind (fun lookup => lookup.tuple[0]?) =
    some
      (Air.Bridge.Branches.bitVecM31
        (Air.Bridge.Branches.selectedPc
          (ltRow kind).pc (ltRow kind).immediateEncoded
          (Air.Bridge.Branches.Lt.taken (ltRow kind))))

def ltOriginalAcceptance
    (kind : Air.Bridge.Branches.Lt.Kind)
    (evaluation : SymbolicEvaluation) : Prop :=
  ltWithoutStateEmitProjection kind evaluation ∧
    evaluation.lookup? 35 =
      some (Air.Bridge.Branches.Lt.stateEmitLookup (ltRow kind))

theorem ltOriginal_sound
    (kind : Air.Bridge.Branches.Lt.Kind)
    (evaluation : SymbolicEvaluation)
    (accepted : ltOriginalAcceptance kind evaluation) :
    ltArchitecturalNextPc kind evaluation := by
  unfold ltArchitecturalNextPc
  rw [accepted.2]
  simp [Air.Bridge.Branches.Lt.stateEmitLookup]

set_option maxRecDepth 40000 in
theorem ltWrongStateEmit_satisfies
    (kind : Air.Bridge.Branches.Lt.Kind) :
    ltWithoutStateEmitProjection kind
      (ltWrongStateEmitEvaluation kind) := by
  have projection :=
    Air.Bridge.Branches.Lt.lookupProjection (ltRow kind) (ltWitness kind)
  have accepted :=
    Air.Bridge.Branches.Lt.exampleAcceptance kind true
  refine ⟨⟨?_, ?_, ?_⟩, ?_, ?_⟩
  · simpa [ltWrongStateEmitEvaluation] using
      Air.Bridge.Branches.Lt.selectorAccepted
        (ltRow kind) (ltWitness kind)
  · rw [
      ltWrongStateEmitEvaluation,
      SymbolicEvaluation.constraintsHold,
    ]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.constraintsHold] using accepted.constraints
    · rfl
  · rw [
      ltWrongStateEmitEvaluation,
      SymbolicEvaluation.fixedLookupsHold,
    ]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.fixedLookupsHold] using
        accepted.fixedLookups
    · simp [
        ltWrongStateEmitLookup,
        EvaluatedLookup.fixedRequestHolds,
        EvaluatedLookup.fixedMembership,
      ]
  · simpa [
      ltWrongStateEmitEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
    ] using projection.1
  · simpa [
      ltWrongStateEmitEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
    ] using projection.2.1

set_option maxRecDepth 40000 in
theorem ltWrongStateEmit_refutes
    (kind : Air.Bridge.Branches.Lt.Kind) :
    ¬ ltArchitecturalNextPc kind
      (ltWrongStateEmitEvaluation kind) := by
  unfold ltArchitecturalNextPc
  have eventBound :
      35 <
        (Air.Bridge.Branches.Lt.evaluation
          (ltRow kind) (ltWitness kind)).events.size := by
    cases kind <;>
      simp [
        Air.Bridge.Branches.Lt.evaluation,
        Air.Bridge.Branches.Lt.Kind.program,
        ltRow,
        ltWitness,
        Air.Bridge.Branches.Lt.exampleRow,
        Air.Bridge.Branches.Lt.exampleWitness,
        LocalProgram.evalSymbolic,
        Air.Generated.Programs.blt,
        Air.Generated.Programs.bltSource,
        Air.Generated.Programs.bge,
        Air.Generated.Programs.bgeSource,
        Air.Generated.Programs.bltu,
        Air.Generated.Programs.bltuSource,
        Air.Generated.Programs.bgeu,
        Air.Generated.Programs.bgeuSource,
      ]
  have mutatedAt :
      (ltWrongStateEmitEvaluation kind).lookup? 35 =
        some (ltWrongStateEmitLookup kind) := by
    rw [
      ltWrongStateEmitEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
      if_pos eventBound,
    ]
    rfl
  rw [mutatedAt]
  intro equality
  have fieldEquality :
      Air.Bridge.Branches.bitVecM31
          (RiscvRefinement.nextPc (ltRow kind).pc) =
        Air.Bridge.Branches.bitVecM31
          (Air.Bridge.Branches.selectedPc
            (ltRow kind).pc (ltRow kind).immediateEncoded
            (Air.Bridge.Branches.Lt.taken (ltRow kind))) := by
    simpa [ltWrongStateEmitLookup] using equality
  rw [Air.Bridge.Branches.Lt.exampleTaken kind true] at fieldEquality
  have values := congrArg M31.val fieldEquality
  simp [
    ltRow,
    Air.Bridge.Branches.Lt.exampleRow,
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

def ltWrongStateEmitControl
    (kind : Air.Bridge.Branches.Lt.Kind) :
    MutationControl
      (ltWithoutStateEmitProjection kind)
      (ltArchitecturalNextPc kind) where
  name := match kind with
    | .blt => "blt-state-projection-load-bearing"
    | .bge => "bge-state-projection-load-bearing"
    | .bltu => "bltu-state-projection-load-bearing"
    | .bgeu => "bgeu-state-projection-load-bearing"
  witness := ltWrongStateEmitEvaluation kind
  satisfies := ltWrongStateEmit_satisfies kind
  refutes := ltWrongStateEmit_refutes kind

def bltStateProjectionMutation :=
  ltWrongStateEmitControl Air.Bridge.Branches.Lt.Kind.blt

def bgeStateProjectionMutation :=
  ltWrongStateEmitControl Air.Bridge.Branches.Lt.Kind.bge

def bltuStateProjectionMutation :=
  ltWrongStateEmitControl Air.Bridge.Branches.Lt.Kind.bltu

def bgeuStateProjectionMutation :=
  ltWrongStateEmitControl Air.Bridge.Branches.Lt.Kind.bgeu

theorem beqStateProjection_mutation_theorem :
    ¬ (∀ evaluation,
      eqWithoutStateEmitProjection
          Air.Bridge.Branches.Eq.Kind.beq evaluation →
        eqOriginalAcceptance
          Air.Bridge.Branches.Eq.Kind.beq evaluation) :=
  beqStateProjectionMutation.strictly_weaker
    (eqOriginalAcceptance Air.Bridge.Branches.Eq.Kind.beq)
    (eqOriginal_sound Air.Bridge.Branches.Eq.Kind.beq)

theorem bneStateProjection_mutation_theorem :
    ¬ (∀ evaluation,
      eqWithoutStateEmitProjection
          Air.Bridge.Branches.Eq.Kind.bne evaluation →
        eqOriginalAcceptance
          Air.Bridge.Branches.Eq.Kind.bne evaluation) :=
  bneStateProjectionMutation.strictly_weaker
    (eqOriginalAcceptance Air.Bridge.Branches.Eq.Kind.bne)
    (eqOriginal_sound Air.Bridge.Branches.Eq.Kind.bne)

theorem bltStateProjection_mutation_theorem :
    ¬ (∀ evaluation,
      ltWithoutStateEmitProjection
          Air.Bridge.Branches.Lt.Kind.blt evaluation →
        ltOriginalAcceptance
          Air.Bridge.Branches.Lt.Kind.blt evaluation) :=
  bltStateProjectionMutation.strictly_weaker
    (ltOriginalAcceptance Air.Bridge.Branches.Lt.Kind.blt)
    (ltOriginal_sound Air.Bridge.Branches.Lt.Kind.blt)

theorem bgeStateProjection_mutation_theorem :
    ¬ (∀ evaluation,
      ltWithoutStateEmitProjection
          Air.Bridge.Branches.Lt.Kind.bge evaluation →
        ltOriginalAcceptance
          Air.Bridge.Branches.Lt.Kind.bge evaluation) :=
  bgeStateProjectionMutation.strictly_weaker
    (ltOriginalAcceptance Air.Bridge.Branches.Lt.Kind.bge)
    (ltOriginal_sound Air.Bridge.Branches.Lt.Kind.bge)

theorem bltuStateProjection_mutation_theorem :
    ¬ (∀ evaluation,
      ltWithoutStateEmitProjection
          Air.Bridge.Branches.Lt.Kind.bltu evaluation →
        ltOriginalAcceptance
          Air.Bridge.Branches.Lt.Kind.bltu evaluation) :=
  bltuStateProjectionMutation.strictly_weaker
    (ltOriginalAcceptance Air.Bridge.Branches.Lt.Kind.bltu)
    (ltOriginal_sound Air.Bridge.Branches.Lt.Kind.bltu)

theorem bgeuStateProjection_mutation_theorem :
    ¬ (∀ evaluation,
      ltWithoutStateEmitProjection
          Air.Bridge.Branches.Lt.Kind.bgeu evaluation →
        ltOriginalAcceptance
          Air.Bridge.Branches.Lt.Kind.bgeu evaluation) :=
  bgeuStateProjectionMutation.strictly_weaker
    (ltOriginalAcceptance Air.Bridge.Branches.Lt.Kind.bgeu)
    (ltOriginal_sound Air.Bridge.Branches.Lt.Kind.bgeu)

end RiscvRefinement.Opcodes.BranchesMutation
