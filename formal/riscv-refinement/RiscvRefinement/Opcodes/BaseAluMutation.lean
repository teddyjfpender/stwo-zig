import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.BaseAluImm
import RiscvRefinement.Opcodes.BaseAluReg

/-!
# Base-ALU state-emission mutation controls

For every base-ALU selector, replace only the generated registers-state
emission with `pc + 8`.  Selector, constraint, fixed-table, program, and state
consume checks remain accepted, while the architectural `pc + 4` contract is
false.  Thus the exact state-emission projection is load-bearing for each of
the eight selectors.
-/

namespace RiscvRefinement.Opcodes.BaseAluMutation

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

private theorem plusEight_ne_nextPc
    (pc : Word)
    (bound : pc.toNat + 4 < M31.modulus)
    (eightBound : pc.toNat + 8 < M31.modulus) :
    Air.Bridge.TeamACommon.bitVecM31 pc + M31.reduce 8 ≠
      Air.Bridge.TeamACommon.bitVecM31 (RiscvRefinement.nextPc pc) := by
  rw [← Air.Bridge.TeamACommon.nextPcField pc bound]
  intro equality
  have pcBound : pc.toNat < M31.modulus := by omega
  have leftBound :
      (Air.Bridge.TeamACommon.bitVecM31 pc).val +
          (M31.reduce 8).val < M31.modulus := by
    rw [
      Air.Bridge.Lui.bitVecM31_val _ pcBound,
      M31.reduce_val_of_lt 8 (by decide),
    ]
    exact eightBound
  have rightBound :
      (Air.Bridge.TeamACommon.bitVecM31 pc).val +
          (M31.reduce 4).val < M31.modulus := by
    rw [
      Air.Bridge.Lui.bitVecM31_val _ pcBound,
      M31.reduce_val_of_lt 4 (by decide),
    ]
    exact bound
  have values := congrArg M31.val equality
  rw [
    M31.add_val_of_lt _ _ leftBound,
    M31.add_val_of_lt _ _ rightBound,
    Air.Bridge.Lui.bitVecM31_val _ pcBound,
    M31.reduce_val_of_lt 8 (by decide),
    M31.reduce_val_of_lt 4 (by decide),
  ] at values
  omega

namespace Imm

abbrev Op := Decode.BaseAluImmOp

private abbrev row :=
  Air.Bridge.BaseAluImm.zeroRow false (BitVec.ofNat 5 2)

private abbrev witness :=
  Air.Bridge.BaseAluImm.zeroWitness false (BitVec.ofNat 5 2)

def wrongStateEmitLookup : EvaluatedLookup where
  ordinal := 25
  domain := .registersState
  numerator := 1
  tuple := #[
    Air.Bridge.BaseAluImm.bitVecM31 row.pc + M31.reduce 8,
    M31.reduce row.clock + 1
  ]
  role := .emit
  tableId := none
  accessOrdinal := none

def wrongEvaluation (op : Op) : SymbolicEvaluation :=
  let original := Air.Bridge.BaseAluImm.evaluation op row witness
  { original with
    events :=
      original.events.setIfInBounds 25 (.lookup wrongStateEmitLookup)
  }

def genericallyAccepted (evaluation : SymbolicEvaluation) : Prop :=
  evaluation.activeSelectorsAccepted = true ∧
    evaluation.constraintsHold = true ∧
    evaluation.fixedLookupsHold = true

def withoutStateEmitProjection
    (op : Op)
    (evaluation : SymbolicEvaluation) : Prop :=
  genericallyAccepted evaluation ∧
    evaluation.lookup? 22 =
      some (Air.Bridge.BaseAluImm.programLookup op row) ∧
    evaluation.lookup? 24 =
      some (Air.Bridge.BaseAluImm.stateConsumeLookup row)

def architecturalNextPc (evaluation : SymbolicEvaluation) : Prop :=
  (evaluation.lookup? 25).bind (fun lookup => lookup.tuple[0]?) =
    some
      (Air.Bridge.BaseAluImm.bitVecM31
        (RiscvRefinement.nextPc row.pc))

def originalAcceptance
    (op : Op)
    (evaluation : SymbolicEvaluation) : Prop :=
  withoutStateEmitProjection op evaluation ∧
    evaluation.lookup? 25 =
      some (Air.Bridge.BaseAluImm.stateEmitLookup row)

theorem original_sound
    (op : Op)
    (evaluation : SymbolicEvaluation)
    (accepted : originalAcceptance op evaluation) :
    architecturalNextPc evaluation := by
  unfold architecturalNextPc
  rw [accepted.2]
  simp [
    Air.Bridge.BaseAluImm.stateEmitLookup,
    Air.Bridge.TeamACommon.nextPcField
      row.pc
      (Air.Bridge.BaseAluImm.zeroAdmission
        false (BitVec.ofNat 5 2)).pcBound,
  ]

set_option maxRecDepth 30000 in
theorem wrongStateEmit_satisfies (op : Op) :
    withoutStateEmitProjection op (wrongEvaluation op) := by
  have projection :=
    Air.Bridge.BaseAluImm.lookupProjection op row witness
  have accepted :=
    Air.Bridge.BaseAluImm.zeroAcceptance
      op false (BitVec.ofNat 5 2)
  refine ⟨⟨?_, ?_, ?_⟩, ?_, ?_⟩
  · simpa [wrongEvaluation] using accepted.selectors
  · rw [wrongEvaluation, SymbolicEvaluation.constraintsHold]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.constraintsHold] using accepted.constraints
    · rfl
  · rw [wrongEvaluation, SymbolicEvaluation.fixedLookupsHold]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.fixedLookupsHold] using accepted.fixedLookups
    · simp [
        wrongStateEmitLookup,
        EvaluatedLookup.fixedRequestHolds,
        EvaluatedLookup.fixedMembership,
      ]
  · simpa [
      wrongEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
    ] using projection.1
  · simpa [
      wrongEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
    ] using projection.2.2.1

set_option maxRecDepth 30000 in
theorem wrongStateEmit_refutes (op : Op) :
    ¬ architecturalNextPc (wrongEvaluation op) := by
  unfold architecturalNextPc
  have eventBound :
      25 <
        (Air.Bridge.BaseAluImm.evaluation op row witness).events.size := by
    cases op <;>
      simp [
        Air.Bridge.BaseAluImm.evaluation,
        Air.Bridge.BaseAluImm.program,
        LocalProgram.evalSymbolic,
        Air.Generated.Programs.xori,
        Air.Generated.Programs.xoriSource,
        Air.Generated.Programs.ori,
        Air.Generated.Programs.oriSource,
        Air.Generated.Programs.andi,
        Air.Generated.Programs.andiSource,
      ]
  have mutatedAt :
      (wrongEvaluation op).lookup? 25 = some wrongStateEmitLookup := by
    rw [
      wrongEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
      if_pos eventBound,
    ]
    rfl
  rw [mutatedAt]
  intro equality
  have fieldEquality :
      Air.Bridge.TeamACommon.bitVecM31 row.pc + M31.reduce 8 =
        Air.Bridge.TeamACommon.bitVecM31
          (RiscvRefinement.nextPc row.pc) := by
    simpa [
      wrongStateEmitLookup,
      Air.Bridge.BaseAluImm.bitVecM31,
    ] using equality
  exact
    plusEight_ne_nextPc row.pc
      (Air.Bridge.BaseAluImm.zeroAdmission
        false (BitVec.ofNat 5 2)).pcBound
      (by decide) fieldEquality

def wrongStateEmitControl (op : Op) :
    MutationControl
      (withoutStateEmitProjection op)
      architecturalNextPc where
  name := s!"{repr op}-wrong-next-pc-state-emit"
  witness := wrongEvaluation op
  satisfies := wrongStateEmit_satisfies op
  refutes := wrongStateEmit_refutes op

theorem mutationCertificate (op : Op) :
    withoutStateEmitProjection op (wrongEvaluation op) ∧
      ¬ architecturalNextPc (wrongEvaluation op) :=
  ⟨wrongStateEmit_satisfies op, wrongStateEmit_refutes op⟩

theorem xori_mutation :
    withoutStateEmitProjection .xori (wrongEvaluation .xori) ∧
      ¬ architecturalNextPc (wrongEvaluation .xori) :=
  mutationCertificate .xori

theorem ori_mutation :
    withoutStateEmitProjection .ori (wrongEvaluation .ori) ∧
      ¬ architecturalNextPc (wrongEvaluation .ori) :=
  mutationCertificate .ori

theorem andi_mutation :
    withoutStateEmitProjection .andi (wrongEvaluation .andi) ∧
      ¬ architecturalNextPc (wrongEvaluation .andi) :=
  mutationCertificate .andi

end Imm

namespace Reg

abbrev Op := Decode.BaseAluRegOp

private abbrev row :=
  Air.Bridge.BaseAluReg.zeroRow
    false (BitVec.ofNat 5 2) (BitVec.ofNat 5 3)

private abbrev witness :=
  Air.Bridge.BaseAluReg.zeroWitness
    false (BitVec.ofNat 5 2) (BitVec.ofNat 5 3)

def wrongStateEmitLookup : EvaluatedLookup where
  ordinal := 32
  domain := .registersState
  numerator := 1
  tuple := #[
    Air.Bridge.BaseAluReg.bitVecM31 row.pc + M31.reduce 8,
    M31.reduce row.clock + 1
  ]
  role := .emit
  tableId := none
  accessOrdinal := none

def wrongEvaluation (op : Op) : SymbolicEvaluation :=
  let original := Air.Bridge.BaseAluReg.evaluation op row witness
  { original with
    events :=
      original.events.setIfInBounds 32 (.lookup wrongStateEmitLookup)
  }

def genericallyAccepted (evaluation : SymbolicEvaluation) : Prop :=
  evaluation.activeSelectorsAccepted = true ∧
    evaluation.constraintsHold = true ∧
    evaluation.fixedLookupsHold = true

def withoutStateEmitProjection
    (op : Op)
    (evaluation : SymbolicEvaluation) : Prop :=
  genericallyAccepted evaluation ∧
    evaluation.lookup? 30 =
      some (Air.Bridge.BaseAluReg.programLookup op row) ∧
    evaluation.lookup? 31 =
      some (Air.Bridge.BaseAluReg.stateConsumeLookup row)

def architecturalNextPc (evaluation : SymbolicEvaluation) : Prop :=
  (evaluation.lookup? 32).bind (fun lookup => lookup.tuple[0]?) =
    some
      (Air.Bridge.BaseAluReg.bitVecM31
        (RiscvRefinement.nextPc row.pc))

def originalAcceptance
    (op : Op)
    (evaluation : SymbolicEvaluation) : Prop :=
  withoutStateEmitProjection op evaluation ∧
    evaluation.lookup? 32 =
      some (Air.Bridge.BaseAluReg.stateEmitLookup row)

theorem original_sound
    (op : Op)
    (evaluation : SymbolicEvaluation)
    (accepted : originalAcceptance op evaluation) :
    architecturalNextPc evaluation := by
  unfold architecturalNextPc
  rw [accepted.2]
  simp [
    Air.Bridge.BaseAluReg.stateEmitLookup,
    Air.Bridge.TeamACommon.nextPcField
      row.pc
      (Air.Bridge.BaseAluReg.zeroAdmission
        false (BitVec.ofNat 5 2) (BitVec.ofNat 5 3)).pcBound,
  ]

set_option maxRecDepth 30000 in
theorem wrongStateEmit_satisfies (op : Op) :
    withoutStateEmitProjection op (wrongEvaluation op) := by
  have projection :=
    Air.Bridge.BaseAluReg.lookupProjection op row witness
  have accepted :=
    Air.Bridge.BaseAluReg.zeroAcceptance
      op false (BitVec.ofNat 5 2) (BitVec.ofNat 5 3)
  refine ⟨⟨?_, ?_, ?_⟩, ?_, ?_⟩
  · simpa [wrongEvaluation] using accepted.selectors
  · rw [wrongEvaluation, SymbolicEvaluation.constraintsHold]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.constraintsHold] using accepted.constraints
    · rfl
  · rw [wrongEvaluation, SymbolicEvaluation.fixedLookupsHold]
    apply all_setIfInBounds_of_all
    · simpa [SymbolicEvaluation.fixedLookupsHold] using accepted.fixedLookups
    · simp [
        wrongStateEmitLookup,
        EvaluatedLookup.fixedRequestHolds,
        EvaluatedLookup.fixedMembership,
      ]
  · simpa [
      wrongEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
    ] using projection.1
  · simpa [
      wrongEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
    ] using projection.2.1

set_option maxRecDepth 30000 in
theorem wrongStateEmit_refutes (op : Op) :
    ¬ architecturalNextPc (wrongEvaluation op) := by
  unfold architecturalNextPc
  have eventBound :
      32 <
        (Air.Bridge.BaseAluReg.evaluation op row witness).events.size := by
    cases op <;>
      simp [
        Air.Bridge.BaseAluReg.evaluation,
        Air.Bridge.BaseAluReg.program,
        LocalProgram.evalSymbolic,
        Air.Generated.Programs.add,
        Air.Generated.Programs.addSource,
        Air.Generated.Programs.sub,
        Air.Generated.Programs.subSource,
        Air.Generated.Programs.xor,
        Air.Generated.Programs.xorSource,
        Air.Generated.Programs.or,
        Air.Generated.Programs.orSource,
        Air.Generated.Programs.and,
        Air.Generated.Programs.andSource,
      ]
  have mutatedAt :
      (wrongEvaluation op).lookup? 32 = some wrongStateEmitLookup := by
    rw [
      wrongEvaluation,
      SymbolicEvaluation.lookup?,
      Array.getElem?_setIfInBounds,
      if_pos eventBound,
    ]
    rfl
  rw [mutatedAt]
  intro equality
  have fieldEquality :
      Air.Bridge.TeamACommon.bitVecM31 row.pc + M31.reduce 8 =
        Air.Bridge.TeamACommon.bitVecM31
          (RiscvRefinement.nextPc row.pc) := by
    simpa [
      wrongStateEmitLookup,
      Air.Bridge.BaseAluReg.bitVecM31,
    ] using equality
  exact
    plusEight_ne_nextPc row.pc
      (Air.Bridge.BaseAluReg.zeroAdmission
        false (BitVec.ofNat 5 2) (BitVec.ofNat 5 3)).pcBound
      (by decide) fieldEquality

def wrongStateEmitControl (op : Op) :
    MutationControl
      (withoutStateEmitProjection op)
      architecturalNextPc where
  name := s!"{repr op}-wrong-next-pc-state-emit"
  witness := wrongEvaluation op
  satisfies := wrongStateEmit_satisfies op
  refutes := wrongStateEmit_refutes op

theorem mutationCertificate (op : Op) :
    withoutStateEmitProjection op (wrongEvaluation op) ∧
      ¬ architecturalNextPc (wrongEvaluation op) :=
  ⟨wrongStateEmit_satisfies op, wrongStateEmit_refutes op⟩

theorem add_mutation :
    withoutStateEmitProjection .add (wrongEvaluation .add) ∧
      ¬ architecturalNextPc (wrongEvaluation .add) :=
  mutationCertificate .add

theorem sub_mutation :
    withoutStateEmitProjection .sub (wrongEvaluation .sub) ∧
      ¬ architecturalNextPc (wrongEvaluation .sub) :=
  mutationCertificate .sub

theorem xor_mutation :
    withoutStateEmitProjection .xor (wrongEvaluation .xor) ∧
      ¬ architecturalNextPc (wrongEvaluation .xor) :=
  mutationCertificate .xor

theorem or_mutation :
    withoutStateEmitProjection .or (wrongEvaluation .or) ∧
      ¬ architecturalNextPc (wrongEvaluation .or) :=
  mutationCertificate .or

theorem and_mutation :
    withoutStateEmitProjection .and (wrongEvaluation .and) ∧
      ¬ architecturalNextPc (wrongEvaluation .and) :=
  mutationCertificate .and

end Reg

end RiscvRefinement.Opcodes.BaseAluMutation
