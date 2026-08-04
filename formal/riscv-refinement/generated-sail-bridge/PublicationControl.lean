import ExecutionControlJump
import ExecutionControlBranches
import RiscvRefinement.Publication.TeamA.Branches
import RiscvRefinement.Publication.TeamA.Control

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 100_000
set_option linter.unusedVariables false

open Sail

namespace LeanRV32IM.Publication

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Generated

namespace EqBranch

abbrev Kind := Air.Bridge.Branches.Eq.Kind
abbrev Row := Air.Bridge.Branches.Eq.RawRow
abbrev Witness := Air.Bridge.Branches.Eq.RawWitness

def selector : Kind → GeneratedOpcodeSelector
  | .beq => .beq
  | .bne => .bne

def decodeKind : Kind → Decode.BranchKind
  | .beq => .beq
  | .bne => .bne

def expectedWord (kind : Kind) (row : Row) : BitVec 32 :=
  Functions.encodeBranchControl (decodeKind kind)
    row.immediateEncoded row.rs2 row.rs1

def decoded (kind : Kind) (row : Row) : instruction :=
  Functions.decodedBranchControl (decodeKind kind)
    row.immediateEncoded row.rs2 row.rs1

def StateBindings
    (kind : Kind) (row : Row)
    (initial : Functions.GeneratedState) : Prop :=
  GeneratedInstructionStateBindings row.pc (expectedWord kind row) initial ∧
    GeneratedReadPairStateBindings initial row.rs1 row.rs2
      row.rs1Previous.word row.rs2Previous.word

def ExactTuple (kind : Kind) (row : Row) : Prop :=
  (Air.Bridge.Branches.Eq.rawProgramLookup row).tuple = #[
    Air.Bridge.Branches.bitVecM31 row.pc,
    M31.reduce (selector kind).manifestId,
    Air.Bridge.Branches.bitVecM31 row.rs1,
    Air.Bridge.Branches.bitVecM31 row.rs2,
    Air.Bridge.Branches.immediateField row.immediateEncoded
  ]

def ExactExecuteClause (kind : Kind) (row : Row) : Prop :=
  Functions.execute (decoded kind row) =
    Functions.execute_BTYPE
      (Decode.branchImmediate row.immediateEncoded)
      (.Regidx row.rs2) (.Regidx row.rs1)
      (Functions.generatedBranchOp (decodeKind kind))

def NormalizedRetirement (kind : Kind) (row : Row) : Prop :=
  match kind with
  | .beq =>
      Functions.completeBaseExecution row.pc
          (Functions.execute_BTYPE
            (Decode.branchImmediate row.immediateEncoded)
            (.Regidx row.rs2) (.Regidx row.rs1) .BEQ) =
        Functions.eraseObservation
          (Functions.normalizedBranchCompletion row.pc
            (do
              let source1 ← Functions.rX_bits (.Regidx row.rs1)
              let source2 ← Functions.rX_bits (.Regidx row.rs2)
              pure (source1 == source2))
            (do
              let currentPc ← Sail.readReg Register.PC
              pure (currentPc + Functions.sign_extend (m := 32)
                (Decode.branchImmediate row.immediateEncoded))))
  | .bne =>
      Functions.completeBaseExecution row.pc
          (Functions.execute_BTYPE
            (Decode.branchImmediate row.immediateEncoded)
            (.Regidx row.rs2) (.Regidx row.rs1) .BNE) =
        Functions.eraseObservation
          (Functions.normalizedBranchCompletion row.pc
            (do
              let source1 ← Functions.rX_bits (.Regidx row.rs1)
              let source2 ← Functions.rX_bits (.Regidx row.rs2)
              pure (source1 != source2))
            (do
              let currentPc ← Sail.readReg Register.PC
              pure (currentPc + Functions.sign_extend (m := 32)
                (Decode.branchImmediate row.immediateEncoded))))

noncomputable def observedProgram (kind : Kind) (row : Row) :=
  Functions.normalizedBranchCompletion row.pc
    (match kind with
    | .beq => do
        let source1 ← Functions.rX_bits (.Regidx row.rs1)
        let source2 ← Functions.rX_bits (.Regidx row.rs2)
        pure (source1 == source2)
    | .bne => do
        let source1 ← Functions.rX_bits (.Regidx row.rs1)
        let source2 ← Functions.rX_bits (.Regidx row.rs2)
        pure (source1 != source2))
    (do
      let currentPc ← Sail.readReg Register.PC
      pure (currentPc + Functions.sign_extend (m := 32)
        (Decode.branchImmediate row.immediateEncoded)))

def ConstructiveExecution
    (kind : Kind) (row : Row) (initial : Functions.GeneratedState)
    (stepNo : Nat) : Prop :=
  Functions.ConstructiveGeneratedExecution stepNo (expectedWord kind row)
    (decoded kind row)
    (Functions.completeBaseExecution row.pc
      (Functions.execute (decoded kind row)))
    (observedProgram kind row) initial
    (RiscvRefinement.Publication.TeamA.Branches.Eq.normalizedRetirement row)

def AcceptedComposition
    (kind : Kind) (row : Row) (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (initial : Functions.GeneratedState)
    (stepNo : Nat) (exitWait : Bool) : Prop :=
  AcceptedGeneratedOpcodeComposition
    (selector kind) kind.program kind.program.source.contentDigest
    (Air.Bridge.Branches.Eq.rawEvaluation row witness) relationHolds
    (expectedWord kind row) (expectedWord kind row) (decoded kind row)
    initial (StateBindings kind row initial)
    (GeneratedInstructionProfileAdmission row.pc (expectedWord kind row) initial)
    (Air.Bridge.Branches.Eq.RawAdmission row)
    (RiscvRefinement.Opcodes.Branches.Eq.RawRefinement row witness)
    (ExactTuple kind row) (ExactExecuteClause kind row)
    (NormalizedRetirement kind row)
    (ConstructiveExecution kind row initial stepNo) stepNo exitWait

def RefinementTheorem (kind : Kind) : Prop :=
  ∀ (row : Row) (witness : Witness row)
    (kindBinds : row.kind = kind)
    (relationHolds : EvaluatedLookup → Prop)
    (admission : Air.Bridge.Branches.Eq.RawAdmission row)
    (accepted : RiscvRefinement.Publication.AcceptedProductionEvaluation
      (Air.Bridge.Branches.Eq.rawEvaluation row witness) relationHolds)
    (initial : Functions.GeneratedState)
    (stateBindings : StateBindings kind row initial)
    (profileAdmission : GeneratedInstructionProfileAdmission
      row.pc (expectedWord kind row) initial)
    (stepNo : Nat) (exitWait : Bool),
    AcceptedComposition kind row witness relationHolds initial stepNo exitWait

theorem accepted_air_refines (kind : Kind) : RefinementTheorem kind := by
  intro row witness kindBinds relationHolds admission accepted initial
    stateBindings profileAdmission stepNo exitWait
  let legacyAcceptance : Air.Bridge.Branches.Eq.RawAcceptance row witness := {
    constraints := accepted.directConstraints
    fixedLookups := accepted.fixedTableRequests
  }
  have localRefinement :
      RiscvRefinement.Opcodes.Branches.Eq.RawRefinement row witness := by
    cases kind
    · exact (RiscvRefinement.Publication.TeamA.Branches.beq_accepted_air_implies_retirement
        row witness kindBinds admission legacyAcceptance).semanticRefinement
    · exact (RiscvRefinement.Publication.TeamA.Branches.bne_accepted_air_implies_retirement
        row witness kindBinds admission legacyAcceptance).semanticRefinement
  have exactTuple : ExactTuple kind row := by
    cases kind
    · simpa [ExactTuple, selector] using
        (RiscvRefinement.Publication.TeamA.Branches.beq_accepted_air_implies_retirement
          row witness kindBinds admission legacyAcceptance).exactProgramTuple
    · simpa [ExactTuple, selector] using
        (RiscvRefinement.Publication.TeamA.Branches.bne_accepted_air_implies_retirement
          row witness kindBinds admission legacyAcceptance).exactProgramTuple
  rcases stateBindings.1.decodeState.mseccfg with
    ⟨mseccfgValue, mseccfgBinding⟩
  have decoderCertificate : Functions.GeneratedDecodeCertificateAt
      (expectedWord kind row) (decoded kind row) initial := by
    exact Functions.decode_branch_control_certificate_at
      (decodeKind kind) row.immediateEncoded row.rs2 row.rs1
      initial mseccfgValue profileAdmission.pauseDisabled
      profileAdmission.landingPadExtensionDisabled
      stateBindings.1.privilege mseccfgBinding
  exact {
    acceptedProduction := accepted
    inputBoundSelector := {
      schemaVersion := by cases kind <;> rfl
      manifestId := by cases kind <;> rfl
      mnemonic := by cases kind <;> rfl
      digest := rfl
      inputWord := rfl
    }
    stateBindings := stateBindings
    profileAdmission := profileAdmission
    admission := admission
    admissionProofUnique := by intro first second; exact Subsingleton.elim first second
    localRefinement := localRefinement
    exactTuple := exactTuple
    decoder := decoderCertificate
    generatedExecuteSuccess := by cases kind <;> rfl
    normalizedRetirement := by
      cases kind
      · exact Functions.complete_BEQ_normalizes _ _ _ _
      · exact Functions.complete_BNE_normalizes _ _ _ _
    constructiveExecution := by
      cases kind <;>
        simpa [ConstructiveExecution, expectedWord, decoded, decodeKind,
          observedProgram, ExecutionControl.eqBranchDecodeKind,
          ExecutionControl.eqBranchCompute] using
          ExecutionControl.eq_branch_constructive _ row witness kindBinds
            initial stepNo stateBindings profileAdmission localRefinement
    fullStepFraming := Functions.generated_full_step_retirement_composition stepNo exitWait
  }
end EqBranch
namespace LtBranch

abbrev Kind := Air.Bridge.Branches.Lt.Kind
abbrev Row := Air.Bridge.Branches.Lt.RawRow
abbrev Witness := Air.Bridge.Branches.Lt.RawWitness

def selector : Kind → GeneratedOpcodeSelector
  | .blt => .blt
  | .bge => .bge
  | .bltu => .bltu
  | .bgeu => .bgeu

def decodeKind : Kind → Decode.BranchKind
  | .blt => .blt
  | .bge => .bge
  | .bltu => .bltu
  | .bgeu => .bgeu

def expectedWord (kind : Kind) (row : Row) : BitVec 32 :=
  Functions.encodeBranchControl (decodeKind kind)
    row.immediateEncoded row.rs2 row.rs1

def decoded (kind : Kind) (row : Row) : instruction :=
  Functions.decodedBranchControl (decodeKind kind)
    row.immediateEncoded row.rs2 row.rs1

def StateBindings
    (kind : Kind) (row : Row)
    (initial : Functions.GeneratedState) : Prop :=
  GeneratedInstructionStateBindings row.pc (expectedWord kind row) initial ∧
    GeneratedReadPairStateBindings initial row.rs1 row.rs2
      row.rs1Previous.word row.rs2Previous.word

def ExactTuple (kind : Kind) (row : Row) : Prop :=
  (Air.Bridge.Branches.Lt.rawProgramLookup row).tuple = #[
    Air.Bridge.Branches.bitVecM31 row.pc,
    M31.reduce (selector kind).manifestId,
    Air.Bridge.Branches.bitVecM31 row.rs1,
    Air.Bridge.Branches.bitVecM31 row.rs2,
    Air.Bridge.Branches.immediateField row.immediateEncoded
  ]

def ExactExecuteClause (kind : Kind) (row : Row) : Prop :=
  Functions.execute (decoded kind row) =
    Functions.execute_BTYPE
      (Decode.branchImmediate row.immediateEncoded)
      (.Regidx row.rs2) (.Regidx row.rs1)
      (Functions.generatedBranchOp (decodeKind kind))

def NormalizedRetirement (kind : Kind) (row : Row) : Prop :=
  Functions.completeBaseExecution row.pc
      (Functions.execute_BTYPE
        (Decode.branchImmediate row.immediateEncoded)
        (.Regidx row.rs2) (.Regidx row.rs1)
        (Functions.generatedBranchOp (decodeKind kind))) =
    Functions.eraseObservation
      (Functions.normalizedBranchCompletion row.pc
        (match kind with
        | .blt => do
            let a ← Functions.rX_bits (.Regidx row.rs1)
            let b ← Functions.rX_bits (.Regidx row.rs2)
            pure (Functions.zopz0zI_s a b)
        | .bge => do
            let a ← Functions.rX_bits (.Regidx row.rs1)
            let b ← Functions.rX_bits (.Regidx row.rs2)
            pure (Functions.zopz0zKzJ_s a b)
        | .bltu => do
            let a ← Functions.rX_bits (.Regidx row.rs1)
            let b ← Functions.rX_bits (.Regidx row.rs2)
            pure (Functions.zopz0zI_u a b)
        | .bgeu => do
            let a ← Functions.rX_bits (.Regidx row.rs1)
            let b ← Functions.rX_bits (.Regidx row.rs2)
            pure (Functions.zopz0zKzJ_u a b))
        (do
          let currentPc ← Sail.readReg Register.PC
          pure (currentPc + Functions.sign_extend (m := 32)
            (Decode.branchImmediate row.immediateEncoded))))

noncomputable def observedProgram (kind : Kind) (row : Row) :=
  Functions.normalizedBranchCompletion row.pc
    (match kind with
    | .blt => do
        let a ← Functions.rX_bits (.Regidx row.rs1)
        let b ← Functions.rX_bits (.Regidx row.rs2)
        pure (Functions.zopz0zI_s a b)
    | .bge => do
        let a ← Functions.rX_bits (.Regidx row.rs1)
        let b ← Functions.rX_bits (.Regidx row.rs2)
        pure (Functions.zopz0zKzJ_s a b)
    | .bltu => do
        let a ← Functions.rX_bits (.Regidx row.rs1)
        let b ← Functions.rX_bits (.Regidx row.rs2)
        pure (Functions.zopz0zI_u a b)
    | .bgeu => do
        let a ← Functions.rX_bits (.Regidx row.rs1)
        let b ← Functions.rX_bits (.Regidx row.rs2)
        pure (Functions.zopz0zKzJ_u a b))
    (do
      let currentPc ← Sail.readReg Register.PC
      pure (currentPc + Functions.sign_extend (m := 32)
        (Decode.branchImmediate row.immediateEncoded)))

def ConstructiveExecution
    (kind : Kind) (row : Row) (initial : Functions.GeneratedState)
    (stepNo : Nat) : Prop :=
  Functions.ConstructiveGeneratedExecution stepNo (expectedWord kind row)
    (decoded kind row)
    (Functions.completeBaseExecution row.pc
      (Functions.execute (decoded kind row)))
    (observedProgram kind row) initial
    (RiscvRefinement.Publication.TeamA.Branches.Lt.normalizedRetirement row)

def AcceptedComposition
    (kind : Kind) (row : Row) (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (initial : Functions.GeneratedState)
    (stepNo : Nat) (exitWait : Bool) : Prop :=
  AcceptedGeneratedOpcodeComposition
    (selector kind) kind.program kind.program.source.contentDigest
    (Air.Bridge.Branches.Lt.rawEvaluation row witness) relationHolds
    (expectedWord kind row) (expectedWord kind row) (decoded kind row)
    initial (StateBindings kind row initial)
    (GeneratedInstructionProfileAdmission row.pc (expectedWord kind row) initial)
    (Air.Bridge.Branches.Lt.RawAdmission row)
    (RiscvRefinement.Opcodes.Branches.Lt.RawRefinement row witness)
    (ExactTuple kind row) (ExactExecuteClause kind row)
    (NormalizedRetirement kind row)
    (ConstructiveExecution kind row initial stepNo) stepNo exitWait

def RefinementTheorem (kind : Kind) : Prop :=
  ∀ (row : Row) (witness : Witness row)
    (kindBinds : row.kind = kind)
    (relationHolds : EvaluatedLookup → Prop)
    (admission : Air.Bridge.Branches.Lt.RawAdmission row)
    (accepted : RiscvRefinement.Publication.AcceptedProductionEvaluation
      (Air.Bridge.Branches.Lt.rawEvaluation row witness) relationHolds)
    (initial : Functions.GeneratedState)
    (stateBindings : StateBindings kind row initial)
    (profileAdmission : GeneratedInstructionProfileAdmission
      row.pc (expectedWord kind row) initial)
    (stepNo : Nat) (exitWait : Bool),
    AcceptedComposition kind row witness relationHolds initial stepNo exitWait

theorem accepted_air_refines (kind : Kind) : RefinementTheorem kind := by
  intro row witness kindBinds relationHolds admission accepted initial
    stateBindings profileAdmission stepNo exitWait
  let legacyAcceptance : Air.Bridge.Branches.Lt.RawAcceptance row witness := {
    constraints := accepted.directConstraints
    fixedLookups := accepted.fixedTableRequests
  }
  have localRefinement :
      RiscvRefinement.Opcodes.Branches.Lt.RawRefinement row witness := by
    cases kind
    · exact (RiscvRefinement.Publication.TeamA.Branches.blt_accepted_air_implies_retirement
        row witness kindBinds admission legacyAcceptance).semanticRefinement
    · exact (RiscvRefinement.Publication.TeamA.Branches.bge_accepted_air_implies_retirement
        row witness kindBinds admission legacyAcceptance).semanticRefinement
    · exact (RiscvRefinement.Publication.TeamA.Branches.bltu_accepted_air_implies_retirement
        row witness kindBinds admission legacyAcceptance).semanticRefinement
    · exact (RiscvRefinement.Publication.TeamA.Branches.bgeu_accepted_air_implies_retirement
        row witness kindBinds admission legacyAcceptance).semanticRefinement
  have exactTuple : ExactTuple kind row := by
    cases kind
    · simpa [ExactTuple, selector] using
        (RiscvRefinement.Publication.TeamA.Branches.blt_accepted_air_implies_retirement
          row witness kindBinds admission legacyAcceptance).exactProgramTuple
    · simpa [ExactTuple, selector] using
        (RiscvRefinement.Publication.TeamA.Branches.bge_accepted_air_implies_retirement
          row witness kindBinds admission legacyAcceptance).exactProgramTuple
    · simpa [ExactTuple, selector] using
        (RiscvRefinement.Publication.TeamA.Branches.bltu_accepted_air_implies_retirement
          row witness kindBinds admission legacyAcceptance).exactProgramTuple
    · simpa [ExactTuple, selector] using
        (RiscvRefinement.Publication.TeamA.Branches.bgeu_accepted_air_implies_retirement
          row witness kindBinds admission legacyAcceptance).exactProgramTuple
  rcases stateBindings.1.decodeState.mseccfg with
    ⟨mseccfgValue, mseccfgBinding⟩
  have decoderCertificate : Functions.GeneratedDecodeCertificateAt
      (expectedWord kind row) (decoded kind row) initial := by
    exact Functions.decode_branch_control_certificate_at
      (decodeKind kind) row.immediateEncoded row.rs2 row.rs1
      initial mseccfgValue profileAdmission.pauseDisabled
      profileAdmission.landingPadExtensionDisabled
      stateBindings.1.privilege mseccfgBinding
  exact {
    acceptedProduction := accepted
    inputBoundSelector := {
      schemaVersion := by cases kind <;> rfl
      manifestId := by cases kind <;> rfl
      mnemonic := by cases kind <;> rfl
      digest := rfl
      inputWord := rfl
    }
    stateBindings := stateBindings
    profileAdmission := profileAdmission
    admission := admission
    admissionProofUnique := by intro first second; exact Subsingleton.elim first second
    localRefinement := localRefinement
    exactTuple := exactTuple
    decoder := decoderCertificate
    generatedExecuteSuccess := by cases kind <;> rfl
    normalizedRetirement := by
      cases kind
      · exact Functions.complete_BLT_normalizes _ _ _ _
      · exact Functions.complete_BGE_normalizes _ _ _ _
      · exact Functions.complete_BLTU_normalizes _ _ _ _
      · exact Functions.complete_BGEU_normalizes _ _ _ _
    constructiveExecution := by
      cases kind <;>
        simpa [ConstructiveExecution, expectedWord, decoded, decodeKind,
          observedProgram, ExecutionControl.ltBranchDecodeKind,
          ExecutionControl.ltBranchCompute] using
          ExecutionControl.lt_branch_constructive _ row witness kindBinds
            initial stepNo stateBindings profileAdmission localRefinement
    fullStepFraming := Functions.generated_full_step_retirement_composition stepNo exitWait
  }
end LtBranch
namespace Jal

abbrev Row := RiscvRefinement.Opcodes.Jal.Row
abbrev Witness := RiscvRefinement.Opcodes.Jal.Witness

def expectedWord (row : Row) : BitVec 32 :=
  Functions.encodeJalControl row.immediateEncoded row.rd

def decoded (row : Row) : instruction :=
  Functions.decodedJalControl row.immediateEncoded row.rd

def StateBindings (row : Row) (initial : Functions.GeneratedState) : Prop :=
  GeneratedInstructionStateBindings row.pc (expectedWord row) initial ∧
    GeneratedDestinationStateBinding initial row.rd row.rdPrevious.word

def ExactTuple (row : Row) : Prop :=
  (Air.Bridge.Jal.programLookup row).tuple = #[
    Air.Bridge.Jal.bitVecM31 row.pc, M31.reduce 33,
    Air.Bridge.Jal.bitVecM31 row.rd,
    Air.Bridge.Jal.immediateField row.immediateEncoded, 0
  ]

def ExactExecuteClause (row : Row) : Prop :=
  Functions.execute (decoded row) = Functions.execute_JAL
    (Decode.jalImmediate row.immediateEncoded) (.Regidx row.rd)

def NormalizedRetirement (row : Row) : Prop :=
  Functions.completeBaseExecution row.pc
      (Functions.execute_JAL (Decode.jalImmediate row.immediateEncoded)
        (.Regidx row.rd)) =
    Functions.eraseObservation
      (Functions.normalizedJumpCompletion row.pc row.rd (pure ())
        (do
          let currentPc ← Sail.readReg Register.PC
          pure (currentPc + Functions.sign_extend (m := 32)
            (Decode.jalImmediate row.immediateEncoded))))

noncomputable def observedProgram (row : Row) :=
  Functions.normalizedJumpCompletion row.pc row.rd (pure ())
    (do
      let currentPc ← Sail.readReg Register.PC
      pure (currentPc + Functions.sign_extend (m := 32)
        (Decode.jalImmediate row.immediateEncoded)))

def ConstructiveExecution
    (row : Row) (initial : Functions.GeneratedState)
    (stepNo : Nat) : Prop :=
  Functions.ConstructiveGeneratedExecution stepNo (expectedWord row)
    (decoded row)
    (Functions.completeBaseExecution row.pc
      (Functions.execute (decoded row)))
    (observedProgram row) initial
    (RiscvRefinement.Opcodes.Jal.airRetirement row)

def AcceptedComposition
    (row : Row) (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (initial : Functions.GeneratedState)
    (stepNo : Nat) (exitWait : Bool) : Prop :=
  AcceptedGeneratedOpcodeComposition .jal Programs.jal
    Programs.jal.source.contentDigest
    (Air.Bridge.Jal.evaluation row witness) relationHolds
    (expectedWord row) (expectedWord row) (decoded row) initial
    (StateBindings row initial)
    (GeneratedInstructionProfileAdmission row.pc (expectedWord row) initial)
    (RiscvRefinement.Opcodes.Jal.Admission row)
    (RiscvRefinement.Opcodes.Jal.Refinement row witness)
    (ExactTuple row) (ExactExecuteClause row) (NormalizedRetirement row)
    (ConstructiveExecution row initial stepNo)
    stepNo exitWait

def RefinementTheorem : Prop :=
  ∀ (row : Row) (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (admission : RiscvRefinement.Opcodes.Jal.Admission row)
    (accepted : RiscvRefinement.Publication.AcceptedProductionEvaluation
      (Air.Bridge.Jal.evaluation row witness) relationHolds)
    (initial : Functions.GeneratedState)
    (stateBindings : StateBindings row initial)
    (profileAdmission : GeneratedInstructionProfileAdmission
      row.pc (expectedWord row) initial)
    (stepNo : Nat) (exitWait : Bool),
    AcceptedComposition row witness relationHolds initial stepNo exitWait

theorem accepted_air_refines : RefinementTheorem := by
  intro row witness relationHolds admission accepted initial stateBindings
    profileAdmission stepNo exitWait
  let legacyAcceptance : RiscvRefinement.Opcodes.Jal.Acceptance row witness := {
    selectors := accepted.activeProductionRow
    constraints := accepted.directConstraints
    fixedLookups := accepted.fixedTableRequests
  }
  have localCertificate :=
    RiscvRefinement.Publication.TeamA.Control.jal_accepted_air_implies_retirement
      row witness admission legacyAcceptance
  rcases stateBindings.1.decodeState.mseccfg with
    ⟨mseccfgValue, mseccfgBinding⟩
  have decoderCertificate := Functions.decode_jal_control_certificate_at
    row.immediateEncoded row.rd initial mseccfgValue
    profileAdmission.pauseDisabled
    profileAdmission.landingPadExtensionDisabled
    stateBindings.1.privilege mseccfgBinding
  exact {
    acceptedProduction := accepted
    inputBoundSelector := {
      schemaVersion := rfl
      manifestId := rfl
      mnemonic := rfl
      digest := rfl
      inputWord := rfl
    }
    stateBindings := stateBindings
    profileAdmission := profileAdmission
    admission := admission
    admissionProofUnique := by intro first second; exact Subsingleton.elim first second
    localRefinement := localCertificate.semanticRefinement
    exactTuple := localCertificate.exactProgramTuple
    decoder := decoderCertificate
    generatedExecuteSuccess := rfl
    normalizedRetirement := Functions.complete_JAL_normalizes _ _ _
    constructiveExecution := by
      simpa [ConstructiveExecution, expectedWord, decoded, observedProgram] using
        ExecutionControl.jal_constructive row witness initial stepNo
          stateBindings profileAdmission admission
          localCertificate.semanticRefinement
    fullStepFraming := Functions.generated_full_step_retirement_composition stepNo exitWait
  }
end Jal
namespace Jalr

abbrev Row := RiscvRefinement.Opcodes.Jalr.Row
abbrev Witness := RiscvRefinement.Opcodes.Jalr.Witness

def expectedWord (row : Row) : BitVec 32 :=
  Functions.encodeJalrControl row.immediate row.rs1 row.rd

def decoded (row : Row) : instruction :=
  Functions.decodedJalrControl row.immediate row.rs1 row.rd

def StateBindings
    (row : Row) (environment : RiscvRefinement.Opcodes.Jalr.Environment row)
    (initial : Functions.GeneratedState) : Prop :=
  GeneratedInstructionStateBindings row.pc (expectedWord row) initial ∧
    GeneratedUnaryRegisterStateBindings initial row.rs1 row.rd
      (environment.pre.registers row.rs1) (environment.pre.registers row.rd)

def ExactTuple (row : Row) : Prop :=
  (Air.Bridge.Jalr.programLookup row).tuple = #[
    Air.Bridge.Jalr.bitVecM31 row.pc, M31.reduce 34,
    Air.Bridge.Jalr.bitVecM31 row.rd, Air.Bridge.Jalr.bitVecM31 row.rs1,
    Air.Bridge.Jalr.immediateField row.immediate
  ]

def ExactExecuteClause (row : Row) : Prop :=
  Functions.execute (decoded row) = Functions.execute_JALR row.immediate
    (.Regidx row.rs1) (.Regidx row.rd)

def NormalizedRetirement (row : Row) : Prop :=
  Functions.completeBaseExecution row.pc
      (Functions.execute_JALR row.immediate (.Regidx row.rs1) (.Regidx row.rd)) =
    Functions.eraseObservation
      (Functions.normalizedJumpCompletion row.pc row.rd
        (Functions.update_elp_state (.Regidx row.rs1))
        (do
          let base ← Functions.rX_bits (.Regidx row.rs1)
          pure (BitVec.update
            (base + Functions.sign_extend (m := 32) row.immediate) 0 0#1)))

noncomputable def observedProgram (row : Row) :=
  Functions.normalizedJumpCompletion row.pc row.rd
    (Functions.update_elp_state (.Regidx row.rs1))
    (do
      let base ← Functions.rX_bits (.Regidx row.rs1)
      pure (BitVec.update
        (base + Functions.sign_extend (m := 32) row.immediate) 0 0#1))

def ConstructiveExecution
    (row : Row)
    (environment : RiscvRefinement.Opcodes.Jalr.Environment row)
    (initial : Functions.GeneratedState)
    (stepNo : Nat) : Prop :=
  Functions.ConstructiveGeneratedExecution stepNo (expectedWord row)
    (decoded row)
    (Functions.completeBaseExecution row.pc
      (Functions.execute (decoded row)))
    (observedProgram row) initial
    (RiscvRefinement.Opcodes.Jalr.airRetirement row)

def AcceptedComposition
    (row : Row) (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : RiscvRefinement.Opcodes.Jalr.Environment row)
    (initial : Functions.GeneratedState)
    (stepNo : Nat) (exitWait : Bool) : Prop :=
  AcceptedGeneratedOpcodeComposition .jalr Programs.jalr
    Programs.jalr.source.contentDigest
    (Air.Bridge.Jalr.evaluation row witness) relationHolds
    (expectedWord row) (expectedWord row) (decoded row) initial
    (StateBindings row environment initial)
    (GeneratedInstructionProfileAdmission row.pc (expectedWord row) initial)
    (RiscvRefinement.Opcodes.Jalr.Admission row)
    (RiscvRefinement.Opcodes.Jalr.Refinement row witness environment)
    (ExactTuple row) (ExactExecuteClause row) (NormalizedRetirement row)
    (ConstructiveExecution row environment initial stepNo)
    stepNo exitWait

def RefinementTheorem : Prop :=
  ∀ (row : Row) (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : RiscvRefinement.Opcodes.Jalr.Environment row)
    (admission : RiscvRefinement.Opcodes.Jalr.Admission row)
    (accepted : RiscvRefinement.Publication.AcceptedProductionEvaluation
      (Air.Bridge.Jalr.evaluation row witness) relationHolds)
    (initial : Functions.GeneratedState)
    (stateBindings : StateBindings row environment initial)
    (profileAdmission : GeneratedInstructionProfileAdmission
      row.pc (expectedWord row) initial)
    (stepNo : Nat) (exitWait : Bool),
    AcceptedComposition row witness relationHolds environment initial stepNo exitWait

theorem accepted_air_refines : RefinementTheorem := by
  intro row witness relationHolds environment admission accepted initial
    stateBindings profileAdmission stepNo exitWait
  let legacyAcceptance : RiscvRefinement.Opcodes.Jalr.Acceptance row witness := {
    selectors := accepted.activeProductionRow
    constraints := accepted.directConstraints
    fixedLookups := accepted.fixedTableRequests
  }
  have localCertificate :=
    RiscvRefinement.Publication.TeamA.Control.jalr_accepted_air_implies_retirement
      row witness environment admission legacyAcceptance
  rcases stateBindings.1.decodeState.mseccfg with
    ⟨mseccfgValue, mseccfgBinding⟩
  have decoderCertificate := Functions.decode_jalr_control_certificate_at
    row.immediate row.rs1 row.rd initial mseccfgValue
    profileAdmission.pauseDisabled
    profileAdmission.landingPadExtensionDisabled
    stateBindings.1.privilege mseccfgBinding
  exact {
    acceptedProduction := accepted
    inputBoundSelector := {
      schemaVersion := rfl
      manifestId := rfl
      mnemonic := rfl
      digest := rfl
      inputWord := rfl
    }
    stateBindings := stateBindings
    profileAdmission := profileAdmission
    admission := admission
    admissionProofUnique := by intro first second; exact Subsingleton.elim first second
    localRefinement := localCertificate.semanticRefinement
    exactTuple := localCertificate.exactProgramTuple
    decoder := decoderCertificate
    generatedExecuteSuccess := rfl
    normalizedRetirement := Functions.complete_JALR_normalizes _ _ _ _
    constructiveExecution := by
      simpa [ConstructiveExecution, expectedWord, decoded, observedProgram] using
        ExecutionControl.jalr_constructive row witness environment initial stepNo
          stateBindings profileAdmission localCertificate.semanticRefinement
    fullStepFraming := Functions.generated_full_step_retirement_composition stepNo exitWait
  }
end Jalr
namespace Auipc

abbrev Row := RiscvRefinement.Opcodes.Auipc.Row
abbrev Witness := RiscvRefinement.Opcodes.Auipc.Witness

def expectedWord (row : Row) : BitVec 32 :=
  Functions.encodeAuipcControl row.immediateEncoded row.rd

def decoded (row : Row) : instruction :=
  Functions.decodedAuipcControl row.immediateEncoded row.rd

def StateBindings (row : Row) (initial : Functions.GeneratedState) : Prop :=
  GeneratedInstructionStateBindings row.pc (expectedWord row) initial ∧
    GeneratedDestinationStateBinding initial row.rd row.rdPrevious.word

def ExactTuple (row : Row) : Prop :=
  (Air.Bridge.Auipc.programLookup row).tuple = #[
    Air.Bridge.Auipc.bitVecM31 row.pc, M31.reduce 36,
    Air.Bridge.Auipc.bitVecM31 row.rd, row.immediateFelt, 0
  ]

def ExactExecuteClause (row : Row) : Prop :=
  Functions.execute (decoded row) = Functions.execute_UTYPE
    row.immediateEncoded (.Regidx row.rd) .AUIPC

def NormalizedRetirement (row : Row) : Prop :=
  Functions.completeBaseExecution row.pc
      (Functions.execute_UTYPE row.immediateEncoded (.Regidx row.rd) .AUIPC) =
    Functions.eraseObservation
      (Functions.normalizedRegisterCompletion row.pc row.rd
        (do
          let sourcePc ← Functions.get_arch_pc ()
          pure (sourcePc + Functions.sign_extend (m := 32)
            (row.immediateEncoded +++ (0x000#12)))))

noncomputable def observedProgram (row : Row) :=
  Functions.normalizedRegisterCompletion row.pc row.rd
    (do
      let sourcePc ← Functions.get_arch_pc ()
      pure (sourcePc + Functions.sign_extend (m := 32)
        (row.immediateEncoded +++ (0x000#12))))

def ConstructiveExecution
    (row : Row) (initial : Functions.GeneratedState)
    (stepNo : Nat) : Prop :=
  Functions.ConstructiveGeneratedExecution stepNo (expectedWord row)
    (decoded row)
    (Functions.completeBaseExecution row.pc
      (Functions.execute (decoded row)))
    (observedProgram row) initial
    (RiscvRefinement.Opcodes.Auipc.airRetirement row)

def AcceptedComposition
    (row : Row) (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (initial : Functions.GeneratedState)
    (stepNo : Nat) (exitWait : Bool) : Prop :=
  AcceptedGeneratedOpcodeComposition .auipc Programs.auipc
    Programs.auipc.source.contentDigest
    (Air.Bridge.Auipc.evaluation row witness) relationHolds
    (expectedWord row) (expectedWord row) (decoded row) initial
    (StateBindings row initial)
    (GeneratedInstructionProfileAdmission row.pc (expectedWord row) initial)
    (RiscvRefinement.Opcodes.Auipc.Admission row)
    (RiscvRefinement.Opcodes.Auipc.Refinement row witness)
    (ExactTuple row) (ExactExecuteClause row) (NormalizedRetirement row)
    (ConstructiveExecution row initial stepNo)
    stepNo exitWait

def RefinementTheorem : Prop :=
  ∀ (row : Row) (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (admission : RiscvRefinement.Opcodes.Auipc.Admission row)
    (accepted : RiscvRefinement.Publication.AcceptedProductionEvaluation
      (Air.Bridge.Auipc.evaluation row witness) relationHolds)
    (initial : Functions.GeneratedState)
    (stateBindings : StateBindings row initial)
    (profileAdmission : GeneratedInstructionProfileAdmission
      row.pc (expectedWord row) initial)
    (stepNo : Nat) (exitWait : Bool),
    AcceptedComposition row witness relationHolds initial stepNo exitWait

theorem accepted_air_refines : RefinementTheorem := by
  intro row witness relationHolds admission accepted initial stateBindings
    profileAdmission stepNo exitWait
  let legacyAcceptance : RiscvRefinement.Opcodes.Auipc.Acceptance row witness := {
    selectors := accepted.activeProductionRow
    constraints := accepted.directConstraints
    fixedLookups := accepted.fixedTableRequests
  }
  have localCertificate :=
    RiscvRefinement.Publication.TeamA.Control.auipc_accepted_air_implies_retirement
      row witness admission legacyAcceptance
  rcases stateBindings.1.decodeState.mseccfg with
    ⟨mseccfgValue, mseccfgBinding⟩
  have decoderCertificate := Functions.decode_auipc_control_certificate_at
    row.immediateEncoded row.rd initial mseccfgValue
    profileAdmission.pauseDisabled
    profileAdmission.landingPadExtensionDisabled
    stateBindings.1.privilege mseccfgBinding
  exact {
    acceptedProduction := accepted
    inputBoundSelector := {
      schemaVersion := rfl
      manifestId := rfl
      mnemonic := rfl
      digest := rfl
      inputWord := rfl
    }
    stateBindings := stateBindings
    profileAdmission := profileAdmission
    admission := admission
    admissionProofUnique := by intro first second; exact Subsingleton.elim first second
    localRefinement := localCertificate.semanticRefinement
    exactTuple := localCertificate.exactProgramTuple
    decoder := decoderCertificate
    generatedExecuteSuccess := rfl
    normalizedRetirement := Functions.complete_AUIPC_normalizes _ _ _
    constructiveExecution := by
      simpa [ConstructiveExecution, expectedWord, decoded, observedProgram] using
        ExecutionControl.auipc_constructive row witness initial stepNo
          stateBindings localCertificate.semanticRefinement
    fullStepFraming := Functions.generated_full_step_retirement_composition stepNo exitWait
  }
end Auipc

theorem BEQ_accepted_air_refines : EqBranch.RefinementTheorem .beq :=
  EqBranch.accepted_air_refines .beq
theorem BNE_accepted_air_refines : EqBranch.RefinementTheorem .bne :=
  EqBranch.accepted_air_refines .bne
theorem BLT_accepted_air_refines : LtBranch.RefinementTheorem .blt :=
  LtBranch.accepted_air_refines .blt
theorem BGE_accepted_air_refines : LtBranch.RefinementTheorem .bge :=
  LtBranch.accepted_air_refines .bge
theorem BLTU_accepted_air_refines : LtBranch.RefinementTheorem .bltu :=
  LtBranch.accepted_air_refines .bltu
theorem BGEU_accepted_air_refines : LtBranch.RefinementTheorem .bgeu :=
  LtBranch.accepted_air_refines .bgeu
theorem JAL_accepted_air_refines : Jal.RefinementTheorem :=
  Jal.accepted_air_refines
theorem JALR_accepted_air_refines : Jalr.RefinementTheorem :=
  Jalr.accepted_air_refines
theorem AUIPC_accepted_air_refines : Auipc.RefinementTheorem :=
  Auipc.accepted_air_refines

end LeanRV32IM.Publication
