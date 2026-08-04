import ExecutionClosure
import DecodeMulDiv
import MulDivArithmetic
import RiscvRefinement.Publication.TeamB.MulhDiv

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 100_000
set_option linter.unusedVariables false

open Sail

namespace LeanRV32IM.Publication

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated

/-! ## MULH / MULHSU / MULHU -/

namespace HighMultiply

abbrev Op := MulhSelector
abbrev Row :=
  RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.Row
abbrev Witness :=
  RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.Witness
abbrev Admission :=
  RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.Admission
abbrev Environment := RiscvRefinement.Opcodes.MulhEnvironment

def selector : Op → GeneratedOpcodeSelector
  | .mulh => .mulh
  | .mulhsu => .mulhsu
  | .mulhu => .mulhu

def generatedOp : Op → Functions.AdmittedMTypeOp
  | .mulh => .mulh
  | .mulhsu => .mulhsu
  | .mulhu => .mulhu

def program : Op → LocalProgram
  | .mulh => Programs.mulh
  | .mulhsu => Programs.mulhsu
  | .mulhu => Programs.mulhu

def word (op : Op) (row : Row) : BitVec 32 :=
  Functions.encodeAdmittedMType (generatedOp op) row.rs2 row.rs1 row.rd

def decoded (op : Op) (row : Row) : instruction :=
  Functions.admittedMTypeInstruction
    (generatedOp op) row.rs2 row.rs1 row.rd

def ExactExecuteClause (op : Op) (row : Row) : Prop :=
  match op with
  | .mulh => Functions.execute (decoded op row) =
      Functions.execute_MUL
        (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd)
        Functions.mulSelectorHighSigned
  | .mulhsu => Functions.execute (decoded op row) =
      Functions.execute_MUL
        (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd)
        Functions.mulSelectorHighSignedUnsigned
  | .mulhu => Functions.execute (decoded op row) =
      Functions.execute_MUL
        (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd)
        Functions.mulSelectorHighUnsigned

def NormalizedRetirement
    (op : Op) (row : Row) (environment : Environment row) : Prop :=
  match op with
  | .mulh => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_MUL
        (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd)
        Functions.mulSelectorHighSigned) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion environment.pre.pc row.rd
          (do
            let source1 ← Functions.rX_bits (.Regidx row.rs1)
            let source2 ← Functions.rX_bits (.Regidx row.rs2)
            pure (Functions.mult_to_bits_half
              Functions.mulSelectorHighSigned.signed_rs1
              Functions.mulSelectorHighSigned.signed_rs2
              source1 source2
              Functions.mulSelectorHighSigned.result_part)))
  | .mulhsu => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_MUL
        (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd)
        Functions.mulSelectorHighSignedUnsigned) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion environment.pre.pc row.rd
          (do
            let source1 ← Functions.rX_bits (.Regidx row.rs1)
            let source2 ← Functions.rX_bits (.Regidx row.rs2)
            pure (Functions.mult_to_bits_half
              Functions.mulSelectorHighSignedUnsigned.signed_rs1
              Functions.mulSelectorHighSignedUnsigned.signed_rs2
              source1 source2
              Functions.mulSelectorHighSignedUnsigned.result_part)))
  | .mulhu => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_MUL
        (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd)
        Functions.mulSelectorHighUnsigned) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion environment.pre.pc row.rd
          (do
            let source1 ← Functions.rX_bits (.Regidx row.rs1)
            let source2 ← Functions.rX_bits (.Regidx row.rs2)
            pure (Functions.mult_to_bits_half
              Functions.mulSelectorHighUnsigned.signed_rs1
              Functions.mulSelectorHighUnsigned.signed_rs2
              source1 source2
              Functions.mulSelectorHighUnsigned.result_part)))

def generatedSelector : Op → mul_op
  | .mulh => Functions.mulSelectorHighSigned
  | .mulhsu => Functions.mulSelectorHighSignedUnsigned
  | .mulhu => Functions.mulSelectorHighUnsigned

def reviewedValue
    (op : Op) (source1 source2 : BitVec 32) : BitVec 32 :=
  match op with
  | .mulh => Sail.Reviewed.executeMulhValue source1 source2
  | .mulhsu => Sail.Reviewed.executeMulhsuValue source1 source2
  | .mulhu => Sail.Reviewed.executeMulhuValue source1 source2

def reviewedRetirement
    (op : Op) (row : Row) (environment : Environment row) : Retirement := {
  nextPc := RiscvRefinement.nextPc environment.pre.pc
  write := RiscvRefinement.architecturalWrite row.rd
    (reviewedValue op (environment.pre.registers row.rs1)
      (environment.pre.registers row.rs2))
  read := none
  store := none
}

def ConstructiveExecution
    (op : Op) (row : Row) (environment : Environment row)
    (initial : Functions.GeneratedState) (stepNo : Nat) : Prop :=
  Functions.ConstructiveGeneratedExecution stepNo
    (word op row) (decoded op row)
    (Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_MUL
        (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd)
        (generatedSelector op)))
    (Functions.normalizedRegisterCompletion environment.pre.pc row.rd
      (do
        let source1 ← Functions.rX_bits (.Regidx row.rs1)
        let source2 ← Functions.rX_bits (.Regidx row.rs2)
        pure (Functions.mult_to_bits_half
          (generatedSelector op).signed_rs1
          (generatedSelector op).signed_rs2 source1 source2
          (generatedSelector op).result_part)))
    initial (reviewedRetirement op row environment)

def LocalRefinement
    (op : Op) (row : Row) (environment : Environment row) : Prop :=
  match op with
  | .mulh =>
      mulhRetirement
          (RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.normalize row) =
        Sail.Reviewed.executeMulh
          environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.rd
  | .mulhsu =>
      mulhRetirement
          (RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.normalize row) =
        Sail.Reviewed.executeMulhsu
          environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.rd
  | .mulhu =>
      mulhRetirement
          (RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.normalize row) =
        Sail.Reviewed.executeMulhu
          environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.rd

def LocalResult
    (op : Op) (row : Row) (witness : Witness row)
    (environment : Environment row) : Prop :=
  LocalRefinement op row environment ∧
    RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.ExactTupleProjection
      row witness

theorem localResult
    (op : Op) (row : Row) (witness : Witness row)
    (environment : Environment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : RiscvRefinement.Publication.AcceptedProductionEvaluation
      ((program op).evalSymbolic
        (RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.columns
          row witness)) relationHolds)
    (admission : Admission row) :
    LocalResult op row witness environment := by
  cases op
  · have selectedAccepted :
        RiscvRefinement.Publication.AcceptedProductionEvaluation
          (Programs.mulh.evalSymbolic
            (RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.columns
              row witness)) relationHolds := by
      simpa only [program] using accepted
    have certificate :=
      RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.mulh_accepted_air_implies_retirement
        row witness environment relationHolds selectedAccepted admission
    change
      (mulhRetirement
          (RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.normalize row) =
        Sail.Reviewed.executeMulh environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.rd) ∧
      RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.ExactTupleProjection
        row witness
    have semantic := certificate.2.2.1
    have exactTuple :=
      RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.exactTupleProjection
        row witness
    exact And.intro semantic exactTuple
  · have selectedAccepted :
        RiscvRefinement.Publication.AcceptedProductionEvaluation
          (Programs.mulhsu.evalSymbolic
            (RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.columns
              row witness)) relationHolds := by
      simpa only [program] using accepted
    have certificate :=
      RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.mulhsu_accepted_air_implies_retirement
        row witness environment relationHolds selectedAccepted admission
    change
      (mulhRetirement
          (RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.normalize row) =
        Sail.Reviewed.executeMulhsu environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.rd) ∧
      RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.ExactTupleProjection
        row witness
    have semantic := certificate.2.2.1
    have exactTuple :=
      RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.exactTupleProjection
        row witness
    exact And.intro semantic exactTuple
  · have selectedAccepted :
        RiscvRefinement.Publication.AcceptedProductionEvaluation
          (Programs.mulhu.evalSymbolic
            (RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.columns
              row witness)) relationHolds := by
      simpa only [program] using accepted
    have certificate :=
      RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.mulhu_accepted_air_implies_retirement
        row witness environment relationHolds selectedAccepted admission
    change
      (mulhRetirement
          (RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.normalize row) =
        Sail.Reviewed.executeMulhu environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.rd) ∧
      RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.ExactTupleProjection
        row witness
    have semantic := certificate.2.2.1
    have exactTuple :=
      RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.exactTupleProjection
        row witness
    exact And.intro semantic exactTuple

def StateBindings
    (op : Op) (row : Row) (environment : Environment row)
    (initial : Functions.GeneratedState) : Prop :=
  GeneratedInstructionStateBindings environment.pre.pc (word op row) initial ∧
    GeneratedBinaryRegisterStateBindings initial row.rs1 row.rs2 row.rd
      (environment.pre.registers row.rs1)
      (environment.pre.registers row.rs2)
      (environment.pre.registers row.rd)

def AcceptedComposition
    (op : Op) (row : Row) (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : Environment row) (initial : Functions.GeneratedState)
    (stepNo : Nat) (exitWait : Bool) : Prop :=
  AcceptedGeneratedOpcodeComposition
    (selector op) (program op) (program op).source.contentDigest
    ((program op).evalSymbolic
      (RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.columns
        row witness))
    relationHolds (word op row) (word op row) (decoded op row) initial
    (StateBindings op row environment initial)
    (GeneratedInstructionProfileAdmission
      environment.pre.pc (word op row) initial)
    (Admission row)
    (LocalRefinement op row environment)
    (RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.ExactTupleProjection
      row witness)
    (ExactExecuteClause op row)
    (NormalizedRetirement op row environment)
    (ConstructiveExecution op row environment initial stepNo)
    stepNo exitWait

def RefinementTheorem (op : Op) : Prop :=
  ∀ (row : Row) (witness : Witness row)
    (environment : Environment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : RiscvRefinement.Publication.AcceptedProductionEvaluation
      ((program op).evalSymbolic
        (RiscvRefinement.Publication.TeamB.MulhDiv.HighMultiply.columns
          row witness)) relationHolds)
    (admission : Admission row)
    (initial : Functions.GeneratedState)
    (stateBindings : StateBindings op row environment initial)
    (profileAdmission : GeneratedInstructionProfileAdmission
      environment.pre.pc (word op row) initial)
    (stepNo : Nat) (exitWait : Bool),
    AcceptedComposition op row witness relationHolds environment
      initial stepNo exitWait

theorem accepted_air_refines (op : Op) : RefinementTheorem op := by
  intro row witness environment relationHolds accepted admission initial
    stateBindings profileAdmission stepNo exitWait
  have localCertificate :=
    localResult op row witness environment relationHolds accepted admission
  rcases stateBindings.1.decodeState.misa with
    ⟨misaValue, misaBinding, misaMEnabled, _misaCDisabled⟩
  rcases stateBindings.1.decodeState.mseccfg with
    ⟨mseccfgValue, mseccfgBinding⟩
  have decoderCertificate :
      Functions.GeneratedDecodeCertificateAt
        (word op row) (decoded op row) initial :=
    Functions.decode_admitted_mtype_certificate_at
      (generatedOp op) row.rs2 row.rs1 row.rd initial
      misaValue mseccfgValue profileAdmission.multiplyEnabled
      profileAdmission.pauseDisabled
      profileAdmission.landingPadExtensionDisabled
      misaBinding misaMEnabled stateBindings.1.privilege mseccfgBinding
  exact {
    acceptedProduction := accepted
    inputBoundSelector := {
      schemaVersion := by cases op <;> rfl
      manifestId := by cases op <;> rfl
      mnemonic := by cases op <;> rfl
      digest := rfl
      inputWord := rfl
    }
    stateBindings := stateBindings
    profileAdmission := profileAdmission
    admission := admission
    admissionProofUnique := fun first second => Subsingleton.elim first second
    localRefinement := localCertificate.1
    exactTuple := localCertificate.2
    decoder := decoderCertificate
    generatedExecuteSuccess := by cases op <;> rfl
    normalizedRetirement := by
      cases op
      · exact Functions.complete_MULH_normalizes _ _ _ _
      · exact Functions.complete_MULHSU_normalizes _ _ _ _
      · exact Functions.complete_MULHU_normalizes _ _ _ _
    constructiveExecution := by
      have executeEq :
          Functions.execute (decoded op row) =
            Functions.execute_MUL (.Regidx row.rs2) (.Regidx row.rs1)
              (.Regidx row.rd) (generatedSelector op) := by
        cases op <;> rfl
      simpa only [executeEq] using
        (ExecutionClosure.constructiveBinaryRegisterExecution
          stepNo (word op row) (decoded op row) environment.pre.pc
          row.rs1 row.rs2 row.rd
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2)
          (fun source1 source2 => Functions.mult_to_bits_half
            (generatedSelector op).signed_rs1
            (generatedSelector op).signed_rs2 source1 source2
            (generatedSelector op).result_part)
          (reviewedValue op (environment.pre.registers row.rs1)
            (environment.pre.registers row.rs2))
          (reviewedRetirement op row environment) initial
          stateBindings.1.programCounter stateBindings.1.landingPadClear
          stateBindings.2.sourceOne stateBindings.2.sourceTwo
          (by
            cases op with
            | mulh => exact Functions.generatedMulhValue_eq_reviewed _ _
            | mulhsu => exact Functions.generatedMulhsuValue_eq_reviewed _ _
            | mulhu => exact Functions.generatedMulhuValue_eq_reviewed _ _)
          (by cases op <;> rfl)
          (by
            cases op with
            | mulh => exact Functions.complete_MULH_normalizes _ _ _ _
            | mulhsu => exact Functions.complete_MULHSU_normalizes _ _ _ _
            | mulhu => exact Functions.complete_MULHU_normalizes _ _ _ _)
          rfl)
    fullStepFraming :=
      Functions.generated_full_step_retirement_composition stepNo exitWait
  }

end HighMultiply

end LeanRV32IM.Publication
