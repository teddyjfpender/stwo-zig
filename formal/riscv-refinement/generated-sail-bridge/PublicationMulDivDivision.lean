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

/-! ## DIV / DIVU / REM / REMU -/

namespace Division

abbrev Op :=
  RiscvRefinement.Publication.TeamB.MulhDiv.Division.Selector
abbrev Row :=
  RiscvRefinement.Publication.TeamB.MulhDiv.Division.Row
abbrev Witness :=
  RiscvRefinement.Publication.TeamB.MulhDiv.Division.Witness
abbrev Admission :=
  RiscvRefinement.Publication.TeamB.MulhDiv.Division.Admission
abbrev Environment := RiscvRefinement.Opcodes.DivEnvironment

def selector : Op → GeneratedOpcodeSelector
  | .div => .div
  | .divu => .divu
  | .rem => .rem
  | .remu => .remu

def generatedOp : Op → Functions.AdmittedMTypeOp
  | .div => .div
  | .divu => .divu
  | .rem => .rem
  | .remu => .remu

def program : Op → LocalProgram
  | .div => Programs.div
  | .divu => Programs.divu
  | .rem => Programs.rem
  | .remu => Programs.remu

def word (op : Op) (row : Row) : BitVec 32 :=
  Functions.encodeAdmittedMType (generatedOp op) row.rs2 row.rs1 row.rd

def decoded (op : Op) (row : Row) : instruction :=
  Functions.admittedMTypeInstruction
    (generatedOp op) row.rs2 row.rs1 row.rd

def ExactExecuteClause (op : Op) (row : Row) : Prop :=
  match op with
  | .div => Functions.execute (decoded op row) =
      Functions.execute_DIV
        (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd) false
  | .divu => Functions.execute (decoded op row) =
      Functions.execute_DIV
        (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd) true
  | .rem => Functions.execute (decoded op row) =
      Functions.execute_REM
        (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd) false
  | .remu => Functions.execute (decoded op row) =
      Functions.execute_REM
        (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd) true

def NormalizedRetirement
    (op : Op) (row : Row) (environment : Environment row) : Prop :=
  match op with
  | .div => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_DIV
        (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd) false) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion environment.pre.pc row.rd
          (Functions.generatedDivValue
            (.Regidx row.rs2) (.Regidx row.rs1) false))
  | .divu => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_DIV
        (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd) true) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion environment.pre.pc row.rd
          (Functions.generatedDivValue
            (.Regidx row.rs2) (.Regidx row.rs1) true))
  | .rem => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_REM
        (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd) false) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion environment.pre.pc row.rd
          (Functions.generatedRemValue
            (.Regidx row.rs2) (.Regidx row.rs1) false))
  | .remu => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_REM
        (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd) true) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion environment.pre.pc row.rd
          (Functions.generatedRemValue
            (.Regidx row.rs2) (.Regidx row.rs1) true))

def reviewedValue
    (op : Op) (source1 source2 : BitVec 32) : BitVec 32 :=
  match op with
  | .div => Sail.Reviewed.executeDivValue source1 source2
  | .divu => Sail.Reviewed.executeDivuValue source1 source2
  | .rem => Sail.Reviewed.executeRemValue source1 source2
  | .remu => Sail.Reviewed.executeRemuValue source1 source2

def reviewedRetirement
    (op : Op) (row : Row) (environment : Environment row) : Retirement := {
  nextPc := RiscvRefinement.nextPc environment.pre.pc
  write := RiscvRefinement.architecturalWrite row.rd
    (reviewedValue op (environment.pre.registers row.rs1)
      (environment.pre.registers row.rs2))
  read := none
  store := none
}

def generatedResult (op : Op) (source1 source2 : BitVec 32) : BitVec 32 :=
  match op with
  | .div => Functions.generatedDivResult source1 source2 false
  | .divu => Functions.generatedDivResult source1 source2 true
  | .rem => Functions.generatedRemResult source1 source2 false
  | .remu => Functions.generatedRemResult source1 source2 true

def ConstructiveExecution
    (op : Op) (row : Row) (environment : Environment row)
    (initial : Functions.GeneratedState) (stepNo : Nat) : Prop :=
  Functions.ConstructiveGeneratedExecution stepNo
    (word op row) (decoded op row)
    (Functions.completeBaseExecution environment.pre.pc
      (Functions.execute (decoded op row)))
    (Functions.normalizedRegisterCompletion environment.pre.pc row.rd (do
      let source1 ← Functions.rX_bits (.Regidx row.rs1)
      let source2 ← Functions.rX_bits (.Regidx row.rs2)
      pure (generatedResult op source1 source2)))
    initial (reviewedRetirement op row environment)

def LocalRefinement
    (op : Op) (row : Row) (environment : Environment row) : Prop :=
  let normalized :=
    RiscvRefinement.Publication.TeamB.MulhDiv.Division.normalize row
  match op with
  | .div => divRetirement normalized = Sail.Reviewed.executeDiv
      environment.pre.pc row.rd
      (environment.pre.registers row.rs1)
      (environment.pre.registers row.rs2)
  | .divu => divRetirement normalized = Sail.Reviewed.executeDivu
      environment.pre.pc row.rd
      (environment.pre.registers row.rs1)
      (environment.pre.registers row.rs2)
  | .rem => divRetirement normalized = Sail.Reviewed.executeRem
      environment.pre.pc row.rd
      (environment.pre.registers row.rs1)
      (environment.pre.registers row.rs2)
  | .remu => divRetirement normalized = Sail.Reviewed.executeRemu
      environment.pre.pc row.rd
      (environment.pre.registers row.rs1)
      (environment.pre.registers row.rs2)

def LocalResult
    (op : Op) (row : Row) (witness : Witness row)
    (environment : Environment row) : Prop :=
  LocalRefinement op row environment ∧
    RiscvRefinement.Publication.TeamB.MulhDiv.Division.ExactTupleProjection
      op row witness

theorem localResult
    (op : Op) (row : Row) (witness : Witness row)
    (environment : Environment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : RiscvRefinement.Publication.AcceptedProductionEvaluation
      ((program op).evalSymbolic
        (RiscvRefinement.Publication.TeamB.MulhDiv.Division.columns
          row witness)) relationHolds)
    (admission : Admission row) :
    LocalResult op row witness environment := by
  cases op
  · have selectedAccepted :
        RiscvRefinement.Publication.AcceptedProductionEvaluation
          (Programs.div.evalSymbolic
            (RiscvRefinement.Publication.TeamB.MulhDiv.Division.columns
              row witness)) relationHolds := by
      simpa only [program] using accepted
    have certificate :=
      RiscvRefinement.Publication.TeamB.MulhDiv.Division.div_accepted_air_implies_retirement
        row witness environment relationHolds selectedAccepted admission
    change
      (divRetirement
          (RiscvRefinement.Publication.TeamB.MulhDiv.Division.normalize row) =
        Sail.Reviewed.executeDiv environment.pre.pc row.rd
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2)) ∧
      RiscvRefinement.Publication.TeamB.MulhDiv.Division.ExactTupleProjection
        .div row witness
    have semantic := certificate.2.2.1
    have exactTuple :=
      RiscvRefinement.Publication.TeamB.MulhDiv.Division.exactTupleProjection
        .div row witness
    exact And.intro semantic exactTuple
  · have selectedAccepted :
        RiscvRefinement.Publication.AcceptedProductionEvaluation
          (Programs.divu.evalSymbolic
            (RiscvRefinement.Publication.TeamB.MulhDiv.Division.columns
              row witness)) relationHolds := by
      simpa only [program] using accepted
    have certificate :=
      RiscvRefinement.Publication.TeamB.MulhDiv.Division.divu_accepted_air_implies_retirement
        row witness environment relationHolds selectedAccepted admission
    change
      (divRetirement
          (RiscvRefinement.Publication.TeamB.MulhDiv.Division.normalize row) =
        Sail.Reviewed.executeDivu environment.pre.pc row.rd
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2)) ∧
      RiscvRefinement.Publication.TeamB.MulhDiv.Division.ExactTupleProjection
        .divu row witness
    have semantic := certificate.2.2.1
    have exactTuple :=
      RiscvRefinement.Publication.TeamB.MulhDiv.Division.exactTupleProjection
        .divu row witness
    exact And.intro semantic exactTuple
  · have selectedAccepted :
        RiscvRefinement.Publication.AcceptedProductionEvaluation
          (Programs.rem.evalSymbolic
            (RiscvRefinement.Publication.TeamB.MulhDiv.Division.columns
              row witness)) relationHolds := by
      simpa only [program] using accepted
    have certificate :=
      RiscvRefinement.Publication.TeamB.MulhDiv.Division.rem_accepted_air_implies_retirement
        row witness environment relationHolds selectedAccepted admission
    change
      (divRetirement
          (RiscvRefinement.Publication.TeamB.MulhDiv.Division.normalize row) =
        Sail.Reviewed.executeRem environment.pre.pc row.rd
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2)) ∧
      RiscvRefinement.Publication.TeamB.MulhDiv.Division.ExactTupleProjection
        .rem row witness
    have semantic := certificate.2.2.1
    have exactTuple :=
      RiscvRefinement.Publication.TeamB.MulhDiv.Division.exactTupleProjection
        .rem row witness
    exact And.intro semantic exactTuple
  · have selectedAccepted :
        RiscvRefinement.Publication.AcceptedProductionEvaluation
          (Programs.remu.evalSymbolic
            (RiscvRefinement.Publication.TeamB.MulhDiv.Division.columns
              row witness)) relationHolds := by
      simpa only [program] using accepted
    have certificate :=
      RiscvRefinement.Publication.TeamB.MulhDiv.Division.remu_accepted_air_implies_retirement
        row witness environment relationHolds selectedAccepted admission
    change
      (divRetirement
          (RiscvRefinement.Publication.TeamB.MulhDiv.Division.normalize row) =
        Sail.Reviewed.executeRemu environment.pre.pc row.rd
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2)) ∧
      RiscvRefinement.Publication.TeamB.MulhDiv.Division.ExactTupleProjection
        .remu row witness
    have semantic := certificate.2.2.1
    have exactTuple :=
      RiscvRefinement.Publication.TeamB.MulhDiv.Division.exactTupleProjection
        .remu row witness
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
      (RiscvRefinement.Publication.TeamB.MulhDiv.Division.columns row witness))
    relationHolds (word op row) (word op row) (decoded op row) initial
    (StateBindings op row environment initial)
    (GeneratedInstructionProfileAdmission
      environment.pre.pc (word op row) initial)
    (Admission row)
    (LocalRefinement op row environment)
    (RiscvRefinement.Publication.TeamB.MulhDiv.Division.ExactTupleProjection
      op row witness)
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
        (RiscvRefinement.Publication.TeamB.MulhDiv.Division.columns row witness))
      relationHolds)
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
      · exact Functions.complete_DIV_normalizes _ _ _ _
      · exact Functions.complete_DIVU_normalizes _ _ _ _
      · exact Functions.complete_REM_normalizes _ _ _ _
      · exact Functions.complete_REMU_normalizes _ _ _ _
    constructiveExecution := by
      unfold ConstructiveExecution
      exact ExecutionClosure.constructiveBinaryRegisterExecution
        stepNo (word op row) (decoded op row) environment.pre.pc
        row.rs1 row.rs2 row.rd
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2) (generatedResult op)
        (reviewedValue op (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2))
        (reviewedRetirement op row environment) initial
        stateBindings.1.programCounter stateBindings.1.landingPadClear
        stateBindings.2.sourceOne stateBindings.2.sourceTwo
        (by
          cases op with
          | div => exact Functions.generatedDivValue_eq_reviewed _ _
          | divu => exact Functions.generatedDivuValue_eq_reviewed _ _
          | rem => exact Functions.generatedRemValue_eq_reviewed _ _
          | remu => exact Functions.generatedRemuValue_eq_reviewed _ _)
        (by cases op <;> rfl)
        (by
          cases op with
          | div => exact Functions.complete_DIV_normalizes _ _ _ _
          | divu => exact Functions.complete_DIVU_normalizes _ _ _ _
          | rem => exact Functions.complete_REM_normalizes _ _ _ _
          | remu => exact Functions.complete_REMU_normalizes _ _ _ _)
        (by cases op <;> rfl)
    fullStepFraming :=
      Functions.generated_full_step_retirement_composition stepNo exitWait
  }

end Division

end LeanRV32IM.Publication
