import ExecutionClosure
import DecodeMulDiv
import MulDivArithmetic
import RiscvRefinement.Publication.TeamB.Multiply

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 100_000
set_option linter.unusedVariables false

open Sail

namespace LeanRV32IM.Publication

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated

/-! ## MUL -/

namespace Multiply

abbrev Row := RiscvRefinement.Publication.TeamB.Multiply.Row
abbrev Witness := RiscvRefinement.Publication.TeamB.Multiply.Witness
abbrev Admission := RiscvRefinement.Publication.TeamB.Multiply.Admission
abbrev Environment := RiscvRefinement.Opcodes.MulEnvironment

def word (row : Row) : BitVec 32 :=
  Functions.encodeAdmittedMType .mul row.rs2 row.rs1 row.rd

def decoded (row : Row) : instruction :=
  Functions.admittedMTypeInstruction .mul row.rs2 row.rs1 row.rd

def ExactExecuteClause (row : Row) : Prop :=
  Functions.execute (decoded row) =
    Functions.execute_MUL
      (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd)
      Functions.mulSelectorLowSigned

def NormalizedRetirement (row : Row) (environment : Environment row) : Prop :=
  Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_MUL
        (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd)
        Functions.mulSelectorLowSigned) =
    Functions.eraseObservation
      (Functions.normalizedRegisterCompletion environment.pre.pc row.rd
        (do
          let source1 ← Functions.rX_bits (.Regidx row.rs1)
          let source2 ← Functions.rX_bits (.Regidx row.rs2)
          pure
            (Functions.mult_to_bits_half
              Functions.mulSelectorLowSigned.signed_rs1
              Functions.mulSelectorLowSigned.signed_rs2
              source1 source2
              Functions.mulSelectorLowSigned.result_part)))

def ConstructiveExecution
    (row : Row) (environment : Environment row)
    (initial : Functions.GeneratedState) (stepNo : Nat) : Prop :=
  Functions.ConstructiveGeneratedExecution stepNo (word row) (decoded row)
    (Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_MUL
        (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd)
        Functions.mulSelectorLowSigned))
    (Functions.normalizedRegisterCompletion environment.pre.pc row.rd
      (do
        let source1 ← Functions.rX_bits (.Regidx row.rs1)
        let source2 ← Functions.rX_bits (.Regidx row.rs2)
        pure (Functions.mult_to_bits_half
          Functions.mulSelectorLowSigned.signed_rs1
          Functions.mulSelectorLowSigned.signed_rs2 source1 source2
          Functions.mulSelectorLowSigned.result_part)))
    initial
    (Sail.Reviewed.executeMul environment.pre.pc
      (environment.pre.registers row.rs1)
      (environment.pre.registers row.rs2) row.rd)

def StateBindings
    (row : Row) (environment : Environment row)
    (initial : Functions.GeneratedState) : Prop :=
  GeneratedInstructionStateBindings environment.pre.pc (word row) initial ∧
    GeneratedBinaryRegisterStateBindings initial row.rs1 row.rs2 row.rd
      (environment.pre.registers row.rs1)
      (environment.pre.registers row.rs2)
      (environment.pre.registers row.rd)

def LocalRefinement (row : Row) (environment : Environment row) : Prop :=
  ∃ fixed : RiscvRefinement.Publication.TeamB.Multiply.FixedConsequences row,
    mulRetirement
        (RiscvRefinement.Publication.TeamB.Multiply.normalize row fixed) =
      Sail.Reviewed.executeMul
        environment.pre.pc
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2)
        row.rd

def AcceptedComposition
    (row : Row) (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : Environment row) (initial : Functions.GeneratedState)
    (stepNo : Nat) (exitWait : Bool) : Prop :=
  AcceptedGeneratedOpcodeComposition
    .mul Programs.mul Programs.mul.source.contentDigest
    (Programs.mul.evalSymbolic
      (RiscvRefinement.Publication.TeamB.Multiply.columns row witness))
    relationHolds (word row) (word row) (decoded row) initial
    (StateBindings row environment initial)
    (GeneratedInstructionProfileAdmission
      environment.pre.pc (word row) initial)
    (Admission row)
    (LocalRefinement row environment)
    (RiscvRefinement.Publication.TeamB.Multiply.ExactTupleProjection
      row witness)
    (ExactExecuteClause row)
    (NormalizedRetirement row environment)
    (ConstructiveExecution row environment initial stepNo)
    stepNo exitWait

def RefinementTheorem : Prop :=
  ∀ (row : Row) (witness : Witness row)
    (environment : Environment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : RiscvRefinement.Publication.AcceptedProductionEvaluation
      (Programs.mul.evalSymbolic
        (RiscvRefinement.Publication.TeamB.Multiply.columns row witness))
      relationHolds)
    (admission : Admission row)
    (initial : Functions.GeneratedState)
    (stateBindings : StateBindings row environment initial)
    (profileAdmission : GeneratedInstructionProfileAdmission
      environment.pre.pc (word row) initial)
    (stepNo : Nat) (exitWait : Bool),
    AcceptedComposition row witness relationHolds environment
      initial stepNo exitWait

theorem accepted_air_refines : RefinementTheorem := by
  intro row witness environment relationHolds accepted admission initial
    stateBindings profileAdmission stepNo exitWait
  let localCertificate :=
    RiscvRefinement.Publication.TeamB.Multiply.mul_accepted_air_implies_retirement
      row witness environment relationHolds accepted admission
  rcases stateBindings.1.decodeState.misa with
    ⟨misaValue, misaBinding, misaMEnabled, _misaCDisabled⟩
  rcases stateBindings.1.decodeState.mseccfg with
    ⟨mseccfgValue, mseccfgBinding⟩
  have decoderCertificate :
      Functions.GeneratedDecodeCertificateAt
        (word row) (decoded row) initial :=
    Functions.decode_admitted_mtype_certificate_at
      .mul row.rs2 row.rs1 row.rd initial misaValue mseccfgValue
      profileAdmission.multiplyEnabled profileAdmission.pauseDisabled
      profileAdmission.landingPadExtensionDisabled
      misaBinding misaMEnabled stateBindings.1.privilege mseccfgBinding
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
    admissionProofUnique := fun first second => Subsingleton.elim first second
    localRefinement := ⟨
      RiscvRefinement.Publication.TeamB.Multiply.fixedConsequences
        row witness accepted.fixedTableRequests,
      localCertificate.2.2.1
    ⟩
    exactTuple := localCertificate.2.2.2.1
    decoder := decoderCertificate
    generatedExecuteSuccess := rfl
    normalizedRetirement :=
      Functions.complete_MUL_normalizes
        environment.pre.pc row.rs2 row.rs1 row.rd
    constructiveExecution := by
      simpa [ConstructiveExecution, decoded] using
        (ExecutionClosure.constructiveBinaryRegisterExecution
          stepNo (word row) (decoded row) environment.pre.pc
          row.rs1 row.rs2 row.rd
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2)
          (fun source1 source2 => Functions.mult_to_bits_half
            .Signed .Signed source1 source2 .Low)
          (Sail.Reviewed.executeMulValue
            (environment.pre.registers row.rs1)
            (environment.pre.registers row.rs2))
          (Sail.Reviewed.executeMul environment.pre.pc
            (environment.pre.registers row.rs1)
            (environment.pre.registers row.rs2) row.rd)
          initial stateBindings.1.programCounter
          stateBindings.1.landingPadClear stateBindings.2.sourceOne
          stateBindings.2.sourceTwo
          (Functions.generatedMulValue_eq_reviewed _ _) rfl
          (Functions.complete_MUL_normalizes _ _ _ _) rfl)
    fullStepFraming :=
      Functions.generated_full_step_retirement_composition stepNo exitWait
  }

end Multiply

end LeanRV32IM.Publication
