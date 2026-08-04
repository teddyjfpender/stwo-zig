import Composition
import DecodeAluBaseState
import DecodeAluIType
import ExecutionCompare
import RiscvRefinement.Publication.TeamA.Compare
import RiscvRefinement.Publication.TeamA.Pilots

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 100_000
set_option linter.unusedVariables false

open Sail

namespace LeanRV32IM.Publication

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Generated

namespace CompareReg

abbrev Kind := Air.Bridge.LtReg.Kind
abbrev Row := RiscvRefinement.Opcodes.Lt.Reg.Row
abbrev Witness := RiscvRefinement.Opcodes.Lt.Reg.Witness
abbrev Admission := RiscvRefinement.Opcodes.Lt.Reg.Admission

def selector : Kind → GeneratedOpcodeSelector
  | .signed => .slt
  | .unsigned => .sltu

def generatedOp : Kind → Functions.AdmittedBaseRTypeOp
  | .signed => .slt
  | .unsigned => .sltu

def word (kind : Kind) (row : Row) : BitVec 32 :=
  Functions.encodeAdmittedBaseRType
    (generatedOp kind) row.rs2 row.rs1 row.rd

def decoded (kind : Kind) (row : Row) : instruction :=
  Functions.admittedBaseRTypeInstruction
    (generatedOp kind) row.rs2 row.rs1 row.rd

def ExactTuple (kind : Kind) (row : Row) : Prop :=
  (Air.Bridge.LtReg.programLookup row).tuple = #[
    Air.Bridge.LtReg.bitVecM31 row.pc,
    M31.reduce (Air.Bridge.LtReg.manifestId kind),
    Air.Bridge.LtReg.bitVecM31 row.rd,
    Air.Bridge.LtReg.bitVecM31 row.rs1,
    Air.Bridge.LtReg.bitVecM31 row.rs2
  ]

def ExactExecuteClause (kind : Kind) (row : Row) : Prop :=
  match kind with
  | .signed => Functions.execute (decoded kind row) =
      Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.rd) .SLT
  | .unsigned => Functions.execute (decoded kind row) =
      Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.rd) .SLTU

def NormalizedRetirement (kind : Kind) (row : Row) : Prop :=
  match kind with
  | .signed => Functions.completeBaseExecution row.pc
      (Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.rd) .SLT) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion row.pc row.rd (do
          let source1 ← Functions.rX_bits (.Regidx row.rs1)
          let source2 ← Functions.rX_bits (.Regidx row.rs2)
          pure (_root_.zero_extend (m := 32)
            (Functions.bool_to_bit (Functions.zopz0zI_s source1 source2)))))
  | .unsigned => Functions.completeBaseExecution row.pc
      (Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.rd) .SLTU) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion row.pc row.rd (do
          let source1 ← Functions.rX_bits (.Regidx row.rs1)
          let source2 ← Functions.rX_bits (.Regidx row.rs2)
          pure (_root_.zero_extend (m := 32)
            (Functions.bool_to_bit (Functions.zopz0zI_u source1 source2)))))

noncomputable def observedProgram (kind : Kind) (row : Row) :=
  match kind with
  | .signed => Functions.normalizedRegisterCompletion row.pc row.rd (do
      let source1 ← Functions.rX_bits (.Regidx row.rs1)
      let source2 ← Functions.rX_bits (.Regidx row.rs2)
      pure (_root_.zero_extend (m := 32)
        (Functions.bool_to_bit (Functions.zopz0zI_s source1 source2))))
  | .unsigned => Functions.normalizedRegisterCompletion row.pc row.rd (do
      let source1 ← Functions.rX_bits (.Regidx row.rs1)
      let source2 ← Functions.rX_bits (.Regidx row.rs2)
      pure (_root_.zero_extend (m := 32)
        (Functions.bool_to_bit (Functions.zopz0zI_u source1 source2))))

def ConstructiveExecution
    (kind : Kind) (row : Row) (initial : Functions.GeneratedState)
    (stepNo : Nat) : Prop :=
  Functions.ConstructiveGeneratedExecution stepNo (word kind row)
    (decoded kind row)
    (Functions.completeBaseExecution row.pc
      (Functions.execute (decoded kind row)))
    (observedProgram kind row) initial
    (RiscvRefinement.Opcodes.Lt.Reg.execute row)

def StateBindings
    (kind : Kind) (row : Row) (initial : Functions.GeneratedState) : Prop :=
  GeneratedInstructionStateBindings row.pc (word kind row) initial ∧
    GeneratedBinaryRegisterStateBindings initial row.rs1 row.rs2 row.rd
      row.rs1Previous.word row.rs2Previous.word row.rdPrevious.word

def AcceptedComposition
    (kind : Kind) (row : Row) (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (initial : Functions.GeneratedState) (stepNo : Nat)
    (exitWait : Bool) : Prop :=
  AcceptedGeneratedOpcodeComposition
    (selector kind) (Air.Bridge.LtReg.program kind)
    (Air.Bridge.LtReg.program kind).source.contentDigest
    ((Air.Bridge.LtReg.program kind).evalSymbolic
      (Air.Bridge.LtReg.columns row witness))
    relationHolds (word kind row) (word kind row) (decoded kind row) initial
    (StateBindings kind row initial)
    (GeneratedInstructionProfileAdmission row.pc (word kind row) initial)
    (Admission row) (RiscvRefinement.Opcodes.Lt.Reg.Refinement row witness)
    (ExactTuple kind row) (ExactExecuteClause kind row)
    (NormalizedRetirement kind row)
    (ConstructiveExecution kind row initial stepNo)
    stepNo exitWait

def RefinementTheorem (kind : Kind) : Prop :=
  ∀ (row : Row) (witness : Witness row) (kindBinds : row.kind = kind)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : RiscvRefinement.Publication.AcceptedProductionEvaluation
      ((Air.Bridge.LtReg.program kind).evalSymbolic
        (Air.Bridge.LtReg.columns row witness)) relationHolds)
    (admission : Admission row) (initial : Functions.GeneratedState)
    (stateBindings : StateBindings kind row initial)
    (profileAdmission : GeneratedInstructionProfileAdmission
      row.pc (word kind row) initial)
    (stepNo : Nat) (exitWait : Bool),
    AcceptedComposition kind row witness relationHolds initial stepNo exitWait

theorem accepted_air_refines (kind : Kind) : RefinementTheorem kind := by
  intro row witness kindBinds relationHolds accepted admission initial
    stateBindings profileAdmission stepNo exitWait
  have legacyAcceptance : Air.Bridge.LtReg.Acceptance row witness := {
    selectors := by
      simpa [Air.Bridge.LtReg.evaluation, kindBinds] using
        accepted.activeProductionRow
    constraints := by
      simpa [Air.Bridge.LtReg.evaluation, kindBinds] using
        accepted.directConstraints
    fixedLookups := by
      simpa [Air.Bridge.LtReg.evaluation, kindBinds] using
        accepted.fixedTableRequests
  }
  have localRefinement :
      RiscvRefinement.Opcodes.Lt.Reg.Refinement row witness := by
    cases kind
    · exact (RiscvRefinement.Publication.TeamA.Compare.slt_accepted_air_implies_retirement
        row witness kindBinds admission legacyAcceptance).semanticRefinement
    · exact (RiscvRefinement.Publication.TeamA.Compare.sltu_accepted_air_implies_retirement
        row witness kindBinds admission legacyAcceptance).semanticRefinement
  have exactTuple : ExactTuple kind row := by
    cases kind
    · simpa [ExactTuple, selector] using
        (RiscvRefinement.Publication.TeamA.Compare.slt_accepted_air_implies_retirement
          row witness kindBinds admission legacyAcceptance).exactProgramTuple
    · simpa [ExactTuple, selector] using
        (RiscvRefinement.Publication.TeamA.Compare.sltu_accepted_air_implies_retirement
          row witness kindBinds admission legacyAcceptance).exactProgramTuple
  have retirement :
      RiscvRefinement.Opcodes.Lt.Reg.execute row = {
        nextPc := nextPc row.pc
        write := architecturalWrite row.rd
          (RiscvRefinement.Opcodes.Lt.Reg.resultWord row)
      } := by
    cases kind
    · exact (RiscvRefinement.Publication.TeamA.Compare.slt_accepted_air_implies_retirement
        row witness kindBinds admission legacyAcceptance).retirement
    · exact (RiscvRefinement.Publication.TeamA.Compare.sltu_accepted_air_implies_retirement
        row witness kindBinds admission legacyAcceptance).retirement
  rcases stateBindings.1.decodeState.mseccfg with
    ⟨mseccfgValue, mseccfgBinding⟩
  have decoderCertificate :
      Functions.GeneratedDecodeCertificateAt
        (word kind row) (decoded kind row) initial :=
    Functions.decode_admitted_base_rtype_certificate_at (generatedOp kind)
      row.rs2 row.rs1 row.rd initial mseccfgValue
      profileAdmission.ntlDisabled profileAdmission.pauseDisabled
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
    admissionProofUnique := fun first second => Subsingleton.elim first second
    localRefinement := localRefinement
    exactTuple := exactTuple
    decoder := decoderCertificate
    generatedExecuteSuccess := by cases kind <;> rfl
    normalizedRetirement := by
      cases kind
      · exact Functions.complete_SLT_normalizes _ _ _ _
      · exact Functions.complete_SLTU_normalizes _ _ _ _
    constructiveExecution := by
      unfold ConstructiveExecution observedProgram
      cases kind
      · apply ExecutionClosure.constructiveBinaryRegisterExecution
          (stepNo := stepNo) (word := word .signed row)
          (decoded := decoded .signed row) (pc := row.pc)
          (rs1 := row.rs1) (rs2 := row.rs2) (rd := row.rd)
          (source1 := row.rs1Previous.word)
          (source2 := row.rs2Previous.word)
          (compute := fun left right => _root_.zero_extend (m := 32)
            (Functions.bool_to_bit (Functions.zopz0zI_s left right)))
          (retirementValue :=
            RiscvRefinement.Opcodes.Lt.Reg.resultWord row)
          (retirement := RiscvRefinement.Opcodes.Lt.Reg.execute row)
          (initial := initial)
        · exact stateBindings.1.programCounter
        · exact stateBindings.1.landingPadClear
        · exact stateBindings.2.sourceOne
        · exact stateBindings.2.sourceTwo
        · simpa [RiscvRefinement.Opcodes.Lt.Reg.resultWord, kindBinds] using
            ExecutionCompare.generatedRegValue_eq_resultWord
              Air.Bridge.LtReg.Kind.signed row.rs1Previous row.rs2Previous
        · simpa [decoded, generatedOp] using
            Functions.execute_RTYPE_SLT_eq
              (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd)
        · simpa [decoded, generatedOp] using
            Functions.complete_SLT_normalizes row.pc row.rs2 row.rs1 row.rd
        · exact retirement
      · apply ExecutionClosure.constructiveBinaryRegisterExecution
          (stepNo := stepNo) (word := word .unsigned row)
          (decoded := decoded .unsigned row) (pc := row.pc)
          (rs1 := row.rs1) (rs2 := row.rs2) (rd := row.rd)
          (source1 := row.rs1Previous.word)
          (source2 := row.rs2Previous.word)
          (compute := fun left right => _root_.zero_extend (m := 32)
            (Functions.bool_to_bit (Functions.zopz0zI_u left right)))
          (retirementValue :=
            RiscvRefinement.Opcodes.Lt.Reg.resultWord row)
          (retirement := RiscvRefinement.Opcodes.Lt.Reg.execute row)
          (initial := initial)
        · exact stateBindings.1.programCounter
        · exact stateBindings.1.landingPadClear
        · exact stateBindings.2.sourceOne
        · exact stateBindings.2.sourceTwo
        · simpa [RiscvRefinement.Opcodes.Lt.Reg.resultWord, kindBinds] using
            ExecutionCompare.generatedRegValue_eq_resultWord
              Air.Bridge.LtReg.Kind.unsigned row.rs1Previous row.rs2Previous
        · simpa [decoded, generatedOp] using
            Functions.execute_RTYPE_SLTU_eq
              (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd)
        · simpa [decoded, generatedOp] using
            Functions.complete_SLTU_normalizes row.pc row.rs2 row.rs1 row.rd
        · exact retirement
    fullStepFraming :=
      Functions.generated_full_step_retirement_composition stepNo exitWait
  }

end CompareReg

namespace CompareImm

abbrev Kind := Air.Bridge.LtImm.Kind
abbrev Row := RiscvRefinement.Opcodes.Lt.Imm.Row
abbrev Witness := RiscvRefinement.Opcodes.Lt.Imm.Witness
abbrev Admission := RiscvRefinement.Opcodes.Lt.Imm.Admission

def selector : Kind → GeneratedOpcodeSelector
  | .signed => .slti
  | .unsigned => .sltiu

def generatedOp : Kind → Functions.AdmittedITypeOp
  | .signed => .slti
  | .unsigned => .sltiu

def word (kind : Kind) (row : Row) : BitVec 32 :=
  Functions.encodeAdmittedIType
    (generatedOp kind) row.immediate row.rs1 row.rd

def decoded (kind : Kind) (row : Row) : instruction :=
  Functions.admittedITypeInstruction
    (generatedOp kind) row.immediate row.rs1 row.rd

def ExactTuple (kind : Kind) (row : Row) : Prop :=
  (Air.Bridge.LtImm.programLookup row).tuple = #[
    Air.Bridge.LtImm.bitVecM31 row.pc,
    M31.reduce (Air.Bridge.LtImm.manifestId kind),
    Air.Bridge.LtImm.bitVecM31 row.rd,
    Air.Bridge.LtImm.bitVecM31 row.rs1,
    Air.Bridge.LtImm.immediateField row
  ]

def ExactExecuteClause (kind : Kind) (row : Row) : Prop :=
  match kind with
  | .signed => Functions.execute (decoded kind row) =
      Functions.execute_ITYPE row.immediate
        (.Regidx row.rs1) (.Regidx row.rd) .SLTI
  | .unsigned => Functions.execute (decoded kind row) =
      Functions.execute_ITYPE row.immediate
        (.Regidx row.rs1) (.Regidx row.rd) .SLTIU

def NormalizedRetirement (kind : Kind) (row : Row) : Prop :=
  match kind with
  | .signed => Functions.completeBaseExecution row.pc
      (Functions.execute_ITYPE row.immediate
        (.Regidx row.rs1) (.Regidx row.rd) .SLTI) =
      Functions.eraseObservation (Functions.normalizedRegisterCompletion
        row.pc row.rd (do
          let source ← Functions.rX_bits (.Regidx row.rs1)
          let immediate : xlenbits :=
            Functions.sign_extend (m := 32) row.immediate
          pure (_root_.zero_extend (m := 32)
            (Functions.bool_to_bit
              (Functions.zopz0zI_s source immediate)))))
  | .unsigned => Functions.completeBaseExecution row.pc
      (Functions.execute_ITYPE row.immediate
        (.Regidx row.rs1) (.Regidx row.rd) .SLTIU) =
      Functions.eraseObservation (Functions.normalizedRegisterCompletion
        row.pc row.rd (do
          let source ← Functions.rX_bits (.Regidx row.rs1)
          let immediate : xlenbits :=
            Functions.sign_extend (m := 32) row.immediate
          pure (_root_.zero_extend (m := 32)
            (Functions.bool_to_bit
              (Functions.zopz0zI_u source immediate)))))

noncomputable def observedProgram (kind : Kind) (row : Row) :=
  match kind with
  | .signed => Functions.normalizedRegisterCompletion row.pc row.rd (do
      let source ← Functions.rX_bits (.Regidx row.rs1)
      let immediate : xlenbits :=
        Functions.sign_extend (m := 32) row.immediate
      pure (_root_.zero_extend (m := 32)
        (Functions.bool_to_bit (Functions.zopz0zI_s source immediate))))
  | .unsigned => Functions.normalizedRegisterCompletion row.pc row.rd (do
      let source ← Functions.rX_bits (.Regidx row.rs1)
      let immediate : xlenbits :=
        Functions.sign_extend (m := 32) row.immediate
      pure (_root_.zero_extend (m := 32)
        (Functions.bool_to_bit (Functions.zopz0zI_u source immediate))))

def ConstructiveExecution
    (kind : Kind) (row : Row) (initial : Functions.GeneratedState)
    (stepNo : Nat) : Prop :=
  Functions.ConstructiveGeneratedExecution stepNo (word kind row)
    (decoded kind row)
    (Functions.completeBaseExecution row.pc
      (Functions.execute (decoded kind row)))
    (observedProgram kind row) initial
    (RiscvRefinement.Opcodes.Lt.Imm.execute row)

def StateBindings
    (kind : Kind) (row : Row) (initial : Functions.GeneratedState) : Prop :=
  GeneratedInstructionStateBindings row.pc (word kind row) initial ∧
    GeneratedUnaryRegisterStateBindings initial row.rs1 row.rd
      row.rs1Previous.word row.rdPrevious.word

def AcceptedComposition
    (kind : Kind) (row : Row) (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (initial : Functions.GeneratedState) (stepNo : Nat)
    (exitWait : Bool) : Prop :=
  AcceptedGeneratedOpcodeComposition
    (selector kind) (Air.Bridge.LtImm.program kind)
    (Air.Bridge.LtImm.program kind).source.contentDigest
    ((Air.Bridge.LtImm.program kind).evalSymbolic
      (Air.Bridge.LtImm.columns row witness))
    relationHolds (word kind row) (word kind row) (decoded kind row) initial
    (StateBindings kind row initial)
    (GeneratedInstructionProfileAdmission row.pc (word kind row) initial)
    (Admission row) (RiscvRefinement.Opcodes.Lt.Imm.Refinement row witness)
    (ExactTuple kind row) (ExactExecuteClause kind row)
    (NormalizedRetirement kind row)
    (ConstructiveExecution kind row initial stepNo)
    stepNo exitWait

def RefinementTheorem (kind : Kind) : Prop :=
  ∀ (row : Row) (witness : Witness row) (kindBinds : row.kind = kind)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : RiscvRefinement.Publication.AcceptedProductionEvaluation
      ((Air.Bridge.LtImm.program kind).evalSymbolic
        (Air.Bridge.LtImm.columns row witness)) relationHolds)
    (admission : Admission row) (initial : Functions.GeneratedState)
    (stateBindings : StateBindings kind row initial)
    (profileAdmission : GeneratedInstructionProfileAdmission
      row.pc (word kind row) initial)
    (stepNo : Nat) (exitWait : Bool),
    AcceptedComposition kind row witness relationHolds initial stepNo exitWait

theorem accepted_air_refines (kind : Kind) : RefinementTheorem kind := by
  intro row witness kindBinds relationHolds accepted admission initial
    stateBindings profileAdmission stepNo exitWait
  have legacyAcceptance : Air.Bridge.LtImm.Acceptance row witness := {
    selectors := by
      simpa [Air.Bridge.LtImm.evaluation, kindBinds] using
        accepted.activeProductionRow
    constraints := by
      simpa [Air.Bridge.LtImm.evaluation, kindBinds] using
        accepted.directConstraints
    fixedLookups := by
      simpa [Air.Bridge.LtImm.evaluation, kindBinds] using
        accepted.fixedTableRequests
  }
  have localRefinement :
      RiscvRefinement.Opcodes.Lt.Imm.Refinement row witness := by
    cases kind
    · exact (RiscvRefinement.Publication.TeamA.Compare.slti_accepted_air_implies_retirement
        row witness kindBinds admission legacyAcceptance).semanticRefinement
    · exact (RiscvRefinement.Publication.TeamA.Compare.sltiu_accepted_air_implies_retirement
        row witness kindBinds admission legacyAcceptance).semanticRefinement
  have exactTuple : ExactTuple kind row := by
    cases kind
    · simpa [ExactTuple, selector] using
        (RiscvRefinement.Publication.TeamA.Compare.slti_accepted_air_implies_retirement
          row witness kindBinds admission legacyAcceptance).exactProgramTuple
    · simpa [ExactTuple, selector] using
        (RiscvRefinement.Publication.TeamA.Compare.sltiu_accepted_air_implies_retirement
          row witness kindBinds admission legacyAcceptance).exactProgramTuple
  have retirement :
      RiscvRefinement.Opcodes.Lt.Imm.execute row = {
        nextPc := nextPc row.pc
        write := architecturalWrite row.rd
          (RiscvRefinement.Opcodes.Lt.Imm.resultWord row)
      } := by
    cases kind
    · exact (RiscvRefinement.Publication.TeamA.Compare.slti_accepted_air_implies_retirement
        row witness kindBinds admission legacyAcceptance).retirement
    · exact (RiscvRefinement.Publication.TeamA.Compare.sltiu_accepted_air_implies_retirement
        row witness kindBinds admission legacyAcceptance).retirement
  rcases stateBindings.1.decodeState.mseccfg with
    ⟨mseccfgValue, mseccfgBinding⟩
  have decoderCertificate :
      Functions.GeneratedDecodeCertificateAt
        (word kind row) (decoded kind row) initial :=
    Functions.decode_admitted_itype_certificate_at (generatedOp kind)
      row.immediate row.rs1 row.rd initial mseccfgValue
      profileAdmission.zicbopDisabled profileAdmission.pauseDisabled
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
    admissionProofUnique := fun first second => Subsingleton.elim first second
    localRefinement := localRefinement
    exactTuple := exactTuple
    decoder := decoderCertificate
    generatedExecuteSuccess := by cases kind <;> rfl
    normalizedRetirement := by
      cases kind
      · exact Functions.complete_SLTI_normalizes _ _ _ _
      · exact Functions.complete_SLTIU_normalizes _ _ _ _
    constructiveExecution := by
      unfold ConstructiveExecution observedProgram
      cases kind
      · apply ExecutionClosure.constructiveUnaryRegisterExecution
          (stepNo := stepNo) (word := word .signed row)
          (decoded := decoded .signed row) (pc := row.pc)
          (rs1 := row.rs1) (rd := row.rd)
          (source := row.rs1Previous.word)
          (compute := fun source => _root_.zero_extend (m := 32)
            (Functions.bool_to_bit (Functions.zopz0zI_s source
              (Functions.sign_extend (m := 32) row.immediate))))
          (retirementValue :=
            RiscvRefinement.Opcodes.Lt.Imm.resultWord row)
          (retirement := RiscvRefinement.Opcodes.Lt.Imm.execute row)
          (initial := initial)
        · exact stateBindings.1.programCounter
        · exact stateBindings.1.landingPadClear
        · exact stateBindings.2.source
        · simpa [RiscvRefinement.Opcodes.Lt.Imm.resultWord, kindBinds] using
            ExecutionCompare.generatedImmValue_eq_resultWord
              Air.Bridge.LtReg.Kind.signed row.rs1Previous row.immediate
        · simpa [decoded, generatedOp] using
            Functions.execute_ITYPE_SLTI_eq row.immediate
              (.Regidx row.rs1) (.Regidx row.rd)
        · simpa [decoded, generatedOp] using
            Functions.complete_SLTI_normalizes
              row.pc row.immediate row.rs1 row.rd
        · exact retirement
      · apply ExecutionClosure.constructiveUnaryRegisterExecution
          (stepNo := stepNo) (word := word .unsigned row)
          (decoded := decoded .unsigned row) (pc := row.pc)
          (rs1 := row.rs1) (rd := row.rd)
          (source := row.rs1Previous.word)
          (compute := fun source => _root_.zero_extend (m := 32)
            (Functions.bool_to_bit (Functions.zopz0zI_u source
              (Functions.sign_extend (m := 32) row.immediate))))
          (retirementValue :=
            RiscvRefinement.Opcodes.Lt.Imm.resultWord row)
          (retirement := RiscvRefinement.Opcodes.Lt.Imm.execute row)
          (initial := initial)
        · exact stateBindings.1.programCounter
        · exact stateBindings.1.landingPadClear
        · exact stateBindings.2.source
        · simpa [RiscvRefinement.Opcodes.Lt.Imm.resultWord, kindBinds] using
            ExecutionCompare.generatedImmValue_eq_resultWord
              Air.Bridge.LtReg.Kind.unsigned row.rs1Previous row.immediate
        · simpa [decoded, generatedOp] using
            Functions.execute_ITYPE_SLTIU_eq row.immediate
              (.Regidx row.rs1) (.Regidx row.rd)
        · simpa [decoded, generatedOp] using
            Functions.complete_SLTIU_normalizes
              row.pc row.immediate row.rs1 row.rd
        · exact retirement
    fullStepFraming :=
      Functions.generated_full_step_retirement_composition stepNo exitWait
  }

end CompareImm

namespace Addi

abbrev Row := AddiRow
abbrev Witness (row : Row) := Air.Bridge.Addi.Witness row
abbrev Environment (row : Row) :=
  RiscvRefinement.Opcodes.AddiEnvironment
    (Air.Bridge.Addi.interpretedRow row)
abbrev Admission (row : Row) := Air.Bridge.Addi.Admission row

def immediate (row : Row) : BitVec 12 :=
  addiImmediate row.imm0 row.imm1 row.immSign

def word (row : Row) (environment : Environment row) : BitVec 32 :=
  environment.word

def expectedWord (row : Row) : BitVec 32 :=
  Functions.encodeAdmittedIType .addi (immediate row) row.rs1 row.rd

def decoded (row : Row) : instruction :=
  Functions.admittedITypeInstruction .addi
    (immediate row) row.rs1 row.rd

def ExactTuple (row : Row) : Prop :=
  (Air.Bridge.Addi.programLookup row).tuple = #[
    Air.Bridge.Addi.bitVecM31 row.pc, M31.reduce 10,
    Air.Bridge.Addi.bitVecM31 row.rd,
    Air.Bridge.Addi.bitVecM31 row.rs1,
    Air.Bridge.Addi.bitVecM31 row.imm0 +
      Air.Bridge.Addi.bitVecM31 row.imm1 * M31.reduce 256 +
      Air.Bridge.Addi.bitVecM31 row.immSign * M31.reduce 2048
  ]

def NormalizedRetirement (row : Row) (environment : Environment row) : Prop :=
  Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_ITYPE (immediate row)
        (.Regidx row.rs1) (.Regidx row.rd) .ADDI) =
    Functions.eraseObservation
      (Functions.normalizedRegisterCompletion environment.pre.pc row.rd (do
        let source ← Functions.rX_bits (.Regidx row.rs1)
        pure (source + Functions.sign_extend (m := 32) (immediate row))))

noncomputable def observedProgram (row : Row) (environment : Environment row) :=
  Functions.normalizedRegisterCompletion environment.pre.pc row.rd (do
    let source ← Functions.rX_bits (.Regidx row.rs1)
    pure (source + Functions.sign_extend (m := 32) (immediate row)))

def ConstructiveExecution
    (row : Row) (environment : Environment row)
    (initial : Functions.GeneratedState) (stepNo : Nat) : Prop :=
  Functions.ConstructiveGeneratedExecution stepNo environment.word
    (decoded row)
    (Functions.completeBaseExecution environment.pre.pc
      (Functions.execute (decoded row)))
    (observedProgram row environment) initial
    (addiRetirement (Air.Bridge.Addi.interpretedRow row))

def StateBindings
    (row : Row) (environment : Environment row)
    (initial : Functions.GeneratedState) : Prop :=
  GeneratedInstructionStateBindings
      environment.pre.pc environment.word initial ∧
    GeneratedUnaryRegisterStateBindings initial row.rs1 row.rd
      (environment.pre.registers row.rs1)
      (environment.pre.registers row.rd)

def AcceptedComposition
    (row : Row) (witness : Witness row) (environment : Environment row)
    (relationHolds : EvaluatedLookup → Prop)
    (initial : Functions.GeneratedState) (stepNo : Nat)
    (exitWait : Bool) : Prop :=
  AcceptedGeneratedOpcodeComposition .addi Programs.addi
    Programs.addi.source.contentDigest
    (Programs.addi.evalSymbolic (Air.Bridge.Addi.columns row witness))
    relationHolds environment.word (expectedWord row) (decoded row) initial
    (StateBindings row environment initial)
    (GeneratedInstructionProfileAdmission
      environment.pre.pc environment.word initial)
    (Admission row)
    (RiscvRefinement.Opcodes.AddiRefinement
      (Air.Bridge.Addi.interpretedRow row) environment)
    (ExactTuple row)
    (Functions.execute (decoded row) = Functions.execute_ITYPE
      (immediate row) (.Regidx row.rs1) (.Regidx row.rd) .ADDI)
    (NormalizedRetirement row environment)
    (ConstructiveExecution row environment initial stepNo)
    stepNo exitWait

def RefinementTheorem : Prop :=
  ∀ (row : Row) (witness : Witness row) (environment : Environment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : RiscvRefinement.Publication.AcceptedProductionEvaluation
      (Programs.addi.evalSymbolic (Air.Bridge.Addi.columns row witness))
      relationHolds)
    (admission : Admission row) (initial : Functions.GeneratedState)
    (stateBindings : StateBindings row environment initial)
    (profileAdmission : GeneratedInstructionProfileAdmission
      environment.pre.pc environment.word initial)
    (stepNo : Nat) (exitWait : Bool),
    AcceptedComposition row witness environment relationHolds
      initial stepNo exitWait

theorem accepted_air_refines : RefinementTheorem := by
  intro row witness environment relationHolds accepted admission initial
    stateBindings profileAdmission stepNo exitWait
  let legacyAcceptance : Air.Bridge.Addi.Acceptance row witness := {
    selectors := accepted.activeProductionRow
    constraints := accepted.directConstraints
    fixedLookups := accepted.fixedTableRequests
  }
  let localCertificate :=
    RiscvRefinement.Publication.TeamA.Pilots.addi_accepted_air_implies_retirement
      row witness environment admission legacyAcceptance
  have wordEq : environment.word = expectedWord row := by
    rw [environment.wordBinds]
    rfl
  rcases stateBindings.1.decodeState.mseccfg with
    ⟨mseccfgValue, mseccfgBinding⟩
  have decoderCertificate :
      Functions.GeneratedDecodeCertificateAt
        environment.word (decoded row) initial := by
    rw [wordEq]
    exact Functions.decode_admitted_itype_certificate_at .addi
      (immediate row) row.rs1 row.rd initial mseccfgValue
      profileAdmission.zicbopDisabled profileAdmission.pauseDisabled
      profileAdmission.landingPadExtensionDisabled
      stateBindings.1.privilege mseccfgBinding
  exact {
    acceptedProduction := accepted
    inputBoundSelector := {
      schemaVersion := rfl
      manifestId := rfl
      mnemonic := rfl
      digest := rfl
      inputWord := wordEq
    }
    stateBindings := stateBindings
    profileAdmission := profileAdmission
    admission := admission
    admissionProofUnique := fun first second => Subsingleton.elim first second
    localRefinement := localCertificate.semanticRefinement
    exactTuple := localCertificate.exactProgramTuple
    decoder := decoderCertificate
    generatedExecuteSuccess := rfl
    normalizedRetirement := Functions.complete_ADDI_normalizes
      environment.pre.pc (immediate row) row.rs1 row.rd
    constructiveExecution := by
      unfold ConstructiveExecution observedProgram
      apply ExecutionClosure.constructiveUnaryRegisterExecution
          (stepNo := stepNo) (word := environment.word)
          (decoded := decoded row) (pc := environment.pre.pc)
          (rs1 := row.rs1) (rd := row.rd)
          (source := environment.pre.registers row.rs1)
          (compute := fun source =>
            source + Functions.sign_extend (m := 32) (immediate row))
          (retirementValue :=
            Sail.Generated.executeAddiValue
              (environment.pre.registers row.rs1) (immediate row))
          (retirement :=
            addiRetirement (Air.Bridge.Addi.interpretedRow row))
          (initial := initial)
      · exact stateBindings.1.programCounter
      · exact stateBindings.1.landingPadClear
      · exact stateBindings.2.source
      · rfl
      · simpa [decoded] using
          Functions.execute_ITYPE_ADDI_eq
            (immediate row) (.Regidx row.rs1) (.Regidx row.rd)
      · simpa [decoded] using Functions.complete_ADDI_normalizes
          environment.pre.pc (immediate row) row.rs1 row.rd
      · simpa [Sail.Generated.executeAddi] using localCertificate.retirement
    fullStepFraming :=
      Functions.generated_full_step_retirement_composition stepNo exitWait
  }

end Addi

theorem SLT_accepted_air_refines : CompareReg.RefinementTheorem .signed :=
  CompareReg.accepted_air_refines .signed
theorem SLTU_accepted_air_refines : CompareReg.RefinementTheorem .unsigned :=
  CompareReg.accepted_air_refines .unsigned
theorem SLTI_accepted_air_refines : CompareImm.RefinementTheorem .signed :=
  CompareImm.accepted_air_refines .signed
theorem SLTIU_accepted_air_refines : CompareImm.RefinementTheorem .unsigned :=
  CompareImm.accepted_air_refines .unsigned
theorem ADDI_accepted_air_refines : Addi.RefinementTheorem :=
  Addi.accepted_air_refines

end LeanRV32IM.Publication
