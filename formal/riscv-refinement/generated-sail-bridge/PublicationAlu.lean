import Composition
import DecodeAluBaseState
import DecodeAluIType
import ExecutionClosure
import RiscvRefinement.Publication.TeamA.BaseAlu
import RiscvRefinement.Publication.TeamA.Pilots

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 100_000
set_option linter.unusedVariables false

open Sail

namespace LeanRV32IM.Publication

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Generated

namespace BaseReg

abbrev Op := RiscvRefinement.Opcodes.BaseAluReg.Op
abbrev Row := RiscvRefinement.Opcodes.BaseAluReg.Row
abbrev Witness := RiscvRefinement.Opcodes.BaseAluReg.Witness
abbrev Environment := RiscvRefinement.Opcodes.BaseAluReg.Environment
abbrev Admission := RiscvRefinement.Opcodes.BaseAluReg.Admission

def selector : Op → GeneratedOpcodeSelector
  | .add => .add
  | .sub => .sub
  | .xor => .xor
  | .or => .or
  | .and => .and

def generatedOp : Op → Functions.AdmittedBaseRTypeOp
  | .add => .add
  | .sub => .sub
  | .xor => .xor
  | .or => .or
  | .and => .and

def word (op : Op) (row : Row) : BitVec 32 :=
  Functions.encodeAdmittedBaseRType
    (generatedOp op) row.rs2 row.rs1 row.rd

def decoded (op : Op) (row : Row) : instruction :=
  Functions.admittedBaseRTypeInstruction
    (generatedOp op) row.rs2 row.rs1 row.rd

def ExactTuple (op : Op) (row : Row) : Prop :=
  (Air.Bridge.BaseAluReg.programLookup op row).tuple = #[
    Air.Bridge.BaseAluReg.bitVecM31 row.pc,
    M31.reduce (RiscvRefinement.Decode.baseAluRegOpcodeId op),
    Air.Bridge.BaseAluReg.bitVecM31 row.rd,
    Air.Bridge.BaseAluReg.bitVecM31 row.rs1,
    Air.Bridge.BaseAluReg.bitVecM31 row.rs2
  ]

def ExactExecuteClause (op : Op) (row : Row) : Prop :=
  match op with
  | .add => Functions.execute (decoded op row) =
      Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.rd) .ADD
  | .sub => Functions.execute (decoded op row) =
      Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.rd) .SUB
  | .xor => Functions.execute (decoded op row) =
      Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.rd) .XOR
  | .or => Functions.execute (decoded op row) =
      Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.rd) .OR
  | .and => Functions.execute (decoded op row) =
      Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.rd) .AND

def NormalizedRetirement
    (op : Op) (row : Row) (environment : Environment row) : Prop :=
  match op with
  | .add => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.rd) .ADD) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion environment.pre.pc row.rd
          (do
            let source1 ← Functions.rX_bits (.Regidx row.rs1)
            let source2 ← Functions.rX_bits (.Regidx row.rs2)
            pure (source1 + source2)))
  | .sub => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.rd) .SUB) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion environment.pre.pc row.rd
          (do
            let source1 ← Functions.rX_bits (.Regidx row.rs1)
            let source2 ← Functions.rX_bits (.Regidx row.rs2)
            pure (source1 - source2)))
  | .xor => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.rd) .XOR) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion environment.pre.pc row.rd
          (do
            let source1 ← Functions.rX_bits (.Regidx row.rs1)
            let source2 ← Functions.rX_bits (.Regidx row.rs2)
            pure (source1 ^^^ source2)))
  | .or => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.rd) .OR) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion environment.pre.pc row.rd
          (do
            let source1 ← Functions.rX_bits (.Regidx row.rs1)
            let source2 ← Functions.rX_bits (.Regidx row.rs2)
            pure (source1 ||| source2)))
  | .and => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.rd) .AND) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion environment.pre.pc row.rd
          (do
            let source1 ← Functions.rX_bits (.Regidx row.rs1)
            let source2 ← Functions.rX_bits (.Regidx row.rs2)
            pure (source1 &&& source2)))

noncomputable def observedProgram
    (op : Op) (row : Row) (environment : Environment row) :=
  match op with
  | .add => Functions.normalizedRegisterCompletion environment.pre.pc row.rd
      (do
        let source1 ← Functions.rX_bits (.Regidx row.rs1)
        let source2 ← Functions.rX_bits (.Regidx row.rs2)
        pure (source1 + source2))
  | .sub => Functions.normalizedRegisterCompletion environment.pre.pc row.rd
      (do
        let source1 ← Functions.rX_bits (.Regidx row.rs1)
        let source2 ← Functions.rX_bits (.Regidx row.rs2)
        pure (source1 - source2))
  | .xor => Functions.normalizedRegisterCompletion environment.pre.pc row.rd
      (do
        let source1 ← Functions.rX_bits (.Regidx row.rs1)
        let source2 ← Functions.rX_bits (.Regidx row.rs2)
        pure (source1 ^^^ source2))
  | .or => Functions.normalizedRegisterCompletion environment.pre.pc row.rd
      (do
        let source1 ← Functions.rX_bits (.Regidx row.rs1)
        let source2 ← Functions.rX_bits (.Regidx row.rs2)
        pure (source1 ||| source2))
  | .and => Functions.normalizedRegisterCompletion environment.pre.pc row.rd
      (do
        let source1 ← Functions.rX_bits (.Regidx row.rs1)
        let source2 ← Functions.rX_bits (.Regidx row.rs2)
        pure (source1 &&& source2))

def ConstructiveExecution
    (op : Op) (row : Row) (environment : Environment row)
    (initial : Functions.GeneratedState) (stepNo : Nat) : Prop :=
  Functions.ConstructiveGeneratedExecution stepNo (word op row)
    (decoded op row)
    (Functions.completeBaseExecution environment.pre.pc
      (Functions.execute (decoded op row)))
    (observedProgram op row environment) initial
    (RiscvRefinement.Opcodes.BaseAluReg.airRetirement row)

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
    (selector op) (Air.Bridge.BaseAluReg.program op)
    (Air.Bridge.BaseAluReg.program op).source.contentDigest
    ((Air.Bridge.BaseAluReg.program op).evalSymbolic
      (Air.Bridge.BaseAluReg.columns op row witness))
    relationHolds (word op row) (word op row) (decoded op row) initial
    (StateBindings op row environment initial)
    (GeneratedInstructionProfileAdmission
      environment.pre.pc (word op row) initial)
    (Admission row)
    (RiscvRefinement.Opcodes.BaseAluReg.Refinement
      op row witness environment)
    (ExactTuple op row) (ExactExecuteClause op row)
    (NormalizedRetirement op row environment)
    (ConstructiveExecution op row environment initial stepNo)
    stepNo exitWait

def RefinementTheorem (op : Op) : Prop :=
  ∀ (row : Row) (witness : Witness row)
    (environment : Environment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : RiscvRefinement.Publication.AcceptedProductionEvaluation
      ((Air.Bridge.BaseAluReg.program op).evalSymbolic
        (Air.Bridge.BaseAluReg.columns op row witness)) relationHolds)
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
  let legacyAcceptance :
      RiscvRefinement.Opcodes.BaseAluReg.Acceptance op row witness := {
    selectors := accepted.activeProductionRow
    constraints := accepted.directConstraints
    fixedLookups := accepted.fixedTableRequests
  }
  let localCertificate :=
    RiscvRefinement.Publication.TeamA.BaseAlu.Reg.accepted_air_implies_retirement
      op row witness environment admission legacyAcceptance
  rcases stateBindings.1.decodeState.mseccfg with
    ⟨mseccfgValue, mseccfgBinding⟩
  have decoderCertificate :
      Functions.GeneratedDecodeCertificateAt
        (word op row) (decoded op row) initial :=
    Functions.decode_admitted_base_rtype_certificate_at
      (generatedOp op) row.rs2 row.rs1 row.rd
      initial mseccfgValue profileAdmission.ntlDisabled
      profileAdmission.pauseDisabled
      profileAdmission.landingPadExtensionDisabled
      stateBindings.1.privilege mseccfgBinding
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
    localRefinement := localCertificate.semanticRefinement
    exactTuple := localCertificate.exactProgramTuple
    decoder := decoderCertificate
    generatedExecuteSuccess := by cases op <;> rfl
    normalizedRetirement := by
      cases op
      · exact Functions.complete_ADD_normalizes _ _ _ _
      · exact Functions.complete_SUB_normalizes _ _ _ _
      · exact Functions.complete_XOR_normalizes _ _ _ _
      · exact Functions.complete_OR_normalizes _ _ _ _
      · exact Functions.complete_AND_normalizes _ _ _ _
    constructiveExecution := by
      unfold ConstructiveExecution observedProgram
      cases op
      · apply ExecutionClosure.constructiveBinaryRegisterExecution
          (stepNo := stepNo) (word := word .add row)
          (decoded := decoded .add row) (pc := environment.pre.pc)
          (rs1 := row.rs1) (rs2 := row.rs2) (rd := row.rd)
          (source1 := environment.pre.registers row.rs1)
          (source2 := environment.pre.registers row.rs2)
          (compute := fun left right => left + right)
          (retirementValue :=
            environment.pre.registers row.rs1 +
              environment.pre.registers row.rs2)
          (retirement :=
            RiscvRefinement.Opcodes.BaseAluReg.airRetirement row)
          (initial := initial)
        · exact stateBindings.1.programCounter
        · exact stateBindings.1.landingPadClear
        · exact stateBindings.2.sourceOne
        · exact stateBindings.2.sourceTwo
        · rfl
        · simpa [decoded, generatedOp] using
            Functions.execute_RTYPE_ADD_eq
              (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd)
        · simpa [decoded, generatedOp] using
            Functions.complete_ADD_normalizes
              environment.pre.pc row.rs2 row.rs1 row.rd
        · simpa [
            RiscvRefinement.Opcodes.BaseAluReg.execute,
            Air.Bridge.BaseAluReg.executeValue,
          ] using localCertificate.retirement
      · apply ExecutionClosure.constructiveBinaryRegisterExecution
          (stepNo := stepNo) (word := word .sub row)
          (decoded := decoded .sub row) (pc := environment.pre.pc)
          (rs1 := row.rs1) (rs2 := row.rs2) (rd := row.rd)
          (source1 := environment.pre.registers row.rs1)
          (source2 := environment.pre.registers row.rs2)
          (compute := fun left right => left - right)
          (retirementValue :=
            environment.pre.registers row.rs1 -
              environment.pre.registers row.rs2)
          (retirement :=
            RiscvRefinement.Opcodes.BaseAluReg.airRetirement row)
          (initial := initial)
        · exact stateBindings.1.programCounter
        · exact stateBindings.1.landingPadClear
        · exact stateBindings.2.sourceOne
        · exact stateBindings.2.sourceTwo
        · rfl
        · simpa [decoded, generatedOp] using
            Functions.execute_RTYPE_SUB_eq
              (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd)
        · simpa [decoded, generatedOp] using
            Functions.complete_SUB_normalizes
              environment.pre.pc row.rs2 row.rs1 row.rd
        · simpa [
            RiscvRefinement.Opcodes.BaseAluReg.execute,
            Air.Bridge.BaseAluReg.executeValue,
          ] using localCertificate.retirement
      · apply ExecutionClosure.constructiveBinaryRegisterExecution
          (stepNo := stepNo) (word := word .xor row)
          (decoded := decoded .xor row) (pc := environment.pre.pc)
          (rs1 := row.rs1) (rs2 := row.rs2) (rd := row.rd)
          (source1 := environment.pre.registers row.rs1)
          (source2 := environment.pre.registers row.rs2)
          (compute := fun left right => left ^^^ right)
          (retirementValue :=
            environment.pre.registers row.rs1 ^^^
              environment.pre.registers row.rs2)
          (retirement :=
            RiscvRefinement.Opcodes.BaseAluReg.airRetirement row)
          (initial := initial)
        · exact stateBindings.1.programCounter
        · exact stateBindings.1.landingPadClear
        · exact stateBindings.2.sourceOne
        · exact stateBindings.2.sourceTwo
        · rfl
        · simpa [decoded, generatedOp] using
            Functions.execute_RTYPE_XOR_eq
              (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd)
        · simpa [decoded, generatedOp] using
            Functions.complete_XOR_normalizes
              environment.pre.pc row.rs2 row.rs1 row.rd
        · simpa [
            RiscvRefinement.Opcodes.BaseAluReg.execute,
            Air.Bridge.BaseAluReg.executeValue,
          ] using localCertificate.retirement
      · apply ExecutionClosure.constructiveBinaryRegisterExecution
          (stepNo := stepNo) (word := word .or row)
          (decoded := decoded .or row) (pc := environment.pre.pc)
          (rs1 := row.rs1) (rs2 := row.rs2) (rd := row.rd)
          (source1 := environment.pre.registers row.rs1)
          (source2 := environment.pre.registers row.rs2)
          (compute := fun left right => left ||| right)
          (retirementValue :=
            environment.pre.registers row.rs1 |||
              environment.pre.registers row.rs2)
          (retirement :=
            RiscvRefinement.Opcodes.BaseAluReg.airRetirement row)
          (initial := initial)
        · exact stateBindings.1.programCounter
        · exact stateBindings.1.landingPadClear
        · exact stateBindings.2.sourceOne
        · exact stateBindings.2.sourceTwo
        · rfl
        · simpa [decoded, generatedOp] using
            Functions.execute_RTYPE_OR_eq
              (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd)
        · simpa [decoded, generatedOp] using
            Functions.complete_OR_normalizes
              environment.pre.pc row.rs2 row.rs1 row.rd
        · simpa [
            RiscvRefinement.Opcodes.BaseAluReg.execute,
            Air.Bridge.BaseAluReg.executeValue,
          ] using localCertificate.retirement
      · apply ExecutionClosure.constructiveBinaryRegisterExecution
          (stepNo := stepNo) (word := word .and row)
          (decoded := decoded .and row) (pc := environment.pre.pc)
          (rs1 := row.rs1) (rs2 := row.rs2) (rd := row.rd)
          (source1 := environment.pre.registers row.rs1)
          (source2 := environment.pre.registers row.rs2)
          (compute := fun left right => left &&& right)
          (retirementValue :=
            environment.pre.registers row.rs1 &&&
              environment.pre.registers row.rs2)
          (retirement :=
            RiscvRefinement.Opcodes.BaseAluReg.airRetirement row)
          (initial := initial)
        · exact stateBindings.1.programCounter
        · exact stateBindings.1.landingPadClear
        · exact stateBindings.2.sourceOne
        · exact stateBindings.2.sourceTwo
        · rfl
        · simpa [decoded, generatedOp] using
            Functions.execute_RTYPE_AND_eq
              (.Regidx row.rs2) (.Regidx row.rs1) (.Regidx row.rd)
        · simpa [decoded, generatedOp] using
            Functions.complete_AND_normalizes
              environment.pre.pc row.rs2 row.rs1 row.rd
        · simpa [
            RiscvRefinement.Opcodes.BaseAluReg.execute,
            Air.Bridge.BaseAluReg.executeValue,
          ] using localCertificate.retirement
    fullStepFraming :=
      Functions.generated_full_step_retirement_composition stepNo exitWait
  }

end BaseReg

namespace BaseImm

abbrev Op := RiscvRefinement.Opcodes.BaseAluImm.Op
abbrev Row := RiscvRefinement.Opcodes.BaseAluImm.Row
abbrev Witness := RiscvRefinement.Opcodes.BaseAluImm.Witness
abbrev Environment := RiscvRefinement.Opcodes.BaseAluImm.Environment
abbrev Admission := RiscvRefinement.Opcodes.BaseAluImm.Admission

def selector : Op → GeneratedOpcodeSelector
  | .xori => .xori
  | .ori => .ori
  | .andi => .andi

def generatedOp : Op → Functions.AdmittedITypeOp
  | .xori => .xori
  | .ori => .ori
  | .andi => .andi

def word (op : Op) (row : Row) : BitVec 32 :=
  Functions.encodeAdmittedIType (generatedOp op)
    (RiscvRefinement.Opcodes.BaseAluImm.immediate row) row.rs1 row.rd

def decoded (op : Op) (row : Row) : instruction :=
  Functions.admittedITypeInstruction (generatedOp op)
    (RiscvRefinement.Opcodes.BaseAluImm.immediate row) row.rs1 row.rd

def ExactTuple (op : Op) (row : Row) : Prop :=
  (Air.Bridge.BaseAluImm.programLookup op row).tuple = #[
    Air.Bridge.BaseAluImm.bitVecM31 row.pc,
    M31.reduce (RiscvRefinement.Decode.baseAluImmOpcodeId op),
    Air.Bridge.BaseAluImm.bitVecM31 row.rd,
    Air.Bridge.BaseAluImm.bitVecM31 row.rs1,
    Air.Bridge.BaseAluImm.immediateUnsignedField row
  ]

def ExactExecuteClause (op : Op) (row : Row) : Prop :=
  match op with
  | .xori => Functions.execute (decoded op row) = Functions.execute_ITYPE
      (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
      (.Regidx row.rs1) (.Regidx row.rd) .XORI
  | .ori => Functions.execute (decoded op row) = Functions.execute_ITYPE
      (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
      (.Regidx row.rs1) (.Regidx row.rd) .ORI
  | .andi => Functions.execute (decoded op row) = Functions.execute_ITYPE
      (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
      (.Regidx row.rs1) (.Regidx row.rd) .ANDI

def NormalizedRetirement
    (op : Op) (row : Row) (environment : Environment row) : Prop :=
  match op with
  | .xori => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_ITYPE
        (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
        (.Regidx row.rs1) (.Regidx row.rd) .XORI) =
      Functions.eraseObservation (Functions.normalizedRegisterCompletion
        environment.pre.pc row.rd (do
          let source ← Functions.rX_bits (.Regidx row.rs1)
          let immediate : xlenbits := Functions.sign_extend
            (m := 32) (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
          pure (source ^^^ immediate)))
  | .ori => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_ITYPE
        (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
        (.Regidx row.rs1) (.Regidx row.rd) .ORI) =
      Functions.eraseObservation (Functions.normalizedRegisterCompletion
        environment.pre.pc row.rd (do
          let source ← Functions.rX_bits (.Regidx row.rs1)
          let immediate : xlenbits := Functions.sign_extend
            (m := 32) (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
          pure (source ||| immediate)))
  | .andi => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_ITYPE
        (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
        (.Regidx row.rs1) (.Regidx row.rd) .ANDI) =
      Functions.eraseObservation (Functions.normalizedRegisterCompletion
        environment.pre.pc row.rd (do
          let source ← Functions.rX_bits (.Regidx row.rs1)
          let immediate : xlenbits := Functions.sign_extend
            (m := 32) (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
          pure (source &&& immediate)))

noncomputable def observedProgram
    (op : Op) (row : Row) (environment : Environment row) :=
  match op with
  | .xori => Functions.normalizedRegisterCompletion environment.pre.pc row.rd
      (do
        let source ← Functions.rX_bits (.Regidx row.rs1)
        let immediate : xlenbits := Functions.sign_extend
          (m := 32) (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
        pure (source ^^^ immediate))
  | .ori => Functions.normalizedRegisterCompletion environment.pre.pc row.rd
      (do
        let source ← Functions.rX_bits (.Regidx row.rs1)
        let immediate : xlenbits := Functions.sign_extend
          (m := 32) (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
        pure (source ||| immediate))
  | .andi => Functions.normalizedRegisterCompletion environment.pre.pc row.rd
      (do
        let source ← Functions.rX_bits (.Regidx row.rs1)
        let immediate : xlenbits := Functions.sign_extend
          (m := 32) (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
        pure (source &&& immediate))

def ConstructiveExecution
    (op : Op) (row : Row) (environment : Environment row)
    (initial : Functions.GeneratedState) (stepNo : Nat) : Prop :=
  Functions.ConstructiveGeneratedExecution stepNo (word op row)
    (decoded op row)
    (Functions.completeBaseExecution environment.pre.pc
      (Functions.execute (decoded op row)))
    (observedProgram op row environment) initial
    (RiscvRefinement.Opcodes.BaseAluImm.airRetirement row)

def StateBindings
    (op : Op) (row : Row) (environment : Environment row)
    (initial : Functions.GeneratedState) : Prop :=
  GeneratedInstructionStateBindings environment.pre.pc (word op row) initial ∧
    GeneratedUnaryRegisterStateBindings initial row.rs1 row.rd
      (environment.pre.registers row.rs1)
      (environment.pre.registers row.rd)

def AcceptedComposition
    (op : Op) (row : Row) (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : Environment row) (initial : Functions.GeneratedState)
    (stepNo : Nat) (exitWait : Bool) : Prop :=
  AcceptedGeneratedOpcodeComposition
    (selector op) (Air.Bridge.BaseAluImm.program op)
    (Air.Bridge.BaseAluImm.program op).source.contentDigest
    ((Air.Bridge.BaseAluImm.program op).evalSymbolic
      (Air.Bridge.BaseAluImm.columns op row witness))
    relationHolds (word op row) (word op row) (decoded op row) initial
    (StateBindings op row environment initial)
    (GeneratedInstructionProfileAdmission
      environment.pre.pc (word op row) initial)
    (Admission row)
    (RiscvRefinement.Opcodes.BaseAluImm.Refinement
      op row witness environment)
    (ExactTuple op row) (ExactExecuteClause op row)
    (NormalizedRetirement op row environment)
    (ConstructiveExecution op row environment initial stepNo)
    stepNo exitWait

def RefinementTheorem (op : Op) : Prop :=
  ∀ (row : Row) (witness : Witness row) (environment : Environment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : RiscvRefinement.Publication.AcceptedProductionEvaluation
      ((Air.Bridge.BaseAluImm.program op).evalSymbolic
        (Air.Bridge.BaseAluImm.columns op row witness)) relationHolds)
    (admission : Admission row) (initial : Functions.GeneratedState)
    (stateBindings : StateBindings op row environment initial)
    (profileAdmission : GeneratedInstructionProfileAdmission
      environment.pre.pc (word op row) initial)
    (stepNo : Nat) (exitWait : Bool),
    AcceptedComposition op row witness relationHolds environment
      initial stepNo exitWait

theorem accepted_air_refines (op : Op) : RefinementTheorem op := by
  intro row witness environment relationHolds accepted admission initial
    stateBindings profileAdmission stepNo exitWait
  let legacyAcceptance :
      RiscvRefinement.Opcodes.BaseAluImm.Acceptance op row witness := {
    selectors := accepted.activeProductionRow
    constraints := accepted.directConstraints
    fixedLookups := accepted.fixedTableRequests
  }
  let localCertificate :=
    RiscvRefinement.Publication.TeamA.BaseAlu.Imm.accepted_air_implies_retirement
      op row witness environment admission legacyAcceptance
  rcases stateBindings.1.decodeState.mseccfg with
    ⟨mseccfgValue, mseccfgBinding⟩
  have decoderCertificate :
      Functions.GeneratedDecodeCertificateAt
        (word op row) (decoded op row) initial :=
    Functions.decode_admitted_itype_certificate_at (generatedOp op)
      (RiscvRefinement.Opcodes.BaseAluImm.immediate row) row.rs1 row.rd
      initial mseccfgValue profileAdmission.zicbopDisabled
      profileAdmission.pauseDisabled
      profileAdmission.landingPadExtensionDisabled
      stateBindings.1.privilege mseccfgBinding
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
    localRefinement := localCertificate.semanticRefinement
    exactTuple := localCertificate.exactProgramTuple
    decoder := decoderCertificate
    generatedExecuteSuccess := by cases op <;> rfl
    normalizedRetirement := by
      cases op
      · simpa [NormalizedRetirement] using
          Functions.complete_XORI_normalizes environment.pre.pc
            (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
            row.rs1 row.rd
      · simpa [NormalizedRetirement] using
          Functions.complete_ORI_normalizes environment.pre.pc
            (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
            row.rs1 row.rd
      · simpa [NormalizedRetirement] using
          Functions.complete_ANDI_normalizes environment.pre.pc
            (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
            row.rs1 row.rd
    constructiveExecution := by
      unfold ConstructiveExecution observedProgram
      cases op
      · apply ExecutionClosure.constructiveUnaryRegisterExecution
          (stepNo := stepNo) (word := word .xori row)
          (decoded := decoded .xori row) (pc := environment.pre.pc)
          (rs1 := row.rs1) (rd := row.rd)
          (source := environment.pre.registers row.rs1)
          (compute := fun source => source ^^^ Functions.sign_extend
            (m := 32) (RiscvRefinement.Opcodes.BaseAluImm.immediate row))
          (retirementValue :=
            environment.pre.registers row.rs1 ^^^ Functions.sign_extend
              (m := 32) (RiscvRefinement.Opcodes.BaseAluImm.immediate row))
          (retirement :=
            RiscvRefinement.Opcodes.BaseAluImm.airRetirement row)
          (initial := initial)
        · exact stateBindings.1.programCounter
        · exact stateBindings.1.landingPadClear
        · exact stateBindings.2.source
        · rfl
        · simpa [decoded, generatedOp] using
            Functions.execute_ITYPE_XORI_eq
              (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
              (.Regidx row.rs1) (.Regidx row.rd)
        · simpa [decoded, generatedOp] using
            Functions.complete_XORI_normalizes environment.pre.pc
              (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
              row.rs1 row.rd
        · simpa [
            RiscvRefinement.Opcodes.BaseAluImm.execute,
            RiscvRefinement.Opcodes.BaseAluImm.executeValue,
          ] using localCertificate.retirement
      · apply ExecutionClosure.constructiveUnaryRegisterExecution
          (stepNo := stepNo) (word := word .ori row)
          (decoded := decoded .ori row) (pc := environment.pre.pc)
          (rs1 := row.rs1) (rd := row.rd)
          (source := environment.pre.registers row.rs1)
          (compute := fun source => source ||| Functions.sign_extend
            (m := 32) (RiscvRefinement.Opcodes.BaseAluImm.immediate row))
          (retirementValue :=
            environment.pre.registers row.rs1 ||| Functions.sign_extend
              (m := 32) (RiscvRefinement.Opcodes.BaseAluImm.immediate row))
          (retirement :=
            RiscvRefinement.Opcodes.BaseAluImm.airRetirement row)
          (initial := initial)
        · exact stateBindings.1.programCounter
        · exact stateBindings.1.landingPadClear
        · exact stateBindings.2.source
        · rfl
        · simpa [decoded, generatedOp] using
            Functions.execute_ITYPE_ORI_eq
              (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
              (.Regidx row.rs1) (.Regidx row.rd)
        · simpa [decoded, generatedOp] using
            Functions.complete_ORI_normalizes environment.pre.pc
              (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
              row.rs1 row.rd
        · simpa [
            RiscvRefinement.Opcodes.BaseAluImm.execute,
            RiscvRefinement.Opcodes.BaseAluImm.executeValue,
          ] using localCertificate.retirement
      · apply ExecutionClosure.constructiveUnaryRegisterExecution
          (stepNo := stepNo) (word := word .andi row)
          (decoded := decoded .andi row) (pc := environment.pre.pc)
          (rs1 := row.rs1) (rd := row.rd)
          (source := environment.pre.registers row.rs1)
          (compute := fun source => source &&& Functions.sign_extend
            (m := 32) (RiscvRefinement.Opcodes.BaseAluImm.immediate row))
          (retirementValue :=
            environment.pre.registers row.rs1 &&& Functions.sign_extend
              (m := 32) (RiscvRefinement.Opcodes.BaseAluImm.immediate row))
          (retirement :=
            RiscvRefinement.Opcodes.BaseAluImm.airRetirement row)
          (initial := initial)
        · exact stateBindings.1.programCounter
        · exact stateBindings.1.landingPadClear
        · exact stateBindings.2.source
        · rfl
        · simpa [decoded, generatedOp] using
            Functions.execute_ITYPE_ANDI_eq
              (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
              (.Regidx row.rs1) (.Regidx row.rd)
        · simpa [decoded, generatedOp] using
            Functions.complete_ANDI_normalizes environment.pre.pc
              (RiscvRefinement.Opcodes.BaseAluImm.immediate row)
              row.rs1 row.rd
        · simpa [
            RiscvRefinement.Opcodes.BaseAluImm.execute,
            RiscvRefinement.Opcodes.BaseAluImm.executeValue,
          ] using localCertificate.retirement
    fullStepFraming :=
      Functions.generated_full_step_retirement_composition stepNo exitWait
  }

end BaseImm

theorem ADD_accepted_air_refines : BaseReg.RefinementTheorem .add :=
  BaseReg.accepted_air_refines .add
theorem SUB_accepted_air_refines : BaseReg.RefinementTheorem .sub :=
  BaseReg.accepted_air_refines .sub
theorem XOR_accepted_air_refines : BaseReg.RefinementTheorem .xor :=
  BaseReg.accepted_air_refines .xor
theorem OR_accepted_air_refines : BaseReg.RefinementTheorem .or :=
  BaseReg.accepted_air_refines .or
theorem AND_accepted_air_refines : BaseReg.RefinementTheorem .and :=
  BaseReg.accepted_air_refines .and
theorem XORI_accepted_air_refines : BaseImm.RefinementTheorem .xori :=
  BaseImm.accepted_air_refines .xori
theorem ORI_accepted_air_refines : BaseImm.RefinementTheorem .ori :=
  BaseImm.accepted_air_refines .ori
theorem ANDI_accepted_air_refines : BaseImm.RefinementTheorem .andi :=
  BaseImm.accepted_air_refines .andi

end LeanRV32IM.Publication
