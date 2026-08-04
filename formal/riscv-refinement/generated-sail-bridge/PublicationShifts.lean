import Composition
import DecodeAluBaseState
import DecodeAluShiftCertificates
import ExecutionClosure
import RiscvRefinement.Publication.TeamB.Shifts

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 100_000
set_option linter.unusedVariables false

open Sail

namespace LeanRV32IM.Publication

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated
open RiscvRefinement.Opcodes

private theorem generatedRegisterShiftAmount_eq
    (value : BitVec 32) :
    Sail.BitVec.extractLsb value (Functions.log2_xlen -i 1) 0 =
      RiscvRefinement.Sail.Reviewed.registerShiftAmount value := by
  apply BitVec.eq_of_toNat_eq
  simp [
    Functions.log2_xlen,
    Sail.BitVec.extractLsb,
    RiscvRefinement.Sail.Reviewed.registerShiftAmount,
  ]

private theorem generatedImmediateShiftAmount_eq
    (amount : BitVec 5) :
    Sail.BitVec.extractLsb ((0#1 : BitVec 1) +++ amount)
        (Functions.log2_xlen -i 1) 0 = amount := by
  simp only [
    Functions.log2_xlen,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ]
  bv_decide

namespace ShiftReg

abbrev Kind := ShiftKind
abbrev Row := ShiftsRegRow
abbrev Witness (row : Row) :=
  RiscvRefinement.Publication.TeamB.Shifts.RegWitness row
abbrev Environment (row : Row) := ShiftsRegEnvironment row

def selector : Kind → GeneratedOpcodeSelector
  | .sll => .sll
  | .srl => .srl
  | .sra => .sra

def program : Kind → LocalProgram :=
  RiscvRefinement.Publication.TeamB.Shifts.regProgram

def generatedOp : Kind → Functions.AdmittedBaseRTypeOp
  | .sll => .sll
  | .srl => .srl
  | .sra => .sra

def expectedIdentity : Kind →
    RiscvRefinement.Publication.ProgramIdentity
  | .sll => RiscvRefinement.Publication.TeamB.Shifts.sllProgramIdentity
  | .srl => RiscvRefinement.Publication.TeamB.Shifts.srlProgramIdentity
  | .sra => RiscvRefinement.Publication.TeamB.Shifts.sraProgramIdentity

def expectedWord (row : Row) : BitVec 32 :=
  Functions.encodeAdmittedBaseRType (generatedOp row.semantic.kind)
    row.rs2 row.rs1 row.semantic.rd

def decoded (row : Row) : instruction :=
  Functions.admittedBaseRTypeInstruction (generatedOp row.semantic.kind)
    row.rs2 row.rs1 row.semantic.rd

def Admission (row : Row) (witness : Witness row) : Prop :=
  RiscvRefinement.Publication.TeamB.Shifts.RegAdmission row ∧
    RiscvRefinement.Publication.TeamB.Shifts.RegBindings row witness

def LocalRefinement
    (kind : Kind) (row : Row) (witness : Witness row)
    (environment : Environment row)
    (relationHolds : EvaluatedLookup → Prop) : Prop :=
  RiscvRefinement.Publication.TeamB.Shifts.RegPublicationResult
    (program kind) (expectedIdentity kind) row witness environment relationHolds

def ExactTuple (row : Row) (witness : Witness row) : Prop :=
  RiscvRefinement.Publication.TeamB.Shifts.RegExactRelationProjection row witness

def ExactExecuteClause (row : Row) : Prop :=
  match row.semantic.kind with
  | .sll => Functions.execute (decoded row) =
      Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.semantic.rd) .SLL
  | .srl => Functions.execute (decoded row) =
      Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.semantic.rd) .SRL
  | .sra => Functions.execute (decoded row) =
      Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.semantic.rd) .SRA

def NormalizedRetirement (row : Row) (environment : Environment row) : Prop :=
  match row.semantic.kind with
  | .sll => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.semantic.rd) .SLL) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion environment.pre.pc
          row.semantic.rd (do
            let source1 ← Functions.rX_bits (.Regidx row.rs1)
            let source2 ← Functions.rX_bits (.Regidx row.rs2)
            pure (Sail.shift_bits_left source1
              (Sail.BitVec.extractLsb source2
                (Functions.log2_xlen -i 1) 0))))
  | .srl => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.semantic.rd) .SRL) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion environment.pre.pc
          row.semantic.rd (do
            let source1 ← Functions.rX_bits (.Regidx row.rs1)
            let source2 ← Functions.rX_bits (.Regidx row.rs2)
            pure (Sail.shift_bits_right source1
              (Sail.BitVec.extractLsb source2
                (Functions.log2_xlen -i 1) 0))))
  | .sra => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_RTYPE (.Regidx row.rs2) (.Regidx row.rs1)
        (.Regidx row.semantic.rd) .SRA) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion environment.pre.pc
          row.semantic.rd (do
            let source1 ← Functions.rX_bits (.Regidx row.rs1)
            let source2 ← Functions.rX_bits (.Regidx row.rs2)
            pure (Functions.shift_bits_right_arith source1
              (Sail.BitVec.extractLsb source2
                (Functions.log2_xlen -i 1) 0))))

noncomputable def observedProgram (row : Row) (environment : Environment row) :=
  match row.semantic.kind with
  | .sll => Functions.normalizedRegisterCompletion environment.pre.pc
      row.semantic.rd (do
        let source1 ← Functions.rX_bits (.Regidx row.rs1)
        let source2 ← Functions.rX_bits (.Regidx row.rs2)
        pure (Sail.shift_bits_left source1
          (Sail.BitVec.extractLsb source2
            (Functions.log2_xlen -i 1) 0)))
  | .srl => Functions.normalizedRegisterCompletion environment.pre.pc
      row.semantic.rd (do
        let source1 ← Functions.rX_bits (.Regidx row.rs1)
        let source2 ← Functions.rX_bits (.Regidx row.rs2)
        pure (Sail.shift_bits_right source1
          (Sail.BitVec.extractLsb source2
            (Functions.log2_xlen -i 1) 0)))
  | .sra => Functions.normalizedRegisterCompletion environment.pre.pc
      row.semantic.rd (do
        let source1 ← Functions.rX_bits (.Regidx row.rs1)
        let source2 ← Functions.rX_bits (.Regidx row.rs2)
        pure (Functions.shift_bits_right_arith source1
          (Sail.BitVec.extractLsb source2
            (Functions.log2_xlen -i 1) 0)))

def ConstructiveExecution
    (row : Row) (environment : Environment row)
    (initial : Functions.GeneratedState) (stepNo : Nat) : Prop :=
  Functions.ConstructiveGeneratedExecution stepNo environment.word
    (decoded row)
    (Functions.completeBaseExecution environment.pre.pc
      (Functions.execute (decoded row)))
    (observedProgram row environment) initial
    (shiftsRegRetirement row)

def StateBindings
    (row : Row) (environment : Environment row)
    (initial : Functions.GeneratedState) : Prop :=
  GeneratedInstructionStateBindings environment.pre.pc environment.word initial ∧
    GeneratedBinaryRegisterStateBindings initial row.rs1 row.rs2
      row.semantic.rd (environment.pre.registers row.rs1)
      (environment.pre.registers row.rs2)
      (environment.pre.registers row.semantic.rd)

def AcceptedComposition
    (kind : Kind) (row : Row) (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : Environment row) (initial : Functions.GeneratedState)
    (stepNo : Nat) (exitWait : Bool) : Prop :=
  AcceptedGeneratedOpcodeComposition (selector kind) (program kind)
    (program kind).source.contentDigest
    ((program kind).evalSymbolic
      (RiscvRefinement.Publication.TeamB.Shifts.regColumns row witness))
    relationHolds environment.word (expectedWord row) (decoded row) initial
    (StateBindings row environment initial)
    (GeneratedInstructionProfileAdmission
      environment.pre.pc environment.word initial)
    (Admission row witness)
    (LocalRefinement kind row witness environment relationHolds)
    (ExactTuple row witness) (ExactExecuteClause row)
    (NormalizedRetirement row environment)
    (ConstructiveExecution row environment initial stepNo)
    stepNo exitWait

def RefinementTheorem (kind : Kind) : Prop :=
  ∀ (row : Row) (witness : Witness row)
    (kindBinds : row.semantic.kind = kind)
    (environment : Environment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : RiscvRefinement.Publication.AcceptedProductionEvaluation
      ((program kind).evalSymbolic
        (RiscvRefinement.Publication.TeamB.Shifts.regColumns row witness))
      relationHolds)
    (admission : Admission row witness)
    (initial : Functions.GeneratedState)
    (stateBindings : StateBindings row environment initial)
    (profileAdmission : GeneratedInstructionProfileAdmission
      environment.pre.pc environment.word initial)
    (stepNo : Nat) (exitWait : Bool),
    AcceptedComposition kind row witness relationHolds environment
      initial stepNo exitWait

theorem accepted_air_refines (kind : Kind) : RefinementTheorem kind := by
  intro row witness kindBinds environment relationHolds accepted admission initial
    stateBindings profileAdmission stepNo exitWait
  have localCertificate :
      LocalRefinement kind row witness environment relationHolds := by
    cases kind
    · exact (RiscvRefinement.Publication.TeamB.Shifts.sll_accepted_air_implies_retirement
        row witness relationHolds environment admission.1 admission.2
        (by simpa [program] using accepted)).1
    · exact (RiscvRefinement.Publication.TeamB.Shifts.srl_accepted_air_implies_retirement
        row witness relationHolds environment admission.1 admission.2
        (by simpa [program] using accepted)).1
    · exact (RiscvRefinement.Publication.TeamB.Shifts.sra_accepted_air_implies_retirement
        row witness relationHolds environment admission.1 admission.2
        (by simpa [program] using accepted)).1
  have wordEq : environment.word = expectedWord row := by
    rw [environment.wordBinds]
    cases kind <;>
      simp [
        expectedWord,
        generatedOp,
        shiftsRegEncoding,
        kindBinds,
        Functions.encodeAdmittedBaseRType,
        Functions.admittedBaseRTypeFunct7,
        Functions.admittedBaseRTypeFunct3,
        RiscvRefinement.Decode.encodeSll,
        RiscvRefinement.Decode.encodeSrl,
        RiscvRefinement.Decode.encodeSra,
        RiscvRefinement.Decode.funct3Sll,
        RiscvRefinement.Decode.funct3Srl,
        RiscvRefinement.Decode.funct3Sra,
      ]
  rcases stateBindings.1.decodeState.mseccfg with
    ⟨mseccfgValue, mseccfgBinding⟩
  have decoderCertificate :
      Functions.GeneratedDecodeCertificateAt
        environment.word (decoded row) initial := by
    rw [wordEq]
    exact Functions.decode_admitted_base_rtype_certificate_at
      (generatedOp row.semantic.kind) row.rs2 row.rs1 row.semantic.rd
      initial mseccfgValue profileAdmission.ntlDisabled
      profileAdmission.pauseDisabled
      profileAdmission.landingPadExtensionDisabled
      stateBindings.1.privilege mseccfgBinding
  exact {
    acceptedProduction := accepted
    inputBoundSelector := {
      schemaVersion := by cases kind <;> rfl
      manifestId := by cases kind <;> rfl
      mnemonic := by cases kind <;> rfl
      digest := rfl
      inputWord := wordEq
    }
    stateBindings := stateBindings
    profileAdmission := profileAdmission
    admission := admission
    admissionProofUnique := fun first second => Subsingleton.elim first second
    localRefinement := localCertificate
    exactTuple := localCertificate.exactOrderedTuples
    decoder := decoderCertificate
    generatedExecuteSuccess := by
      cases kind <;>
        simp [
          ExactExecuteClause,
          decoded,
          generatedOp,
          kindBinds,
          Functions.admittedBaseRTypeInstruction,
        ] <;> rfl
    normalizedRetirement := by
      cases kind
      · simpa [NormalizedRetirement, kindBinds] using
          Functions.complete_SLL_normalizes environment.pre.pc
            row.rs2 row.rs1 row.semantic.rd
      · simpa [NormalizedRetirement, kindBinds] using
          Functions.complete_SRL_normalizes environment.pre.pc
            row.rs2 row.rs1 row.semantic.rd
      · simpa [NormalizedRetirement, kindBinds] using
          Functions.complete_SRA_normalizes environment.pre.pc
            row.rs2 row.rs1 row.semantic.rd
    constructiveExecution := by
      unfold ConstructiveExecution observedProgram
      cases kind
      · simp only [kindBinds]
        apply ExecutionClosure.constructiveBinaryRegisterExecution
          (stepNo := stepNo) (word := environment.word)
          (decoded := decoded row) (pc := environment.pre.pc)
          (rs1 := row.rs1) (rs2 := row.rs2) (rd := row.semantic.rd)
          (source1 := environment.pre.registers row.rs1)
          (source2 := environment.pre.registers row.rs2)
          (compute := fun source amount => Sail.shift_bits_left source
            (Sail.BitVec.extractLsb amount
              (Functions.log2_xlen -i 1) 0))
          (retirementValue :=
            RiscvRefinement.Sail.Reviewed.executeSllValue
              (environment.pre.registers row.rs1)
              (RiscvRefinement.Sail.Reviewed.registerShiftAmount
                (environment.pre.registers row.rs2)))
          (retirement := shiftsRegRetirement row) (initial := initial)
        · exact stateBindings.1.programCounter
        · exact stateBindings.1.landingPadClear
        · exact stateBindings.2.sourceOne
        · exact stateBindings.2.sourceTwo
        · rw [generatedRegisterShiftAmount_eq]
          rfl
        · simpa [decoded, generatedOp, kindBinds] using
            Functions.execute_RTYPE_SLL_eq (.Regidx row.rs2)
              (.Regidx row.rs1) (.Regidx row.semantic.rd)
        · simpa [decoded, generatedOp, kindBinds] using
            Functions.complete_SLL_normalizes environment.pre.pc
              row.rs2 row.rs1 row.semantic.rd
        · simpa [shiftsRegExecute,
            RiscvRefinement.Sail.Reviewed.executeSll, kindBinds] using
            localCertificate.semantic.retirement
      · simp only [kindBinds]
        apply ExecutionClosure.constructiveBinaryRegisterExecution
          (stepNo := stepNo) (word := environment.word)
          (decoded := decoded row) (pc := environment.pre.pc)
          (rs1 := row.rs1) (rs2 := row.rs2) (rd := row.semantic.rd)
          (source1 := environment.pre.registers row.rs1)
          (source2 := environment.pre.registers row.rs2)
          (compute := fun source amount => Sail.shift_bits_right source
            (Sail.BitVec.extractLsb amount
              (Functions.log2_xlen -i 1) 0))
          (retirementValue :=
            RiscvRefinement.Sail.Reviewed.executeSrlValue
              (environment.pre.registers row.rs1)
              (RiscvRefinement.Sail.Reviewed.registerShiftAmount
                (environment.pre.registers row.rs2)))
          (retirement := shiftsRegRetirement row) (initial := initial)
        · exact stateBindings.1.programCounter
        · exact stateBindings.1.landingPadClear
        · exact stateBindings.2.sourceOne
        · exact stateBindings.2.sourceTwo
        · rw [generatedRegisterShiftAmount_eq]
          rfl
        · simpa [decoded, generatedOp, kindBinds] using
            Functions.execute_RTYPE_SRL_eq (.Regidx row.rs2)
              (.Regidx row.rs1) (.Regidx row.semantic.rd)
        · simpa [decoded, generatedOp, kindBinds] using
            Functions.complete_SRL_normalizes environment.pre.pc
              row.rs2 row.rs1 row.semantic.rd
        · simpa [shiftsRegExecute,
            RiscvRefinement.Sail.Reviewed.executeSrl, kindBinds] using
            localCertificate.semantic.retirement
      · simp only [kindBinds]
        apply ExecutionClosure.constructiveBinaryRegisterExecution
          (stepNo := stepNo) (word := environment.word)
          (decoded := decoded row) (pc := environment.pre.pc)
          (rs1 := row.rs1) (rs2 := row.rs2) (rd := row.semantic.rd)
          (source1 := environment.pre.registers row.rs1)
          (source2 := environment.pre.registers row.rs2)
          (compute := fun source amount =>
            Functions.shift_bits_right_arith source
              (Sail.BitVec.extractLsb amount
                (Functions.log2_xlen -i 1) 0))
          (retirementValue :=
            RiscvRefinement.Sail.Reviewed.executeSraValue
              (environment.pre.registers row.rs1)
              (RiscvRefinement.Sail.Reviewed.registerShiftAmount
                (environment.pre.registers row.rs2)))
          (retirement := shiftsRegRetirement row) (initial := initial)
        · exact stateBindings.1.programCounter
        · exact stateBindings.1.landingPadClear
        · exact stateBindings.2.sourceOne
        · exact stateBindings.2.sourceTwo
        · rw [generatedRegisterShiftAmount_eq]
          rfl
        · simpa [decoded, generatedOp, kindBinds] using
            Functions.execute_RTYPE_SRA_eq (.Regidx row.rs2)
              (.Regidx row.rs1) (.Regidx row.semantic.rd)
        · simpa [decoded, generatedOp, kindBinds] using
            Functions.complete_SRA_normalizes environment.pre.pc
              row.rs2 row.rs1 row.semantic.rd
        · simpa [shiftsRegExecute,
            RiscvRefinement.Sail.Reviewed.executeSra, kindBinds] using
            localCertificate.semantic.retirement
    fullStepFraming :=
      Functions.generated_full_step_retirement_composition stepNo exitWait
  }

end ShiftReg

namespace ShiftImm

abbrev Kind := ShiftKind
abbrev Row := ShiftsImmRow
abbrev Witness (row : Row) :=
  RiscvRefinement.Publication.TeamB.Shifts.ImmWitness row
abbrev Environment (row : Row) := ShiftsImmEnvironment row

def selector : Kind → GeneratedOpcodeSelector
  | .sll => .slli
  | .srl => .srli
  | .sra => .srai

def program : Kind → LocalProgram :=
  RiscvRefinement.Publication.TeamB.Shifts.immProgram

def generatedOp : Kind → Functions.AdmittedShiftITypeOp
  | .sll => .slli
  | .srl => .srli
  | .sra => .srai

def expectedIdentity : Kind →
    RiscvRefinement.Publication.ProgramIdentity
  | .sll => RiscvRefinement.Publication.TeamB.Shifts.slliProgramIdentity
  | .srl => RiscvRefinement.Publication.TeamB.Shifts.srliProgramIdentity
  | .sra => RiscvRefinement.Publication.TeamB.Shifts.sraiProgramIdentity

def expectedWord (row : Row) : BitVec 32 :=
  Functions.encodeAdmittedShiftIType (generatedOp row.semantic.kind)
    (shiftsImmShamt row) row.rs1 row.semantic.rd

def decoded (row : Row) : instruction :=
  Functions.admittedShiftITypeInstruction (generatedOp row.semantic.kind)
    (shiftsImmShamt row) row.rs1 row.semantic.rd

def Admission (row : Row) (witness : Witness row) : Prop :=
  RiscvRefinement.Publication.TeamB.Shifts.ImmAdmission row ∧
    RiscvRefinement.Publication.TeamB.Shifts.ImmBindings row witness

def LocalRefinement
    (kind : Kind) (row : Row) (witness : Witness row)
    (environment : Environment row)
    (relationHolds : EvaluatedLookup → Prop) : Prop :=
  RiscvRefinement.Publication.TeamB.Shifts.ImmPublicationResult
    (program kind) (expectedIdentity kind) row witness environment relationHolds

def ExactTuple (row : Row) (witness : Witness row) : Prop :=
  RiscvRefinement.Publication.TeamB.Shifts.ImmExactRelationProjection row witness

def ExactExecuteClause (row : Row) : Prop :=
  match row.semantic.kind with
  | .sll => Functions.execute (decoded row) =
      Functions.execute_SHIFTIOP ((0#1 : BitVec 1) +++ shiftsImmShamt row)
        (.Regidx row.rs1) (.Regidx row.semantic.rd) .SLLI
  | .srl => Functions.execute (decoded row) =
      Functions.execute_SHIFTIOP ((0#1 : BitVec 1) +++ shiftsImmShamt row)
        (.Regidx row.rs1) (.Regidx row.semantic.rd) .SRLI
  | .sra => Functions.execute (decoded row) =
      Functions.execute_SHIFTIOP ((0#1 : BitVec 1) +++ shiftsImmShamt row)
        (.Regidx row.rs1) (.Regidx row.semantic.rd) .SRAI

def NormalizedRetirement (row : Row) (environment : Environment row) : Prop :=
  match row.semantic.kind with
  | .sll => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_SHIFTIOP
        ((0#1 : BitVec 1) +++ shiftsImmShamt row)
        (.Regidx row.rs1) (.Regidx row.semantic.rd) .SLLI) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion environment.pre.pc
          row.semantic.rd (do
            let source ← Functions.rX_bits (.Regidx row.rs1)
            let amount := Sail.BitVec.extractLsb
              ((0#1 : BitVec 1) +++ shiftsImmShamt row)
              (Functions.log2_xlen -i 1) 0
            pure (Sail.shift_bits_left source amount)))
  | .srl => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_SHIFTIOP
        ((0#1 : BitVec 1) +++ shiftsImmShamt row)
        (.Regidx row.rs1) (.Regidx row.semantic.rd) .SRLI) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion environment.pre.pc
          row.semantic.rd (do
            let source ← Functions.rX_bits (.Regidx row.rs1)
            let amount := Sail.BitVec.extractLsb
              ((0#1 : BitVec 1) +++ shiftsImmShamt row)
              (Functions.log2_xlen -i 1) 0
            pure (Sail.shift_bits_right source amount)))
  | .sra => Functions.completeBaseExecution environment.pre.pc
      (Functions.execute_SHIFTIOP
        ((0#1 : BitVec 1) +++ shiftsImmShamt row)
        (.Regidx row.rs1) (.Regidx row.semantic.rd) .SRAI) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion environment.pre.pc
          row.semantic.rd (do
            let source ← Functions.rX_bits (.Regidx row.rs1)
            let amount := Sail.BitVec.extractLsb
              ((0#1 : BitVec 1) +++ shiftsImmShamt row)
              (Functions.log2_xlen -i 1) 0
            pure (Functions.shift_bits_right_arith source amount)))

noncomputable def observedProgram (row : Row) (environment : Environment row) :=
  match row.semantic.kind with
  | .sll => Functions.normalizedRegisterCompletion environment.pre.pc
      row.semantic.rd (do
        let source ← Functions.rX_bits (.Regidx row.rs1)
        let amount := Sail.BitVec.extractLsb
          ((0#1 : BitVec 1) +++ shiftsImmShamt row)
          (Functions.log2_xlen -i 1) 0
        pure (Sail.shift_bits_left source amount))
  | .srl => Functions.normalizedRegisterCompletion environment.pre.pc
      row.semantic.rd (do
        let source ← Functions.rX_bits (.Regidx row.rs1)
        let amount := Sail.BitVec.extractLsb
          ((0#1 : BitVec 1) +++ shiftsImmShamt row)
          (Functions.log2_xlen -i 1) 0
        pure (Sail.shift_bits_right source amount))
  | .sra => Functions.normalizedRegisterCompletion environment.pre.pc
      row.semantic.rd (do
        let source ← Functions.rX_bits (.Regidx row.rs1)
        let amount := Sail.BitVec.extractLsb
          ((0#1 : BitVec 1) +++ shiftsImmShamt row)
          (Functions.log2_xlen -i 1) 0
        pure (Functions.shift_bits_right_arith source amount))

def ConstructiveExecution
    (row : Row) (environment : Environment row)
    (initial : Functions.GeneratedState) (stepNo : Nat) : Prop :=
  Functions.ConstructiveGeneratedExecution stepNo environment.word
    (decoded row)
    (Functions.completeBaseExecution environment.pre.pc
      (Functions.execute (decoded row)))
    (observedProgram row environment) initial
    (shiftsImmRetirement row)

def StateBindings
    (row : Row) (environment : Environment row)
    (initial : Functions.GeneratedState) : Prop :=
  GeneratedInstructionStateBindings environment.pre.pc environment.word initial ∧
    GeneratedUnaryRegisterStateBindings initial row.rs1 row.semantic.rd
      (environment.pre.registers row.rs1)
      (environment.pre.registers row.semantic.rd)

def AcceptedComposition
    (kind : Kind) (row : Row) (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : Environment row) (initial : Functions.GeneratedState)
    (stepNo : Nat) (exitWait : Bool) : Prop :=
  AcceptedGeneratedOpcodeComposition (selector kind) (program kind)
    (program kind).source.contentDigest
    ((program kind).evalSymbolic
      (RiscvRefinement.Publication.TeamB.Shifts.immColumns row witness))
    relationHolds environment.word (expectedWord row) (decoded row) initial
    (StateBindings row environment initial)
    (GeneratedInstructionProfileAdmission
      environment.pre.pc environment.word initial)
    (Admission row witness)
    (LocalRefinement kind row witness environment relationHolds)
    (ExactTuple row witness) (ExactExecuteClause row)
    (NormalizedRetirement row environment)
    (ConstructiveExecution row environment initial stepNo)
    stepNo exitWait

def RefinementTheorem (kind : Kind) : Prop :=
  ∀ (row : Row) (witness : Witness row)
    (kindBinds : row.semantic.kind = kind)
    (environment : Environment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : RiscvRefinement.Publication.AcceptedProductionEvaluation
      ((program kind).evalSymbolic
        (RiscvRefinement.Publication.TeamB.Shifts.immColumns row witness))
      relationHolds)
    (admission : Admission row witness)
    (initial : Functions.GeneratedState)
    (stateBindings : StateBindings row environment initial)
    (profileAdmission : GeneratedInstructionProfileAdmission
      environment.pre.pc environment.word initial)
    (stepNo : Nat) (exitWait : Bool),
    AcceptedComposition kind row witness relationHolds environment
      initial stepNo exitWait

theorem accepted_air_refines (kind : Kind) : RefinementTheorem kind := by
  intro row witness kindBinds environment relationHolds accepted admission initial
    stateBindings profileAdmission stepNo exitWait
  have localCertificate :
      LocalRefinement kind row witness environment relationHolds := by
    cases kind
    · exact (RiscvRefinement.Publication.TeamB.Shifts.slli_accepted_air_implies_retirement
        row witness relationHolds environment admission.1 admission.2
        (by simpa [program] using accepted)).1
    · exact (RiscvRefinement.Publication.TeamB.Shifts.srli_accepted_air_implies_retirement
        row witness relationHolds environment admission.1 admission.2
        (by simpa [program] using accepted)).1
    · exact (RiscvRefinement.Publication.TeamB.Shifts.srai_accepted_air_implies_retirement
        row witness relationHolds environment admission.1 admission.2
        (by simpa [program] using accepted)).1
  have wordEq : environment.word = expectedWord row := by
    rw [environment.wordBinds]
    cases kind <;>
      simp [
        expectedWord,
        generatedOp,
        shiftsImmEncoding,
        kindBinds,
        Functions.encodeAdmittedShiftIType,
        Functions.admittedShiftITypeFunct7,
        Functions.admittedShiftITypeFunct3,
        RiscvRefinement.Decode.encodeSlli,
        RiscvRefinement.Decode.encodeSrli,
        RiscvRefinement.Decode.encodeSrai,
      ]
  rcases stateBindings.1.decodeState.mseccfg with
    ⟨mseccfgValue, mseccfgBinding⟩
  have decoderCertificate :
      Functions.GeneratedDecodeCertificateAt
        environment.word (decoded row) initial := by
    rw [wordEq]
    exact Functions.decode_admitted_shift_itype_certificate_at
      (generatedOp row.semantic.kind) (shiftsImmShamt row)
      row.rs1 row.semantic.rd initial mseccfgValue
      profileAdmission.pauseDisabled
      profileAdmission.landingPadExtensionDisabled
      stateBindings.1.privilege mseccfgBinding
  exact {
    acceptedProduction := accepted
    inputBoundSelector := {
      schemaVersion := by cases kind <;> rfl
      manifestId := by cases kind <;> rfl
      mnemonic := by cases kind <;> rfl
      digest := rfl
      inputWord := wordEq
    }
    stateBindings := stateBindings
    profileAdmission := profileAdmission
    admission := admission
    admissionProofUnique := fun first second => Subsingleton.elim first second
    localRefinement := localCertificate
    exactTuple := localCertificate.exactOrderedTuples
    decoder := decoderCertificate
    generatedExecuteSuccess := by
      cases kind <;>
        simp [
          ExactExecuteClause,
          decoded,
          generatedOp,
          kindBinds,
          Functions.admittedShiftITypeInstruction,
        ] <;> rfl
    normalizedRetirement := by
      cases kind
      · simpa [NormalizedRetirement, kindBinds] using
          Functions.complete_SLLI_normalizes environment.pre.pc
            ((0#1 : BitVec 1) +++ shiftsImmShamt row)
            row.rs1 row.semantic.rd
      · simpa [NormalizedRetirement, kindBinds] using
          Functions.complete_SRLI_normalizes environment.pre.pc
            ((0#1 : BitVec 1) +++ shiftsImmShamt row)
            row.rs1 row.semantic.rd
      · simpa [NormalizedRetirement, kindBinds] using
          Functions.complete_SRAI_normalizes environment.pre.pc
            ((0#1 : BitVec 1) +++ shiftsImmShamt row)
            row.rs1 row.semantic.rd
    constructiveExecution := by
      unfold ConstructiveExecution observedProgram
      cases kind
      · simp only [kindBinds]
        apply ExecutionClosure.constructiveUnaryRegisterExecution
          (stepNo := stepNo) (word := environment.word)
          (decoded := decoded row) (pc := environment.pre.pc)
          (rs1 := row.rs1) (rd := row.semantic.rd)
          (source := environment.pre.registers row.rs1)
          (compute := fun source => Sail.shift_bits_left source
            (Sail.BitVec.extractLsb
              ((0#1 : BitVec 1) +++ shiftsImmShamt row)
              (Functions.log2_xlen -i 1) 0))
          (retirementValue :=
            RiscvRefinement.Sail.Reviewed.executeSllValue
              (environment.pre.registers row.rs1) (shiftsImmShamt row))
          (retirement := shiftsImmRetirement row) (initial := initial)
        · exact stateBindings.1.programCounter
        · exact stateBindings.1.landingPadClear
        · exact stateBindings.2.source
        · rw [generatedImmediateShiftAmount_eq]
          rfl
        · simpa [decoded, generatedOp, kindBinds] using
            Functions.execute_SHIFTIOP_SLLI_eq
              ((0#1 : BitVec 1) +++ shiftsImmShamt row)
              (.Regidx row.rs1) (.Regidx row.semantic.rd)
        · simpa [decoded, generatedOp, kindBinds] using
            Functions.complete_SLLI_normalizes environment.pre.pc
              ((0#1 : BitVec 1) +++ shiftsImmShamt row)
              row.rs1 row.semantic.rd
        · simpa [shiftsImmExecute,
            RiscvRefinement.Sail.Reviewed.executeSlli, kindBinds] using
            localCertificate.semantic.retirement
      · simp only [kindBinds]
        apply ExecutionClosure.constructiveUnaryRegisterExecution
          (stepNo := stepNo) (word := environment.word)
          (decoded := decoded row) (pc := environment.pre.pc)
          (rs1 := row.rs1) (rd := row.semantic.rd)
          (source := environment.pre.registers row.rs1)
          (compute := fun source => Sail.shift_bits_right source
            (Sail.BitVec.extractLsb
              ((0#1 : BitVec 1) +++ shiftsImmShamt row)
              (Functions.log2_xlen -i 1) 0))
          (retirementValue :=
            RiscvRefinement.Sail.Reviewed.executeSrlValue
              (environment.pre.registers row.rs1) (shiftsImmShamt row))
          (retirement := shiftsImmRetirement row) (initial := initial)
        · exact stateBindings.1.programCounter
        · exact stateBindings.1.landingPadClear
        · exact stateBindings.2.source
        · rw [generatedImmediateShiftAmount_eq]
          rfl
        · simpa [decoded, generatedOp, kindBinds] using
            Functions.execute_SHIFTIOP_SRLI_eq
              ((0#1 : BitVec 1) +++ shiftsImmShamt row)
              (.Regidx row.rs1) (.Regidx row.semantic.rd)
        · simpa [decoded, generatedOp, kindBinds] using
            Functions.complete_SRLI_normalizes environment.pre.pc
              ((0#1 : BitVec 1) +++ shiftsImmShamt row)
              row.rs1 row.semantic.rd
        · simpa [shiftsImmExecute,
            RiscvRefinement.Sail.Reviewed.executeSrli, kindBinds] using
            localCertificate.semantic.retirement
      · simp only [kindBinds]
        apply ExecutionClosure.constructiveUnaryRegisterExecution
          (stepNo := stepNo) (word := environment.word)
          (decoded := decoded row) (pc := environment.pre.pc)
          (rs1 := row.rs1) (rd := row.semantic.rd)
          (source := environment.pre.registers row.rs1)
          (compute := fun source => Functions.shift_bits_right_arith source
            (Sail.BitVec.extractLsb
              ((0#1 : BitVec 1) +++ shiftsImmShamt row)
              (Functions.log2_xlen -i 1) 0))
          (retirementValue :=
            RiscvRefinement.Sail.Reviewed.executeSraValue
              (environment.pre.registers row.rs1) (shiftsImmShamt row))
          (retirement := shiftsImmRetirement row) (initial := initial)
        · exact stateBindings.1.programCounter
        · exact stateBindings.1.landingPadClear
        · exact stateBindings.2.source
        · rw [generatedImmediateShiftAmount_eq]
          rfl
        · simpa [decoded, generatedOp, kindBinds] using
            Functions.execute_SHIFTIOP_SRAI_eq
              ((0#1 : BitVec 1) +++ shiftsImmShamt row)
              (.Regidx row.rs1) (.Regidx row.semantic.rd)
        · simpa [decoded, generatedOp, kindBinds] using
            Functions.complete_SRAI_normalizes environment.pre.pc
              ((0#1 : BitVec 1) +++ shiftsImmShamt row)
              row.rs1 row.semantic.rd
        · simpa [shiftsImmExecute,
            RiscvRefinement.Sail.Reviewed.executeSrai, kindBinds] using
            localCertificate.semantic.retirement
    fullStepFraming :=
      Functions.generated_full_step_retirement_composition stepNo exitWait
  }

end ShiftImm

theorem SLL_accepted_air_refines : ShiftReg.RefinementTheorem .sll :=
  ShiftReg.accepted_air_refines .sll
theorem SRL_accepted_air_refines : ShiftReg.RefinementTheorem .srl :=
  ShiftReg.accepted_air_refines .srl
theorem SRA_accepted_air_refines : ShiftReg.RefinementTheorem .sra :=
  ShiftReg.accepted_air_refines .sra
theorem SLLI_accepted_air_refines : ShiftImm.RefinementTheorem .sll :=
  ShiftImm.accepted_air_refines .sll
theorem SRLI_accepted_air_refines : ShiftImm.RefinementTheorem .srl :=
  ShiftImm.accepted_air_refines .srl
theorem SRAI_accepted_air_refines : ShiftImm.RefinementTheorem .sra :=
  ShiftImm.accepted_air_refines .sra

end LeanRV32IM.Publication
