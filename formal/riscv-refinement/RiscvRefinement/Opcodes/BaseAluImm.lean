import RiscvRefinement.Air.Bridge.BaseAluImm
import RiscvRefinement.Opcodes.Addi

/-!
# RV32I bitwise-immediate production refinement

This module closes XORI, ORI, and ANDI from the exact generated AIR programs
to canonical decode and normalized architectural retirement.  In particular,
the byte-wise fixed-table result is shown to be the corresponding 32-bit
operation against the sign-extended I-immediate.
-/

namespace RiscvRefinement.Opcodes.BaseAluImm

open RiscvRefinement

abbrev Op := Decode.BaseAluImmOp
abbrev Row := Air.Bridge.BaseAluImm.Row
abbrev Witness := Air.Bridge.BaseAluImm.Witness
abbrev Admission := Air.Bridge.BaseAluImm.Admission
abbrev Acceptance := Air.Bridge.BaseAluImm.Acceptance

def immediate (row : Row) : BitVec 12 :=
  row.immSign.append (row.imm1.append row.imm0)

def word (op : Op) (row : Row) : InstructionWord :=
  Decode.encodeBaseAluImm op (immediate row) row.rs1 row.rd

def executeValue (op : Op) (source : Word) (imm : BitVec 12) : Word :=
  let extended := BitVec.signExtend 32 imm
  match op with
  | .xori => source ^^^ extended
  | .ori => source ||| extended
  | .andi => source &&& extended

def execute
    (op : Op)
    (pc source : Word)
    (rd : RegisterIndex)
    (imm : BitVec 12) : Retirement where
  nextPc := RiscvRefinement.nextPc pc
  write := architecturalWrite rd (executeValue op source imm)

def airRetirement (row : Row) : Retirement where
  nextPc := RiscvRefinement.nextPc row.pc
  write := architecturalWrite row.rd row.rdNext.word

def programTuple (op : Op) (row : Row) : ProgramTuple where
  pc := row.pc
  opcodeId := Decode.baseAluImmOpcodeId op
  rd := row.rd.toNat
  rs1 := row.rs1.toNat
  operand := (immediate row).toNat

structure Environment (row : Row) where
  pre : PreState
  pcBinds : row.pc = pre.pc
  sourceBinds : row.rs1Previous.word = pre.registers row.rs1
  destinationBinds : row.rdPrevious.word = pre.registers row.rd

theorem immediateWord (row : Row) :
    (Air.Bridge.BaseAluImm.immediateBytes row).word =
      BitVec.signExtend 32 (immediate row) := by
  change
    (Air.Bridge.BaseAluImm.immediateBytes row).word =
      BitVec.signExtend 32
        (Air.Generated.addiImmediate row.imm0 row.imm1 row.immSign)
  rw [← Opcodes.addi_immediate_refines row.imm0 row.imm1 row.immSign]
  apply BitVec.eq_of_toNat_eq
  simp only [
    WordBytes.word_toNat,
    WordBytes.value,
    Air.Bridge.BaseAluImm.immediateBytes,
    Air.Generated.addiAirImmediate,
    Air.Generated.addiImmediateValue,
    BitVec.toNat_ofNat,
    Nat.reducePow,
  ]
  have imm1Bound := row.imm1.isLt
  have signBound := row.immSign.isLt
  have imm0Bound := row.imm0.isLt
  simp only [Nat.reducePow] at imm0Bound imm1Bound signBound
  rw [
    Nat.mod_eq_of_lt (by omega :
      row.imm1.toNat + 248 * row.immSign.toNat < 256),
    Nat.mod_eq_of_lt (by omega :
      255 * row.immSign.toNat < 256),
  ]
  rw [Nat.mod_eq_of_lt]
  omega

theorem bitwiseBytesWord
    (op : Op)
    (left right : WordBytes) :
    (Air.Bridge.BaseAluImm.bitwiseBytes op left right).word =
      match op with
      | .xori => left.word ^^^ right.word
      | .ori => left.word ||| right.word
      | .andi => left.word &&& right.word := by
  cases op <;>
    simp only [
      Air.Bridge.BaseAluImm.bitwiseBytes,
      Air.Bridge.BaseAluImm.bitwiseByte,
      WordBytes.word_append,
      BitVec.append_eq,
    ]
  · rw [BitVec.xor_append, BitVec.xor_append, BitVec.xor_append]
  · rw [BitVec.or_append, BitVec.or_append, BitVec.or_append]
  · rw [BitVec.and_append, BitVec.and_append, BitVec.and_append]

theorem resultIsArchitectural
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (production : Air.Bridge.BaseAluImm.ProductionRefinement op row witness) :
    row.result.word = executeValue op row.rs1Previous.word (immediate row) := by
  rw [production.resultValue, production.sourceValue, bitwiseBytesWord,
    immediateWord]
  cases op <;> rfl

theorem exactProgramTuple (op : Op) (row : Row) :
    programTuple op row = {
      pc := row.pc
      opcodeId := Decode.baseAluImmOpcodeId op
      rd := row.rd.toNat
      rs1 := row.rs1.toNat
      operand := (immediate row).toNat
    } := rfl

theorem xori_selectorAccepted
    (row : Row)
    (witness : Witness row) :
    (Air.Bridge.BaseAluImm.evaluation .xori row witness).activeSelectorsAccepted =
      true :=
  Air.Bridge.BaseAluImm.selectorAccepted .xori row witness

theorem ori_selectorAccepted
    (row : Row)
    (witness : Witness row) :
    (Air.Bridge.BaseAluImm.evaluation .ori row witness).activeSelectorsAccepted =
      true :=
  Air.Bridge.BaseAluImm.selectorAccepted .ori row witness

theorem andi_selectorAccepted
    (row : Row)
    (witness : Witness row) :
    (Air.Bridge.BaseAluImm.evaluation .andi row witness).activeSelectorsAccepted =
      true :=
  Air.Bridge.BaseAluImm.selectorAccepted .andi row witness

theorem xori_exactProgramTuple (row : Row) :
    (Air.Bridge.BaseAluImm.programLookup .xori row).tuple = #[
      Air.Bridge.BaseAluImm.bitVecM31 row.pc,
      M31.reduce 13,
      Air.Bridge.BaseAluImm.bitVecM31 row.rd,
      Air.Bridge.BaseAluImm.bitVecM31 row.rs1,
      Air.Bridge.BaseAluImm.immediateUnsignedField row
    ] := by
  rfl

theorem ori_exactProgramTuple (row : Row) :
    (Air.Bridge.BaseAluImm.programLookup .ori row).tuple = #[
      Air.Bridge.BaseAluImm.bitVecM31 row.pc,
      M31.reduce 14,
      Air.Bridge.BaseAluImm.bitVecM31 row.rd,
      Air.Bridge.BaseAluImm.bitVecM31 row.rs1,
      Air.Bridge.BaseAluImm.immediateUnsignedField row
    ] := by
  rfl

theorem andi_exactProgramTuple (row : Row) :
    (Air.Bridge.BaseAluImm.programLookup .andi row).tuple = #[
      Air.Bridge.BaseAluImm.bitVecM31 row.pc,
      M31.reduce 15,
      Air.Bridge.BaseAluImm.bitVecM31 row.rd,
      Air.Bridge.BaseAluImm.bitVecM31 row.rs1,
      Air.Bridge.BaseAluImm.immediateUnsignedField row
    ] := by
  rfl

structure Refinement
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (environment : Environment row) : Prop where
  production : Air.Bridge.BaseAluImm.ProductionRefinement op row witness
  decode :
    Decode.isBaseAluImm op (word op row) = true ∧
      Decode.decodeIImmediate (word op row) = immediate row ∧
      Decode.decodeRs1 (word op row) = row.rs1 ∧
      Decode.decodeRd (word op row) = row.rd
  program :
    programTuple op row = {
      pc := row.pc
      opcodeId := Decode.baseAluImmOpcodeId op
      rd := row.rd.toNat
      rs1 := row.rs1.toNat
      operand := (immediate row).toNat
    }
  exactProgramLookup :
    (Air.Bridge.BaseAluImm.evaluation op row witness).lookup? 22 =
      some (Air.Bridge.BaseAluImm.programLookup op row)
  source :
    row.rs1Next.word = environment.pre.registers row.rs1
  destination :
    row.rdNext.word =
      architecturalValue row.rd
        (executeValue op (environment.pre.registers row.rs1) (immediate row))
  retirement :
    airRetirement row =
      execute op environment.pre.pc
        (environment.pre.registers row.rs1) row.rd (immediate row)
  zeroRegister :
    row.rd = zeroRegister → (airRetirement row).write = none
  noMemoryEffect :
    (airRetirement row).read = none ∧
      (airRetirement row).store = none

theorem refines
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (environment : Environment row)
    (admission : Admission row)
    (accepted : Acceptance op row witness) :
    Refinement op row witness environment := by
  have production :=
    Air.Bridge.BaseAluImm.sound op row witness admission accepted
  have result :
      row.result.word =
        executeValue op (environment.pre.registers row.rs1) (immediate row) := by
    rw [← environment.sourceBinds]
    exact resultIsArchitectural op row witness production
  have destination :
      row.rdNext.word =
        architecturalValue row.rd
          (executeValue op (environment.pre.registers row.rs1) (immediate row)) := by
    rw [production.destinationValue, result]
  refine {
    production
    decode :=
      Decode.encode_base_alu_imm_is_canonical
        op (immediate row) row.rs1 row.rd
    program := exactProgramTuple op row
    exactProgramLookup := production.program
    source := by
      rw [production.sourceValue, environment.sourceBinds]
    destination
    retirement := ?_
    zeroRegister := ?_
    noMemoryEffect := by simp [airRetirement]
  }
  · simp only [airRetirement, execute]
    rw [environment.pcBinds, destination, architecturalWrite_value]
  · intro zero
    simp [airRetirement, zero, architecturalWrite]

theorem xori_refines
    (row : Row) (witness : Witness row) (environment : Environment row)
    (admission : Admission row) (accepted : Acceptance .xori row witness) :
    Refinement .xori row witness environment :=
  refines .xori row witness environment admission accepted

theorem ori_refines
    (row : Row) (witness : Witness row) (environment : Environment row)
    (admission : Admission row) (accepted : Acceptance .ori row witness) :
    Refinement .ori row witness environment :=
  refines .ori row witness environment admission accepted

theorem andi_refines
    (row : Row) (witness : Witness row) (environment : Environment row)
    (admission : Admission row) (accepted : Acceptance .andi row witness) :
    Refinement .andi row witness environment :=
  refines .andi row witness environment admission accepted

def zeroPreState : PreState where
  pc := BitVec.ofNat 32 0x1000
  registers := fun _ => zeroWord
  x0IsZero := rfl

def zeroEnvironment
    (zeroDestination : Bool)
    (rs1 : RegisterIndex) :
    Environment (Air.Bridge.BaseAluImm.zeroRow zeroDestination rs1) where
  pre := zeroPreState
  pcBinds := rfl
  sourceBinds := WordBytes.zero_word
  destinationBinds := WordBytes.zero_word

theorem refinementNonvacuous (op : Op) :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance op row witness ∧
        Refinement op row witness environment := by
  let rs1 : RegisterIndex := BitVec.ofNat 5 2
  exact ⟨
    Air.Bridge.BaseAluImm.zeroRow false rs1,
    Air.Bridge.BaseAluImm.zeroWitness false rs1,
    zeroEnvironment false rs1,
    Air.Bridge.BaseAluImm.zeroAdmission false rs1,
    Air.Bridge.BaseAluImm.zeroAcceptance op false rs1,
    refines op _ _ _ (Air.Bridge.BaseAluImm.zeroAdmission false rs1)
      (Air.Bridge.BaseAluImm.zeroAcceptance op false rs1)
  ⟩

theorem zeroDestinationRefinementNonvacuous (op : Op) :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance op row witness ∧
        Refinement op row witness environment ∧ row.rd = zeroRegister := by
  let rs1 : RegisterIndex := BitVec.ofNat 5 2
  exact ⟨
    Air.Bridge.BaseAluImm.zeroRow true rs1,
    Air.Bridge.BaseAluImm.zeroWitness true rs1,
    zeroEnvironment true rs1,
    Air.Bridge.BaseAluImm.zeroAdmission true rs1,
    Air.Bridge.BaseAluImm.zeroAcceptance op true rs1,
    refines op _ _ _ (Air.Bridge.BaseAluImm.zeroAdmission true rs1)
      (Air.Bridge.BaseAluImm.zeroAcceptance op true rs1),
    by rfl
  ⟩

theorem sourceAliasRefinementNonvacuous (op : Op) :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance op row witness ∧
        Refinement op row witness environment ∧ row.rd = row.rs1 := by
  let rs1 : RegisterIndex := BitVec.ofNat 5 1
  exact ⟨
    Air.Bridge.BaseAluImm.zeroRow false rs1,
    Air.Bridge.BaseAluImm.zeroWitness false rs1,
    zeroEnvironment false rs1,
    Air.Bridge.BaseAluImm.zeroAdmission false rs1,
    Air.Bridge.BaseAluImm.zeroAcceptance op false rs1,
    refines op _ _ _ (Air.Bridge.BaseAluImm.zeroAdmission false rs1)
      (Air.Bridge.BaseAluImm.zeroAcceptance op false rs1),
    by rfl
  ⟩

theorem xori_nonvacuous :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance .xori row witness ∧
        Refinement .xori row witness environment :=
  refinementNonvacuous .xori

theorem ori_nonvacuous :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance .ori row witness ∧
        Refinement .ori row witness environment :=
  refinementNonvacuous .ori

theorem andi_nonvacuous :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance .andi row witness ∧
        Refinement .andi row witness environment :=
  refinementNonvacuous .andi

end RiscvRefinement.Opcodes.BaseAluImm
