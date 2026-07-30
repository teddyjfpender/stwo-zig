import RiscvRefinement.Air.Family.Shifts
import RiscvRefinement.Bridge.DecodeTeamB
import RiscvRefinement.Sail.Reviewed.Shifts

/-!
# Refinement of the six RV32I shift opcodes

`SLLI`, `SRLI`, `SRAI` (family `shifts_imm`) and `SLL`, `SRL`, `SRA` (family
`shifts_reg`) both instantiate the shared `shift_common.zig` semantics, so both
sides of this file reduce to the one shared family theorem in
`RiscvRefinement/Air/Family/Shifts.lean`.

The architectural side is the reviewed capsule
`RiscvRefinement/Sail/Reviewed/Shifts.lean`; see the boundary note there. No
theorem below claims generated-Sail status.
-/

namespace RiscvRefinement.Opcodes

open RiscvRefinement
open RiscvRefinement.Air.Family
open RiscvRefinement.Sail.Reviewed

/-! ## Shift-immediate family: SLLI / SRLI / SRAI -/

/-- The `imm_truncated` column read as the five-bit `shamt` field. -/
def shiftsImmShamt (row : ShiftsImmRow) : BitVec 5 :=
  BitVec.ofNat 5 row.immTruncated

def shiftsImmEncoding (row : ShiftsImmRow) : InstructionWord :=
  match row.semantic.kind with
  | ShiftKind.sll =>
      Decode.encodeSlli (shiftsImmShamt row) row.rs1 row.semantic.rd
  | ShiftKind.srl =>
      Decode.encodeSrli (shiftsImmShamt row) row.rs1 row.semantic.rd
  | ShiftKind.sra =>
      Decode.encodeSrai (shiftsImmShamt row) row.rs1 row.semantic.rd

def shiftsImmAdmits (kind : ShiftKind) (word : InstructionWord) : Bool :=
  match kind with
  | ShiftKind.sll => Decode.isSlli word
  | ShiftKind.srl => Decode.isSrli word
  | ShiftKind.sra => Decode.isSrai word

def shiftsImmValue
    (kind : ShiftKind)
    (source : Word)
    (shamt : BitVec 5) :
    Word :=
  match kind with
  | ShiftKind.sll => executeSllValue source shamt
  | ShiftKind.srl => executeSrlValue source shamt
  | ShiftKind.sra => executeSraValue source shamt

def shiftsImmExecute
    (kind : ShiftKind)
    (pc source : Word)
    (rd : RegisterIndex)
    (shamt : BitVec 5) :
    Retirement :=
  match kind with
  | ShiftKind.sll => executeSlli pc source rd shamt
  | ShiftKind.srl => executeSrli pc source rd shamt
  | ShiftKind.sra => executeSrai pc source rd shamt

structure ShiftsImmEnvironment (row : ShiftsImmRow) where
  pre : PreState
  word : InstructionWord
  pcBinds : row.pc = pre.pc
  wordBinds : word = shiftsImmEncoding row
  sourceBinds : row.semantic.rs1Previous.word = pre.registers row.rs1
  destinationBinds :
    row.semantic.rdPrevious.word = pre.registers row.semantic.rd

/-- The five-bit `shamt` field carries exactly the committed `shift_amount`;
in particular the shift amount can never exceed 31. -/
theorem shifts_imm_shamt_toNat
    (row : ShiftsImmRow)
    (holds : ShiftsImmHolds row) :
    (shiftsImmShamt row).toNat = row.semantic.shiftAmount := by
  have bind := holds.immediateBinds
  have bound := shift_amount_lt_32 row.semantic holds.core
  simp only [shiftsImmShamt, BitVec.toNat_ofNat, Nat.reducePow]
  omega

/-- The shared family theorem, instantiated at the immediate row: byte and carry
movement forces the committed result to be the architectural shift. -/
theorem shifts_imm_result_word
    (row : ShiftsImmRow)
    (holds : ShiftsImmHolds row) :
    row.semantic.result.word =
      shiftsImmValue row.semantic.kind row.semantic.rs1Next.word
        (shiftsImmShamt row) := by
  have amount := shifts_imm_shamt_toNat row holds
  cases kind : row.semantic.kind with
  | sll =>
    simp only [shiftsImmValue, executeSllValue, amount]
    exact shift_left_word row.semantic holds.core kind
  | srl =>
    have notLeft : row.semantic.kind ≠ ShiftKind.sll := by rw [kind]; decide
    have notArith : row.semantic.kind ≠ ShiftKind.sra := by rw [kind]; decide
    have sign : row.semantic.rs1Sign = false :=
      holds.core.signIsLogicalZero notArith
    simp only [shiftsImmValue, executeSrlValue, amount]
    exact shift_right_logical_word row.semantic holds.core notLeft sign
  | sra =>
    simp only [shiftsImmValue, executeSraValue, amount]
    exact shift_right_arithmetic_word row.semantic holds.core kind

theorem shifts_imm_source_word
    (row : ShiftsImmRow)
    (environment : ShiftsImmEnvironment row)
    (holds : ShiftsImmHolds row) :
    row.semantic.rs1Next.word = environment.pre.registers row.rs1 := by
  rw [holds.core.sourceReadOnly, environment.sourceBinds]

theorem shifts_imm_destination_word
    (row : ShiftsImmRow)
    (environment : ShiftsImmEnvironment row)
    (holds : ShiftsImmHolds row) :
    row.semantic.rdNext.word =
      architecturalValue row.semantic.rd
        (shiftsImmValue row.semantic.kind (environment.pre.registers row.rs1)
          (shiftsImmShamt row)) := by
  rw [shift_destination_value row.semantic holds.core,
    shifts_imm_result_word row holds,
    shifts_imm_source_word row environment holds]

theorem shifts_imm_decodes
    (row : ShiftsImmRow)
    (environment : ShiftsImmEnvironment row) :
    shiftsImmAdmits row.semantic.kind environment.word = true ∧
      Decode.decodeShamt environment.word = shiftsImmShamt row ∧
      Decode.decodeRs1 environment.word = row.rs1 ∧
      Decode.decodeRd environment.word = row.semantic.rd := by
  rw [environment.wordBinds]
  cases kind : row.semantic.kind with
  | sll =>
    simp only [shiftsImmAdmits, shiftsImmEncoding, kind]
    exact Decode.encode_slli_is_canonical (shiftsImmShamt row) row.rs1
      row.semantic.rd
  | srl =>
    simp only [shiftsImmAdmits, shiftsImmEncoding, kind]
    exact Decode.encode_srli_is_canonical (shiftsImmShamt row) row.rs1
      row.semantic.rd
  | sra =>
    simp only [shiftsImmAdmits, shiftsImmEncoding, kind]
    exact Decode.encode_srai_is_canonical (shiftsImmShamt row) row.rs1
      row.semantic.rd

/-- Complete refinement claim for one shift-immediate row. -/
structure ShiftsImmRefinement
    (row : ShiftsImmRow)
    (environment : ShiftsImmEnvironment row) :
    Prop where
  decode :
    shiftsImmAdmits row.semantic.kind environment.word = true ∧
      Decode.decodeShamt environment.word = shiftsImmShamt row ∧
      Decode.decodeRs1 environment.word = row.rs1 ∧
      Decode.decodeRd environment.word = row.semantic.rd
  maskedAmount :
    row.immTruncated = (shiftsImmShamt row).toNat ∧ row.immTruncated < 32
  retirement :
    shiftsImmRetirement row =
      shiftsImmExecute row.semantic.kind environment.pre.pc
        (environment.pre.registers row.rs1) row.semantic.rd
        (shiftsImmShamt row)
  noMemoryEffect :
    (shiftsImmRetirement row).read = none ∧
      (shiftsImmRetirement row).store = none
  programTuple :
    (shiftsImmRelations row).program = {
      pc := environment.pre.pc
      opcodeId := shiftsImmOpcodeId row.semantic.kind
      rd := row.semantic.rd.toNat
      rs1 := row.rs1.toNat
      operand := (shiftsImmShamt row).toNat
    }
  stateConsume :
    (shiftsImmRelations row).stateConsume = {
      pc := environment.pre.pc
      clock := row.clock
    }
  stateEmit :
    (shiftsImmRelations row).stateEmit = {
      pc := nextPc environment.pre.pc
      clock := row.clock + 1
    }
  sourceConsume :
    (shiftsImmRelations row).sourceConsume = {
      addr := row.rs1
      clock := row.rs1PreviousClock
      value := environment.pre.registers row.rs1
    }
  sourceEmit :
    (shiftsImmRelations row).sourceEmit = {
      addr := row.rs1
      clock := accessClock row.clock 1
      value := environment.pre.registers row.rs1
    }
  destinationConsume :
    (shiftsImmRelations row).destinationConsume = {
      addr := row.semantic.rd
      clock := row.rdPreviousClock
      value := environment.pre.registers row.semantic.rd
    }
  destinationEmit :
    (shiftsImmRelations row).destinationEmit = {
      addr := row.semantic.rd
      clock := accessClock row.clock 2
      value :=
        architecturalValue row.semantic.rd
          (shiftsImmValue row.semantic.kind
            (environment.pre.registers row.rs1) (shiftsImmShamt row))
    }

/-- The shared shift-immediate refinement theorem. `slli_refines`,
`srli_refines` and `srai_refines` below are its three selector instances. -/
theorem shifts_imm_refines
    (row : ShiftsImmRow)
    (environment : ShiftsImmEnvironment row)
    (holds : ShiftsImmHolds row) :
    ShiftsImmRefinement row environment := by
  have amount := shifts_imm_shamt_toNat row holds
  have bound := shift_amount_lt_32 row.semantic holds.core
  have write :
      architecturalWrite row.semantic.rd row.semantic.rdNext.word =
        architecturalWrite row.semantic.rd
          (shiftsImmValue row.semantic.kind
            (environment.pre.registers row.rs1) (shiftsImmShamt row)) := by
    rw [shifts_imm_destination_word row environment holds,
      architecturalWrite_value]
  refine {
    decode := shifts_imm_decodes row environment
    maskedAmount := ⟨by rw [amount]; exact holds.immediateBinds, ?_⟩
    retirement := ?_
    noMemoryEffect := ⟨rfl, rfl⟩
    programTuple := ?_
    stateConsume := by simp [shiftsImmRelations, environment.pcBinds]
    stateEmit := by simp [shiftsImmRelations, environment.pcBinds]
    sourceConsume := by simp [shiftsImmRelations, environment.sourceBinds]
    sourceEmit := by
      simp [shiftsImmRelations, shifts_imm_source_word row environment holds]
    destinationConsume := by
      simp [shiftsImmRelations, environment.destinationBinds]
    destinationEmit := by
      simp [shiftsImmRelations,
        shifts_imm_destination_word row environment holds]
  }
  · rw [holds.immediateBinds]; exact bound
  · simp only [shiftsImmRetirement, holds.nextPcResult, environment.pcBinds,
      write]
    cases kind : row.semantic.kind <;>
      simp only [shiftsImmExecute, shiftsImmValue, executeSlli, executeSrli,
        executeSrai]
  · simp only [shiftsImmRelations, shiftsImmProgramTuple, environment.pcBinds,
      amount, holds.immediateBinds]

theorem slli_refines
    (row : ShiftsImmRow)
    (environment : ShiftsImmEnvironment row)
    (holds : ShiftsImmHolds row)
    (kind : row.semantic.kind = ShiftKind.sll) :
    ShiftsImmRefinement row environment ∧
      Decode.isSlli environment.word = true ∧
      shiftsImmRetirement row =
        executeSlli environment.pre.pc (environment.pre.registers row.rs1)
          row.semantic.rd (shiftsImmShamt row) := by
  have refines := shifts_imm_refines row environment holds
  refine ⟨refines, ?_, ?_⟩
  · have decode := refines.decode.1
    rwa [kind, shiftsImmAdmits] at decode
  · have retire := refines.retirement
    rwa [kind, shiftsImmExecute] at retire

theorem srli_refines
    (row : ShiftsImmRow)
    (environment : ShiftsImmEnvironment row)
    (holds : ShiftsImmHolds row)
    (kind : row.semantic.kind = ShiftKind.srl) :
    ShiftsImmRefinement row environment ∧
      Decode.isSrli environment.word = true ∧
      shiftsImmRetirement row =
        executeSrli environment.pre.pc (environment.pre.registers row.rs1)
          row.semantic.rd (shiftsImmShamt row) ∧
      row.semantic.rs1Sign = false := by
  have refines := shifts_imm_refines row environment holds
  refine ⟨refines, ?_, ?_, ?_⟩
  · have decode := refines.decode.1
    rwa [kind, shiftsImmAdmits] at decode
  · have retire := refines.retirement
    rwa [kind, shiftsImmExecute] at retire
  · exact holds.core.signIsLogicalZero (by rw [kind]; decide)

theorem srai_refines
    (row : ShiftsImmRow)
    (environment : ShiftsImmEnvironment row)
    (holds : ShiftsImmHolds row)
    (kind : row.semantic.kind = ShiftKind.sra) :
    ShiftsImmRefinement row environment ∧
      Decode.isSrai environment.word = true ∧
      shiftsImmRetirement row =
        executeSrai environment.pre.pc (environment.pre.registers row.rs1)
          row.semantic.rd (shiftsImmShamt row) ∧
      row.semantic.rs1Sign =
        (environment.pre.registers row.rs1).msb := by
  have refines := shifts_imm_refines row environment holds
  have source := shifts_imm_source_word row environment holds
  refine ⟨refines, ?_, ?_, ?_⟩
  · have decode := refines.decode.1
    rwa [kind, shiftsImmAdmits] at decode
  · have retire := refines.retirement
    rwa [kind, shiftsImmExecute] at retire
  · rw [← source]
    cases sign : row.semantic.rs1Sign
    · rw [shift_source_msb_false row.semantic holds.core kind sign]
    · rw [shift_source_msb_true row.semantic holds.core kind sign]

/-! ## Shift-register family: SLL / SRL / SRA

The only architectural difference from the immediate family is where the shift
amount comes from: `X(rs2)[4..0]` instead of the instruction's `shamt` field.
`shiftsRegValue` is therefore literally `shiftsImmValue` at the masked amount,
which is the shared `shift_common.zig` semantics showing through. -/

def shiftsRegEncoding (row : ShiftsRegRow) : InstructionWord :=
  match row.semantic.kind with
  | ShiftKind.sll => Decode.encodeSll row.rs2 row.rs1 row.semantic.rd
  | ShiftKind.srl => Decode.encodeSrl row.rs2 row.rs1 row.semantic.rd
  | ShiftKind.sra => Decode.encodeSra row.rs2 row.rs1 row.semantic.rd

def shiftsRegAdmits (kind : ShiftKind) (word : InstructionWord) : Bool :=
  match kind with
  | ShiftKind.sll => Decode.isSll word
  | ShiftKind.srl => Decode.isSrl word
  | ShiftKind.sra => Decode.isSra word

def shiftsRegValue (kind : ShiftKind) (source amount : Word) : Word :=
  shiftsImmValue kind source (registerShiftAmount amount)

def shiftsRegExecute
    (kind : ShiftKind)
    (pc source amount : Word)
    (rd : RegisterIndex) :
    Retirement :=
  match kind with
  | ShiftKind.sll => executeSll pc source amount rd
  | ShiftKind.srl => executeSrl pc source amount rd
  | ShiftKind.sra => executeSra pc source amount rd

structure ShiftsRegEnvironment (row : ShiftsRegRow) where
  pre : PreState
  word : InstructionWord
  pcBinds : row.pc = pre.pc
  wordBinds : word = shiftsRegEncoding row
  sourceBinds : row.semantic.rs1Previous.word = pre.registers row.rs1
  secondSourceBinds : row.rs2Previous.word = pre.registers row.rs2
  destinationBinds :
    row.semantic.rdPrevious.word = pre.registers row.semantic.rd

theorem shifts_reg_second_source_word
    (row : ShiftsRegRow)
    (environment : ShiftsRegEnvironment row)
    (holds : ShiftsRegHolds row) :
    row.rs2Next.word = environment.pre.registers row.rs2 := by
  rw [holds.secondSourceReadOnly, environment.secondSourceBinds]

/-- The five-bit mask gate: the committed `shift_amount` is exactly
`X(rs2)[4..0]`, never the whole register. -/
theorem shifts_reg_amount_toNat
    (row : ShiftsRegRow)
    (environment : ShiftsRegEnvironment row)
    (holds : ShiftsRegHolds row) :
    (registerShiftAmount (environment.pre.registers row.rs2)).toNat =
      row.semantic.shiftAmount := by
  rw [registerShiftAmount_toNat,
    ← shifts_reg_second_source_word row environment holds,
    ← shifts_reg_amount_is_masked row holds]

theorem shifts_reg_result_word
    (row : ShiftsRegRow)
    (environment : ShiftsRegEnvironment row)
    (holds : ShiftsRegHolds row) :
    row.semantic.result.word =
      shiftsRegValue row.semantic.kind row.semantic.rs1Next.word
        (environment.pre.registers row.rs2) := by
  have amount := shifts_reg_amount_toNat row environment holds
  simp only [shiftsRegValue]
  cases kind : row.semantic.kind with
  | sll =>
    simp only [shiftsImmValue, executeSllValue, amount]
    exact shift_left_word row.semantic holds.core kind
  | srl =>
    have notLeft : row.semantic.kind ≠ ShiftKind.sll := by rw [kind]; decide
    have notArith : row.semantic.kind ≠ ShiftKind.sra := by rw [kind]; decide
    have sign : row.semantic.rs1Sign = false :=
      holds.core.signIsLogicalZero notArith
    simp only [shiftsImmValue, executeSrlValue, amount]
    exact shift_right_logical_word row.semantic holds.core notLeft sign
  | sra =>
    simp only [shiftsImmValue, executeSraValue, amount]
    exact shift_right_arithmetic_word row.semantic holds.core kind

theorem shifts_reg_source_word
    (row : ShiftsRegRow)
    (environment : ShiftsRegEnvironment row)
    (holds : ShiftsRegHolds row) :
    row.semantic.rs1Next.word = environment.pre.registers row.rs1 := by
  rw [holds.core.sourceReadOnly, environment.sourceBinds]

theorem shifts_reg_destination_word
    (row : ShiftsRegRow)
    (environment : ShiftsRegEnvironment row)
    (holds : ShiftsRegHolds row) :
    row.semantic.rdNext.word =
      architecturalValue row.semantic.rd
        (shiftsRegValue row.semantic.kind (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2)) := by
  rw [shift_destination_value row.semantic holds.core,
    shifts_reg_result_word row environment holds,
    shifts_reg_source_word row environment holds]

theorem shifts_reg_decodes
    (row : ShiftsRegRow)
    (environment : ShiftsRegEnvironment row) :
    shiftsRegAdmits row.semantic.kind environment.word = true ∧
      Decode.decodeRs2 environment.word = row.rs2 ∧
      Decode.decodeRs1 environment.word = row.rs1 ∧
      Decode.decodeRd environment.word = row.semantic.rd := by
  rw [environment.wordBinds]
  cases kind : row.semantic.kind with
  | sll =>
    simp only [shiftsRegAdmits, shiftsRegEncoding, kind]
    exact Decode.encode_sll_is_canonical row.rs2 row.rs1 row.semantic.rd
  | srl =>
    simp only [shiftsRegAdmits, shiftsRegEncoding, kind]
    exact Decode.encode_srl_is_canonical row.rs2 row.rs1 row.semantic.rd
  | sra =>
    simp only [shiftsRegAdmits, shiftsRegEncoding, kind]
    exact Decode.encode_sra_is_canonical row.rs2 row.rs1 row.semantic.rd

/-- Complete refinement claim for one shift-register row. -/
structure ShiftsRegRefinement
    (row : ShiftsRegRow)
    (environment : ShiftsRegEnvironment row) :
    Prop where
  decode :
    shiftsRegAdmits row.semantic.kind environment.word = true ∧
      Decode.decodeRs2 environment.word = row.rs2 ∧
      Decode.decodeRs1 environment.word = row.rs1 ∧
      Decode.decodeRd environment.word = row.semantic.rd
  maskedAmount :
    row.semantic.shiftAmount =
      (environment.pre.registers row.rs2).toNat % 32 ∧
      row.semantic.shiftAmount < 32
  retirement :
    shiftsRegRetirement row =
      shiftsRegExecute row.semantic.kind environment.pre.pc
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2) row.semantic.rd
  noMemoryEffect :
    (shiftsRegRetirement row).read = none ∧
      (shiftsRegRetirement row).store = none
  programTuple :
    (shiftsRegRelations row).program = {
      pc := environment.pre.pc
      opcodeId := shiftsRegOpcodeId row.semantic.kind
      rd := row.semantic.rd.toNat
      rs1 := row.rs1.toNat
      operand := row.rs2.toNat
    }
  stateConsume :
    (shiftsRegRelations row).stateConsume = {
      pc := environment.pre.pc
      clock := row.clock
    }
  stateEmit :
    (shiftsRegRelations row).stateEmit = {
      pc := nextPc environment.pre.pc
      clock := row.clock + 1
    }
  sourceConsume :
    (shiftsRegRelations row).sourceConsume = {
      addr := row.rs1
      clock := row.rs1PreviousClock
      value := environment.pre.registers row.rs1
    }
  sourceEmit :
    (shiftsRegRelations row).sourceEmit = {
      addr := row.rs1
      clock := accessClock row.clock 1
      value := environment.pre.registers row.rs1
    }
  secondSourceConsume :
    (shiftsRegRelations row).secondSourceConsume = {
      addr := row.rs2
      clock := row.rs2PreviousClock
      value := environment.pre.registers row.rs2
    }
  secondSourceEmit :
    (shiftsRegRelations row).secondSourceEmit = {
      addr := row.rs2
      clock := accessClock row.clock 2
      value := environment.pre.registers row.rs2
    }
  destinationConsume :
    (shiftsRegRelations row).destinationConsume = {
      addr := row.semantic.rd
      clock := row.rdPreviousClock
      value := environment.pre.registers row.semantic.rd
    }
  destinationEmit :
    (shiftsRegRelations row).destinationEmit = {
      addr := row.semantic.rd
      clock := accessClock row.clock 3
      value :=
        architecturalValue row.semantic.rd
          (shiftsRegValue row.semantic.kind
            (environment.pre.registers row.rs1)
            (environment.pre.registers row.rs2))
    }

/-- The shared shift-register refinement theorem. `sll_refines`, `srl_refines`
and `sra_refines` below are its three selector instances. -/
theorem shifts_reg_refines
    (row : ShiftsRegRow)
    (environment : ShiftsRegEnvironment row)
    (holds : ShiftsRegHolds row) :
    ShiftsRegRefinement row environment := by
  have amount := shifts_reg_amount_toNat row environment holds
  have bound := shift_amount_lt_32 row.semantic holds.core
  have write :
      architecturalWrite row.semantic.rd row.semantic.rdNext.word =
        architecturalWrite row.semantic.rd
          (shiftsRegValue row.semantic.kind
            (environment.pre.registers row.rs1)
            (environment.pre.registers row.rs2)) := by
    rw [shifts_reg_destination_word row environment holds,
      architecturalWrite_value]
  refine {
    decode := shifts_reg_decodes row environment
    maskedAmount := ⟨?_, bound⟩
    retirement := ?_
    noMemoryEffect := ⟨rfl, rfl⟩
    programTuple := by
      simp [shiftsRegRelations, shiftsRegProgramTuple, environment.pcBinds]
    stateConsume := by simp [shiftsRegRelations, environment.pcBinds]
    stateEmit := by simp [shiftsRegRelations, environment.pcBinds]
    sourceConsume := by simp [shiftsRegRelations, environment.sourceBinds]
    sourceEmit := by
      simp [shiftsRegRelations, shifts_reg_source_word row environment holds]
    secondSourceConsume := by
      simp [shiftsRegRelations, environment.secondSourceBinds]
    secondSourceEmit := by
      simp [shiftsRegRelations,
        shifts_reg_second_source_word row environment holds]
    destinationConsume := by
      simp [shiftsRegRelations, environment.destinationBinds]
    destinationEmit := by
      simp [shiftsRegRelations,
        shifts_reg_destination_word row environment holds]
  }
  · rw [← amount, registerShiftAmount_toNat]
  · simp only [shiftsRegRetirement, holds.nextPcResult, environment.pcBinds,
      write]
    cases kind : row.semantic.kind <;>
      simp only [shiftsRegExecute, shiftsRegValue, shiftsImmValue, executeSll,
        executeSrl, executeSra]

theorem sll_refines
    (row : ShiftsRegRow)
    (environment : ShiftsRegEnvironment row)
    (holds : ShiftsRegHolds row)
    (kind : row.semantic.kind = ShiftKind.sll) :
    ShiftsRegRefinement row environment ∧
      Decode.isSll environment.word = true ∧
      shiftsRegRetirement row =
        executeSll environment.pre.pc (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.semantic.rd := by
  have refines := shifts_reg_refines row environment holds
  refine ⟨refines, ?_, ?_⟩
  · have decode := refines.decode.1
    rwa [kind, shiftsRegAdmits] at decode
  · have retire := refines.retirement
    rwa [kind, shiftsRegExecute] at retire

theorem srl_refines
    (row : ShiftsRegRow)
    (environment : ShiftsRegEnvironment row)
    (holds : ShiftsRegHolds row)
    (kind : row.semantic.kind = ShiftKind.srl) :
    ShiftsRegRefinement row environment ∧
      Decode.isSrl environment.word = true ∧
      shiftsRegRetirement row =
        executeSrl environment.pre.pc (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.semantic.rd ∧
      row.semantic.rs1Sign = false := by
  have refines := shifts_reg_refines row environment holds
  refine ⟨refines, ?_, ?_, ?_⟩
  · have decode := refines.decode.1
    rwa [kind, shiftsRegAdmits] at decode
  · have retire := refines.retirement
    rwa [kind, shiftsRegExecute] at retire
  · exact holds.core.signIsLogicalZero (by rw [kind]; decide)

theorem sra_refines
    (row : ShiftsRegRow)
    (environment : ShiftsRegEnvironment row)
    (holds : ShiftsRegHolds row)
    (kind : row.semantic.kind = ShiftKind.sra) :
    ShiftsRegRefinement row environment ∧
      Decode.isSra environment.word = true ∧
      shiftsRegRetirement row =
        executeSra environment.pre.pc (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.semantic.rd ∧
      row.semantic.rs1Sign = (environment.pre.registers row.rs1).msb := by
  have refines := shifts_reg_refines row environment holds
  have source := shifts_reg_source_word row environment holds
  refine ⟨refines, ?_, ?_, ?_⟩
  · have decode := refines.decode.1
    rwa [kind, shiftsRegAdmits] at decode
  · have retire := refines.retirement
    rwa [kind, shiftsRegExecute] at retire
  · rw [← source]
    cases sign : row.semantic.rs1Sign
    · rw [shift_source_msb_false row.semantic holds.core kind sign]
    · rw [shift_source_msb_true row.semantic holds.core kind sign]

/-! ## Non-vacuity

Six honest witnesses, one per opcode, each exercising a boundary the
constraint system could otherwise get wrong: shift amount 0, shift amount 31,
a negative operand so the arithmetic sign-fill path is actually taken, and an
aliased `rd = rs1` row. -/

/-- Little-endian byte literal helper for the witnesses. -/
def shiftBytes (b0 b1 b2 b3 : Nat) : WordBytes where
  limb0 := BitVec.ofNat 8 b0
  limb1 := BitVec.ofNat 8 b1
  limb2 := BitVec.ofNat 8 b2
  limb3 := BitVec.ofNat 8 b3

/-! ### SLLI by 31: the maximal left shift, limb offset 3 and bit offset 7 -/

def slliWitnessPre : PreState where
  pc := BitVec.ofNat 32 0x1000
  registers := fun index =>
    if index = BitVec.ofNat 5 5 then BitVec.ofNat 32 1 else zeroWord
  x0IsZero := by decide

def slliWitnessSemantic : ShiftRow where
  rs1Previous := shiftBytes 1 0 0 0
  rs1Next := shiftBytes 1 0 0 0
  rs1Sign := false
  kind := ShiftKind.sll
  limbIndex := 3
  bitIndex := 7
  carry0 := 0
  carry1 := 0
  carry2 := 0
  carry3 := 0
  result := shiftBytes 0 0 0 0x80
  rd := BitVec.ofNat 5 7
  rdPrevious := WordBytes.zero
  rdNext := shiftBytes 0 0 0 0x80
  rdNonzero := true

def slliWitnessRow : ShiftsImmRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rdPreviousClock := 0
  immTruncated := 31
  semantic := slliWitnessSemantic
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem slli_witness_holds : ShiftsImmHolds slliWitnessRow := by
  refine {
    core := ?_
    clockPositive := by decide
    sourceClock := ?_
    destinationClock := ?_
    immediateBinds := rfl
    nextPcResult := rfl
  }
  · refine {
      limbIndexRange := by decide
      bitIndexRange := by decide
      signIsLogicalZero := fun _ => rfl
      signLowerBound := fun h => absurd h (by decide)
      signUpperBound := fun h => absurd h (by decide)
      carry0Range := by decide
      carry1Range := by decide
      carry2Range := by decide
      carry3Range := by decide
      sourceReadOnly := rfl
      leftMovement := ?_
      rightMovement := fun h => absurd rfl h
      destinationFlag := by decide
      destinationLimb0 := by decide
      destinationLimb1 := by decide
      destinationLimb2 := by decide
      destinationLimb3 := by decide
    }
    intro _
    refine ⟨?_, ?_, ?_, ?_⟩ <;> decide
  · simp [validPreviousClock, accessClock, slliWitnessRow]
  · simp [validPreviousClock, accessClock, slliWitnessRow]

def slliWitnessEnvironment : ShiftsImmEnvironment slliWitnessRow where
  pre := slliWitnessPre
  word := shiftsImmEncoding slliWitnessRow
  pcBinds := rfl
  wordBinds := rfl
  sourceBinds := by decide
  destinationBinds := by decide

theorem slli_exists :
    ∃ (row : ShiftsImmRow) (environment : ShiftsImmEnvironment row),
      ShiftsImmHolds row ∧
        ShiftsImmRefinement row environment ∧
        row.semantic.shiftAmount = 31 ∧
        row.semantic.result.word = BitVec.ofNat 32 0x80000000 :=
  ⟨
    slliWitnessRow,
    slliWitnessEnvironment,
    slli_witness_holds,
    shifts_imm_refines slliWitnessRow slliWitnessEnvironment slli_witness_holds,
    by decide,
    by decide,
  ⟩

/-! ### SRLI by 0: the identity boundary -/

def srliWitnessPre : PreState where
  pc := BitVec.ofNat 32 0x1000
  registers := fun index =>
    if index = BitVec.ofNat 5 5 then BitVec.ofNat 32 0x12345678 else zeroWord
  x0IsZero := by decide

def srliWitnessSemantic : ShiftRow where
  rs1Previous := shiftBytes 0x78 0x56 0x34 0x12
  rs1Next := shiftBytes 0x78 0x56 0x34 0x12
  rs1Sign := false
  kind := ShiftKind.srl
  limbIndex := 0
  bitIndex := 0
  carry0 := 0
  carry1 := 0
  carry2 := 0
  carry3 := 0
  result := shiftBytes 0x78 0x56 0x34 0x12
  rd := BitVec.ofNat 5 7
  rdPrevious := WordBytes.zero
  rdNext := shiftBytes 0x78 0x56 0x34 0x12
  rdNonzero := true

def srliWitnessRow : ShiftsImmRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rdPreviousClock := 0
  immTruncated := 0
  semantic := srliWitnessSemantic
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem srli_witness_holds : ShiftsImmHolds srliWitnessRow := by
  refine {
    core := ?_
    clockPositive := by decide
    sourceClock := ?_
    destinationClock := ?_
    immediateBinds := rfl
    nextPcResult := rfl
  }
  · refine {
      limbIndexRange := by decide
      bitIndexRange := by decide
      signIsLogicalZero := fun _ => rfl
      signLowerBound := fun h => absurd h (by decide)
      signUpperBound := fun h => absurd h (by decide)
      carry0Range := by decide
      carry1Range := by decide
      carry2Range := by decide
      carry3Range := by decide
      sourceReadOnly := rfl
      leftMovement := fun h => absurd h (by decide)
      rightMovement := ?_
      destinationFlag := by decide
      destinationLimb0 := by decide
      destinationLimb1 := by decide
      destinationLimb2 := by decide
      destinationLimb3 := by decide
    }
    intro _
    refine ⟨?_, ?_, ?_, ?_⟩ <;> decide
  · simp [validPreviousClock, accessClock, srliWitnessRow]
  · simp [validPreviousClock, accessClock, srliWitnessRow]

def srliWitnessEnvironment : ShiftsImmEnvironment srliWitnessRow where
  pre := srliWitnessPre
  word := shiftsImmEncoding srliWitnessRow
  pcBinds := rfl
  wordBinds := rfl
  sourceBinds := by decide
  destinationBinds := by decide

theorem srli_exists :
    ∃ (row : ShiftsImmRow) (environment : ShiftsImmEnvironment row),
      ShiftsImmHolds row ∧
        ShiftsImmRefinement row environment ∧
        row.semantic.shiftAmount = 0 ∧
        row.semantic.result.word = BitVec.ofNat 32 0x12345678 :=
  ⟨
    srliWitnessRow,
    srliWitnessEnvironment,
    srli_witness_holds,
    shifts_imm_refines srliWitnessRow srliWitnessEnvironment srli_witness_holds,
    by decide,
    by decide,
  ⟩

/-! ### SRAI by 8 on a negative operand: the sign-fill path -/

def sraiWitnessPre : PreState where
  pc := BitVec.ofNat 32 0x1000
  registers := fun index =>
    if index = BitVec.ofNat 5 5 then BitVec.ofNat 32 0x80000000 else zeroWord
  x0IsZero := by decide

def sraiWitnessSemantic : ShiftRow where
  rs1Previous := shiftBytes 0 0 0 0x80
  rs1Next := shiftBytes 0 0 0 0x80
  rs1Sign := true
  kind := ShiftKind.sra
  limbIndex := 1
  bitIndex := 0
  carry0 := 0
  carry1 := 0
  carry2 := 0
  carry3 := 0
  result := shiftBytes 0 0 0x80 0xff
  rd := BitVec.ofNat 5 7
  rdPrevious := WordBytes.zero
  rdNext := shiftBytes 0 0 0x80 0xff
  rdNonzero := true

def sraiWitnessRow : ShiftsImmRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rdPreviousClock := 0
  immTruncated := 8
  semantic := sraiWitnessSemantic
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem srai_witness_holds : ShiftsImmHolds sraiWitnessRow := by
  refine {
    core := ?_
    clockPositive := by decide
    sourceClock := ?_
    destinationClock := ?_
    immediateBinds := rfl
    nextPcResult := rfl
  }
  · refine {
      limbIndexRange := by decide
      bitIndexRange := by decide
      signIsLogicalZero := fun h => absurd rfl h
      signLowerBound := fun _ => by decide
      signUpperBound := fun _ => by decide
      carry0Range := by decide
      carry1Range := by decide
      carry2Range := by decide
      carry3Range := by decide
      sourceReadOnly := rfl
      leftMovement := fun h => absurd h (by decide)
      rightMovement := ?_
      destinationFlag := by decide
      destinationLimb0 := by decide
      destinationLimb1 := by decide
      destinationLimb2 := by decide
      destinationLimb3 := by decide
    }
    intro _
    refine ⟨?_, ?_, ?_, ?_⟩ <;> decide
  · simp [validPreviousClock, accessClock, sraiWitnessRow]
  · simp [validPreviousClock, accessClock, sraiWitnessRow]

def sraiWitnessEnvironment : ShiftsImmEnvironment sraiWitnessRow where
  pre := sraiWitnessPre
  word := shiftsImmEncoding sraiWitnessRow
  pcBinds := rfl
  wordBinds := rfl
  sourceBinds := by decide
  destinationBinds := by decide

/-- The `SRAI` witness takes the sign-fill path: the operand is negative, the
sign witness is set, and the result is `0xff800000`, which the zero-filling
`SRLI` movement could not have produced. -/
theorem srai_exists :
    ∃ (row : ShiftsImmRow) (environment : ShiftsImmEnvironment row),
      ShiftsImmHolds row ∧
        ShiftsImmRefinement row environment ∧
        row.semantic.rs1Sign = true ∧
        row.semantic.rs1Next.word.msb = true ∧
        row.semantic.shiftAmount = 8 ∧
        row.semantic.result.word = BitVec.ofNat 32 0xff800000 ∧
        row.semantic.result.word ≠
          row.semantic.rs1Next.word >>> row.semantic.shiftAmount :=
  ⟨
    sraiWitnessRow,
    sraiWitnessEnvironment,
    srai_witness_holds,
    shifts_imm_refines sraiWitnessRow sraiWitnessEnvironment srai_witness_holds,
    rfl,
    by decide,
    by decide,
    by decide,
    by decide,
  ⟩

/-! ### SLL with `rd = rs1`: the aliased destination -/

def sllWitnessPre : PreState where
  pc := BitVec.ofNat 32 0x1000
  registers := fun index =>
    if index = BitVec.ofNat 5 5 then BitVec.ofNat 32 0x11
    else if index = BitVec.ofNat 5 6 then BitVec.ofNat 32 1
    else zeroWord
  x0IsZero := by decide

def sllWitnessSemantic : ShiftRow where
  rs1Previous := shiftBytes 0x11 0 0 0
  rs1Next := shiftBytes 0x11 0 0 0
  rs1Sign := false
  kind := ShiftKind.sll
  limbIndex := 0
  bitIndex := 1
  carry0 := 0
  carry1 := 0
  carry2 := 0
  carry3 := 0
  result := shiftBytes 0x22 0 0 0
  rd := BitVec.ofNat 5 5
  rdPrevious := shiftBytes 0x11 0 0 0
  rdNext := shiftBytes 0x22 0 0 0
  rdNonzero := true

def sllWitnessRow : ShiftsRegRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rs2 := BitVec.ofNat 5 6
  rs2PreviousClock := 0
  rs2Previous := shiftBytes 1 0 0 0
  rs2Next := shiftBytes 1 0 0 0
  rdPreviousClock := 0
  semantic := sllWitnessSemantic
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem sll_witness_holds : ShiftsRegHolds sllWitnessRow := by
  refine {
    core := ?_
    clockPositive := by decide
    sourceClock := ?_
    secondSourceClock := ?_
    destinationClock := ?_
    secondSourceReadOnly := rfl
    shiftAmountBinds := ⟨0, by decide, by decide⟩
    nextPcResult := rfl
  }
  · refine {
      limbIndexRange := by decide
      bitIndexRange := by decide
      signIsLogicalZero := fun _ => rfl
      signLowerBound := fun h => absurd h (by decide)
      signUpperBound := fun h => absurd h (by decide)
      carry0Range := by decide
      carry1Range := by decide
      carry2Range := by decide
      carry3Range := by decide
      sourceReadOnly := rfl
      leftMovement := ?_
      rightMovement := fun h => absurd rfl h
      destinationFlag := by decide
      destinationLimb0 := by decide
      destinationLimb1 := by decide
      destinationLimb2 := by decide
      destinationLimb3 := by decide
    }
    intro _
    refine ⟨?_, ?_, ?_, ?_⟩ <;> decide
  · simp [validPreviousClock, accessClock, sllWitnessRow]
  · simp [validPreviousClock, accessClock, sllWitnessRow]
  · simp [validPreviousClock, accessClock, sllWitnessRow]

def sllWitnessEnvironment : ShiftsRegEnvironment sllWitnessRow where
  pre := sllWitnessPre
  word := shiftsRegEncoding sllWitnessRow
  pcBinds := rfl
  wordBinds := rfl
  sourceBinds := by decide
  secondSourceBinds := by decide
  destinationBinds := by decide

theorem sll_exists :
    ∃ (row : ShiftsRegRow) (environment : ShiftsRegEnvironment row),
      ShiftsRegHolds row ∧
        ShiftsRegRefinement row environment ∧
        row.semantic.rd = row.rs1 ∧
        row.semantic.result.word = BitVec.ofNat 32 0x22 :=
  ⟨
    sllWitnessRow,
    sllWitnessEnvironment,
    sll_witness_holds,
    shifts_reg_refines sllWitnessRow sllWitnessEnvironment sll_witness_holds,
    rfl,
    by decide,
  ⟩

/-! ### SRL by a register holding 31 -/

def srlWitnessPre : PreState where
  pc := BitVec.ofNat 32 0x1000
  registers := fun index =>
    if index = BitVec.ofNat 5 5 then BitVec.ofNat 32 0xffffffff
    else if index = BitVec.ofNat 5 6 then BitVec.ofNat 32 31
    else zeroWord
  x0IsZero := by decide

def srlWitnessSemantic : ShiftRow where
  rs1Previous := shiftBytes 0xff 0xff 0xff 0xff
  rs1Next := shiftBytes 0xff 0xff 0xff 0xff
  rs1Sign := false
  kind := ShiftKind.srl
  limbIndex := 3
  bitIndex := 7
  carry0 := 0
  carry1 := 0
  carry2 := 0
  carry3 := 127
  result := shiftBytes 1 0 0 0
  rd := BitVec.ofNat 5 7
  rdPrevious := WordBytes.zero
  rdNext := shiftBytes 1 0 0 0
  rdNonzero := true

def srlWitnessRow : ShiftsRegRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rs2 := BitVec.ofNat 5 6
  rs2PreviousClock := 0
  rs2Previous := shiftBytes 31 0 0 0
  rs2Next := shiftBytes 31 0 0 0
  rdPreviousClock := 0
  semantic := srlWitnessSemantic
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem srl_witness_holds : ShiftsRegHolds srlWitnessRow := by
  refine {
    core := ?_
    clockPositive := by decide
    sourceClock := ?_
    secondSourceClock := ?_
    destinationClock := ?_
    secondSourceReadOnly := rfl
    shiftAmountBinds := ⟨0, by decide, by decide⟩
    nextPcResult := rfl
  }
  · refine {
      limbIndexRange := by decide
      bitIndexRange := by decide
      signIsLogicalZero := fun _ => rfl
      signLowerBound := fun h => absurd h (by decide)
      signUpperBound := fun h => absurd h (by decide)
      carry0Range := by decide
      carry1Range := by decide
      carry2Range := by decide
      carry3Range := by decide
      sourceReadOnly := rfl
      leftMovement := fun h => absurd h (by decide)
      rightMovement := ?_
      destinationFlag := by decide
      destinationLimb0 := by decide
      destinationLimb1 := by decide
      destinationLimb2 := by decide
      destinationLimb3 := by decide
    }
    intro _
    refine ⟨?_, ?_, ?_, ?_⟩ <;> decide
  · simp [validPreviousClock, accessClock, srlWitnessRow]
  · simp [validPreviousClock, accessClock, srlWitnessRow]
  · simp [validPreviousClock, accessClock, srlWitnessRow]

def srlWitnessEnvironment : ShiftsRegEnvironment srlWitnessRow where
  pre := srlWitnessPre
  word := shiftsRegEncoding srlWitnessRow
  pcBinds := rfl
  wordBinds := rfl
  sourceBinds := by decide
  secondSourceBinds := by decide
  destinationBinds := by decide

theorem srl_exists :
    ∃ (row : ShiftsRegRow) (environment : ShiftsRegEnvironment row),
      ShiftsRegHolds row ∧
        ShiftsRegRefinement row environment ∧
        row.semantic.shiftAmount = 31 ∧
        row.semantic.result.word = BitVec.ofNat 32 1 :=
  ⟨
    srlWitnessRow,
    srlWitnessEnvironment,
    srl_witness_holds,
    shifts_reg_refines srlWitnessRow srlWitnessEnvironment srl_witness_holds,
    by decide,
    by decide,
  ⟩

/-! ### SRA by a register holding 255: masking and sign fill together -/

def sraWitnessPre : PreState where
  pc := BitVec.ofNat 32 0x1000
  registers := fun index =>
    if index = BitVec.ofNat 5 5 then BitVec.ofNat 32 0xffffffff
    else if index = BitVec.ofNat 5 6 then BitVec.ofNat 32 0xff
    else zeroWord
  x0IsZero := by decide

def sraWitnessSemantic : ShiftRow where
  rs1Previous := shiftBytes 0xff 0xff 0xff 0xff
  rs1Next := shiftBytes 0xff 0xff 0xff 0xff
  rs1Sign := true
  kind := ShiftKind.sra
  limbIndex := 3
  bitIndex := 7
  carry0 := 0
  carry1 := 0
  carry2 := 0
  carry3 := 127
  result := shiftBytes 0xff 0xff 0xff 0xff
  rd := BitVec.ofNat 5 7
  rdPrevious := WordBytes.zero
  rdNext := shiftBytes 0xff 0xff 0xff 0xff
  rdNonzero := true

def sraWitnessRow : ShiftsRegRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rs2 := BitVec.ofNat 5 6
  rs2PreviousClock := 0
  rs2Previous := shiftBytes 0xff 0 0 0
  rs2Next := shiftBytes 0xff 0 0 0
  rdPreviousClock := 0
  semantic := sraWitnessSemantic
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem sra_witness_holds : ShiftsRegHolds sraWitnessRow := by
  refine {
    core := ?_
    clockPositive := by decide
    sourceClock := ?_
    secondSourceClock := ?_
    destinationClock := ?_
    secondSourceReadOnly := rfl
    shiftAmountBinds := ⟨7, by decide, by decide⟩
    nextPcResult := rfl
  }
  · refine {
      limbIndexRange := by decide
      bitIndexRange := by decide
      signIsLogicalZero := fun h => absurd rfl h
      signLowerBound := fun _ => by decide
      signUpperBound := fun _ => by decide
      carry0Range := by decide
      carry1Range := by decide
      carry2Range := by decide
      carry3Range := by decide
      sourceReadOnly := rfl
      leftMovement := fun h => absurd h (by decide)
      rightMovement := ?_
      destinationFlag := by decide
      destinationLimb0 := by decide
      destinationLimb1 := by decide
      destinationLimb2 := by decide
      destinationLimb3 := by decide
    }
    intro _
    refine ⟨?_, ?_, ?_, ?_⟩ <;> decide
  · simp [validPreviousClock, accessClock, sraWitnessRow]
  · simp [validPreviousClock, accessClock, sraWitnessRow]
  · simp [validPreviousClock, accessClock, sraWitnessRow]

def sraWitnessEnvironment : ShiftsRegEnvironment sraWitnessRow where
  pre := sraWitnessPre
  word := shiftsRegEncoding sraWitnessRow
  pcBinds := rfl
  wordBinds := rfl
  sourceBinds := by decide
  secondSourceBinds := by decide
  destinationBinds := by decide

/-- The `SRA` witness exercises the five-bit mask (`rs2 = 255` shifts by 31, not
by 255) together with the sign fill on a negative operand. -/
theorem sra_exists :
    ∃ (row : ShiftsRegRow) (environment : ShiftsRegEnvironment row),
      ShiftsRegHolds row ∧
        ShiftsRegRefinement row environment ∧
        row.rs2Next.word.toNat = 255 ∧
        row.semantic.shiftAmount = 31 ∧
        row.semantic.rs1Sign = true ∧
        row.semantic.result.word = BitVec.ofNat 32 0xffffffff :=
  ⟨
    sraWitnessRow,
    sraWitnessEnvironment,
    sra_witness_holds,
    shifts_reg_refines sraWitnessRow sraWitnessEnvironment sra_witness_holds,
    by decide,
    by decide,
    rfl,
    by decide,
  ⟩

end RiscvRefinement.Opcodes
