import RiscvRefinement.Air.Generated.Pilot
import RiscvRefinement.Air.Bridge.Lui
import RiscvRefinement.Bridge.Decode
import RiscvRefinement.Sail.Generated.Pilot

namespace RiscvRefinement.Opcodes

open RiscvRefinement
open RiscvRefinement.Air.Generated
open RiscvRefinement.Sail.Generated

structure LuiEnvironment (row : LuiRow) where
  pre : PreState
  word : InstructionWord
  pcBinds : row.pc = pre.pc
  wordBinds :
    word =
      Decode.encodeLui
        (luiImmediate row.imm0 row.imm1 row.imm2)
        row.rd
  destinationBinds : row.rdPrevious.word = pre.registers row.rd

structure LuiRefinement
    (row : LuiRow)
    (environment : LuiEnvironment row) :
    Prop where
  decode :
    Decode.isLui environment.word = true ∧
      Decode.decodeLuiImmediate environment.word =
        luiImmediate row.imm0 row.imm1 row.imm2 ∧
      Decode.decodeRd environment.word = row.rd
  retirement :
    luiRetirement row =
      executeLui
        environment.pre.pc
        row.rd
        (luiImmediate row.imm0 row.imm1 row.imm2)
  programTuple :
    (luiRelations row).program = {
      pc := environment.pre.pc
      opcodeId := 35
      rd := row.rd.toNat
      rs1 := (luiImmediate row.imm0 row.imm1 row.imm2).toNat
      operand := 0
    }
  stateConsume :
    (luiRelations row).stateConsume = {
      pc := environment.pre.pc
      clock := row.clock
    }
  stateEmit :
    (luiRelations row).stateEmit = {
      pc := nextPc environment.pre.pc
      clock := row.clock + 1
    }
  destinationConsume :
    (luiRelations row).destinationConsume = {
      addr := row.rd
      clock := row.rdPreviousClock
      value := environment.pre.registers row.rd
    }
  destinationEmit :
    (luiRelations row).destinationEmit = {
      addr := row.rd
      clock := accessClock row.clock 1
      value :=
        architecturalValue row.rd
          (executeLuiValue
            (luiImmediate row.imm0 row.imm1 row.imm2))
    }

theorem lui_value_refines
    (imm0 : BitVec 4)
    (imm1 imm2 : BitVec 8) :
    luiResult imm0 imm1 imm2 =
      executeLuiValue (luiImmediate imm0 imm1 imm2) := by
  simp only [
    luiResult,
    executeLuiValue,
    luiImmediate,
  ]
  bv_decide

theorem lui_result_bytes_refine
    (imm0 : BitVec 4)
    (imm1 imm2 : BitVec 8) :
    (luiResultBytes imm0 imm1 imm2).word =
      luiResult imm0 imm1 imm2 := by
  apply BitVec.eq_of_toNat_eq
  simp only [
    WordBytes.word_toNat,
    WordBytes.value,
    luiResultBytes,
    luiResult,
    luiImmediate,
    BitVec.append_eq,
    toNat_append_arith,
    BitVec.toNat_ofNat,
    Nat.reducePow,
    Nat.zero_mod,
  ]
  omega

theorem lui_destination_from_constraints
    (row : LuiRow)
    (holds : LuiHolds row) :
    row.rdNext.word =
      architecturalValue row.rd
        (luiResult row.imm0 row.imm1 row.imm2) := by
  by_cases hzero : row.rd = zeroRegister
  · have hflag : row.rdNonzero = false := by
      rw [holds.destinationFlag]
      simp [hzero]
    rw [hzero, architecturalValue_zero]
    apply BitVec.eq_of_toNat_eq
    simp only [WordBytes.word_toNat]
    simp [
      WordBytes.value,
      holds.destinationLimb0,
      holds.destinationLimb1,
      holds.destinationLimb2,
      holds.destinationLimb3,
      hflag,
      WordBytes.zero,
      zeroWord,
    ]
  · have hflag : row.rdNonzero = true := by
      rw [holds.destinationFlag]
      simp [hzero]
    rw [architecturalValue]
    simp only [hzero, ↓reduceIte]
    rw [← lui_result_bytes_refine]
    apply BitVec.eq_of_toNat_eq
    simp only [WordBytes.word_toNat]
    simp [
      WordBytes.value,
      holds.destinationLimb0,
      holds.destinationLimb1,
      holds.destinationLimb2,
      holds.destinationLimb3,
      hflag,
    ]

theorem lui_refines
    (row : LuiRow)
    (environment : LuiEnvironment row)
    (holds : LuiHolds row) :
    LuiRefinement row environment := by
  constructor
  · rw [environment.wordBinds]
    exact Decode.encode_lui_is_canonical
      (luiImmediate row.imm0 row.imm1 row.imm2)
      row.rd
  · unfold luiRetirement executeLui
    rw [
      holds.nextPcResult,
      environment.pcBinds,
      lui_destination_from_constraints row holds,
      lui_value_refines,
      architecturalWrite_value,
    ]
  · simp [luiRelations, luiProgramTuple, environment.pcBinds]
  · simp [luiRelations, environment.pcBinds]
  · simp [luiRelations, environment.pcBinds]
  · simp [
      luiRelations,
      environment.destinationBinds,
    ]
  · simp [
      luiRelations,
      lui_destination_from_constraints row holds,
      lui_value_refines,
    ]

theorem lui_production_refines
    (row : LuiRow)
    (witness : Air.Bridge.Lui.Witness row)
    (environment :
      LuiEnvironment (Air.Bridge.Lui.interpretedRow row))
    (admission : Air.Bridge.Lui.Admission row)
    (accepted : Air.Bridge.Lui.Acceptance row witness) :
    LuiRefinement (Air.Bridge.Lui.interpretedRow row) environment :=
  lui_refines
    (Air.Bridge.Lui.interpretedRow row)
    environment
    (Air.Bridge.Lui.sound row witness admission accepted)

def productionLuiPreState : PreState where
  pc := BitVec.ofNat 32 0x1000
  registers := fun _ => zeroWord
  x0IsZero := rfl

def productionLuiEnvironment :
    LuiEnvironment
      (Air.Bridge.Lui.interpretedRow Air.Bridge.Lui.exampleRow) where
  pre := productionLuiPreState
  word :=
    Decode.encodeLui
      (luiImmediate
        Air.Bridge.Lui.exampleRow.imm0
        Air.Bridge.Lui.exampleRow.imm1
        Air.Bridge.Lui.exampleRow.imm2)
      Air.Bridge.Lui.exampleRow.rd
  pcBinds := rfl
  wordBinds := rfl
  destinationBinds := by
    decide

theorem lui_production_nonvacuous :
    ∃ (row : LuiRow)
      (witness : Air.Bridge.Lui.Witness row)
      (environment :
        LuiEnvironment (Air.Bridge.Lui.interpretedRow row)),
      Air.Bridge.Lui.Admission row ∧
        Air.Bridge.Lui.Acceptance row witness ∧
        LuiRefinement (Air.Bridge.Lui.interpretedRow row) environment :=
  ⟨
    Air.Bridge.Lui.exampleRow,
    Air.Bridge.Lui.exampleWitness,
    productionLuiEnvironment,
    Air.Bridge.Lui.exampleAdmission,
    Air.Bridge.Lui.exampleAcceptance,
    lui_production_refines
      Air.Bridge.Lui.exampleRow
      Air.Bridge.Lui.exampleWitness
      productionLuiEnvironment
      Air.Bridge.Lui.exampleAdmission
      Air.Bridge.Lui.exampleAcceptance
  ⟩

def zeroProductionLuiEnvironment
    (zeroDestination : Bool) :
    LuiEnvironment
      (Air.Bridge.Lui.interpretedRow
        (Air.Bridge.Lui.zeroRow zeroDestination)) where
  pre := productionLuiPreState
  word :=
    Decode.encodeLui
      (luiImmediate
        (Air.Bridge.Lui.zeroRow zeroDestination).imm0
        (Air.Bridge.Lui.zeroRow zeroDestination).imm1
        (Air.Bridge.Lui.zeroRow zeroDestination).imm2)
      (Air.Bridge.Lui.zeroRow zeroDestination).rd
  pcBinds := rfl
  wordBinds := rfl
  destinationBinds := by
    simp [
      Air.Bridge.Lui.interpretedRow,
      Air.Bridge.Lui.zeroRow,
      productionLuiPreState,
      WordBytes.zero_word,
    ]

theorem lui_zero_destination_production_nonvacuous :
    ∃ (row : LuiRow)
      (witness : Air.Bridge.Lui.Witness row)
      (environment :
        LuiEnvironment (Air.Bridge.Lui.interpretedRow row)),
      Air.Bridge.Lui.Admission row ∧
        Air.Bridge.Lui.Acceptance row witness ∧
        LuiRefinement (Air.Bridge.Lui.interpretedRow row) environment ∧
        row.rd = zeroRegister :=
  ⟨
    Air.Bridge.Lui.zeroRow true,
    Air.Bridge.Lui.zeroWitness true,
    zeroProductionLuiEnvironment true,
    Air.Bridge.Lui.zeroAdmission true,
    Air.Bridge.Lui.zeroAcceptance true,
    lui_production_refines
      (Air.Bridge.Lui.zeroRow true)
      (Air.Bridge.Lui.zeroWitness true)
      (zeroProductionLuiEnvironment true)
      (Air.Bridge.Lui.zeroAdmission true)
      (Air.Bridge.Lui.zeroAcceptance true),
    rfl
  ⟩

end RiscvRefinement.Opcodes
