import RiscvRefinement.Air.Generated.Pilot
import RiscvRefinement.Bridge.Decode
import RiscvRefinement.Sail.Generated.Pilot

namespace RiscvRefinement.Opcodes

open RiscvRefinement
open RiscvRefinement.Air.Generated
open RiscvRefinement.Sail.Generated

structure AddiEnvironment (row : AddiRow) where
  pre : PreState
  word : InstructionWord
  pcBinds : row.pc = pre.pc
  wordBinds :
    word =
      Decode.encodeAddi
        (addiImmediate row.imm0 row.imm1 row.immSign)
        row.rs1
        row.rd
  sourceBinds : row.rs1Previous.word = pre.registers row.rs1
  destinationBinds : row.rdPrevious.word = pre.registers row.rd

structure AddiRefinement
    (row : AddiRow)
    (environment : AddiEnvironment row) :
    Prop where
  decode :
    Decode.isAddi environment.word = true ∧
      Decode.decodeIImmediate environment.word =
        addiImmediate row.imm0 row.imm1 row.immSign ∧
      Decode.decodeRs1 environment.word = row.rs1 ∧
      Decode.decodeRd environment.word = row.rd
  retirement :
    addiRetirement row =
      executeAddi
        environment.pre.pc
        (environment.pre.registers row.rs1)
        row.rd
        (addiImmediate row.imm0 row.imm1 row.immSign)
  programTuple :
    (addiRelations row).program = {
      pc := environment.pre.pc
      opcodeId := 10
      rd := row.rd.toNat
      rs1 := row.rs1.toNat
      operand := (addiImmediate row.imm0 row.imm1 row.immSign).toNat
    }
  stateConsume :
    (addiRelations row).stateConsume = {
      pc := environment.pre.pc
      clock := row.clock
    }
  stateEmit :
    (addiRelations row).stateEmit = {
      pc := nextPc environment.pre.pc
      clock := row.clock + 1
    }
  sourceConsume :
    (addiRelations row).sourceConsume = {
      addr := row.rs1
      clock := row.rs1PreviousClock
      value := environment.pre.registers row.rs1
    }
  sourceEmit :
    (addiRelations row).sourceEmit = {
      addr := row.rs1
      clock := accessClock row.clock 1
      value := environment.pre.registers row.rs1
    }
  destinationConsume :
    (addiRelations row).destinationConsume = {
      addr := row.rd
      clock := row.rdPreviousClock
      value := environment.pre.registers row.rd
    }
  destinationEmit :
    (addiRelations row).destinationEmit = {
      addr := row.rd
      clock := accessClock row.clock 2
      value :=
        architecturalValue row.rd
          (executeAddiValue
            (environment.pre.registers row.rs1)
            (addiImmediate row.imm0 row.imm1 row.immSign))
    }

theorem addi_immediate_refines
    (imm0 : BitVec 8)
    (imm1 : BitVec 3)
    (sign : BitVec 1) :
    addiAirImmediate imm0 imm1 sign =
      BitVec.signExtend 32 (addiImmediate imm0 imm1 sign) := by
  have hSignBound := sign.isLt
  simp only [Nat.reducePow] at hSignBound
  have hSign : sign.toNat = 0 ∨ sign.toNat = 1 := by omega
  rcases hSign with hSign | hSign
  · have hSignEq : sign = BitVec.ofNat 1 0 := by
      apply BitVec.eq_of_toNat_eq
      simp [hSign]
    rw [hSignEq]
    apply BitVec.eq_of_toNat_eq
    simp only [
      addiAirImmediate,
      addiImmediateValue,
      addiImmediate,
      BitVec.toNat_ofNat,
      BitVec.toNat_signExtend,
      BitVec.toNat_setWidth,
      BitVec.append_eq,
      toNat_append_arith,
      Nat.reducePow,
      BitVec.msb_append,
    ]
    simp
    congr 1 <;> omega
  · have hSignEq : sign = BitVec.ofNat 1 1 := by
      apply BitVec.eq_of_toNat_eq
      simp [hSign]
    rw [hSignEq]
    apply BitVec.eq_of_toNat_eq
    simp only [
      addiAirImmediate,
      addiImmediateValue,
      addiImmediate,
      BitVec.toNat_ofNat,
      BitVec.toNat_signExtend,
      BitVec.toNat_setWidth,
      BitVec.append_eq,
      toNat_append_arith,
      Nat.reducePow,
      BitVec.msb_append,
    ]
    simp
    have h0 := imm0.isLt
    have h1 := imm1.isLt
    simp only [Nat.reducePow] at h0 h1
    rw [Nat.mod_eq_of_lt (by omega), Nat.mod_eq_of_lt (by omega)]
    omega

theorem addi_immediate_value_lt
    (imm0 : BitVec 8)
    (imm1 : BitVec 3)
    (sign : BitVec 1) :
    addiImmediateValue imm0 imm1 sign < 2 ^ 32 := by
  have h0 := imm0.isLt
  have h1 := imm1.isLt
  have hSign := sign.isLt
  simp only [Nat.reducePow] at h0 h1 hSign ⊢
  simp only [addiImmediateValue]
  omega

theorem addi_source_from_constraints
    (row : AddiRow)
    (holds : AddiHolds row) :
    row.rs1Next.word = row.rs1Previous.word :=
  congrArg WordBytes.word <|
    WordBytes.eq_of_limbs
      row.rs1Next
      row.rs1Previous
      holds.sourceLimb0
      holds.sourceLimb1
      holds.sourceLimb2
      holds.sourceLimb3

theorem addi_arithmetic_from_constraints
    (row : AddiRow)
    (holds : AddiHolds row) :
    row.result.word =
      addiResult row.rs1Next.word row.imm0 row.imm1 row.immSign := by
  rcases holds.carryRecurrence with
    ⟨carry1, carry2, carry3, carry4, limb0, limb1, limb2, limb3⟩
  unfold addiResult
  apply BitVec.eq_of_toNat_eq
  simp only [
    WordBytes.word_toNat,
    BitVec.toNat_add,
    addiAirImmediate,
    BitVec.toNat_ofNat,
    Nat.reducePow,
  ]
  rw [Nat.mod_eq_of_lt (addi_immediate_value_lt row.imm0 row.imm1 row.immSign)]
  have total :
      row.rs1Next.value +
          addiImmediateValue row.imm0 row.imm1 row.immSign =
        row.result.value + 4294967296 * carry4.toNat := by
    simp only [WordBytes.value, addiImmediateValue]
    omega
  rw [total]
  have resultBound := row.result.value_lt
  simp only [Nat.reducePow] at resultBound
  omega

theorem addi_destination_from_constraints
    (row : AddiRow)
    (holds : AddiHolds row) :
    row.rdNext.word =
      architecturalValue row.rd row.result.word := by
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

theorem addi_value_refines
    (source : Word)
    (imm0 : BitVec 8)
    (imm1 : BitVec 3)
    (sign : BitVec 1) :
    addiResult source imm0 imm1 sign =
      executeAddiValue source (addiImmediate imm0 imm1 sign) := by
  simp [
    addiResult,
    executeAddiValue,
    addi_immediate_refines,
  ]

theorem addi_refines
    (row : AddiRow)
    (environment : AddiEnvironment row)
    (holds : AddiHolds row) :
    AddiRefinement row environment := by
  constructor
  · rw [environment.wordBinds]
    exact Decode.encode_addi_is_canonical
      (addiImmediate row.imm0 row.imm1 row.immSign)
      row.rs1
      row.rd
  · unfold addiRetirement executeAddi
    rw [
      holds.nextPcResult,
      environment.pcBinds,
      addi_destination_from_constraints row holds,
      addi_arithmetic_from_constraints row holds,
      addi_source_from_constraints row holds,
      environment.sourceBinds,
      addi_value_refines,
      architecturalWrite_value,
    ]
  · simp [addiRelations, addiProgramTuple, environment.pcBinds]
  · simp [addiRelations, environment.pcBinds]
  · simp [addiRelations, environment.pcBinds]
  · simp [addiRelations, environment.sourceBinds]
  · simp [
      addiRelations,
      addi_source_from_constraints row holds,
      environment.sourceBinds,
    ]
  · simp [addiRelations, environment.destinationBinds]
  · simp [
      addiRelations,
      addi_destination_from_constraints row holds,
      addi_arithmetic_from_constraints row holds,
      addi_source_from_constraints row holds,
      environment.sourceBinds,
      addi_value_refines,
    ]

end RiscvRefinement.Opcodes
