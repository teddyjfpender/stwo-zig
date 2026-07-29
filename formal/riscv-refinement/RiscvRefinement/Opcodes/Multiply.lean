-- RV32M multiply refinements: `MUL`, `MULH`, `MULHSU`, `MULHU`.
--
-- The AIR side is the reviewed transcription of the production symbolic AIR
-- export (RiscvRefinement/Air/Family/Multiply.lean). The architectural side is
-- a REVIEWED NORMALIZED CAPSULE of the Sail `MUL` clause
-- (RiscvRefinement/Sail/Reviewed/Multiply.lean), not a generated-Sail theorem:
-- no Sail compiler is available in this environment, and replacing that
-- capsule with a generated definition slice is the open obligation.
--
-- The frozen decode bridge (RiscvRefinement/Bridge/Decode.lean) carries no
-- R-type encoder, so these environments bind architectural state only; the
-- instruction-word decode obligation for the R-type multiply encodings is not
-- claimed here.

import RiscvRefinement.Air.Family.Multiply
import RiscvRefinement.Sail.Reviewed.Multiply

namespace RiscvRefinement.Opcodes

open RiscvRefinement
open RiscvRefinement.Air.Family
open RiscvRefinement.Sail.Reviewed

/-! ## Bridging the AIR's eight-limb operand to a 64-bit bit vector -/

/-- Zero extension to 64 bits is the AIR's unsigned operand. -/
theorem multiplyExtendedSetWidth (bytes : WordBytes) :
    (BitVec.setWidth 64 bytes.word).toNat = multiplyExtendedValue bytes false := by
  rw [BitVec.toNat_setWidth_of_le (by omega)]
  simp only [WordBytes.word_toNat, multiplyExtendedValue]

/-- Sign extension to 64 bits is the AIR's signed operand, provided the sign
witness is the operand's bit 31. -/
theorem multiplyExtendedSignExtend
    (bytes : WordBytes)
    (sign : Bool)
    (binding : bytes.word.msb = sign) :
    (BitVec.signExtend 64 bytes.word).toNat =
      multiplyExtendedValue bytes sign := by
  cases sign
  · rw [BitVec.signExtend_eq_setWidth_of_msb_false binding]
    exact multiplyExtendedSetWidth bytes
  · have fill : ∀ x : Word, x.msb = true →
        BitVec.signExtend 64 x = (BitVec.ofNat 32 4294967295).append x := by
      intro x hx
      bv_decide
    rw [fill bytes.word binding, BitVec.append_eq, toNat_append_arith]
    simp only [multiplyExtendedValue, WordBytes.word_toNat, BitVec.toNat_ofNat,
      Nat.reducePow]
    omega

/-! ## MUL -/

structure MulEnvironment (row : MulRow) where
  pre : PreState
  pcBinds : row.pc = pre.pc
  sourceOneBinds : row.rs1Previous.word = pre.registers row.rs1
  sourceTwoBinds : row.rs2Previous.word = pre.registers row.rs2
  destinationBinds : row.rdPrevious.word = pre.registers row.rd

structure MulRefinement
    (row : MulRow)
    (environment : MulEnvironment row) :
    Prop where
  retirement :
    mulRetirement row =
      executeMul
        environment.pre.pc
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2)
        row.rd
  nextProgramCounter :
    (mulRetirement row).nextPc = nextPc environment.pre.pc
  noMemoryRead : (mulRetirement row).read = none
  noMemoryWrite : (mulRetirement row).store = none
  zeroDestination :
    row.rd = zeroRegister → (mulRetirement row).write = none
  programTuple :
    (mulRelations row).program = {
      pc := environment.pre.pc
      opcodeId := 37
      rd := row.rd.toNat
      rs1 := row.rs1.toNat
      operand := row.rs2.toNat
    }
  stateConsume :
    (mulRelations row).stateConsume = {
      pc := environment.pre.pc
      clock := row.clock
    }
  stateEmit :
    (mulRelations row).stateEmit = {
      pc := nextPc environment.pre.pc
      clock := row.clock + 1
    }
  sourceOneConsume :
    (mulRelations row).sourceOneConsume = {
      addr := row.rs1
      clock := row.rs1PreviousClock
      value := environment.pre.registers row.rs1
    }
  sourceOneEmit :
    (mulRelations row).sourceOneEmit = {
      addr := row.rs1
      clock := accessClock row.clock 1
      value := environment.pre.registers row.rs1
    }
  sourceTwoConsume :
    (mulRelations row).sourceTwoConsume = {
      addr := row.rs2
      clock := row.rs2PreviousClock
      value := environment.pre.registers row.rs2
    }
  sourceTwoEmit :
    (mulRelations row).sourceTwoEmit = {
      addr := row.rs2
      clock := accessClock row.clock 2
      value := environment.pre.registers row.rs2
    }
  destinationConsume :
    (mulRelations row).destinationConsume = {
      addr := row.rd
      clock := row.rdPreviousClock
      value := environment.pre.registers row.rd
    }
  destinationEmit :
    (mulRelations row).destinationEmit = {
      addr := row.rd
      clock := accessClock row.clock 3
      value :=
        architecturalValue row.rd
          (executeMulValue
            (environment.pre.registers row.rs1)
            (environment.pre.registers row.rs2))
    }

/-- The written word is the architectural `MUL` value: the low 32 bits of the
complete integer product, derived from the AIR carry chain. -/
theorem mulValueRefines (row : MulRow) (holds : MulHolds row) :
    row.result.word =
      executeMulValue row.rs1Previous.word row.rs2Previous.word := by
  rw [executeMulValue_eq_mul, mulResultWord row holds,
    mulSourceOneStable row holds, mulSourceTwoStable row holds]

theorem mul_refines
    (row : MulRow)
    (environment : MulEnvironment row)
    (holds : MulHolds row) :
    MulRefinement row environment := by
  have value := mulValueRefines row holds
  rw [environment.sourceOneBinds, environment.sourceTwoBinds] at value
  constructor
  · unfold mulRetirement executeMul
    rw [holds.nextPcResult, environment.pcBinds,
      mulDestinationValue row holds, architecturalWrite_value, value]
  · simp [mulRetirement, holds.nextPcResult, environment.pcBinds]
  · rfl
  · rfl
  · intro isZero
    simp [mulRetirement, isZero, architecturalWrite]
  · simp [mulRelations, mulProgramTuple, environment.pcBinds]
  · simp [mulRelations, environment.pcBinds]
  · simp [mulRelations, environment.pcBinds]
  · simp [mulRelations, environment.sourceOneBinds]
  · simp [mulRelations, mulSourceOneStable row holds, environment.sourceOneBinds]
  · simp [mulRelations, environment.sourceTwoBinds]
  · simp [mulRelations, mulSourceTwoStable row holds, environment.sourceTwoBinds]
  · simp [mulRelations, environment.destinationBinds]
  · simp [mulRelations, mulDestinationValue row holds, value]

/-! ## MULH / MULHSU / MULHU -/

structure MulhEnvironment (row : MulhRow) where
  pre : PreState
  pcBinds : row.pc = pre.pc
  sourceOneBinds : row.rs1Previous.word = pre.registers row.rs1
  sourceTwoBinds : row.rs2Previous.word = pre.registers row.rs2
  destinationBinds : row.rdPrevious.word = pre.registers row.rd

/-- The shared high-word projection: whatever 64-bit extension of the two
operands the AIR's sign witnesses describe, the written word is bits 63..32 of
their product. All three selectors are instances of this. -/
theorem mulhResultFromOperands
    (row : MulhRow)
    (holds : MulhHolds row)
    (left right : BitVec 64)
    (leftBinds : left.toNat = multiplyExtendedValue row.rs1Next row.rs1Sign)
    (rightBinds : right.toNat = multiplyExtendedValue row.rs2Next row.rs2Sign) :
    row.result.word = BitVec.setWidth 32 ((left * right) >>> 32) := by
  apply BitVec.eq_of_toNat_eq
  simp only [WordBytes.word_toNat, BitVec.toNat_setWidth,
    BitVec.toNat_ushiftRight, BitVec.toNat_mul, leftBinds, rightBinds,
    Nat.shiftRight_eq_div_pow, Nat.reducePow]
  exact (mulhHighWord row holds).symm

/-- The `rs1` sign witness is bit 31 of `rs1`, from the AIR range check. -/
theorem mulhSourceOneSign
    (row : MulhRow)
    (holds : MulhHolds row)
    (signed : row.selector.signedSourceOne = true) :
    row.rs1Next.word.msb = row.rs1Sign := by
  obtain ⟨rest, witness⟩ := holds.signedSourceOne signed
  exact multiplySignIsMsb row.rs1Next row.rs1Sign rest witness

/-- The `rs2` sign witness is bit 31 of `rs2`, from the AIR range check. -/
theorem mulhSourceTwoSign
    (row : MulhRow)
    (holds : MulhHolds row)
    (signed : row.selector.signedSourceTwo = true) :
    row.rs2Next.word.msb = row.rs2Sign := by
  obtain ⟨rest, witness⟩ := holds.signedSourceTwo signed
  exact multiplySignIsMsb row.rs2Next row.rs2Sign rest witness

theorem mulhValueRefines
    (row : MulhRow)
    (holds : MulhHolds row)
    (selector : row.selector = MulhSelector.mulh) :
    row.result.word =
      executeMulhValue row.rs1Previous.word row.rs2Previous.word := by
  rw [← mulhSourceOneStable row holds, ← mulhSourceTwoStable row holds,
    executeMulhValue]
  exact mulhResultFromOperands row holds _ _
    (multiplyExtendedSignExtend row.rs1Next row.rs1Sign
      (mulhSourceOneSign row holds (by rw [selector]; rfl)))
    (multiplyExtendedSignExtend row.rs2Next row.rs2Sign
      (mulhSourceTwoSign row holds (by rw [selector]; rfl)))

theorem mulhsuValueRefines
    (row : MulhRow)
    (holds : MulhHolds row)
    (selector : row.selector = MulhSelector.mulhsu) :
    row.result.word =
      executeMulhsuValue row.rs1Previous.word row.rs2Previous.word := by
  have signTwo : row.rs2Sign = false :=
    holds.unsignedSourceTwo (by rw [selector]; rfl)
  rw [← mulhSourceOneStable row holds, ← mulhSourceTwoStable row holds,
    executeMulhsuValue]
  refine mulhResultFromOperands row holds _ _
    (multiplyExtendedSignExtend row.rs1Next row.rs1Sign
      (mulhSourceOneSign row holds (by rw [selector]; rfl))) ?_
  rw [signTwo]
  exact multiplyExtendedSetWidth row.rs2Next

theorem mulhuValueRefines
    (row : MulhRow)
    (holds : MulhHolds row)
    (selector : row.selector = MulhSelector.mulhu) :
    row.result.word =
      executeMulhuValue row.rs1Previous.word row.rs2Previous.word := by
  have signOne : row.rs1Sign = false :=
    holds.unsignedSourceOne (by rw [selector]; rfl)
  have signTwo : row.rs2Sign = false :=
    holds.unsignedSourceTwo (by rw [selector]; rfl)
  rw [← mulhSourceOneStable row holds, ← mulhSourceTwoStable row holds,
    executeMulhuValue]
  refine mulhResultFromOperands row holds _ _ ?_ ?_
  · rw [signOne]
    exact multiplyExtendedSetWidth row.rs1Next
  · rw [signTwo]
    exact multiplyExtendedSetWidth row.rs2Next

/-- The selector-independent half of the high-multiply refinement: program
counter, absence of any memory effect, the `x0` rule, and every state and
register bus tuple except the destination write-back value. -/
structure MulhBusRefinement
    (row : MulhRow)
    (environment : MulhEnvironment row) :
    Prop where
  nextProgramCounter :
    (mulhRetirement row).nextPc = nextPc environment.pre.pc
  noMemoryRead : (mulhRetirement row).read = none
  noMemoryWrite : (mulhRetirement row).store = none
  zeroDestination :
    row.rd = zeroRegister → (mulhRetirement row).write = none
  stateConsume :
    (mulhRelations row).stateConsume = {
      pc := environment.pre.pc
      clock := row.clock
    }
  stateEmit :
    (mulhRelations row).stateEmit = {
      pc := nextPc environment.pre.pc
      clock := row.clock + 1
    }
  sourceOneConsume :
    (mulhRelations row).sourceOneConsume = {
      addr := row.rs1
      clock := row.rs1PreviousClock
      value := environment.pre.registers row.rs1
    }
  sourceOneEmit :
    (mulhRelations row).sourceOneEmit = {
      addr := row.rs1
      clock := accessClock row.clock 1
      value := environment.pre.registers row.rs1
    }
  sourceTwoConsume :
    (mulhRelations row).sourceTwoConsume = {
      addr := row.rs2
      clock := row.rs2PreviousClock
      value := environment.pre.registers row.rs2
    }
  sourceTwoEmit :
    (mulhRelations row).sourceTwoEmit = {
      addr := row.rs2
      clock := accessClock row.clock 2
      value := environment.pre.registers row.rs2
    }
  destinationConsume :
    (mulhRelations row).destinationConsume = {
      addr := row.rd
      clock := row.rdPreviousClock
      value := environment.pre.registers row.rd
    }

theorem mulh_bus_refines
    (row : MulhRow)
    (environment : MulhEnvironment row)
    (holds : MulhHolds row) :
    MulhBusRefinement row environment := by
  constructor
  · simp [mulhRetirement, holds.nextPcResult, environment.pcBinds]
  · rfl
  · rfl
  · intro isZero
    simp [mulhRetirement, isZero, architecturalWrite]
  · simp [mulhRelations, environment.pcBinds]
  · simp [mulhRelations, environment.pcBinds]
  · simp [mulhRelations, environment.sourceOneBinds]
  · simp [mulhRelations, mulhSourceOneStable row holds,
      environment.sourceOneBinds]
  · simp [mulhRelations, environment.sourceTwoBinds]
  · simp [mulhRelations, mulhSourceTwoStable row holds,
      environment.sourceTwoBinds]
  · simp [mulhRelations, environment.destinationBinds]

structure MulhRefinement
    (row : MulhRow)
    (environment : MulhEnvironment row) :
    Prop where
  bus : MulhBusRefinement row environment
  retirement :
    mulhRetirement row =
      executeMulh
        environment.pre.pc
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2)
        row.rd
  programTuple :
    (mulhRelations row).program = {
      pc := environment.pre.pc
      opcodeId := 38
      rd := row.rd.toNat
      rs1 := row.rs1.toNat
      operand := row.rs2.toNat
    }
  destinationEmit :
    (mulhRelations row).destinationEmit = {
      addr := row.rd
      clock := accessClock row.clock 3
      value :=
        architecturalValue row.rd
          (executeMulhValue
            (environment.pre.registers row.rs1)
            (environment.pre.registers row.rs2))
    }

structure MulhsuRefinement
    (row : MulhRow)
    (environment : MulhEnvironment row) :
    Prop where
  bus : MulhBusRefinement row environment
  retirement :
    mulhRetirement row =
      executeMulhsu
        environment.pre.pc
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2)
        row.rd
  programTuple :
    (mulhRelations row).program = {
      pc := environment.pre.pc
      opcodeId := 39
      rd := row.rd.toNat
      rs1 := row.rs1.toNat
      operand := row.rs2.toNat
    }
  destinationEmit :
    (mulhRelations row).destinationEmit = {
      addr := row.rd
      clock := accessClock row.clock 3
      value :=
        architecturalValue row.rd
          (executeMulhsuValue
            (environment.pre.registers row.rs1)
            (environment.pre.registers row.rs2))
    }

structure MulhuRefinement
    (row : MulhRow)
    (environment : MulhEnvironment row) :
    Prop where
  bus : MulhBusRefinement row environment
  retirement :
    mulhRetirement row =
      executeMulhu
        environment.pre.pc
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2)
        row.rd
  programTuple :
    (mulhRelations row).program = {
      pc := environment.pre.pc
      opcodeId := 40
      rd := row.rd.toNat
      rs1 := row.rs1.toNat
      operand := row.rs2.toNat
    }
  destinationEmit :
    (mulhRelations row).destinationEmit = {
      addr := row.rd
      clock := accessClock row.clock 3
      value :=
        architecturalValue row.rd
          (executeMulhuValue
            (environment.pre.registers row.rs1)
            (environment.pre.registers row.rs2))
    }

theorem mulh_refines
    (row : MulhRow)
    (environment : MulhEnvironment row)
    (holds : MulhHolds row)
    (selector : row.selector = MulhSelector.mulh) :
    MulhRefinement row environment := by
  have value := mulhValueRefines row holds selector
  rw [environment.sourceOneBinds, environment.sourceTwoBinds] at value
  refine ⟨mulh_bus_refines row environment holds, ?_, ?_, ?_⟩
  · unfold mulhRetirement executeMulh
    rw [holds.nextPcResult, environment.pcBinds,
      mulhDestinationValue row holds, architecturalWrite_value, value]
  · simp [mulhRelations, mulhProgramTuple, environment.pcBinds, selector,
      MulhSelector.opcodeId]
  · simp [mulhRelations, mulhDestinationValue row holds, value]

theorem mulhsu_refines
    (row : MulhRow)
    (environment : MulhEnvironment row)
    (holds : MulhHolds row)
    (selector : row.selector = MulhSelector.mulhsu) :
    MulhsuRefinement row environment := by
  have value := mulhsuValueRefines row holds selector
  rw [environment.sourceOneBinds, environment.sourceTwoBinds] at value
  refine ⟨mulh_bus_refines row environment holds, ?_, ?_, ?_⟩
  · unfold mulhRetirement executeMulhsu
    rw [holds.nextPcResult, environment.pcBinds,
      mulhDestinationValue row holds, architecturalWrite_value, value]
  · simp [mulhRelations, mulhProgramTuple, environment.pcBinds, selector,
      MulhSelector.opcodeId]
  · simp [mulhRelations, mulhDestinationValue row holds, value]

theorem mulhu_refines
    (row : MulhRow)
    (environment : MulhEnvironment row)
    (holds : MulhHolds row)
    (selector : row.selector = MulhSelector.mulhu) :
    MulhuRefinement row environment := by
  have value := mulhuValueRefines row holds selector
  rw [environment.sourceOneBinds, environment.sourceTwoBinds] at value
  refine ⟨mulh_bus_refines row environment holds, ?_, ?_, ?_⟩
  · unfold mulhRetirement executeMulhu
    rw [holds.nextPcResult, environment.pcBinds,
      mulhDestinationValue row holds, architecturalWrite_value, value]
  · simp [mulhRelations, mulhProgramTuple, environment.pcBinds, selector,
      MulhSelector.opcodeId]
  · simp [mulhRelations, mulhDestinationValue row holds, value]

/-! ## Non-vacuity witnesses: honest rows for each selector -/

def honestMulRow : MulRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 9
  rd := BitVec.ofNat 5 7
  rdPreviousClock := 0
  rdPrevious := {
    limb0 := BitVec.ofNat 8 0
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 0
  }
  rdNext := {
    limb0 := BitVec.ofNat 8 1
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 0
  }
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rs1Previous := {
    limb0 := BitVec.ofNat 8 255
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  rs1Next := {
    limb0 := BitVec.ofNat 8 255
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  rs2 := BitVec.ofNat 5 6
  rs2PreviousClock := 0
  rs2Previous := {
    limb0 := BitVec.ofNat 8 255
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  rs2Next := {
    limb0 := BitVec.ofNat 8 255
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  result := {
    limb0 := BitVec.ofNat 8 1
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 0
  }
  carry0 := BitVec.ofNat 11 254
  carry1 := BitVec.ofNat 11 509
  carry2 := BitVec.ofNat 11 764
  carry3 := BitVec.ofNat 11 1019
  rdNonzero := true
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem honestMulRow_holds : MulHolds honestMulRow where
  clockPositive := by decide
  sourceOneClock := by
    simp [validPreviousClock, accessClock, honestMulRow]
  sourceTwoClock := by
    simp [validPreviousClock, accessClock, honestMulRow]
  destinationClock := by
    simp [validPreviousClock, accessClock, honestMulRow]
  sourceOneLimb0 := rfl
  sourceOneLimb1 := rfl
  sourceOneLimb2 := rfl
  sourceOneLimb3 := rfl
  sourceTwoLimb0 := rfl
  sourceTwoLimb1 := rfl
  sourceTwoLimb2 := rfl
  sourceTwoLimb3 := rfl
  productLimb0 := by decide
  productLimb1 := by decide
  productLimb2 := by decide
  productLimb3 := by decide
  destinationFlag := by decide
  destinationLimb0 := by decide
  destinationLimb1 := by decide
  destinationLimb2 := by decide
  destinationLimb3 := by decide
  nextPcResult := rfl

def aliasedMulRow : MulRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 9
  rd := BitVec.ofNat 5 5
  rdPreviousClock := 33
  rdPrevious := {
    limb0 := BitVec.ofNat 8 15
    limb1 := BitVec.ofNat 8 15
    limb2 := BitVec.ofNat 8 15
    limb3 := BitVec.ofNat 8 15
  }
  rdNext := {
    limb0 := BitVec.ofNat 8 60
    limb1 := BitVec.ofNat 8 105
    limb2 := BitVec.ofNat 8 135
    limb3 := BitVec.ofNat 8 150
  }
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rs1Previous := {
    limb0 := BitVec.ofNat 8 15
    limb1 := BitVec.ofNat 8 15
    limb2 := BitVec.ofNat 8 15
    limb3 := BitVec.ofNat 8 15
  }
  rs1Next := {
    limb0 := BitVec.ofNat 8 15
    limb1 := BitVec.ofNat 8 15
    limb2 := BitVec.ofNat 8 15
    limb3 := BitVec.ofNat 8 15
  }
  rs2 := BitVec.ofNat 5 6
  rs2PreviousClock := 0
  rs2Previous := {
    limb0 := BitVec.ofNat 8 4
    limb1 := BitVec.ofNat 8 3
    limb2 := BitVec.ofNat 8 2
    limb3 := BitVec.ofNat 8 1
  }
  rs2Next := {
    limb0 := BitVec.ofNat 8 4
    limb1 := BitVec.ofNat 8 3
    limb2 := BitVec.ofNat 8 2
    limb3 := BitVec.ofNat 8 1
  }
  result := {
    limb0 := BitVec.ofNat 8 60
    limb1 := BitVec.ofNat 8 105
    limb2 := BitVec.ofNat 8 135
    limb3 := BitVec.ofNat 8 150
  }
  carry0 := BitVec.ofNat 11 0
  carry1 := BitVec.ofNat 11 0
  carry2 := BitVec.ofNat 11 0
  carry3 := BitVec.ofNat 11 0
  rdNonzero := true
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem aliasedMulRow_holds : MulHolds aliasedMulRow where
  clockPositive := by decide
  sourceOneClock := by
    simp [validPreviousClock, accessClock, aliasedMulRow]
  sourceTwoClock := by
    simp [validPreviousClock, accessClock, aliasedMulRow]
  destinationClock := by
    simp [validPreviousClock, accessClock, aliasedMulRow]
  sourceOneLimb0 := rfl
  sourceOneLimb1 := rfl
  sourceOneLimb2 := rfl
  sourceOneLimb3 := rfl
  sourceTwoLimb0 := rfl
  sourceTwoLimb1 := rfl
  sourceTwoLimb2 := rfl
  sourceTwoLimb3 := rfl
  productLimb0 := by decide
  productLimb1 := by decide
  productLimb2 := by decide
  productLimb3 := by decide
  destinationFlag := by decide
  destinationLimb0 := by decide
  destinationLimb1 := by decide
  destinationLimb2 := by decide
  destinationLimb3 := by decide
  nextPcResult := rfl

def honestMulhuRow : MulhRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 9
  rd := BitVec.ofNat 5 7
  rdPreviousClock := 0
  rdPrevious := {
    limb0 := BitVec.ofNat 8 0
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 0
  }
  rdNext := {
    limb0 := BitVec.ofNat 8 254
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rs1Previous := {
    limb0 := BitVec.ofNat 8 255
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  rs1Next := {
    limb0 := BitVec.ofNat 8 255
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  rs2 := BitVec.ofNat 5 6
  rs2PreviousClock := 0
  rs2Previous := {
    limb0 := BitVec.ofNat 8 255
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  rs2Next := {
    limb0 := BitVec.ofNat 8 255
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  rdHigh := {
    limb0 := BitVec.ofNat 8 1
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 0
  }
  rs1Sign := false
  rs2Sign := false
  selector := MulhSelector.mulhu
  result := {
    limb0 := BitVec.ofNat 8 254
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  carry0 := BitVec.ofNat 11 254
  carry1 := BitVec.ofNat 11 509
  carry2 := BitVec.ofNat 11 764
  carry3 := BitVec.ofNat 11 1019
  carry4 := BitVec.ofNat 11 765
  carry5 := BitVec.ofNat 11 510
  carry6 := BitVec.ofNat 11 255
  carry7 := BitVec.ofNat 11 0
  rdNonzero := true
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem honestMulhuRow_holds : MulhHolds honestMulhuRow where
  clockPositive := by decide
  sourceOneClock := by
    simp [validPreviousClock, accessClock, honestMulhuRow]
  sourceTwoClock := by
    simp [validPreviousClock, accessClock, honestMulhuRow]
  destinationClock := by
    simp [validPreviousClock, accessClock, honestMulhuRow]
  sourceOneLimb0 := rfl
  sourceOneLimb1 := rfl
  sourceOneLimb2 := rfl
  sourceOneLimb3 := rfl
  sourceTwoLimb0 := rfl
  sourceTwoLimb1 := rfl
  sourceTwoLimb2 := rfl
  sourceTwoLimb3 := rfl
  unsignedSourceOne := fun _ => rfl
  unsignedSourceTwo := fun _ => rfl
  signedSourceOne := by
    intro request
    exact absurd request (by decide)
  signedSourceTwo := by
    intro request
    exact absurd request (by decide)
  productLimb0 := by decide
  productLimb1 := by decide
  productLimb2 := by decide
  productLimb3 := by decide
  productLimb4 := by decide
  productLimb5 := by decide
  productLimb6 := by decide
  productLimb7 := by decide
  destinationFlag := by decide
  destinationLimb0 := by decide
  destinationLimb1 := by decide
  destinationLimb2 := by decide
  destinationLimb3 := by decide
  nextPcResult := rfl

def honestMulhRow : MulhRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 9
  rd := BitVec.ofNat 5 7
  rdPreviousClock := 0
  rdPrevious := {
    limb0 := BitVec.ofNat 8 0
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 0
  }
  rdNext := {
    limb0 := BitVec.ofNat 8 0
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 64
  }
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rs1Previous := {
    limb0 := BitVec.ofNat 8 0
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 128
  }
  rs1Next := {
    limb0 := BitVec.ofNat 8 0
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 128
  }
  rs2 := BitVec.ofNat 5 6
  rs2PreviousClock := 0
  rs2Previous := {
    limb0 := BitVec.ofNat 8 0
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 128
  }
  rs2Next := {
    limb0 := BitVec.ofNat 8 0
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 128
  }
  rdHigh := {
    limb0 := BitVec.ofNat 8 0
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 0
  }
  rs1Sign := true
  rs2Sign := true
  selector := MulhSelector.mulh
  result := {
    limb0 := BitVec.ofNat 8 0
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 64
  }
  carry0 := BitVec.ofNat 11 0
  carry1 := BitVec.ofNat 11 0
  carry2 := BitVec.ofNat 11 0
  carry3 := BitVec.ofNat 11 0
  carry4 := BitVec.ofNat 11 0
  carry5 := BitVec.ofNat 11 0
  carry6 := BitVec.ofNat 11 64
  carry7 := BitVec.ofNat 11 255
  rdNonzero := true
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem honestMulhRow_holds : MulhHolds honestMulhRow where
  clockPositive := by decide
  sourceOneClock := by
    simp [validPreviousClock, accessClock, honestMulhRow]
  sourceTwoClock := by
    simp [validPreviousClock, accessClock, honestMulhRow]
  destinationClock := by
    simp [validPreviousClock, accessClock, honestMulhRow]
  sourceOneLimb0 := rfl
  sourceOneLimb1 := rfl
  sourceOneLimb2 := rfl
  sourceOneLimb3 := rfl
  sourceTwoLimb0 := rfl
  sourceTwoLimb1 := rfl
  sourceTwoLimb2 := rfl
  sourceTwoLimb3 := rfl
  unsignedSourceOne := by
    intro request
    exact absurd request (by decide)
  unsignedSourceTwo := by
    intro request
    exact absurd request (by decide)
  signedSourceOne := fun _ =>
    ⟨BitVec.ofNat 7 0, by decide⟩
  signedSourceTwo := fun _ =>
    ⟨BitVec.ofNat 7 0, by decide⟩
  productLimb0 := by decide
  productLimb1 := by decide
  productLimb2 := by decide
  productLimb3 := by decide
  productLimb4 := by decide
  productLimb5 := by decide
  productLimb6 := by decide
  productLimb7 := by decide
  destinationFlag := by decide
  destinationLimb0 := by decide
  destinationLimb1 := by decide
  destinationLimb2 := by decide
  destinationLimb3 := by decide
  nextPcResult := rfl

def honestMulhsuRow : MulhRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 9
  rd := BitVec.ofNat 5 7
  rdPreviousClock := 0
  rdPrevious := {
    limb0 := BitVec.ofNat 8 0
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 0
  }
  rdNext := {
    limb0 := BitVec.ofNat 8 255
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rs1Previous := {
    limb0 := BitVec.ofNat 8 255
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  rs1Next := {
    limb0 := BitVec.ofNat 8 255
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  rs2 := BitVec.ofNat 5 6
  rs2PreviousClock := 0
  rs2Previous := {
    limb0 := BitVec.ofNat 8 2
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 0
  }
  rs2Next := {
    limb0 := BitVec.ofNat 8 2
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 0
  }
  rdHigh := {
    limb0 := BitVec.ofNat 8 254
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  rs1Sign := true
  rs2Sign := false
  selector := MulhSelector.mulhsu
  result := {
    limb0 := BitVec.ofNat 8 255
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  carry0 := BitVec.ofNat 11 1
  carry1 := BitVec.ofNat 11 1
  carry2 := BitVec.ofNat 11 1
  carry3 := BitVec.ofNat 11 1
  carry4 := BitVec.ofNat 11 1
  carry5 := BitVec.ofNat 11 1
  carry6 := BitVec.ofNat 11 1
  carry7 := BitVec.ofNat 11 1
  rdNonzero := true
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem honestMulhsuRow_holds : MulhHolds honestMulhsuRow where
  clockPositive := by decide
  sourceOneClock := by
    simp [validPreviousClock, accessClock, honestMulhsuRow]
  sourceTwoClock := by
    simp [validPreviousClock, accessClock, honestMulhsuRow]
  destinationClock := by
    simp [validPreviousClock, accessClock, honestMulhsuRow]
  sourceOneLimb0 := rfl
  sourceOneLimb1 := rfl
  sourceOneLimb2 := rfl
  sourceOneLimb3 := rfl
  sourceTwoLimb0 := rfl
  sourceTwoLimb1 := rfl
  sourceTwoLimb2 := rfl
  sourceTwoLimb3 := rfl
  unsignedSourceOne := by
    intro request
    exact absurd request (by decide)
  unsignedSourceTwo := fun _ => rfl
  signedSourceOne := fun _ =>
    ⟨BitVec.ofNat 7 127, by decide⟩
  signedSourceTwo := by
    intro request
    exact absurd request (by decide)
  productLimb0 := by decide
  productLimb1 := by decide
  productLimb2 := by decide
  productLimb3 := by decide
  productLimb4 := by decide
  productLimb5 := by decide
  productLimb6 := by decide
  productLimb7 := by decide
  destinationFlag := by decide
  destinationLimb0 := by decide
  destinationLimb1 := by decide
  destinationLimb2 := by decide
  destinationLimb3 := by decide
  nextPcResult := rfl

def aliasedMulhuRow : MulhRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 9
  rd := BitVec.ofNat 5 5
  rdPreviousClock := 33
  rdPrevious := {
    limb0 := BitVec.ofNat 8 255
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  rdNext := {
    limb0 := BitVec.ofNat 8 254
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rs1Previous := {
    limb0 := BitVec.ofNat 8 255
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  rs1Next := {
    limb0 := BitVec.ofNat 8 255
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  rs2 := BitVec.ofNat 5 6
  rs2PreviousClock := 0
  rs2Previous := {
    limb0 := BitVec.ofNat 8 255
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  rs2Next := {
    limb0 := BitVec.ofNat 8 255
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  rdHigh := {
    limb0 := BitVec.ofNat 8 1
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 0
  }
  rs1Sign := false
  rs2Sign := false
  selector := MulhSelector.mulhu
  result := {
    limb0 := BitVec.ofNat 8 254
    limb1 := BitVec.ofNat 8 255
    limb2 := BitVec.ofNat 8 255
    limb3 := BitVec.ofNat 8 255
  }
  carry0 := BitVec.ofNat 11 254
  carry1 := BitVec.ofNat 11 509
  carry2 := BitVec.ofNat 11 764
  carry3 := BitVec.ofNat 11 1019
  carry4 := BitVec.ofNat 11 765
  carry5 := BitVec.ofNat 11 510
  carry6 := BitVec.ofNat 11 255
  carry7 := BitVec.ofNat 11 0
  rdNonzero := true
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem aliasedMulhuRow_holds : MulhHolds aliasedMulhuRow where
  clockPositive := by decide
  sourceOneClock := by
    simp [validPreviousClock, accessClock, aliasedMulhuRow]
  sourceTwoClock := by
    simp [validPreviousClock, accessClock, aliasedMulhuRow]
  destinationClock := by
    simp [validPreviousClock, accessClock, aliasedMulhuRow]
  sourceOneLimb0 := rfl
  sourceOneLimb1 := rfl
  sourceOneLimb2 := rfl
  sourceOneLimb3 := rfl
  sourceTwoLimb0 := rfl
  sourceTwoLimb1 := rfl
  sourceTwoLimb2 := rfl
  sourceTwoLimb3 := rfl
  unsignedSourceOne := fun _ => rfl
  unsignedSourceTwo := fun _ => rfl
  signedSourceOne := by
    intro request
    exact absurd request (by decide)
  signedSourceTwo := by
    intro request
    exact absurd request (by decide)
  productLimb0 := by decide
  productLimb1 := by decide
  productLimb2 := by decide
  productLimb3 := by decide
  productLimb4 := by decide
  productLimb5 := by decide
  productLimb6 := by decide
  productLimb7 := by decide
  destinationFlag := by decide
  destinationLimb0 := by decide
  destinationLimb1 := by decide
  destinationLimb2 := by decide
  destinationLimb3 := by decide
  nextPcResult := rfl

/-! ## Non-vacuity

Concrete honest rows for all four selectors, each carrying the AIR
constraints it is supposed to exercise: a maximal unsigned product whose
high word is nonzero, a negative x negative `MULH`, a negative x unsigned
`MULHSU`, and aliased `rd = rs1` rows for both families. Every row below
satisfies the transcribed constraint system and therefore its refinement
theorem, so none of the refinements above is vacuous. -/

/-- Pre-state placing `sourceOne` in `x5`, `sourceTwo` in `x6` and
`destination` in `x7`. -/
def multiplyPreState (sourceOne sourceTwo destination : Word) : PreState where
  pc := BitVec.ofNat 32 0x1000
  registers := fun index =>
    if index = BitVec.ofNat 5 5 then sourceOne
    else if index = BitVec.ofNat 5 6 then sourceTwo
    else if index = BitVec.ofNat 5 7 then destination
    else zeroWord
  x0IsZero := rfl

def honestMulEnvironment : MulEnvironment honestMulRow where
  pre :=
    multiplyPreState
      (BitVec.ofNat 32 0xffffffff)
      (BitVec.ofNat 32 0xffffffff)
      (BitVec.ofNat 32 0)
  pcBinds := rfl
  sourceOneBinds := by decide
  sourceTwoBinds := by decide
  destinationBinds := by decide

def aliasedMulEnvironment : MulEnvironment aliasedMulRow where
  pre :=
    multiplyPreState
      (BitVec.ofNat 32 0x0f0f0f0f)
      (BitVec.ofNat 32 0x01020304)
      (BitVec.ofNat 32 0)
  pcBinds := rfl
  sourceOneBinds := by decide
  sourceTwoBinds := by decide
  destinationBinds := by decide

def honestMulhuEnvironment : MulhEnvironment honestMulhuRow where
  pre :=
    multiplyPreState
      (BitVec.ofNat 32 0xffffffff)
      (BitVec.ofNat 32 0xffffffff)
      (BitVec.ofNat 32 0)
  pcBinds := rfl
  sourceOneBinds := by decide
  sourceTwoBinds := by decide
  destinationBinds := by decide

def honestMulhEnvironment : MulhEnvironment honestMulhRow where
  pre :=
    multiplyPreState
      (BitVec.ofNat 32 0x80000000)
      (BitVec.ofNat 32 0x80000000)
      (BitVec.ofNat 32 0)
  pcBinds := rfl
  sourceOneBinds := by decide
  sourceTwoBinds := by decide
  destinationBinds := by decide

def honestMulhsuEnvironment : MulhEnvironment honestMulhsuRow where
  pre :=
    multiplyPreState
      (BitVec.ofNat 32 0xffffffff)
      (BitVec.ofNat 32 0x00000002)
      (BitVec.ofNat 32 0)
  pcBinds := rfl
  sourceOneBinds := by decide
  sourceTwoBinds := by decide
  destinationBinds := by decide

def aliasedMulhuEnvironment : MulhEnvironment aliasedMulhuRow where
  pre :=
    multiplyPreState
      (BitVec.ofNat 32 0xffffffff)
      (BitVec.ofNat 32 0xffffffff)
      (BitVec.ofNat 32 0)
  pcBinds := rfl
  sourceOneBinds := by decide
  sourceTwoBinds := by decide
  destinationBinds := by decide

/-- `MUL` is non-vacuous, on a row whose carry chain is fully exercised:
`0xffffffff * 0xffffffff` needs carries 254, 509, 764 and 1019. -/
theorem mul_exists :
    ∃ (row : MulRow) (environment : MulEnvironment row),
      MulHolds row ∧ MulRefinement row environment :=
  ⟨honestMulRow, honestMulEnvironment, honestMulRow_holds,
    mul_refines honestMulRow honestMulEnvironment honestMulRow_holds⟩

/-- `MUL` with the destination aliased onto the first source register. -/
theorem mul_aliased_exists :
    ∃ (row : MulRow) (environment : MulEnvironment row),
      MulHolds row ∧ row.rd = row.rs1 ∧ MulRefinement row environment :=
  ⟨aliasedMulRow, aliasedMulEnvironment, aliasedMulRow_holds, rfl,
    mul_refines aliasedMulRow aliasedMulEnvironment aliasedMulRow_holds⟩

/-- `MULHU` is non-vacuous with a nonzero high word: the eight-limb
recurrence really is exercised. -/
theorem mulhu_exists :
    ∃ (row : MulhRow) (environment : MulhEnvironment row),
      MulhHolds row ∧
        row.selector = MulhSelector.mulhu ∧
        row.result.word ≠ zeroWord ∧
        MulhuRefinement row environment :=
  ⟨honestMulhuRow, honestMulhuEnvironment, honestMulhuRow_holds, rfl,
    by decide,
    mulhu_refines honestMulhuRow honestMulhuEnvironment
      honestMulhuRow_holds rfl⟩

/-- `MULH` on a negative x negative pair, `-2 ^ 31 * -2 ^ 31`, whose high
word `0x40000000` is nonzero. -/
theorem mulh_exists :
    ∃ (row : MulhRow) (environment : MulhEnvironment row),
      MulhHolds row ∧
        row.selector = MulhSelector.mulh ∧
        row.rs1Next.word.msb = true ∧
        row.rs2Next.word.msb = true ∧
        row.result.word ≠ zeroWord ∧
        MulhRefinement row environment :=
  ⟨honestMulhRow, honestMulhEnvironment, honestMulhRow_holds, rfl,
    by decide, by decide, by decide,
    mulh_refines honestMulhRow honestMulhEnvironment honestMulhRow_holds rfl⟩

/-- `MULHSU` on a negative first operand and an unsigned second operand,
`-1 * 2`, whose high word `0xffffffff` is nonzero. -/
theorem mulhsu_exists :
    ∃ (row : MulhRow) (environment : MulhEnvironment row),
      MulhHolds row ∧
        row.selector = MulhSelector.mulhsu ∧
        row.rs1Next.word.msb = true ∧
        row.rs2Sign = false ∧
        row.result.word ≠ zeroWord ∧
        MulhsuRefinement row environment :=
  ⟨honestMulhsuRow, honestMulhsuEnvironment, honestMulhsuRow_holds, rfl,
    by decide, rfl, by decide,
    mulhsu_refines honestMulhsuRow honestMulhsuEnvironment
      honestMulhsuRow_holds rfl⟩

/-- A high multiply with the destination aliased onto the first source. -/
theorem mulhu_aliased_exists :
    ∃ (row : MulhRow) (environment : MulhEnvironment row),
      MulhHolds row ∧
        row.selector = MulhSelector.mulhu ∧
        row.rd = row.rs1 ∧
        MulhuRefinement row environment :=
  ⟨aliasedMulhuRow, aliasedMulhuEnvironment, aliasedMulhuRow_holds, rfl, rfl,
    mulhu_refines aliasedMulhuRow aliasedMulhuEnvironment
      aliasedMulhuRow_holds rfl⟩

end RiscvRefinement.Opcodes

