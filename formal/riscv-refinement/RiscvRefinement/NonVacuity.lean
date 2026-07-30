import RiscvRefinement.Opcodes.Addi
import RiscvRefinement.Opcodes.Lui

namespace RiscvRefinement.NonVacuity

open RiscvRefinement
open RiscvRefinement.Air.Generated
open RiscvRefinement.Opcodes

def zeroPreState (pc : Word) : PreState where
  pc := pc
  registers := fun _ => zeroWord
  x0IsZero := rfl

def honestLuiRow : LuiRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rd := BitVec.ofNat 5 7
  rdPreviousClock := 0
  rdPrevious := WordBytes.zero
  rdNext :=
    luiResultBytes
      (BitVec.ofNat 4 0xc)
      (BitVec.ofNat 8 0xab)
      (BitVec.ofNat 8 0xde)
  imm0 := BitVec.ofNat 4 0xc
  imm1 := BitVec.ofNat 8 0xab
  imm2 := BitVec.ofNat 8 0xde
  rdNonzero := true
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem honest_lui_holds : LuiHolds honestLuiRow := by
  refine {
    clockPositive := by decide
    destinationClock := ?_
    destinationFlag := by decide
    destinationLimb0 := rfl
    destinationLimb1 := rfl
    destinationLimb2 := rfl
    destinationLimb3 := rfl
    nextPcResult := rfl
  }
  simp [validPreviousClock, accessClock, honestLuiRow]

def honestLuiEnvironment : LuiEnvironment honestLuiRow where
  pre := zeroPreState (BitVec.ofNat 32 0x1000)
  word :=
    Decode.encodeLui
      (luiImmediate honestLuiRow.imm0 honestLuiRow.imm1 honestLuiRow.imm2)
      honestLuiRow.rd
  pcBinds := rfl
  wordBinds := rfl
  destinationBinds := rfl

theorem lui_exists :
    ∃ (row : LuiRow) (environment : LuiEnvironment row),
      LuiHolds row ∧ LuiRefinement row environment :=
  ⟨
    honestLuiRow,
    honestLuiEnvironment,
    honest_lui_holds,
    lui_refines honestLuiRow honestLuiEnvironment honest_lui_holds,
  ⟩

def honestAddiPreState : PreState where
  pc := BitVec.ofNat 32 0x1000
  registers := fun index =>
    if index = BitVec.ofNat 5 5
    then BitVec.ofNat 32 0x7fffffff
    else zeroWord
  x0IsZero := by decide

def honestAddiRow : AddiRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rd := BitVec.ofNat 5 6
  rdPreviousClock := 0
  rdPrevious := WordBytes.zero
  rdNext := {
    limb0 := BitVec.ofNat 8 0
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 0x80
  }
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rs1Previous := {
    limb0 := BitVec.ofNat 8 0xff
    limb1 := BitVec.ofNat 8 0xff
    limb2 := BitVec.ofNat 8 0xff
    limb3 := BitVec.ofNat 8 0x7f
  }
  rs1Next := {
    limb0 := BitVec.ofNat 8 0xff
    limb1 := BitVec.ofNat 8 0xff
    limb2 := BitVec.ofNat 8 0xff
    limb3 := BitVec.ofNat 8 0x7f
  }
  imm0 := BitVec.ofNat 8 1
  imm1 := BitVec.ofNat 3 0
  immSign := BitVec.ofNat 1 0
  result := {
    limb0 := BitVec.ofNat 8 0
    limb1 := BitVec.ofNat 8 0
    limb2 := BitVec.ofNat 8 0
    limb3 := BitVec.ofNat 8 0x80
  }
  rdNonzero := true
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem honest_addi_holds : AddiHolds honestAddiRow := by
  refine {
    clockPositive := by decide
    sourceClock := ?_
    destinationClock := ?_
    sourceLimb0 := rfl
    sourceLimb1 := rfl
    sourceLimb2 := rfl
    sourceLimb3 := rfl
    carryRecurrence := ?_
    destinationFlag := by decide
    destinationLimb0 := rfl
    destinationLimb1 := rfl
    destinationLimb2 := rfl
    destinationLimb3 := rfl
    nextPcResult := rfl
  }
  · simp [validPreviousClock, accessClock, honestAddiRow]
  · simp [validPreviousClock, accessClock, honestAddiRow]
  · exact ⟨1#1, 1#1, 1#1, 0#1, by decide, by decide, by decide, by decide⟩

def honestAddiEnvironment : AddiEnvironment honestAddiRow where
  pre := honestAddiPreState
  word :=
    Decode.encodeAddi
      (addiImmediate
        honestAddiRow.imm0
        honestAddiRow.imm1
        honestAddiRow.immSign)
      honestAddiRow.rs1
      honestAddiRow.rd
  pcBinds := rfl
  wordBinds := rfl
  sourceBinds := by decide
  destinationBinds := by decide

def honestAddiProductionWitness :
    Air.Bridge.Addi.Witness honestAddiRow where
  destinationInverse := M31.reduce 1789569706

theorem honest_addi_production_admission :
    Air.Bridge.Addi.Admission honestAddiRow := by
  constructor <;> decide

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem honest_addi_production_acceptance :
    Air.Bridge.Addi.Acceptance
      honestAddiRow honestAddiProductionWitness := by
  refine {
    selectors :=
      Air.Bridge.Addi.selectorAccepted
        honestAddiRow honestAddiProductionWitness
    constraints := ?_
    fixedLookups := ?_
  }
  · apply
      (Air.Bridge.Addi.constraintsHold_iff
        honestAddiRow honestAddiProductionWitness).mpr
    simp [
      Air.Bridge.Addi.ConstraintEquations,
      Air.Bridge.Addi.carry1Field,
      Air.Bridge.Addi.carry2Field,
      Air.Bridge.Addi.carry3Field,
      Air.Bridge.Addi.carry4Field,
      Air.Bridge.Addi.immediateLimb1Field,
      Air.Bridge.Addi.signLimbField,
      honestAddiRow,
      honestAddiProductionWitness,
      Air.Bridge.Addi.boolM31,
      Air.Bridge.Lui.boolM31,
      Air.Bridge.Addi.bitVecM31,
      Air.Bridge.Lui.bitVecM31,
      WordBytes.zero,
    ] <;> decide
  · rw [Air.Bridge.Addi.fixedLookupsHold_eq]
    decide

def honestAddiProductionEnvironment :
    AddiEnvironment (Air.Bridge.Addi.interpretedRow honestAddiRow) where
  pre := honestAddiPreState
  word :=
    Decode.encodeAddi
      (addiImmediate
        honestAddiRow.imm0
        honestAddiRow.imm1
        honestAddiRow.immSign)
      honestAddiRow.rs1
      honestAddiRow.rd
  pcBinds := rfl
  wordBinds := rfl
  sourceBinds := by decide
  destinationBinds := by decide

theorem addi_production_overflow_exists :
    Air.Bridge.Addi.Admission honestAddiRow ∧
      Air.Bridge.Addi.Acceptance
        honestAddiRow honestAddiProductionWitness ∧
      honestAddiRow.rs1Previous.word =
        BitVec.ofNat 32 0x7fffffff ∧
      honestAddiRow.result.word =
        BitVec.ofNat 32 0x80000000 ∧
      AddiRefinement
        (Air.Bridge.Addi.interpretedRow honestAddiRow)
        honestAddiProductionEnvironment := by
  exact ⟨
    honest_addi_production_admission,
    honest_addi_production_acceptance,
    by decide,
    by decide,
    addi_production_refines
      honestAddiRow
      honestAddiProductionWitness
      honestAddiProductionEnvironment
      honest_addi_production_admission
      honest_addi_production_acceptance
  ⟩

theorem addi_exists :
    ∃ (row : AddiRow) (environment : AddiEnvironment row),
      AddiHolds row ∧ AddiRefinement row environment :=
  ⟨
    honestAddiRow,
    honestAddiEnvironment,
    honest_addi_holds,
    addi_refines honestAddiRow honestAddiEnvironment honest_addi_holds,
  ⟩

end RiscvRefinement.NonVacuity
