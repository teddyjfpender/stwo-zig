import RiscvRefinement.Air.Bridge.Auipc

/-!
# AUIPC production refinement

This module binds canonical RV32I U-type decode to the exact generated
production AIR row.  The resulting retirement advances to `pc + 4`, writes
the wrapping 32-bit sum `pc + (imm20 << 12)` unless `rd = x0`, and has no
memory effect.

Boundary: this is the opcode-retirement contract consumed by the
generated-Sail composition layer.  It does not by itself claim the full
fetch/trap/interrupt step-loop framing theorem.
-/

namespace RiscvRefinement.Opcodes.Auipc

open RiscvRefinement

abbrev Row := Air.Bridge.Auipc.Row
abbrev Witness := Air.Bridge.Auipc.Witness
abbrev Admission := Air.Bridge.Auipc.Admission
abbrev Acceptance := Air.Bridge.Auipc.Acceptance

def word (row : Row) : InstructionWord :=
  Decode.encodeAuipc row.immediateEncoded row.rd

def execute
    (pc : Word)
    (rd : RegisterIndex)
    (encoded : BitVec 20) : Retirement where
  nextPc := RiscvRefinement.nextPc pc
  write :=
    architecturalWrite rd
      (Air.Bridge.Auipc.pcRelativeValue pc encoded)

def airRetirement (row : Row) : Retirement where
  nextPc := RiscvRefinement.nextPc row.pc
  write := architecturalWrite row.rd row.rdNext.word

def programTuple (row : Row) : ProgramTuple where
  pc := row.pc
  opcodeId := 36
  rd := row.rd.toNat
  rs1 :=
    Air.Bridge.Auipc.immediateFieldValue
      row.immediateEncoded
  operand := 0

structure Refinement
    (row : Row)
    (witness : Witness row) : Prop where
  production :
    Air.Bridge.Auipc.ProductionRefinement row witness
  decode :
    Decode.isAuipc (word row) = true ∧
      Decode.decodeLuiImmediate (word row) =
        row.immediateEncoded ∧
      Decode.decodeRd (word row) = row.rd
  program :
    programTuple row = {
      pc := row.pc
      opcodeId := 36
      rd := row.rd.toNat
      rs1 :=
        Air.Bridge.Auipc.immediateFieldValue
          row.immediateEncoded
      operand := 0
    }
  programLookup :
    (Air.Bridge.Auipc.evaluation row witness).lookup? 17 =
      some (Air.Bridge.Auipc.programLookup row)
  stateConsume :
    (Air.Bridge.Auipc.evaluation row witness).lookup? 18 =
      some (Air.Bridge.Auipc.stateConsumeLookup row)
  stateEmit :
    (Air.Bridge.Auipc.evaluation row witness).lookup? 19 =
      some (Air.Bridge.Auipc.stateEmitLookup row)
  destinationConsume :
    (Air.Bridge.Auipc.evaluation row witness).lookup? 26 =
      some (Air.Bridge.Auipc.destinationConsumeLookup row)
  destinationEmit :
    (Air.Bridge.Auipc.evaluation row witness).lookup? 27 =
      some (Air.Bridge.Auipc.destinationEmitLookup row)
  immediateDecomposition :
    row.immediateLimbs.word =
      Air.Bridge.Auipc.immediateWord
        row.immediateEncoded
  immediateSign :
    row.immediateSign =
      (Air.Bridge.Auipc.immediateWord
        row.immediateEncoded).msb
  retirement :
    airRetirement row =
      execute row.pc row.rd row.immediateEncoded
  zeroRegister :
    row.rd = zeroRegister →
      (airRetirement row).write = none
  noMemoryEffect :
    (airRetirement row).read = none ∧
      (airRetirement row).store = none

theorem refines
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    Refinement row witness := by
  have production :=
    Air.Bridge.Auipc.sound
      row witness admission accepted
  refine {
    production
    decode :=
      Decode.encode_auipc_is_canonical
        row.immediateEncoded row.rd
    program := rfl
    programLookup := production.exactLookups.1
    stateConsume := production.exactLookups.2.1
    stateEmit := production.exactLookups.2.2.1
    destinationConsume :=
      production.exactLookups.2.2.2.2.2.2.2.2.2.1
    destinationEmit :=
      production.exactLookups.2.2.2.2.2.2.2.2.2.2.1
    immediateDecomposition :=
      production.immediateDecomposition
    immediateSign := production.immediateSign
    retirement := ?_
    zeroRegister := ?_
    noMemoryEffect := by simp [airRetirement]
  }
  · simp only [airRetirement, execute]
    rw [production.destination, architecturalWrite_value]
  · intro zero
    simp [airRetirement, zero, architecturalWrite]

theorem auipcExists :
    ∃ (row : Row) (witness : Witness row),
      Admission row ∧
        Acceptance row witness ∧
        Refinement row witness :=
  ⟨Air.Bridge.Auipc.exampleRow,
    Air.Bridge.Auipc.exampleWitness,
    Air.Bridge.Auipc.exampleAdmission,
    Air.Bridge.Auipc.exampleAcceptance,
    refines
      Air.Bridge.Auipc.exampleRow
      Air.Bridge.Auipc.exampleWitness
      Air.Bridge.Auipc.exampleAdmission
      Air.Bridge.Auipc.exampleAcceptance⟩

theorem auipcX0Exists :
    ∃ (row : Row) (witness : Witness row),
      row.rd = zeroRegister ∧
        Admission row ∧
        Acceptance row witness ∧
        Refinement row witness :=
  ⟨Air.Bridge.Auipc.x0ExampleRow,
    Air.Bridge.Auipc.x0ExampleWitness,
    rfl,
    Air.Bridge.Auipc.x0ExampleAdmission,
    Air.Bridge.Auipc.x0ExampleAcceptance,
    refines
      Air.Bridge.Auipc.x0ExampleRow
      Air.Bridge.Auipc.x0ExampleWitness
      Air.Bridge.Auipc.x0ExampleAdmission
      Air.Bridge.Auipc.x0ExampleAcceptance⟩

end RiscvRefinement.Opcodes.Auipc
