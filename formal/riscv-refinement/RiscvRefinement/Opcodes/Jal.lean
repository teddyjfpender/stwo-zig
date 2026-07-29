import RiscvRefinement.Air.Bridge.Jal

/-!
# JAL production refinement

This module binds canonical RV32I J-type decode to the exact generated
production AIR row.  The resulting retirement writes `pc + 4` (unless `rd` is
`x0`), jumps by the sign-extended 21-bit immediate, and has no memory effect.

Boundary: this is the opcode-retirement contract consumed by the generated-Sail
composition layer.  It does not by itself claim the full fetch/trap/interrupt
step-loop framing theorem.
-/

namespace RiscvRefinement.Opcodes.Jal

open RiscvRefinement

abbrev Row := Air.Bridge.Jal.Row
abbrev Witness := Air.Bridge.Jal.Witness
abbrev Admission := Air.Bridge.Jal.Admission
abbrev Acceptance := Air.Bridge.Jal.Acceptance

def word (row : Row) : InstructionWord :=
  Decode.encodeJal row.immediateEncoded row.rd

def execute
    (pc : Word)
    (rd : RegisterIndex)
    (encoded : BitVec 20) : Retirement where
  nextPc := Air.Bridge.Jal.jumpTarget pc encoded
  write := architecturalWrite rd (RiscvRefinement.nextPc pc)

def airRetirement (row : Row) : Retirement where
  nextPc := Air.Bridge.Jal.jumpTarget row.pc row.immediateEncoded
  write := architecturalWrite row.rd row.rdNext.word

def programTuple (row : Row) : ProgramTuple where
  pc := row.pc
  opcodeId := 33
  rd := row.rd.toNat
  rs1 := Air.Bridge.Jal.immediateFieldValue row.immediateEncoded
  operand := 0

structure Refinement
    (row : Row)
    (witness : Witness row) : Prop where
  production :
    Air.Bridge.Jal.ProductionRefinement row witness
  decode :
    Decode.isJal (word row) = true ∧
      Decode.decodeJImmediate (word row) =
        Decode.jalImmediate row.immediateEncoded ∧
      Decode.decodeRd (word row) = row.rd
  program :
    programTuple row = {
      pc := row.pc
      opcodeId := 33
      rd := row.rd.toNat
      rs1 := Air.Bridge.Jal.immediateFieldValue row.immediateEncoded
      operand := 0
    }
  programLookup :
    (Air.Bridge.Jal.evaluation row witness).lookup? 10 =
      some (Air.Bridge.Jal.programLookup row)
  stateConsume :
    (Air.Bridge.Jal.evaluation row witness).lookup? 11 =
      some (Air.Bridge.Jal.stateConsumeLookup row)
  stateEmit :
    (Air.Bridge.Jal.evaluation row witness).lookup? 12 =
      some (Air.Bridge.Jal.stateEmitLookup row)
  destinationConsume :
    (Air.Bridge.Jal.evaluation row witness).lookup? 15 =
      some (Air.Bridge.Jal.destinationConsumeLookup row)
  destinationEmit :
    (Air.Bridge.Jal.evaluation row witness).lookup? 16 =
      some (Air.Bridge.Jal.destinationEmitLookup row)
  retirement :
    airRetirement row =
      execute row.pc row.rd row.immediateEncoded
  zeroRegister :
    row.rd = zeroRegister → (airRetirement row).write = none
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
    Air.Bridge.Jal.sound row witness admission accepted
  refine {
    production
    decode :=
      Decode.encode_jal_is_canonical
        row.immediateEncoded row.rd
    program := rfl
    programLookup := production.exactLookups.1
    stateConsume := production.exactLookups.2.1
    stateEmit := production.exactLookups.2.2.1
    destinationConsume :=
      production.exactLookups.2.2.2.2.2.1
    destinationEmit :=
      production.exactLookups.2.2.2.2.2.2.1
    retirement := ?_
    zeroRegister := ?_
    noMemoryEffect := by simp [airRetirement]
  }
  · simp only [airRetirement, execute]
    rw [production.destination, architecturalWrite_value]
  · intro zero
    simp [airRetirement, zero, architecturalWrite]

theorem jalExists :
    ∃ (row : Row) (witness : Witness row),
      Admission row ∧
        Acceptance row witness ∧
        Refinement row witness :=
  ⟨Air.Bridge.Jal.exampleRow,
    Air.Bridge.Jal.exampleWitness,
    Air.Bridge.Jal.exampleAdmission,
    Air.Bridge.Jal.exampleAcceptance,
    refines
      Air.Bridge.Jal.exampleRow
      Air.Bridge.Jal.exampleWitness
      Air.Bridge.Jal.exampleAdmission
      Air.Bridge.Jal.exampleAcceptance⟩

end RiscvRefinement.Opcodes.Jal
