import RiscvRefinement.Air.Bridge.Jalr

/-!
# JALR production refinement

For a successful RV32IM row, JALR adds the sign-extended I-immediate to `rs1`
modulo `2^32`, clears bit zero, retires at that aligned target, and writes
`pc + 4` to `rd` unless `rd = x0`.

Boundary: this is the normalized opcode retirement consumed by the generated
Sail composition layer; it does not claim the still-open whole-step framing
theorem.
-/

namespace RiscvRefinement.Opcodes.Jalr

open RiscvRefinement

abbrev Row := Air.Bridge.Jalr.Row
abbrev Witness := Air.Bridge.Jalr.Witness
abbrev Admission := Air.Bridge.Jalr.Admission
abbrev Acceptance := Air.Bridge.Jalr.Acceptance

def word (row : Row) : InstructionWord :=
  Decode.encodeJalr row.immediate row.rs1 row.rd

def execute (row : Row) : Retirement where
  nextPc :=
    Air.Bridge.Jalr.jumpTarget row.rs1Value.word row.immediate
  write := architecturalWrite row.rd (RiscvRefinement.nextPc row.pc)

structure Refinement (row : Row) (witness : Witness row) : Prop where
  production : Air.Bridge.Jalr.ProductionRefinement row witness
  decode :
    Decode.isJalr (word row) = true ∧
      Decode.decodeIImmediate (word row) = row.immediate ∧
      Decode.decodeRs1 (word row) = row.rs1 ∧
      Decode.decodeRd (word row) = row.rd
  retirement :
    execute row = {
      nextPc :=
        Air.Bridge.Jalr.jumpTarget row.rs1Value.word row.immediate
      write :=
        architecturalWrite row.rd (RiscvRefinement.nextPc row.pc)
      read := none
      store := none
    }
  exactProgramTuple :
    (Air.Bridge.Jalr.programLookup row).tuple = #[
      Air.Bridge.Jalr.bitVecM31 row.pc,
      M31.reduce 34,
      Air.Bridge.Jalr.bitVecM31 row.rd,
      Air.Bridge.Jalr.bitVecM31 row.rs1,
      Air.Bridge.Jalr.immediateField row.immediate
    ]
  exactStateTarget :
    (Air.Bridge.Jalr.stateEmitLookup row).tuple[0]? =
      some
        (Air.Bridge.Jalr.bitVecM31
          (Air.Bridge.Jalr.jumpTarget
            row.rs1Value.word row.immediate))
  exactSourceValue :
    (Air.Bridge.Jalr.sourceConsumeLookup row).tuple[3]? =
        some (Air.Bridge.Jalr.bitVecM31 row.rs1Value.limb0) ∧
      (Air.Bridge.Jalr.sourceEmitLookup row).tuple[3]? =
        some (Air.Bridge.Jalr.bitVecM31 row.rs1Value.limb0)
  exactDestinationValue :
    (Air.Bridge.Jalr.rdNext row).word =
      architecturalValue row.rd (RiscvRefinement.nextPc row.pc)
  successfulAlignment :
    (execute row).nextPc.toNat % 4 = 0
  noMemoryEffect :
    (execute row).read = none ∧ (execute row).store = none

theorem refines
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    Refinement row witness := by
  have production :=
    Air.Bridge.Jalr.sound row witness admission accepted
  refine {
    production := production
    decode :=
      Decode.encode_jalr_is_canonical row.immediate row.rs1 row.rd
    retirement := rfl
    exactProgramTuple := rfl
    exactStateTarget := production.nextPc
    exactSourceValue := by
      simp [
        Air.Bridge.Jalr.sourceConsumeLookup,
        Air.Bridge.Jalr.sourceEmitLookup,
      ]
    exactDestinationValue := production.destination
    successfulAlignment := admission.targetAligned
    noMemoryEffect := by simp [execute]
  }

theorem jalr_exists :
    ∃ row witness,
      Admission row ∧ Acceptance row witness ∧
        Refinement row witness :=
  ⟨Air.Bridge.Jalr.exampleRow,
    Air.Bridge.Jalr.exampleWitness,
    Air.Bridge.Jalr.exampleAdmission,
    Air.Bridge.Jalr.exampleAcceptance,
    refines
      Air.Bridge.Jalr.exampleRow
      Air.Bridge.Jalr.exampleWitness
      Air.Bridge.Jalr.exampleAdmission
      Air.Bridge.Jalr.exampleAcceptance⟩

end RiscvRefinement.Opcodes.Jalr
