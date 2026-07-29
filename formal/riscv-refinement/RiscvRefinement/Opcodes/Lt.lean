import RiscvRefinement.Air.Bridge.LtImm
import RiscvRefinement.Bridge.DecodeLt

/-!
# SLT/SLTU/SLTI/SLTIU production refinement

The two generated comparison gadgets use the same architectural result: one
when the selected signed or unsigned ordering holds, zero otherwise.  These
theorems connect the exact generated AIR evaluations and lookup tuples to
canonical RV32I decode and normalized retirement.
-/

namespace RiscvRefinement.Opcodes.Lt

open RiscvRefinement

namespace Reg

abbrev Row := Air.Bridge.LtReg.Row
abbrev Witness := Air.Bridge.LtReg.Witness
abbrev Admission := Air.Bridge.LtReg.Admission
abbrev Acceptance := Air.Bridge.LtReg.Acceptance
abbrev Kind := Air.Bridge.LtReg.Kind

def word (row : Row) : InstructionWord :=
  match row.kind with
  | .signed => Decode.encodeSlt row.rs2 row.rs1 row.rd
  | .unsigned => Decode.encodeSltu row.rs2 row.rs1 row.rd

def decodeSelector (kind : Kind) : InstructionWord → Bool
  | instruction =>
      match kind with
      | .signed => Decode.isSlt instruction
      | .unsigned => Decode.isSltu instruction

def resultWord (row : Row) : Word :=
  (Air.Bridge.LtReg.comparisonBytes
    (Air.Bridge.LtReg.semanticLess
      row.kind row.rs1Previous row.rs2Previous)).word

def execute (row : Row) : Retirement where
  nextPc := RiscvRefinement.nextPc row.pc
  write := architecturalWrite row.rd (resultWord row)

theorem canonicalDecode (row : Row) :
    decodeSelector row.kind (word row) = true ∧
      Decode.decodeRs2 (word row) = row.rs2 ∧
      Decode.decodeRs1 (word row) = row.rs1 ∧
      Decode.decodeRd (word row) = row.rd := by
  cases kind : row.kind
  · simpa [word, decodeSelector, kind] using
      Decode.encode_slt_is_canonical row.rs2 row.rs1 row.rd
  · simpa [word, decodeSelector, kind] using
      Decode.encode_sltu_is_canonical row.rs2 row.rs1 row.rd

theorem destinationWord
    (row : Row)
    (witness : Witness row)
    (production : Air.Bridge.LtReg.ProductionRefinement row witness) :
    row.rdNext.word = architecturalValue row.rd (resultWord row) := by
  rcases production.sourcesReadOnly with ⟨sourceOne, sourceTwo⟩
  rcases production.destination with ⟨flag, destination⟩
  rw [sourceOne, sourceTwo] at destination
  by_cases zero : row.rd = zeroRegister
  · have flagZero : row.rdNonzero = false := by
      rw [flag]
      simp [zero]
    simp [destination, flagZero, architecturalValue, zero, resultWord]
  · have flagOne : row.rdNonzero = true := by
      rw [flag]
      simp [zero]
    simp [destination, flagOne, architecturalValue, zero, resultWord]

structure Refinement (row : Row) (witness : Witness row) : Prop where
  production : Air.Bridge.LtReg.ProductionRefinement row witness
  decode :
    decodeSelector row.kind (word row) = true ∧
      Decode.decodeRs2 (word row) = row.rs2 ∧
      Decode.decodeRs1 (word row) = row.rs1 ∧
      Decode.decodeRd (word row) = row.rd
  retirement :
    execute row = {
      nextPc := RiscvRefinement.nextPc row.pc
      write := architecturalWrite row.rd (resultWord row)
      read := none
      store := none
    }
  exactProgramTuple :
    (Air.Bridge.LtReg.programLookup row).tuple = #[
      Air.Bridge.LtReg.bitVecM31 row.pc,
      M31.reduce (Air.Bridge.LtReg.manifestId row.kind),
      Air.Bridge.LtReg.bitVecM31 row.rd,
      Air.Bridge.LtReg.bitVecM31 row.rs1,
      Air.Bridge.LtReg.bitVecM31 row.rs2
    ]
  exactDestination :
    row.rdNext.word = architecturalValue row.rd (resultWord row)
  noMemoryEffect :
    (execute row).read = none ∧ (execute row).store = none

theorem refines
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    Refinement row witness := by
  have production :=
    Air.Bridge.LtReg.sound row witness admission accepted
  exact {
    production := production
    decode := canonicalDecode row
    retirement := rfl
    exactProgramTuple := rfl
    exactDestination := destinationWord row witness production
    noMemoryEffect := by simp [execute]
  }

theorem slt_selectorAccepted
    (row : Row)
    (witness : Witness row)
    (_kind : row.kind = .signed) :
    (Air.Bridge.LtReg.evaluation row witness).activeSelectorsAccepted = true :=
  Air.Bridge.LtReg.selectorAccepted row witness

theorem sltu_selectorAccepted
    (row : Row)
    (witness : Witness row)
    (_kind : row.kind = .unsigned) :
    (Air.Bridge.LtReg.evaluation row witness).activeSelectorsAccepted = true :=
  Air.Bridge.LtReg.selectorAccepted row witness

theorem slt_refines
    (row : Row)
    (witness : Witness row)
    (_kind : row.kind = .signed)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    Refinement row witness :=
  refines row witness admission accepted

theorem sltu_refines
    (row : Row)
    (witness : Witness row)
    (_kind : row.kind = .unsigned)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    Refinement row witness :=
  refines row witness admission accepted

theorem slt_exactProgramTuple
    (row : Row)
    (kind : row.kind = .signed) :
    (Air.Bridge.LtReg.programLookup row).tuple = #[
      Air.Bridge.LtReg.bitVecM31 row.pc, M31.reduce 3,
      Air.Bridge.LtReg.bitVecM31 row.rd,
      Air.Bridge.LtReg.bitVecM31 row.rs1,
      Air.Bridge.LtReg.bitVecM31 row.rs2
    ] := by
  simp [Air.Bridge.LtReg.programLookup,
    Air.Bridge.LtReg.manifestId, kind]

theorem sltu_exactProgramTuple
    (row : Row)
    (kind : row.kind = .unsigned) :
    (Air.Bridge.LtReg.programLookup row).tuple = #[
      Air.Bridge.LtReg.bitVecM31 row.pc, M31.reduce 4,
      Air.Bridge.LtReg.bitVecM31 row.rd,
      Air.Bridge.LtReg.bitVecM31 row.rs1,
      Air.Bridge.LtReg.bitVecM31 row.rs2
    ] := by
  simp [Air.Bridge.LtReg.programLookup,
    Air.Bridge.LtReg.manifestId, kind]

theorem slt_nonvacuous :
    ∃ row witness,
      row.kind = .signed ∧ row.rd = row.rs1 ∧
        Admission row ∧ Acceptance row witness ∧ Refinement row witness :=
  ⟨Air.Bridge.LtReg.highBitRow .signed,
    Air.Bridge.LtReg.highBitWitness .signed,
    rfl, rfl,
    Air.Bridge.LtReg.highBitAdmission .signed,
    Air.Bridge.LtReg.highBitAcceptance .signed,
    slt_refines _ _ rfl
      (Air.Bridge.LtReg.highBitAdmission .signed)
      (Air.Bridge.LtReg.highBitAcceptance .signed)⟩

theorem sltu_nonvacuous :
    ∃ row witness,
      row.kind = .unsigned ∧ row.rd = zeroRegister ∧
        Admission row ∧ Acceptance row witness ∧ Refinement row witness :=
  ⟨Air.Bridge.LtReg.highBitRow .unsigned,
    Air.Bridge.LtReg.highBitWitness .unsigned,
    rfl, rfl,
    Air.Bridge.LtReg.highBitAdmission .unsigned,
    Air.Bridge.LtReg.highBitAcceptance .unsigned,
    sltu_refines _ _ rfl
      (Air.Bridge.LtReg.highBitAdmission .unsigned)
      (Air.Bridge.LtReg.highBitAcceptance .unsigned)⟩

theorem signedUnsignedHighBitDistinction :
    Air.Bridge.LtReg.semanticLess .signed
        Air.Bridge.LtReg.highBitBytes WordBytes.zero = true ∧
      Air.Bridge.LtReg.semanticLess .unsigned
        Air.Bridge.LtReg.highBitBytes WordBytes.zero = false :=
  ⟨Air.Bridge.LtReg.signedHighBitResult,
    Air.Bridge.LtReg.unsignedHighBitResult⟩

end Reg

namespace Imm

abbrev Row := Air.Bridge.LtImm.Row
abbrev Witness := Air.Bridge.LtImm.Witness
abbrev Admission := Air.Bridge.LtImm.Admission
abbrev Acceptance := Air.Bridge.LtImm.Acceptance
abbrev Kind := Air.Bridge.LtImm.Kind

def word (row : Row) : InstructionWord :=
  match row.kind with
  | .signed => Decode.encodeSlti row.immediate row.rs1 row.rd
  | .unsigned => Decode.encodeSltiu row.immediate row.rs1 row.rd

def decodeSelector (kind : Kind) : InstructionWord → Bool
  | instruction =>
      match kind with
      | .signed => Decode.isSlti instruction
      | .unsigned => Decode.isSltiu instruction

def resultWord (row : Row) : Word :=
  (Air.Bridge.LtImm.resultBytes
    (Air.Bridge.LtImm.comparison
      row.kind row.rs1Value row.immediate)).word

def execute (row : Row) : Retirement where
  nextPc := RiscvRefinement.nextPc row.pc
  write := architecturalWrite row.rd (resultWord row)

theorem canonicalDecode (row : Row) :
    decodeSelector row.kind (word row) = true ∧
      Decode.decodeIImmediate (word row) = row.immediate ∧
      Decode.decodeRs1 (word row) = row.rs1 ∧
      Decode.decodeRd (word row) = row.rd := by
  cases kind : row.kind
  · simpa [word, decodeSelector, kind] using
      Decode.encode_slti_is_canonical row.immediate row.rs1 row.rd
  · simpa [word, decodeSelector, kind] using
      Decode.encode_sltiu_is_canonical row.immediate row.rs1 row.rd

theorem destinationBytesWord (row : Row) :
    (Air.Bridge.LtImm.destinationBytes row.rd
      (Air.Bridge.LtImm.comparison
        row.kind row.rs1Value row.immediate)).word =
      architecturalValue row.rd (resultWord row) := by
  by_cases zero : row.rd = zeroRegister
  · simp [Air.Bridge.LtImm.destinationBytes,
      Air.Bridge.LtImm.destinationNonzero, architecturalValue,
      resultWord, zero]
  · simp [Air.Bridge.LtImm.destinationBytes,
      Air.Bridge.LtImm.destinationNonzero, architecturalValue,
      resultWord, zero]

structure Refinement (row : Row) (witness : Witness row) : Prop where
  production : Air.Bridge.LtImm.ProductionRefinement row witness
  decode :
    decodeSelector row.kind (word row) = true ∧
      Decode.decodeIImmediate (word row) = row.immediate ∧
      Decode.decodeRs1 (word row) = row.rs1 ∧
      Decode.decodeRd (word row) = row.rd
  retirement :
    execute row = {
      nextPc := RiscvRefinement.nextPc row.pc
      write := architecturalWrite row.rd (resultWord row)
      read := none
      store := none
    }
  exactProgramTuple :
    (Air.Bridge.LtImm.programLookup row).tuple = #[
      Air.Bridge.LtImm.bitVecM31 row.pc,
      M31.reduce (Air.Bridge.LtImm.manifestId row.kind),
      Air.Bridge.LtImm.bitVecM31 row.rd,
      Air.Bridge.LtImm.bitVecM31 row.rs1,
      Air.Bridge.LtImm.immediateField row
    ]
  exactDestination :
    (Air.Bridge.LtImm.destinationBytes row.rd
      (Air.Bridge.LtImm.comparison
        row.kind row.rs1Value row.immediate)).word =
      architecturalValue row.rd (resultWord row)
  noMemoryEffect :
    (execute row).read = none ∧ (execute row).store = none

theorem refines
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    Refinement row witness := by
  exact {
    production := Air.Bridge.LtImm.sound row witness admission accepted
    decode := canonicalDecode row
    retirement := rfl
    exactProgramTuple := rfl
    exactDestination := destinationBytesWord row
    noMemoryEffect := by simp [execute]
  }

theorem slti_selectorAccepted
    (row : Row)
    (witness : Witness row)
    (_kind : row.kind = .signed) :
    (Air.Bridge.LtImm.evaluation row witness).activeSelectorsAccepted = true :=
  Air.Bridge.LtImm.selectorAccepted row witness

theorem sltiu_selectorAccepted
    (row : Row)
    (witness : Witness row)
    (_kind : row.kind = .unsigned) :
    (Air.Bridge.LtImm.evaluation row witness).activeSelectorsAccepted = true :=
  Air.Bridge.LtImm.selectorAccepted row witness

theorem slti_refines
    (row : Row)
    (witness : Witness row)
    (_kind : row.kind = .signed)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    Refinement row witness :=
  refines row witness admission accepted

theorem sltiu_refines
    (row : Row)
    (witness : Witness row)
    (_kind : row.kind = .unsigned)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    Refinement row witness :=
  refines row witness admission accepted

theorem slti_exactProgramTuple
    (row : Row)
    (kind : row.kind = .signed) :
    (Air.Bridge.LtImm.programLookup row).tuple = #[
      Air.Bridge.LtImm.bitVecM31 row.pc, M31.reduce 11,
      Air.Bridge.LtImm.bitVecM31 row.rd,
      Air.Bridge.LtImm.bitVecM31 row.rs1,
      Air.Bridge.LtImm.immediateField row
    ] := by
  simp [Air.Bridge.LtImm.programLookup,
    Air.Bridge.LtImm.manifestId, kind]

theorem sltiu_exactProgramTuple
    (row : Row)
    (kind : row.kind = .unsigned) :
    (Air.Bridge.LtImm.programLookup row).tuple = #[
      Air.Bridge.LtImm.bitVecM31 row.pc, M31.reduce 12,
      Air.Bridge.LtImm.bitVecM31 row.rd,
      Air.Bridge.LtImm.bitVecM31 row.rs1,
      Air.Bridge.LtImm.immediateField row
    ] := by
  simp [Air.Bridge.LtImm.programLookup,
    Air.Bridge.LtImm.manifestId, kind]

theorem slti_nonvacuous :
    ∃ row witness,
      row.kind = .signed ∧ row.rd = row.rs1 ∧
        Admission row ∧ Acceptance row witness ∧ Refinement row witness :=
  ⟨Air.Bridge.LtImm.highBitRow .signed,
    Air.Bridge.LtImm.highBitWitness .signed,
    rfl, rfl,
    Air.Bridge.LtImm.highBitAdmission .signed,
    Air.Bridge.LtImm.highBitAcceptance .signed,
    slti_refines _ _ rfl
      (Air.Bridge.LtImm.highBitAdmission .signed)
      (Air.Bridge.LtImm.highBitAcceptance .signed)⟩

theorem sltiu_nonvacuous :
    ∃ row witness,
      row.kind = .unsigned ∧ row.rd = zeroRegister ∧
        Admission row ∧ Acceptance row witness ∧ Refinement row witness :=
  ⟨Air.Bridge.LtImm.highBitRow .unsigned,
    Air.Bridge.LtImm.highBitWitness .unsigned,
    rfl, rfl,
    Air.Bridge.LtImm.highBitAdmission .unsigned,
    Air.Bridge.LtImm.highBitAcceptance .unsigned,
    sltiu_refines _ _ rfl
      (Air.Bridge.LtImm.highBitAdmission .unsigned)
      (Air.Bridge.LtImm.highBitAcceptance .unsigned)⟩

theorem signedUnsignedHighBitDistinction :
    Air.Bridge.LtImm.comparison .signed
        Air.Bridge.LtReg.highBitBytes (BitVec.ofNat 12 0) = true ∧
      Air.Bridge.LtImm.comparison .unsigned
        Air.Bridge.LtReg.highBitBytes (BitVec.ofNat 12 0) = false :=
  ⟨Air.Bridge.LtImm.signedHighBitResult,
    Air.Bridge.LtImm.unsignedHighBitResult⟩

end Imm

end RiscvRefinement.Opcodes.Lt
