import RiscvRefinement.Publication.TeamA.Common
import RiscvRefinement.Opcodes.Lt

/-!
# Accepted production AIR implies comparison retirement

These four selector-specific theorems retain the signed/unsigned discriminator
as an explicit premise.  The accepted generated program yields the full
ordered lookup projection, canonical decode, architectural comparison and
normalized retirement.
-/

namespace RiscvRefinement.Publication.TeamA.Compare

open RiscvRefinement
open RiscvRefinement.Publication.TeamA

namespace Reg

abbrev Row := RiscvRefinement.Opcodes.Lt.Reg.Row
abbrev Witness := RiscvRefinement.Opcodes.Lt.Reg.Witness
abbrev Admission := RiscvRefinement.Opcodes.Lt.Reg.Admission
abbrev Acceptance := RiscvRefinement.Opcodes.Lt.Reg.Acceptance
abbrev Refinement := RiscvRefinement.Opcodes.Lt.Reg.Refinement

end Reg

namespace Imm

abbrev Row := RiscvRefinement.Opcodes.Lt.Imm.Row
abbrev Witness := RiscvRefinement.Opcodes.Lt.Imm.Witness
abbrev Admission := RiscvRefinement.Opcodes.Lt.Imm.Admission
abbrev Acceptance := RiscvRefinement.Opcodes.Lt.Imm.Acceptance
abbrev Refinement := RiscvRefinement.Opcodes.Lt.Imm.Refinement

end Imm

theorem slt_accepted_air_implies_retirement
    (row : Reg.Row)
    (witness : Reg.Witness row)
    (kind : row.kind = .signed)
    (admission : Reg.Admission row)
    (accepted : Reg.Acceptance row witness) :
    AcceptedAirCertificate
      .slt
      (Reg.Admission row)
      (Reg.Acceptance row witness)
      (Air.Bridge.LtReg.ProductionRefinement row witness)
      (Reg.Refinement row witness)
      (RiscvRefinement.Opcodes.Lt.Reg.execute row = {
        nextPc := RiscvRefinement.nextPc row.pc
        write := architecturalWrite row.rd
          (RiscvRefinement.Opcodes.Lt.Reg.resultWord row)
        read := none
        store := none
      })
      ((Air.Bridge.LtReg.programLookup row).tuple = #[
        Air.Bridge.LtReg.bitVecM31 row.pc,
        M31.reduce 3,
        Air.Bridge.LtReg.bitVecM31 row.rd,
        Air.Bridge.LtReg.bitVecM31 row.rs1,
        Air.Bridge.LtReg.bitVecM31 row.rs2
      ]) := by
  have semantic :=
    RiscvRefinement.Opcodes.Lt.Reg.slt_refines
      row witness kind admission accepted
  exact {
    admission
    acceptance := accepted
    exactProduction := semantic.production
    semanticRefinement := semantic
    retirement := semantic.retirement
    exactProgramTuple :=
      RiscvRefinement.Opcodes.Lt.Reg.slt_exactProgramTuple row kind
    selectorUnique := fun candidate sameId =>
      TeamA.selectorUnique .slt candidate sameId
    admissionProofUnique := fun other =>
      TeamA.admissionProofUnique admission other
  }

theorem sltu_accepted_air_implies_retirement
    (row : Reg.Row)
    (witness : Reg.Witness row)
    (kind : row.kind = .unsigned)
    (admission : Reg.Admission row)
    (accepted : Reg.Acceptance row witness) :
    AcceptedAirCertificate
      .sltu
      (Reg.Admission row)
      (Reg.Acceptance row witness)
      (Air.Bridge.LtReg.ProductionRefinement row witness)
      (Reg.Refinement row witness)
      (RiscvRefinement.Opcodes.Lt.Reg.execute row = {
        nextPc := RiscvRefinement.nextPc row.pc
        write := architecturalWrite row.rd
          (RiscvRefinement.Opcodes.Lt.Reg.resultWord row)
        read := none
        store := none
      })
      ((Air.Bridge.LtReg.programLookup row).tuple = #[
        Air.Bridge.LtReg.bitVecM31 row.pc,
        M31.reduce 4,
        Air.Bridge.LtReg.bitVecM31 row.rd,
        Air.Bridge.LtReg.bitVecM31 row.rs1,
        Air.Bridge.LtReg.bitVecM31 row.rs2
      ]) := by
  have semantic :=
    RiscvRefinement.Opcodes.Lt.Reg.sltu_refines
      row witness kind admission accepted
  exact {
    admission
    acceptance := accepted
    exactProduction := semantic.production
    semanticRefinement := semantic
    retirement := semantic.retirement
    exactProgramTuple :=
      RiscvRefinement.Opcodes.Lt.Reg.sltu_exactProgramTuple row kind
    selectorUnique := fun candidate sameId =>
      TeamA.selectorUnique .sltu candidate sameId
    admissionProofUnique := fun other =>
      TeamA.admissionProofUnique admission other
  }

theorem slti_accepted_air_implies_retirement
    (row : Imm.Row)
    (witness : Imm.Witness row)
    (kind : row.kind = .signed)
    (admission : Imm.Admission row)
    (accepted : Imm.Acceptance row witness) :
    AcceptedAirCertificate
      .slti
      (Imm.Admission row)
      (Imm.Acceptance row witness)
      (Air.Bridge.LtImm.ProductionRefinement row witness)
      (Imm.Refinement row witness)
      (RiscvRefinement.Opcodes.Lt.Imm.execute row = {
        nextPc := RiscvRefinement.nextPc row.pc
        write := architecturalWrite row.rd
          (RiscvRefinement.Opcodes.Lt.Imm.resultWord row)
        read := none
        store := none
      })
      ((Air.Bridge.LtImm.programLookup row).tuple = #[
        Air.Bridge.LtImm.bitVecM31 row.pc,
        M31.reduce 11,
        Air.Bridge.LtImm.bitVecM31 row.rd,
        Air.Bridge.LtImm.bitVecM31 row.rs1,
        Air.Bridge.LtImm.immediateField row
      ]) := by
  have semantic :=
    RiscvRefinement.Opcodes.Lt.Imm.slti_refines
      row witness kind admission accepted
  exact {
    admission
    acceptance := accepted
    exactProduction := semantic.production
    semanticRefinement := semantic
    retirement := semantic.retirement
    exactProgramTuple :=
      RiscvRefinement.Opcodes.Lt.Imm.slti_exactProgramTuple row kind
    selectorUnique := fun candidate sameId =>
      TeamA.selectorUnique .slti candidate sameId
    admissionProofUnique := fun other =>
      TeamA.admissionProofUnique admission other
  }

theorem sltiu_accepted_air_implies_retirement
    (row : Imm.Row)
    (witness : Imm.Witness row)
    (kind : row.kind = .unsigned)
    (admission : Imm.Admission row)
    (accepted : Imm.Acceptance row witness) :
    AcceptedAirCertificate
      .sltiu
      (Imm.Admission row)
      (Imm.Acceptance row witness)
      (Air.Bridge.LtImm.ProductionRefinement row witness)
      (Imm.Refinement row witness)
      (RiscvRefinement.Opcodes.Lt.Imm.execute row = {
        nextPc := RiscvRefinement.nextPc row.pc
        write := architecturalWrite row.rd
          (RiscvRefinement.Opcodes.Lt.Imm.resultWord row)
        read := none
        store := none
      })
      ((Air.Bridge.LtImm.programLookup row).tuple = #[
        Air.Bridge.LtImm.bitVecM31 row.pc,
        M31.reduce 12,
        Air.Bridge.LtImm.bitVecM31 row.rd,
        Air.Bridge.LtImm.bitVecM31 row.rs1,
        Air.Bridge.LtImm.immediateField row
      ]) := by
  have semantic :=
    RiscvRefinement.Opcodes.Lt.Imm.sltiu_refines
      row witness kind admission accepted
  exact {
    admission
    acceptance := accepted
    exactProduction := semantic.production
    semanticRefinement := semantic
    retirement := semantic.retirement
    exactProgramTuple :=
      RiscvRefinement.Opcodes.Lt.Imm.sltiu_exactProgramTuple row kind
    selectorUnique := fun candidate sameId =>
      TeamA.selectorUnique .sltiu candidate sameId
    admissionProofUnique := fun other =>
      TeamA.admissionProofUnique admission other
  }

end RiscvRefinement.Publication.TeamA.Compare
