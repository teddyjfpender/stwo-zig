import RiscvRefinement.Publication.TeamA.Common
import RiscvRefinement.Opcodes.BaseAluReg
import RiscvRefinement.Opcodes.BaseAluImm

/-!
# Accepted production AIR implies base-ALU retirement

The eight theorems in this module point in the FV-2 direction: production AIR
acceptance and an admitted pre-state environment imply the exact ordered
production projection and the normalized architectural retirement.
-/

namespace RiscvRefinement.Publication.TeamA.BaseAlu

open RiscvRefinement
open RiscvRefinement.Publication.TeamA

namespace Reg

abbrev Op := RiscvRefinement.Opcodes.BaseAluReg.Op
abbrev Row := RiscvRefinement.Opcodes.BaseAluReg.Row
abbrev Witness := RiscvRefinement.Opcodes.BaseAluReg.Witness
abbrev Environment := RiscvRefinement.Opcodes.BaseAluReg.Environment
abbrev Admission := RiscvRefinement.Opcodes.BaseAluReg.Admission
abbrev Acceptance := RiscvRefinement.Opcodes.BaseAluReg.Acceptance
abbrev Refinement := RiscvRefinement.Opcodes.BaseAluReg.Refinement
abbrev airRetirement := RiscvRefinement.Opcodes.BaseAluReg.airRetirement
abbrev execute := RiscvRefinement.Opcodes.BaseAluReg.execute

open RiscvRefinement.Opcodes.BaseAluReg

def selector : Op → Selector
  | .add => .add
  | .sub => .sub
  | .xor => .xor
  | .or => .or
  | .and => .and

theorem accepted_air_implies_retirement
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (environment : Environment row)
    (admission : Admission row)
    (accepted : Acceptance op row witness) :
    AcceptedAirCertificate
      (selector op)
      (Admission row)
      (Acceptance op row witness)
      (Air.Bridge.BaseAluReg.ProductionRefinement op row witness)
      (Refinement op row witness environment)
      (airRetirement row =
        execute op environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.rd)
      ((Air.Bridge.BaseAluReg.programLookup op row).tuple = #[
        Air.Bridge.BaseAluReg.bitVecM31 row.pc,
        M31.reduce (Decode.baseAluRegOpcodeId op),
        Air.Bridge.BaseAluReg.bitVecM31 row.rd,
        Air.Bridge.BaseAluReg.bitVecM31 row.rs1,
        Air.Bridge.BaseAluReg.bitVecM31 row.rs2
      ]) := by
  have semantic :=
    RiscvRefinement.Opcodes.BaseAluReg.refines
      op row witness environment admission accepted
  exact {
    admission
    acceptance := accepted
    exactProduction := semantic.production
    semanticRefinement := semantic
    retirement := semantic.retirement
    exactProgramTuple := by rfl
    selectorUnique := fun candidate sameId =>
      TeamA.selectorUnique (selector op) candidate sameId
    admissionProofUnique := fun other =>
      TeamA.admissionProofUnique admission other
  }

end Reg

namespace Imm

abbrev Op := RiscvRefinement.Opcodes.BaseAluImm.Op
abbrev Row := RiscvRefinement.Opcodes.BaseAluImm.Row
abbrev Witness := RiscvRefinement.Opcodes.BaseAluImm.Witness
abbrev Environment := RiscvRefinement.Opcodes.BaseAluImm.Environment
abbrev Admission := RiscvRefinement.Opcodes.BaseAluImm.Admission
abbrev Acceptance := RiscvRefinement.Opcodes.BaseAluImm.Acceptance
abbrev Refinement := RiscvRefinement.Opcodes.BaseAluImm.Refinement
abbrev airRetirement := RiscvRefinement.Opcodes.BaseAluImm.airRetirement
abbrev execute := RiscvRefinement.Opcodes.BaseAluImm.execute
abbrev immediate := RiscvRefinement.Opcodes.BaseAluImm.immediate

open RiscvRefinement.Opcodes.BaseAluImm

def selector : Op → Selector
  | .xori => .xori
  | .ori => .ori
  | .andi => .andi

theorem accepted_air_implies_retirement
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (environment : Environment row)
    (admission : Admission row)
    (accepted : Acceptance op row witness) :
    AcceptedAirCertificate
      (selector op)
      (Admission row)
      (Acceptance op row witness)
      (Air.Bridge.BaseAluImm.ProductionRefinement op row witness)
      (Refinement op row witness environment)
      (airRetirement row =
        execute op environment.pre.pc
          (environment.pre.registers row.rs1) row.rd (immediate row))
      ((Air.Bridge.BaseAluImm.programLookup op row).tuple = #[
        Air.Bridge.BaseAluImm.bitVecM31 row.pc,
        M31.reduce (Decode.baseAluImmOpcodeId op),
        Air.Bridge.BaseAluImm.bitVecM31 row.rd,
        Air.Bridge.BaseAluImm.bitVecM31 row.rs1,
        Air.Bridge.BaseAluImm.immediateUnsignedField row
      ]) := by
  have semantic :=
    RiscvRefinement.Opcodes.BaseAluImm.refines
      op row witness environment admission accepted
  exact {
    admission
    acceptance := accepted
    exactProduction := semantic.production
    semanticRefinement := semantic
    retirement := semantic.retirement
    exactProgramTuple := by rfl
    selectorUnique := fun candidate sameId =>
      TeamA.selectorUnique (selector op) candidate sameId
    admissionProofUnique := fun other =>
      TeamA.admissionProofUnique admission other
  }

end Imm

theorem add_accepted_air_implies_retirement
    (row : Reg.Row)
    (witness : Reg.Witness row)
    (environment : Reg.Environment row)
    (admission : Reg.Admission row)
    (accepted : Reg.Acceptance .add row witness) :
    AcceptedAirCertificate
      .add
      (Reg.Admission row)
      (Reg.Acceptance .add row witness)
      (Air.Bridge.BaseAluReg.ProductionRefinement .add row witness)
      (Reg.Refinement .add row witness environment)
      (Reg.airRetirement row =
        Reg.execute .add environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.rd)
      ((Air.Bridge.BaseAluReg.programLookup .add row).tuple = #[
        Air.Bridge.BaseAluReg.bitVecM31 row.pc,
        M31.reduce 0,
        Air.Bridge.BaseAluReg.bitVecM31 row.rd,
        Air.Bridge.BaseAluReg.bitVecM31 row.rs1,
        Air.Bridge.BaseAluReg.bitVecM31 row.rs2
      ]) :=
  Reg.accepted_air_implies_retirement
    .add row witness environment admission accepted

theorem sub_accepted_air_implies_retirement
    (row : Reg.Row)
    (witness : Reg.Witness row)
    (environment : Reg.Environment row)
    (admission : Reg.Admission row)
    (accepted : Reg.Acceptance .sub row witness) :
    AcceptedAirCertificate
      .sub
      (Reg.Admission row)
      (Reg.Acceptance .sub row witness)
      (Air.Bridge.BaseAluReg.ProductionRefinement .sub row witness)
      (Reg.Refinement .sub row witness environment)
      (Reg.airRetirement row =
        Reg.execute .sub environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.rd)
      ((Air.Bridge.BaseAluReg.programLookup .sub row).tuple = #[
        Air.Bridge.BaseAluReg.bitVecM31 row.pc,
        M31.reduce 1,
        Air.Bridge.BaseAluReg.bitVecM31 row.rd,
        Air.Bridge.BaseAluReg.bitVecM31 row.rs1,
        Air.Bridge.BaseAluReg.bitVecM31 row.rs2
      ]) :=
  Reg.accepted_air_implies_retirement
    .sub row witness environment admission accepted

theorem xor_accepted_air_implies_retirement
    (row : Reg.Row)
    (witness : Reg.Witness row)
    (environment : Reg.Environment row)
    (admission : Reg.Admission row)
    (accepted : Reg.Acceptance .xor row witness) :
    AcceptedAirCertificate
      .xor
      (Reg.Admission row)
      (Reg.Acceptance .xor row witness)
      (Air.Bridge.BaseAluReg.ProductionRefinement .xor row witness)
      (Reg.Refinement .xor row witness environment)
      (Reg.airRetirement row =
        Reg.execute .xor environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.rd)
      ((Air.Bridge.BaseAluReg.programLookup .xor row).tuple = #[
        Air.Bridge.BaseAluReg.bitVecM31 row.pc,
        M31.reduce 5,
        Air.Bridge.BaseAluReg.bitVecM31 row.rd,
        Air.Bridge.BaseAluReg.bitVecM31 row.rs1,
        Air.Bridge.BaseAluReg.bitVecM31 row.rs2
      ]) :=
  Reg.accepted_air_implies_retirement
    .xor row witness environment admission accepted

theorem or_accepted_air_implies_retirement
    (row : Reg.Row)
    (witness : Reg.Witness row)
    (environment : Reg.Environment row)
    (admission : Reg.Admission row)
    (accepted : Reg.Acceptance .or row witness) :
    AcceptedAirCertificate
      .or
      (Reg.Admission row)
      (Reg.Acceptance .or row witness)
      (Air.Bridge.BaseAluReg.ProductionRefinement .or row witness)
      (Reg.Refinement .or row witness environment)
      (Reg.airRetirement row =
        Reg.execute .or environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.rd)
      ((Air.Bridge.BaseAluReg.programLookup .or row).tuple = #[
        Air.Bridge.BaseAluReg.bitVecM31 row.pc,
        M31.reduce 8,
        Air.Bridge.BaseAluReg.bitVecM31 row.rd,
        Air.Bridge.BaseAluReg.bitVecM31 row.rs1,
        Air.Bridge.BaseAluReg.bitVecM31 row.rs2
      ]) :=
  Reg.accepted_air_implies_retirement
    .or row witness environment admission accepted

theorem and_accepted_air_implies_retirement
    (row : Reg.Row)
    (witness : Reg.Witness row)
    (environment : Reg.Environment row)
    (admission : Reg.Admission row)
    (accepted : Reg.Acceptance .and row witness) :
    AcceptedAirCertificate
      .and
      (Reg.Admission row)
      (Reg.Acceptance .and row witness)
      (Air.Bridge.BaseAluReg.ProductionRefinement .and row witness)
      (Reg.Refinement .and row witness environment)
      (Reg.airRetirement row =
        Reg.execute .and environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.rd)
      ((Air.Bridge.BaseAluReg.programLookup .and row).tuple = #[
        Air.Bridge.BaseAluReg.bitVecM31 row.pc,
        M31.reduce 9,
        Air.Bridge.BaseAluReg.bitVecM31 row.rd,
        Air.Bridge.BaseAluReg.bitVecM31 row.rs1,
        Air.Bridge.BaseAluReg.bitVecM31 row.rs2
      ]) :=
  Reg.accepted_air_implies_retirement
    .and row witness environment admission accepted

theorem xori_accepted_air_implies_retirement
    (row : Imm.Row)
    (witness : Imm.Witness row)
    (environment : Imm.Environment row)
    (admission : Imm.Admission row)
    (accepted : Imm.Acceptance .xori row witness) :
    AcceptedAirCertificate
      .xori
      (Imm.Admission row)
      (Imm.Acceptance .xori row witness)
      (Air.Bridge.BaseAluImm.ProductionRefinement .xori row witness)
      (Imm.Refinement .xori row witness environment)
      (Imm.airRetirement row =
        Imm.execute .xori environment.pre.pc
          (environment.pre.registers row.rs1) row.rd (Imm.immediate row))
      ((Air.Bridge.BaseAluImm.programLookup .xori row).tuple = #[
        Air.Bridge.BaseAluImm.bitVecM31 row.pc,
        M31.reduce 13,
        Air.Bridge.BaseAluImm.bitVecM31 row.rd,
        Air.Bridge.BaseAluImm.bitVecM31 row.rs1,
        Air.Bridge.BaseAluImm.immediateUnsignedField row
      ]) :=
  Imm.accepted_air_implies_retirement
    .xori row witness environment admission accepted

theorem ori_accepted_air_implies_retirement
    (row : Imm.Row)
    (witness : Imm.Witness row)
    (environment : Imm.Environment row)
    (admission : Imm.Admission row)
    (accepted : Imm.Acceptance .ori row witness) :
    AcceptedAirCertificate
      .ori
      (Imm.Admission row)
      (Imm.Acceptance .ori row witness)
      (Air.Bridge.BaseAluImm.ProductionRefinement .ori row witness)
      (Imm.Refinement .ori row witness environment)
      (Imm.airRetirement row =
        Imm.execute .ori environment.pre.pc
          (environment.pre.registers row.rs1) row.rd (Imm.immediate row))
      ((Air.Bridge.BaseAluImm.programLookup .ori row).tuple = #[
        Air.Bridge.BaseAluImm.bitVecM31 row.pc,
        M31.reduce 14,
        Air.Bridge.BaseAluImm.bitVecM31 row.rd,
        Air.Bridge.BaseAluImm.bitVecM31 row.rs1,
        Air.Bridge.BaseAluImm.immediateUnsignedField row
      ]) :=
  Imm.accepted_air_implies_retirement
    .ori row witness environment admission accepted

theorem andi_accepted_air_implies_retirement
    (row : Imm.Row)
    (witness : Imm.Witness row)
    (environment : Imm.Environment row)
    (admission : Imm.Admission row)
    (accepted : Imm.Acceptance .andi row witness) :
    AcceptedAirCertificate
      .andi
      (Imm.Admission row)
      (Imm.Acceptance .andi row witness)
      (Air.Bridge.BaseAluImm.ProductionRefinement .andi row witness)
      (Imm.Refinement .andi row witness environment)
      (Imm.airRetirement row =
        Imm.execute .andi environment.pre.pc
          (environment.pre.registers row.rs1) row.rd (Imm.immediate row))
      ((Air.Bridge.BaseAluImm.programLookup .andi row).tuple = #[
        Air.Bridge.BaseAluImm.bitVecM31 row.pc,
        M31.reduce 15,
        Air.Bridge.BaseAluImm.bitVecM31 row.rd,
        Air.Bridge.BaseAluImm.bitVecM31 row.rs1,
        Air.Bridge.BaseAluImm.immediateUnsignedField row
      ]) :=
  Imm.accepted_air_implies_retirement
    .andi row witness environment admission accepted

end RiscvRefinement.Publication.TeamA.BaseAlu
