import RiscvRefinement.Publication.TeamA.Common
import RiscvRefinement.Opcodes.Jal
import RiscvRefinement.Opcodes.Jalr
import RiscvRefinement.Opcodes.Auipc
import RiscvRefinement.Opcodes.Fence

/-!
# Accepted production AIR implies control/system retirement

JAL, JALR, AUIPC and FENCE expose their exact generated lookup order through
the existing `ProductionRefinement` structures.  These wrappers make the
accepted-AIR implication and exact program tuple uniform with the other Team A
families.
-/

namespace RiscvRefinement.Publication.TeamA.Control

open RiscvRefinement
open RiscvRefinement.Publication.TeamA

theorem jal_accepted_air_implies_retirement
    (row : RiscvRefinement.Opcodes.Jal.Row)
    (witness : RiscvRefinement.Opcodes.Jal.Witness row)
    (admission : RiscvRefinement.Opcodes.Jal.Admission row)
    (accepted : RiscvRefinement.Opcodes.Jal.Acceptance row witness) :
    AcceptedAirCertificate
      .jal
      (RiscvRefinement.Opcodes.Jal.Admission row)
      (RiscvRefinement.Opcodes.Jal.Acceptance row witness)
      (Air.Bridge.Jal.ProductionRefinement row witness)
      (RiscvRefinement.Opcodes.Jal.Refinement row witness)
      (RiscvRefinement.Opcodes.Jal.airRetirement row =
        RiscvRefinement.Opcodes.Jal.execute
          row.pc row.rd row.immediateEncoded)
      ((Air.Bridge.Jal.programLookup row).tuple = #[
        Air.Bridge.Jal.bitVecM31 row.pc,
        M31.reduce 33,
        Air.Bridge.Jal.bitVecM31 row.rd,
        Air.Bridge.Jal.immediateField row.immediateEncoded,
        0
      ]) := by
  have semantic :=
    RiscvRefinement.Opcodes.Jal.refines
      row witness admission accepted
  exact {
    admission
    acceptance := accepted
    exactProduction := semantic.production
    semanticRefinement := semantic
    retirement := semantic.retirement
    exactProgramTuple := by rfl
    selectorUnique := fun candidate sameId =>
      TeamA.selectorUnique .jal candidate sameId
    admissionProofUnique := fun other =>
      TeamA.admissionProofUnique admission other
  }

theorem jalr_accepted_air_implies_retirement
    (row : RiscvRefinement.Opcodes.Jalr.Row)
    (witness : RiscvRefinement.Opcodes.Jalr.Witness row)
    (environment : RiscvRefinement.Opcodes.Jalr.Environment row)
    (admission : RiscvRefinement.Opcodes.Jalr.Admission row)
    (accepted : RiscvRefinement.Opcodes.Jalr.Acceptance row witness) :
    AcceptedAirCertificate
      .jalr
      (RiscvRefinement.Opcodes.Jalr.Admission row)
      (RiscvRefinement.Opcodes.Jalr.Acceptance row witness)
      (Air.Bridge.Jalr.ProductionRefinement row witness)
      (RiscvRefinement.Opcodes.Jalr.Refinement row witness environment)
      (RiscvRefinement.Opcodes.Jalr.airRetirement row =
        RiscvRefinement.Opcodes.Jalr.execute
          environment.pre.pc
          (environment.pre.registers row.rs1)
          row.rd row.immediate)
      ((Air.Bridge.Jalr.programLookup row).tuple = #[
        Air.Bridge.Jalr.bitVecM31 row.pc,
        M31.reduce 34,
        Air.Bridge.Jalr.bitVecM31 row.rd,
        Air.Bridge.Jalr.bitVecM31 row.rs1,
        Air.Bridge.Jalr.immediateField row.immediate
      ]) := by
  have semantic :=
    RiscvRefinement.Opcodes.Jalr.jalr_refines
      row witness environment admission accepted
  exact {
    admission
    acceptance := accepted
    exactProduction := semantic.production
    semanticRefinement := semantic
    retirement := semantic.retirement
    exactProgramTuple :=
      RiscvRefinement.Opcodes.Jalr.jalr_exactProgramTuple row
    selectorUnique := fun candidate sameId =>
      TeamA.selectorUnique .jalr candidate sameId
    admissionProofUnique := fun other =>
      TeamA.admissionProofUnique admission other
  }

theorem auipc_accepted_air_implies_retirement
    (row : RiscvRefinement.Opcodes.Auipc.Row)
    (witness : RiscvRefinement.Opcodes.Auipc.Witness row)
    (admission : RiscvRefinement.Opcodes.Auipc.Admission row)
    (accepted : RiscvRefinement.Opcodes.Auipc.Acceptance row witness) :
    AcceptedAirCertificate
      .auipc
      (RiscvRefinement.Opcodes.Auipc.Admission row)
      (RiscvRefinement.Opcodes.Auipc.Acceptance row witness)
      (Air.Bridge.Auipc.ProductionRefinement row witness)
      (RiscvRefinement.Opcodes.Auipc.Refinement row witness)
      (RiscvRefinement.Opcodes.Auipc.airRetirement row =
        RiscvRefinement.Opcodes.Auipc.execute
          row.pc row.rd row.immediateEncoded)
      ((Air.Bridge.Auipc.programLookup row).tuple = #[
        Air.Bridge.Auipc.bitVecM31 row.pc,
        M31.reduce 36,
        Air.Bridge.Auipc.bitVecM31 row.rd,
        row.immediateFelt,
        0
      ]) := by
  have semantic :=
    RiscvRefinement.Opcodes.Auipc.refines
      row witness admission accepted
  exact {
    admission
    acceptance := accepted
    exactProduction := semantic.production
    semanticRefinement := semantic
    retirement := semantic.retirement
    exactProgramTuple := by rfl
    selectorUnique := fun candidate sameId =>
      TeamA.selectorUnique .auipc candidate sameId
    admissionProofUnique := fun other =>
      TeamA.admissionProofUnique admission other
  }

/--
FENCE's generated program has no witness columns and its direct constraints,
selector and fixed requests hold for every row.  Keeping this acceptance
record explicit gives its publication theorem the same premise shape as the
other twenty-three selectors.
-/
structure FenceAcceptance (row : Air.Bridge.Fence.Row) : Prop where
  selectors :
    (Air.Bridge.Fence.evaluation row).activeSelectorsAccepted = true
  constraints :
    (Air.Bridge.Fence.evaluation row).constraintsHold = true
  fixedLookups :
    (Air.Bridge.Fence.evaluation row).fixedLookupsHold = true

theorem fenceAcceptance (row : Air.Bridge.Fence.Row) :
    FenceAcceptance row where
  selectors := Air.Bridge.Fence.selectorAccepted row
  constraints := Air.Bridge.Fence.constraintsHold row
  fixedLookups := Air.Bridge.Fence.fixedLookupsHold row

theorem fence_accepted_air_implies_retirement
    (row : Air.Bridge.Fence.Row)
    (admission : Air.Bridge.Fence.Admission row)
    (accepted : FenceAcceptance row) :
    AcceptedAirCertificate
      .fence
      (Air.Bridge.Fence.Admission row)
      (FenceAcceptance row)
      (Air.Bridge.Fence.ProductionRefinement row)
      (RiscvRefinement.Opcodes.Fence.Refinement row)
      (RiscvRefinement.Opcodes.Fence.execute row.pc = {
        nextPc := RiscvRefinement.nextPc row.pc
        write := none
        read := none
        store := none
      })
      ((Air.Bridge.Fence.programLookup row).tuple = #[
        Air.Bridge.Fence.bitVecM31 row.pc,
        M31.reduce 45,
        Air.Bridge.Fence.bitVecM31 row.rd,
        Air.Bridge.Fence.bitVecM31 row.rs1,
        Air.Bridge.Fence.bitVecM31 row.immediate
      ]) := by
  have semantic :=
    RiscvRefinement.Opcodes.Fence.refines row admission
  exact {
    admission
    acceptance := accepted
    exactProduction := semantic.production
    semanticRefinement := semantic
    retirement := semantic.retirement
    exactProgramTuple := by rfl
    selectorUnique := fun candidate sameId =>
      TeamA.selectorUnique .fence candidate sameId
    admissionProofUnique := fun other =>
      TeamA.admissionProofUnique admission other
  }

end RiscvRefinement.Publication.TeamA.Control
