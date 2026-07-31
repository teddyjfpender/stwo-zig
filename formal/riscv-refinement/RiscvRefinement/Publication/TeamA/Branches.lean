import RiscvRefinement.Publication.TeamA.Common
import RiscvRefinement.Opcodes.Branches

/-!
# Accepted production AIR implies branch retirement

The production-facing branch proofs use raw independent AIR columns.  The
certificate therefore records the exact state-emission tuple as the bridge to
the normalized `Retirement`, in addition to the complete ordered production
projection carried by `RawProductionRefinement`.
-/

namespace RiscvRefinement.Publication.TeamA.Branches

open RiscvRefinement
open RiscvRefinement.Publication.TeamA

namespace Eq

abbrev Row := RiscvRefinement.Opcodes.Branches.Eq.RawRow
abbrev Witness := RiscvRefinement.Opcodes.Branches.Eq.RawWitness
abbrev Admission := RiscvRefinement.Opcodes.Branches.Eq.RawAdmission
abbrev Acceptance := RiscvRefinement.Opcodes.Branches.Eq.RawAcceptance
abbrev Refinement := RiscvRefinement.Opcodes.Branches.Eq.RawRefinement

def normalizedRetirement (row : Row) : Retirement where
  nextPc :=
    Air.Bridge.Branches.selectedPc
      row.pc row.immediateEncoded
      (RiscvRefinement.Opcodes.Branches.Eq.rawExpectedTaken row)
  write := none

theorem build
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness)
    (programTuple :
      (Air.Bridge.Branches.Eq.rawProgramLookup row).tuple = #[
        Air.Bridge.Branches.bitVecM31 row.pc,
        M31.reduce selector.manifestId,
        Air.Bridge.Branches.bitVecM31 row.rs1,
        Air.Bridge.Branches.bitVecM31 row.rs2,
        Air.Bridge.Branches.immediateField row.immediateEncoded
      ]) :
    AcceptedAirCertificate
      selector
      (Admission row)
      (Acceptance row witness)
      (Air.Bridge.Branches.Eq.RawProductionRefinement row witness)
      (Refinement row witness)
      ((Air.Bridge.Branches.Eq.rawStateEmitLookup row).tuple[0]? =
        some (Air.Bridge.Branches.bitVecM31
          (normalizedRetirement row).nextPc))
      ((Air.Bridge.Branches.Eq.rawProgramLookup row).tuple = #[
        Air.Bridge.Branches.bitVecM31 row.pc,
        M31.reduce selector.manifestId,
        Air.Bridge.Branches.bitVecM31 row.rs1,
        Air.Bridge.Branches.bitVecM31 row.rs2,
        Air.Bridge.Branches.immediateField row.immediateEncoded
      ]) := by
  have semantic :=
    RiscvRefinement.Opcodes.Branches.Eq.rawRefines
      row witness admission accepted
  exact {
    admission
    acceptance := accepted
    exactProduction := semantic.production
    semanticRefinement := semantic
    retirement := by
      simpa [normalizedRetirement] using semantic.retirementPc
    exactProgramTuple := programTuple
    selectorUnique := fun candidate sameId =>
      TeamA.selectorUnique selector candidate sameId
    admissionProofUnique := fun other =>
      TeamA.admissionProofUnique admission other
  }

end Eq

namespace Lt

abbrev Row := RiscvRefinement.Opcodes.Branches.Lt.RawRow
abbrev Witness := RiscvRefinement.Opcodes.Branches.Lt.RawWitness
abbrev Admission := RiscvRefinement.Opcodes.Branches.Lt.RawAdmission
abbrev Acceptance := RiscvRefinement.Opcodes.Branches.Lt.RawAcceptance
abbrev Refinement := RiscvRefinement.Opcodes.Branches.Lt.RawRefinement

def normalizedRetirement (row : Row) : Retirement where
  nextPc :=
    Air.Bridge.Branches.selectedPc
      row.pc row.immediateEncoded
      (RiscvRefinement.Opcodes.Branches.Lt.rawExpectedTaken row)
  write := none

theorem build
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness)
    (programTuple :
      (Air.Bridge.Branches.Lt.rawProgramLookup row).tuple = #[
        Air.Bridge.Branches.bitVecM31 row.pc,
        M31.reduce selector.manifestId,
        Air.Bridge.Branches.bitVecM31 row.rs1,
        Air.Bridge.Branches.bitVecM31 row.rs2,
        Air.Bridge.Branches.immediateField row.immediateEncoded
      ]) :
    AcceptedAirCertificate
      selector
      (Admission row)
      (Acceptance row witness)
      (Air.Bridge.Branches.Lt.RawProductionRefinement row witness)
      (Refinement row witness)
      ((Air.Bridge.Branches.Lt.rawStateEmitLookup row).tuple[0]? =
        some (Air.Bridge.Branches.bitVecM31
          (normalizedRetirement row).nextPc))
      ((Air.Bridge.Branches.Lt.rawProgramLookup row).tuple = #[
        Air.Bridge.Branches.bitVecM31 row.pc,
        M31.reduce selector.manifestId,
        Air.Bridge.Branches.bitVecM31 row.rs1,
        Air.Bridge.Branches.bitVecM31 row.rs2,
        Air.Bridge.Branches.immediateField row.immediateEncoded
      ]) := by
  have semantic :=
    RiscvRefinement.Opcodes.Branches.Lt.rawRefines
      row witness admission accepted
  exact {
    admission
    acceptance := accepted
    exactProduction := semantic.production
    semanticRefinement := semantic
    retirement := by
      simpa [normalizedRetirement] using semantic.retirementPc
    exactProgramTuple := programTuple
    selectorUnique := fun candidate sameId =>
      TeamA.selectorUnique selector candidate sameId
    admissionProofUnique := fun other =>
      TeamA.admissionProofUnique admission other
  }

end Lt

theorem beq_accepted_air_implies_retirement
    (row : Eq.Row)
    (witness : Eq.Witness row)
    (kind : row.kind = .beq)
    (admission : Eq.Admission row)
    (accepted : Eq.Acceptance row witness) :
    AcceptedAirCertificate
      .beq
      (Eq.Admission row)
      (Eq.Acceptance row witness)
      (Air.Bridge.Branches.Eq.RawProductionRefinement row witness)
      (Eq.Refinement row witness)
      ((Air.Bridge.Branches.Eq.rawStateEmitLookup row).tuple[0]? =
        some (Air.Bridge.Branches.bitVecM31
          (Eq.normalizedRetirement row).nextPc))
      ((Air.Bridge.Branches.Eq.rawProgramLookup row).tuple = #[
        Air.Bridge.Branches.bitVecM31 row.pc,
        M31.reduce 27,
        Air.Bridge.Branches.bitVecM31 row.rs1,
        Air.Bridge.Branches.bitVecM31 row.rs2,
        Air.Bridge.Branches.immediateField row.immediateEncoded
      ]) :=
  Eq.build .beq row witness admission accepted
    (RiscvRefinement.Opcodes.Branches.Eq.beq_tuple_theorem
      row kind admission)

theorem bne_accepted_air_implies_retirement
    (row : Eq.Row)
    (witness : Eq.Witness row)
    (kind : row.kind = .bne)
    (admission : Eq.Admission row)
    (accepted : Eq.Acceptance row witness) :
    AcceptedAirCertificate
      .bne
      (Eq.Admission row)
      (Eq.Acceptance row witness)
      (Air.Bridge.Branches.Eq.RawProductionRefinement row witness)
      (Eq.Refinement row witness)
      ((Air.Bridge.Branches.Eq.rawStateEmitLookup row).tuple[0]? =
        some (Air.Bridge.Branches.bitVecM31
          (Eq.normalizedRetirement row).nextPc))
      ((Air.Bridge.Branches.Eq.rawProgramLookup row).tuple = #[
        Air.Bridge.Branches.bitVecM31 row.pc,
        M31.reduce 28,
        Air.Bridge.Branches.bitVecM31 row.rs1,
        Air.Bridge.Branches.bitVecM31 row.rs2,
        Air.Bridge.Branches.immediateField row.immediateEncoded
      ]) :=
  Eq.build .bne row witness admission accepted
    (RiscvRefinement.Opcodes.Branches.Eq.bne_tuple_theorem
      row kind admission)

theorem blt_accepted_air_implies_retirement
    (row : Lt.Row)
    (witness : Lt.Witness row)
    (kind : row.kind = .blt)
    (admission : Lt.Admission row)
    (accepted : Lt.Acceptance row witness) :
    AcceptedAirCertificate
      .blt
      (Lt.Admission row)
      (Lt.Acceptance row witness)
      (Air.Bridge.Branches.Lt.RawProductionRefinement row witness)
      (Lt.Refinement row witness)
      ((Air.Bridge.Branches.Lt.rawStateEmitLookup row).tuple[0]? =
        some (Air.Bridge.Branches.bitVecM31
          (Lt.normalizedRetirement row).nextPc))
      ((Air.Bridge.Branches.Lt.rawProgramLookup row).tuple = #[
        Air.Bridge.Branches.bitVecM31 row.pc,
        M31.reduce 29,
        Air.Bridge.Branches.bitVecM31 row.rs1,
        Air.Bridge.Branches.bitVecM31 row.rs2,
        Air.Bridge.Branches.immediateField row.immediateEncoded
      ]) :=
  Lt.build .blt row witness admission accepted
    (RiscvRefinement.Opcodes.Branches.Lt.blt_tuple_theorem
      row kind admission)

theorem bge_accepted_air_implies_retirement
    (row : Lt.Row)
    (witness : Lt.Witness row)
    (kind : row.kind = .bge)
    (admission : Lt.Admission row)
    (accepted : Lt.Acceptance row witness) :
    AcceptedAirCertificate
      .bge
      (Lt.Admission row)
      (Lt.Acceptance row witness)
      (Air.Bridge.Branches.Lt.RawProductionRefinement row witness)
      (Lt.Refinement row witness)
      ((Air.Bridge.Branches.Lt.rawStateEmitLookup row).tuple[0]? =
        some (Air.Bridge.Branches.bitVecM31
          (Lt.normalizedRetirement row).nextPc))
      ((Air.Bridge.Branches.Lt.rawProgramLookup row).tuple = #[
        Air.Bridge.Branches.bitVecM31 row.pc,
        M31.reduce 30,
        Air.Bridge.Branches.bitVecM31 row.rs1,
        Air.Bridge.Branches.bitVecM31 row.rs2,
        Air.Bridge.Branches.immediateField row.immediateEncoded
      ]) :=
  Lt.build .bge row witness admission accepted
    (RiscvRefinement.Opcodes.Branches.Lt.bge_tuple_theorem
      row kind admission)

theorem bltu_accepted_air_implies_retirement
    (row : Lt.Row)
    (witness : Lt.Witness row)
    (kind : row.kind = .bltu)
    (admission : Lt.Admission row)
    (accepted : Lt.Acceptance row witness) :
    AcceptedAirCertificate
      .bltu
      (Lt.Admission row)
      (Lt.Acceptance row witness)
      (Air.Bridge.Branches.Lt.RawProductionRefinement row witness)
      (Lt.Refinement row witness)
      ((Air.Bridge.Branches.Lt.rawStateEmitLookup row).tuple[0]? =
        some (Air.Bridge.Branches.bitVecM31
          (Lt.normalizedRetirement row).nextPc))
      ((Air.Bridge.Branches.Lt.rawProgramLookup row).tuple = #[
        Air.Bridge.Branches.bitVecM31 row.pc,
        M31.reduce 31,
        Air.Bridge.Branches.bitVecM31 row.rs1,
        Air.Bridge.Branches.bitVecM31 row.rs2,
        Air.Bridge.Branches.immediateField row.immediateEncoded
      ]) :=
  Lt.build .bltu row witness admission accepted
    (RiscvRefinement.Opcodes.Branches.Lt.bltu_tuple_theorem
      row kind admission)

theorem bgeu_accepted_air_implies_retirement
    (row : Lt.Row)
    (witness : Lt.Witness row)
    (kind : row.kind = .bgeu)
    (admission : Lt.Admission row)
    (accepted : Lt.Acceptance row witness) :
    AcceptedAirCertificate
      .bgeu
      (Lt.Admission row)
      (Lt.Acceptance row witness)
      (Air.Bridge.Branches.Lt.RawProductionRefinement row witness)
      (Lt.Refinement row witness)
      ((Air.Bridge.Branches.Lt.rawStateEmitLookup row).tuple[0]? =
        some (Air.Bridge.Branches.bitVecM31
          (Lt.normalizedRetirement row).nextPc))
      ((Air.Bridge.Branches.Lt.rawProgramLookup row).tuple = #[
        Air.Bridge.Branches.bitVecM31 row.pc,
        M31.reduce 32,
        Air.Bridge.Branches.bitVecM31 row.rs1,
        Air.Bridge.Branches.bitVecM31 row.rs2,
        Air.Bridge.Branches.immediateField row.immediateEncoded
      ]) :=
  Lt.build .bgeu row witness admission accepted
    (RiscvRefinement.Opcodes.Branches.Lt.bgeu_tuple_theorem
      row kind admission)

end RiscvRefinement.Publication.TeamA.Branches
