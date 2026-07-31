import RiscvRefinement.Publication.TeamA.Common
import RiscvRefinement.Opcodes.Lui
import RiscvRefinement.Opcodes.Addi

/-!
# Accepted production AIR implies LUI/ADDI retirement

These are the two original pilot selectors.  The publication statements start
from acceptance by the exact generated `Programs.lui` / `Programs.addi`
evaluators, retain the complete ordered lookup projection, and conclude the
same normalized retirement used by the architectural opcode proofs.
-/

namespace RiscvRefinement.Publication.TeamA.Pilots

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Generated
open RiscvRefinement.Publication.TeamA

def LuiOrderedLookups
    (row : LuiRow)
    (witness : Air.Bridge.Lui.Witness row) : Prop :=
  (Air.Bridge.Lui.evaluation row witness).lookup? 9 =
      some (Air.Bridge.Lui.programLookup row) ∧
    (Air.Bridge.Lui.evaluation row witness).lookup? 10 =
      some (Air.Bridge.Lui.stateConsumeLookup row) ∧
    (Air.Bridge.Lui.evaluation row witness).lookup? 11 =
      some (Air.Bridge.Lui.stateEmitLookup row) ∧
    (Air.Bridge.Lui.evaluation row witness).lookup? 12 =
      some (Air.Bridge.Lui.immediateLookup row) ∧
    (Air.Bridge.Lui.evaluation row witness).lookup? 13 =
      some (Air.Bridge.Lui.destinationConsumeLookup row) ∧
    (Air.Bridge.Lui.evaluation row witness).lookup? 14 =
      some (Air.Bridge.Lui.destinationEmitLookup row) ∧
    (Air.Bridge.Lui.evaluation row witness).lookup? 15 =
      some (Air.Bridge.Lui.clockLookup row)

structure LuiExactProduction
    (row : LuiRow)
    (witness : Air.Bridge.Lui.Witness row) : Prop where
  identity :
    Programs.lui.source.schemaVersion = 2 ∧
      Programs.lui.source.family = .lui ∧
      Programs.lui.source.opcodeSelector.manifestId = 35 ∧
      Programs.lui.source.opcodeSelector.mnemonic = "lui" ∧
      Programs.lui.source.contentDigest =
        "d5eb5ca5127828f57d7fb52c292ea3a74e39b1a26334c935fc66535dfca9f3ef"
  orderedLookups : LuiOrderedLookups row witness

theorem lui_accepted_air_implies_retirement
    (row : LuiRow)
    (witness : Air.Bridge.Lui.Witness row)
    (environment :
      Opcodes.LuiEnvironment (Air.Bridge.Lui.interpretedRow row))
    (admission : Air.Bridge.Lui.Admission row)
    (accepted : Air.Bridge.Lui.Acceptance row witness) :
    AcceptedAirCertificate
      .lui
      (Air.Bridge.Lui.Admission row)
      (Air.Bridge.Lui.Acceptance row witness)
      (LuiExactProduction row witness)
      (Opcodes.LuiRefinement
        (Air.Bridge.Lui.interpretedRow row) environment)
      (luiRetirement (Air.Bridge.Lui.interpretedRow row) =
        Sail.Generated.executeLui
          environment.pre.pc
          (Air.Bridge.Lui.interpretedRow row).rd
          (luiImmediate
            (Air.Bridge.Lui.interpretedRow row).imm0
            (Air.Bridge.Lui.interpretedRow row).imm1
            (Air.Bridge.Lui.interpretedRow row).imm2))
      ((Air.Bridge.Lui.programLookup row).tuple = #[
        Air.Bridge.Lui.bitVecM31 row.pc,
        M31.reduce 35,
        Air.Bridge.Lui.bitVecM31 row.rd,
        Air.Bridge.Lui.bitVecM31 row.imm0 +
          Air.Bridge.Lui.bitVecM31 row.imm1 * M31.reduce 16 +
          Air.Bridge.Lui.bitVecM31 row.imm2 * M31.reduce 4096,
        0
      ]) := by
  have semantic :=
    Opcodes.lui_production_refines
      row witness environment admission accepted
  exact {
    admission
    acceptance := accepted
    exactProduction := {
      identity := ⟨rfl, rfl, rfl, rfl, rfl⟩
      orderedLookups := Air.Bridge.Lui.lookup_projection row witness
    }
    semanticRefinement := semantic
    retirement := semantic.retirement
    exactProgramTuple := by rfl
    selectorUnique := fun candidate sameId =>
      TeamA.selectorUnique .lui candidate sameId
    admissionProofUnique := fun other =>
      TeamA.admissionProofUnique admission other
  }

structure AddiExactProduction
    (row : AddiRow)
    (witness : Air.Bridge.Addi.Witness row) : Prop where
  identity :
    Programs.addi.source.schemaVersion = 2 ∧
      Programs.addi.source.family = .baseAluImm ∧
      Programs.addi.source.opcodeSelector.manifestId = 10 ∧
      Programs.addi.source.opcodeSelector.mnemonic = "addi" ∧
      Programs.addi.source.contentDigest =
        "03e6006a68391ad90474d815dd03bce08feee4145e8ef0b37eaa757bc48d2bea"
  orderedLookups :
    (Air.Bridge.Addi.evaluation row witness).lookup? 22 =
        some (Air.Bridge.Addi.programLookup row) ∧
      (Air.Bridge.Addi.evaluation row witness).lookup? 23 =
        some (Air.Bridge.Addi.immediateLookup row) ∧
      (Air.Bridge.Addi.evaluation row witness).lookup? 24 =
        some (Air.Bridge.Addi.stateConsumeLookup row) ∧
      (Air.Bridge.Addi.evaluation row witness).lookup? 25 =
        some (Air.Bridge.Addi.stateEmitLookup row) ∧
      (Air.Bridge.Addi.evaluation row witness).lookup? 26 =
        some (Air.Bridge.Addi.sourceConsumeLookup row) ∧
      (Air.Bridge.Addi.evaluation row witness).lookup? 27 =
        some (Air.Bridge.Addi.sourceEmitLookup row) ∧
      (Air.Bridge.Addi.evaluation row witness).lookup? 28 =
        some (Air.Bridge.Addi.sourceClockLookup row) ∧
      (Air.Bridge.Addi.evaluation row witness).lookup? 29 =
        some (Air.Bridge.Addi.bitwiseLookup0 row) ∧
      (Air.Bridge.Addi.evaluation row witness).lookup? 30 =
        some (Air.Bridge.Addi.bitwiseLookup1 row) ∧
      (Air.Bridge.Addi.evaluation row witness).lookup? 31 =
        some (Air.Bridge.Addi.bitwiseLookup2 row) ∧
      (Air.Bridge.Addi.evaluation row witness).lookup? 32 =
        some (Air.Bridge.Addi.bitwiseLookup3 row) ∧
      (Air.Bridge.Addi.evaluation row witness).lookup? 33 =
        some (Air.Bridge.Addi.resultLowLookup row) ∧
      (Air.Bridge.Addi.evaluation row witness).lookup? 34 =
        some (Air.Bridge.Addi.resultHighLookup row) ∧
      (Air.Bridge.Addi.evaluation row witness).lookup? 35 =
        some (Air.Bridge.Addi.destinationConsumeLookup row) ∧
      (Air.Bridge.Addi.evaluation row witness).lookup? 36 =
        some (Air.Bridge.Addi.destinationEmitLookup row) ∧
      (Air.Bridge.Addi.evaluation row witness).lookup? 37 =
        some (Air.Bridge.Addi.destinationClockLookup row)

theorem addi_accepted_air_implies_retirement
    (row : AddiRow)
    (witness : Air.Bridge.Addi.Witness row)
    (environment :
      Opcodes.AddiEnvironment (Air.Bridge.Addi.interpretedRow row))
    (admission : Air.Bridge.Addi.Admission row)
    (accepted : Air.Bridge.Addi.Acceptance row witness) :
    AcceptedAirCertificate
      .addi
      (Air.Bridge.Addi.Admission row)
      (Air.Bridge.Addi.Acceptance row witness)
      (AddiExactProduction row witness)
      (Opcodes.AddiRefinement
        (Air.Bridge.Addi.interpretedRow row) environment)
      (addiRetirement (Air.Bridge.Addi.interpretedRow row) =
        Sail.Generated.executeAddi
          environment.pre.pc
          (environment.pre.registers
            (Air.Bridge.Addi.interpretedRow row).rs1)
          (Air.Bridge.Addi.interpretedRow row).rd
          (addiImmediate
            (Air.Bridge.Addi.interpretedRow row).imm0
            (Air.Bridge.Addi.interpretedRow row).imm1
            (Air.Bridge.Addi.interpretedRow row).immSign))
      ((Air.Bridge.Addi.programLookup row).tuple = #[
        Air.Bridge.Addi.bitVecM31 row.pc,
        M31.reduce 10,
        Air.Bridge.Addi.bitVecM31 row.rd,
        Air.Bridge.Addi.bitVecM31 row.rs1,
        Air.Bridge.Addi.bitVecM31 row.imm0 +
          Air.Bridge.Addi.bitVecM31 row.imm1 * M31.reduce 256 +
          Air.Bridge.Addi.bitVecM31 row.immSign * M31.reduce 2048
      ]) := by
  have semantic :=
    Opcodes.addi_production_refines
      row witness environment admission accepted
  exact {
    admission
    acceptance := accepted
    exactProduction := {
      identity := ⟨rfl, rfl, rfl, rfl, rfl⟩
      orderedLookups := Air.Bridge.Addi.lookup_projection row witness
    }
    semanticRefinement := semantic
    retirement := semantic.retirement
    exactProgramTuple := by rfl
    selectorUnique := fun candidate sameId =>
      TeamA.selectorUnique .addi candidate sameId
    admissionProofUnique := fun other =>
      TeamA.admissionProofUnique admission other
  }

end RiscvRefinement.Publication.TeamA.Pilots
