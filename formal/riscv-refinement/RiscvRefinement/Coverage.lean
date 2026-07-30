import RiscvRefinement.NonVacuity

namespace RiscvRefinement.Coverage

inductive PilotOpcode
  | lui
  | addi
deriving DecidableEq, Repr

def covered : List PilotOpcode := [.lui, .addi]

theorem pilot_coverage_exact :
    covered.length = 2 ∧
      covered.contains .lui ∧
      covered.contains .addi := by
  decide

/-!
The pilot list above is deliberately retained: it describes the older
generated-normalizer artifact and must not silently acquire a stronger claim.
The inventory below is the production-AIR certificate partition introduced by
issues #136 and #137.  Its `AirEvidence` field records the two different proof
grades honestly; neither grade implies full generated-Sail step framing or
publication-level frontend verification.
-/

inductive Team
  | a
  | b
deriving DecidableEq, Repr

inductive AirEvidence
  | exactGeneratedLocalProgram
  | reviewedFamilyCapsule
deriving DecidableEq, Repr

structure OpcodeCertificate where
  manifestId : Nat
  mnemonic : String
  team : Team
  airEvidence : AirEvidence
deriving DecidableEq, Repr

private def teamA
    (manifestId : Nat)
    (mnemonic : String) :
    OpcodeCertificate where
  manifestId
  mnemonic
  team := .a
  airEvidence := .exactGeneratedLocalProgram

private def teamB
    (manifestId : Nat)
    (mnemonic : String) :
    OpcodeCertificate where
  manifestId
  mnemonic
  team := .b
  airEvidence := .reviewedFamilyCapsule

def aggregateCovered : List OpcodeCertificate := [
  teamA 0 "add",
  teamA 1 "sub",
  teamB 2 "sll",
  teamA 3 "slt",
  teamA 4 "sltu",
  teamA 5 "xor",
  teamB 6 "srl",
  teamB 7 "sra",
  teamA 8 "or",
  teamA 9 "and",
  teamA 10 "addi",
  teamA 11 "slti",
  teamA 12 "sltiu",
  teamA 13 "xori",
  teamA 14 "ori",
  teamA 15 "andi",
  teamB 16 "slli",
  teamB 17 "srli",
  teamB 18 "srai",
  teamB 19 "lb",
  teamB 20 "lh",
  teamB 21 "lw",
  teamB 22 "lbu",
  teamB 23 "lhu",
  teamB 24 "sb",
  teamB 25 "sh",
  teamB 26 "sw",
  teamA 27 "beq",
  teamA 28 "bne",
  teamA 29 "blt",
  teamA 30 "bge",
  teamA 31 "bltu",
  teamA 32 "bgeu",
  teamA 33 "jal",
  teamA 34 "jalr",
  teamA 35 "lui",
  teamA 36 "auipc",
  teamB 37 "mul",
  teamB 38 "mulh",
  teamB 39 "mulhsu",
  teamB 40 "mulhu",
  teamB 41 "div",
  teamB 42 "divu",
  teamB 43 "rem",
  teamB 44 "remu",
  teamA 45 "fence"
]

def teamACovered : List OpcodeCertificate :=
  aggregateCovered.filter (fun certificate => certificate.team == .a)

def teamBCovered : List OpcodeCertificate :=
  aggregateCovered.filter (fun certificate => certificate.team == .b)

theorem aggregate_coverage_exact :
    aggregateCovered.length = 46 ∧
      aggregateCovered.map (·.manifestId) = List.range 46 ∧
      (aggregateCovered.map (·.mnemonic)).Nodup := by
  decide

theorem team_a_coverage_exact :
    teamACovered.length = 24 ∧
      (teamACovered.map (·.manifestId)).Nodup ∧
      teamACovered.all
        (fun certificate =>
          certificate.airEvidence == .exactGeneratedLocalProgram) := by
  decide

theorem team_b_coverage_exact :
    teamBCovered.length = 22 ∧
      (teamBCovered.map (·.manifestId)).Nodup ∧
      teamBCovered.all
        (fun certificate =>
          certificate.airEvidence == .reviewedFamilyCapsule) := by
  decide

end RiscvRefinement.Coverage
