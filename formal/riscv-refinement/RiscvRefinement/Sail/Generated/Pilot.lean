-- GENERATED FILE. DO NOT EDIT.
-- Generator: scripts/riscv_refinement.py
-- Regenerate: python3 scripts/riscv_refinement.py generate
-- Source: exact-profile Sail 0.20.2 theorem-backend definition slices.
-- Binding: fail-closed generated-definition AST translation receipt.
-- Boundary: checked execute-clause translation/input binding. Normalized
-- retirement composition remains LUI/ADDI-only; no full-step theorem or
-- publication binding is claimed.

import RiscvRefinement.Common

namespace RiscvRefinement.Sail.Generated

open RiscvRefinement

def executeUtypeDefinitionDigest : String :=
  "f746995b8c903140529bb742379c295bee8d95a02de2d730990dc77fe1cacf1c"

def executeItypeDefinitionDigest : String :=
  "1d014d14c56ab01dc511fc36c8c6ee4dea56a63708257b8a5df451e7c6f6b17d"

def executeRtypeDefinitionDigest : String :=
  "01359d58d0543ce431b7315caf9961ea80329de2f017f2ea6cb205a7149cd628"

def translationReceiptDigest : String :=
  "008459d979422ef9e471897bfc0436e33b1fd7c7c5af77c2211be74a2280fa25"

def executeUtypeAstDigest : String :=
  "3b5919cc27dc576d206d41137efd031cb23979f46557d94282cfb05f83b095dc"

def executeItypeAstDigest : String :=
  "048f9d35651afaff301d78af5f6f7ccfb94ac9bf7d16d42af644411556c6e0e5"

def executeRtypeAstDigest : String :=
  "f170c513e07496f203d74207e9b70c4f0587805feacdd49d9fdd17a1b5381d92"

def inputBoundTeamASelectors : List String := [
  "LUI", "AUIPC",
  "ADDI", "XORI", "ORI", "ANDI", "SLTI", "SLTIU",
  "ADD", "SUB", "XOR", "OR", "AND", "SLT", "SLTU",
  "BEQ", "BNE", "BLT", "BGE", "BLTU", "BGEU",
  "JAL", "JALR", "FENCE"
]

def normalizedRetirementSelectors : List String := ["LUI", "ADDI"]

def generatedFullStepFramingEstablished : Bool := false

def publicationBindingEstablished : Bool := false

def executeLuiValue (imm : BitVec 20) : Word :=
  BitVec.signExtend 32 (imm.append (BitVec.ofNat 12 0))

def executeAddiValue (source : Word) (imm : BitVec 12) : Word :=
  source + BitVec.signExtend 32 imm

def executeLui
    (pc : Word)
    (rd : RegisterIndex)
    (imm : BitVec 20) :
    Retirement where
  nextPc := nextPc pc
  write := architecturalWrite rd (executeLuiValue imm)

def executeAddi
    (pc : Word)
    (source : Word)
    (rd : RegisterIndex)
    (imm : BitVec 12) :
    Retirement where
  nextPc := nextPc pc
  write := architecturalWrite rd (executeAddiValue source imm)

end RiscvRefinement.Sail.Generated
