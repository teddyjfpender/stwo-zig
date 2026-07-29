-- GENERATED FILE. DO NOT EDIT.
-- Generator: scripts/riscv_refinement.py
-- Regenerate: python3 scripts/riscv_refinement.py generate
-- Source: exact-profile Sail 0.20.2 theorem-backend definition slices.
-- Binding: fail-closed generated-definition AST translation receipt.
-- Boundary: checked execute-clause normalization; no step-monad theorem yet.

import RiscvRefinement.Common

namespace RiscvRefinement.Sail.Generated

open RiscvRefinement

def executeUtypeDefinitionDigest : String :=
  "f746995b8c903140529bb742379c295bee8d95a02de2d730990dc77fe1cacf1c"

def executeItypeDefinitionDigest : String :=
  "1d014d14c56ab01dc511fc36c8c6ee4dea56a63708257b8a5df451e7c6f6b17d"

def translationReceiptDigest : String :=
  "708ed95872d6b32a6b80806af94fd8e4210cdb280150453688a2f9315b2f22e2"

def executeUtypeAstDigest : String :=
  "3b5919cc27dc576d206d41137efd031cb23979f46557d94282cfb05f83b095dc"

def executeItypeAstDigest : String :=
  "1d44a5fef2e5a4cb65dc4f66da1f6b08d37b1f4fd9d043205b91e28e8fca7fe6"

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
