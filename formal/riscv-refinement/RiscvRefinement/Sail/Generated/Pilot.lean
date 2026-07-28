-- GENERATED FILE. DO NOT EDIT.
-- Generator: scripts/riscv_refinement.py
-- Regenerate: python3 scripts/riscv_refinement.py generate
-- Source: exact-profile Sail 0.20.2 theorem-backend definition slices.
-- Boundary: reviewed normalized capsule; no generated-monad theorem yet.

import RiscvRefinement.Common

namespace RiscvRefinement.Sail.Generated

open RiscvRefinement

def executeUtypeDefinitionDigest : String :=
  "f746995b8c903140529bb742379c295bee8d95a02de2d730990dc77fe1cacf1c"

def executeItypeDefinitionDigest : String :=
  "1d014d14c56ab01dc511fc36c8c6ee4dea56a63708257b8a5df451e7c6f6b17d"

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
