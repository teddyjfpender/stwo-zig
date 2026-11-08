"""Lean source template for the generated LUI AIR IR v2 round trip."""

AIR_PROGRAM_LEAN_TEMPLATE = """\
-- GENERATED FILE. DO NOT EDIT.
-- Generator: scripts/riscv_refinement.py
-- Regenerate: python3 scripts/riscv_refinement.py generate
-- Binding: exact canonical production AIR IR v2 for LUI.

import RiscvRefinement.Air

namespace RiscvRefinement.Air.Generated

open RiscvRefinement

def luiProgramJson : String :=
  __LUI_PROGRAM_JSON__

def luiProgramDecodes : Bool :=
  match ConstraintProgram.decodeCanonical luiProgramJson with
  | .ok _ => true
  | .error _ => false

#guard luiProgramDecodes

private def m31 (value : Nat) : M31 :=
  M31.reduce value

def luiInactiveRow : Array M31 :=
  Array.replicate 18 0

def luiActiveRow : Array M31 :=
  #[
    m31 1, m31 8, m31 4096,
    m31 7, m31 0, m31 0, m31 0, m31 0, m31 0,
    m31 0, m31 192, m31 171, m31 222,
    m31 12, m31 171, m31 222,
    m31 1, m31 1840700269
  ]

def luiInactiveRowIsRejected : Bool :=
  match ConstraintProgram.decodeCanonical luiProgramJson with
  | .error _ => false
  | .ok program =>
    match program.eval luiInactiveRow with
    | .error _ => false
    | .ok evaluation =>
          !evaluation.rowActive &&
          !evaluation.constraintsHold &&
          evaluation.fixedLookupsHold &&
          evaluation.liveLookups.isEmpty

#guard luiInactiveRowIsRejected

def luiActiveRowEvaluates : Bool :=
  match ConstraintProgram.decodeCanonical luiProgramJson with
  | .error _ => false
  | .ok program =>
    match program.eval luiActiveRow with
    | .error _ => false
    | .ok evaluation =>
          evaluation.activeSelectorsAccepted &&
          evaluation.constraintsHold &&
          evaluation.fixedLookupsHold &&
          evaluation.liveLookups.size == 7 &&
          evaluation.projection.nextPc.toNat == 4100 &&
          evaluation.projection.programEvent.tuple.map M31.toNat ==
            #[4096, 35, 7, 912060, 0]

#guard luiActiveRowEvaluates

end RiscvRefinement.Air.Generated
"""
