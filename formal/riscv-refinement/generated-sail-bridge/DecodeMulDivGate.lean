import DecodeMulDivState

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000

open Sail

namespace LeanRV32IM.Functions

/-!
The generated decoder reaches the M family through one of two feature gates.
Keeping the disabled continuation opaque is essential: once M is enabled the
continuation is unreachable, and elaborating it expands the remainder of the
entire generated decoder.
-/

noncomputable def generatedMultiplyMTypeBody
    (decoded : instruction)
    (fallback : SailM instruction) : SailM instruction := do
  let mEnabled ← currentlyEnabled extension.Ext_M
  let zmmulEnabled ← currentlyEnabled extension.Ext_Zmmul
  match (←
    if mEnabled || zmmulEnabled then
      pure (some decoded)
    else
      pure none) with
  | some result => pure result
  | none => fallback

noncomputable def generatedDivisionMTypeBody
    (decoded : instruction)
    (fallback : SailM instruction) : SailM instruction := do
  let mEnabled ← currentlyEnabled extension.Ext_M
  match (←
    if mEnabled then
      pure (some decoded)
    else
      pure none) with
  | some result => pure result
  | none => fallback

noncomputable def generatedMultiplyMTypeGate
    (decoded : instruction)
    (fallback : SailM instruction) : SailM instruction := do
  let _ ← generatedUtypeDecodePreamble
  generatedMultiplyMTypeBody decoded fallback

noncomputable def generatedDivisionMTypeGate
    (decoded : instruction)
    (fallback : SailM instruction) : SailM instruction := do
  let _ ← generatedUtypeDecodePreamble
  generatedDivisionMTypeBody decoded fallback

/-!
Pre-simplification factoring lemmas.  They rewrite the live gate to an opaque
name before the simplifier visits the disabled continuation.
-/

theorem generatedMultiplyMTypeGate_factor
    (decoded : instruction)
    (fallback : SailM instruction) :
    (do
      let pauseEnabled ← currentlyEnabled extension.Ext_Zihintpause
      let landingPadEnabled ← currentlyEnabled extension.Ext_Zicfilp
      let mEnabled ← currentlyEnabled extension.Ext_M
      let zmmulEnabled ← currentlyEnabled extension.Ext_Zmmul
      match (←
        if mEnabled || zmmulEnabled then
          pure (some decoded)
        else
          pure none) with
      | some result => pure result
      | none => fallback) =
      generatedMultiplyMTypeGate decoded fallback := by
  simp only [
    generatedMultiplyMTypeGate,
    generatedMultiplyMTypeBody,
    generatedUtypeDecodePreamble,
    bind_assoc,
    pure_bind,
  ]

theorem generatedDivisionMTypeGate_factor
    (decoded : instruction)
    (fallback : SailM instruction) :
    (do
      let pauseEnabled ← currentlyEnabled extension.Ext_Zihintpause
      let landingPadEnabled ← currentlyEnabled extension.Ext_Zicfilp
      let mEnabled ← currentlyEnabled extension.Ext_M
      match (←
        if mEnabled then
          pure (some decoded)
        else
          pure none) with
      | some result => pure result
      | none => fallback) =
      generatedDivisionMTypeGate decoded fallback := by
  simp only [
    generatedDivisionMTypeGate,
    generatedDivisionMTypeBody,
    generatedUtypeDecodePreamble,
    bind_assoc,
    pure_bind,
  ]

theorem generatedMultiplyMTypeGate_exact_at
    (decoded : instruction)
    (fallback : SailM instruction)
    (initial : GeneratedState)
    (misaValue : BitVec 32)
    (mseccfgValue : BitVec 64)
    (multiplyEnabled : hartSupports extension.Ext_M = true)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled : hartSupports extension.Ext_Zicfilp = false)
    (misaBinding :
      initial.regs.get? Register.misa = some misaValue)
    (misaMEnabled : _get_Misa_M misaValue = 1#1)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding :
      initial.regs.get? Register.mseccfg = some mseccfgValue) :
    generatedMultiplyMTypeGate decoded fallback initial =
      .ok decoded initial := by
  simp only [
    generatedMultiplyMTypeGate,
    generatedMultiplyMTypeBody,
    generatedUtypeDecodePreamble_exact_at
      initial mseccfgValue pauseDisabled landingPadDisabled
      privilegeBinding mseccfgBinding,
    currentlyEnabled_m_enabled_at
      initial misaValue multiplyEnabled misaBinding misaMEnabled,
    currentlyEnabled_zmmul_enabled_at
      initial misaValue multiplyEnabled misaBinding misaMEnabled,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
    Bool.true_or,
    eq_self,
    if_true,
    pure_bind,
  ]

theorem generatedDivisionMTypeGate_exact_at
    (decoded : instruction)
    (fallback : SailM instruction)
    (initial : GeneratedState)
    (misaValue : BitVec 32)
    (mseccfgValue : BitVec 64)
    (multiplyEnabled : hartSupports extension.Ext_M = true)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled : hartSupports extension.Ext_Zicfilp = false)
    (misaBinding :
      initial.regs.get? Register.misa = some misaValue)
    (misaMEnabled : _get_Misa_M misaValue = 1#1)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding :
      initial.regs.get? Register.mseccfg = some mseccfgValue) :
    generatedDivisionMTypeGate decoded fallback initial =
      .ok decoded initial := by
  simp only [
    generatedDivisionMTypeGate,
    generatedDivisionMTypeBody,
    generatedUtypeDecodePreamble_exact_at
      initial mseccfgValue pauseDisabled landingPadDisabled
      privilegeBinding mseccfgBinding,
    currentlyEnabled_m_enabled_at
      initial misaValue multiplyEnabled misaBinding misaMEnabled,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
    eq_self,
    if_true,
    pure_bind,
  ]

end LeanRV32IM.Functions
