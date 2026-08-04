import DecodeMulDivEncoding

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000

open Sail

namespace LeanRV32IM.Functions

theorem currentlyEnabled_m_enabled_at
    (initial : GeneratedState)
    (misaValue : BitVec 32)
    (multiplyEnabled : hartSupports extension.Ext_M = true)
    (misaBinding :
      initial.regs.get? Register.misa = some misaValue)
    (misaMEnabled : _get_Misa_M misaValue = 1#1) :
    currentlyEnabled extension.Ext_M initial =
      .ok true initial := by
  simp [
    currentlyEnabled,
    PreSail.readReg,
    multiplyEnabled,
    misaBinding,
    misaMEnabled,
    bind,
    EStateM.bind,
    EStateM.map,
    pure,
    EStateM.pure,
    MonadState.get,
    getThe,
    MonadStateOf.get,
    EStateM.get,
  ]

theorem currentlyEnabled_zicfilp_disabled_at
    (initial : GeneratedState)
    (mseccfgValue : BitVec 64)
    (landingPadDisabled : hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding :
      initial.regs.get? Register.mseccfg = some mseccfgValue) :
    currentlyEnabled extension.Ext_Zicfilp initial =
      .ok false initial := by
  simp [
    currentlyEnabled,
    get_xLPE,
    PreSail.readReg,
    landingPadDisabled,
    privilegeBinding,
    mseccfgBinding,
    bind,
    EStateM.bind,
    EStateM.map,
    pure,
    EStateM.pure,
    MonadState.get,
    getThe,
    MonadStateOf.get,
    EStateM.get,
  ]

theorem currentlyEnabled_zmmul_enabled_at
    (initial : GeneratedState)
    (misaValue : BitVec 32)
    (multiplyEnabled : hartSupports extension.Ext_M = true)
    (misaBinding :
      initial.regs.get? Register.misa = some misaValue)
    (misaMEnabled : _get_Misa_M misaValue = 1#1) :
    currentlyEnabled extension.Ext_Zmmul initial =
      .ok true initial := by
  simp [
    currentlyEnabled,
    currentlyEnabled_m_enabled_at
      initial misaValue multiplyEnabled misaBinding misaMEnabled,
    bind,
    EStateM.bind,
    EStateM.map,
    pure,
    EStateM.pure,
  ]

end LeanRV32IM.Functions
