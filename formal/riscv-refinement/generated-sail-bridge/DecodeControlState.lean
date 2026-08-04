import DecodeControl

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000

open Sail

namespace LeanRV32IM.Functions

/-!
State-indexed, constructive decoder certificates for the admitted RV32I
control encodings.  The generated decoder eagerly evaluates its PAUSE and
landing-pad prefix, so exact success is tied to the concrete privilege and
`mseccfg` bindings instead of being stated as an all-state implication.
-/

private theorem generatedControlDecodeProgram_exact_at
    (decoded : instruction)
    (initial : GeneratedState)
    (mseccfgValue : BitVec 64)
    (pauseDisabled :
      hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled :
      hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding :
      initial.regs.get? Register.mseccfg = some mseccfgValue) :
    generatedUtypeDecodeProgram decoded initial =
      .ok decoded initial := by
  simp [
    generatedUtypeDecodeProgram,
    bind,
    EStateM.bind,
    EStateM.map,
    pure,
    EStateM.pure,
    generatedUtypeDecodePreamble_exact_at
      initial mseccfgValue pauseDisabled landingPadDisabled
      privilegeBinding mseccfgBinding,
  ]

theorem decode_auipc_control_certificate_at
    (imm : BitVec 20) (rd : BitVec 5)
    (initial : GeneratedState) (mseccfgValue : BitVec 64)
    (pauseDisabled :
      hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled :
      hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding :
      initial.regs.get? Register.mseccfg = some mseccfgValue) :
    GeneratedDecodeCertificateAt
      (encodeAuipcControl imm rd) (decodedAuipcControl imm rd) initial := by
  constructor
  rw [ext_decode_auipc_control imm rd landingPadDisabled]
  exact generatedControlDecodeProgram_exact_at
    _ initial mseccfgValue pauseDisabled landingPadDisabled
    privilegeBinding mseccfgBinding

theorem decode_jal_control_certificate_at
    (imm : BitVec 20) (rd : BitVec 5)
    (initial : GeneratedState) (mseccfgValue : BitVec 64)
    (pauseDisabled :
      hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled :
      hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding :
      initial.regs.get? Register.mseccfg = some mseccfgValue) :
    GeneratedDecodeCertificateAt
      (encodeJalControl imm rd) (decodedJalControl imm rd) initial := by
  constructor
  rw [ext_decode_jal_control imm rd]
  exact generatedControlDecodeProgram_exact_at
    _ initial mseccfgValue pauseDisabled landingPadDisabled
    privilegeBinding mseccfgBinding

theorem decode_jalr_control_certificate_at
    (imm : BitVec 12) (rs1 rd : BitVec 5)
    (initial : GeneratedState) (mseccfgValue : BitVec 64)
    (pauseDisabled :
      hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled :
      hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding :
      initial.regs.get? Register.mseccfg = some mseccfgValue) :
    GeneratedDecodeCertificateAt
      (encodeJalrControl imm rs1 rd)
      (decodedJalrControl imm rs1 rd) initial := by
  constructor
  rw [ext_decode_jalr_control imm rs1 rd]
  exact generatedControlDecodeProgram_exact_at
    _ initial mseccfgValue pauseDisabled landingPadDisabled
    privilegeBinding mseccfgBinding

theorem decode_branch_control_certificate_at
    (kind : RiscvRefinement.Decode.BranchKind)
    (imm : BitVec 12) (rs2 rs1 : BitVec 5)
    (initial : GeneratedState) (mseccfgValue : BitVec 64)
    (pauseDisabled :
      hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled :
      hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding :
      initial.regs.get? Register.mseccfg = some mseccfgValue) :
    GeneratedDecodeCertificateAt
      (encodeBranchControl kind imm rs2 rs1)
      (decodedBranchControl kind imm rs2 rs1) initial := by
  constructor
  rw [ext_decode_branch_control kind imm rs2 rs1]
  exact generatedControlDecodeProgram_exact_at
    _ initial mseccfgValue pauseDisabled landingPadDisabled
    privilegeBinding mseccfgBinding

end LeanRV32IM.Functions
