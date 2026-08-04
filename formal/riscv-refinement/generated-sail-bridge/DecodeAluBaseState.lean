import DecodeAluBase

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000

open Sail

namespace LeanRV32IM.Functions

/-!
The expensive generated base-decoder normalization is compiled in
`DecodeAluBase`.  This small module keeps the state-indexed, constructive
certificate separate so changes to the bound-state contract do not force the
decoder core to elaborate again.
-/

/-- Constructive generated decode for one admitted base R-type instruction. -/
theorem decode_admitted_base_rtype_certificate_at
    (op : AdmittedBaseRTypeOp)
    (rs2 rs1 rd : BitVec 5)
    (initial : GeneratedState)
    (mseccfgValue : BitVec 64)
    (ntlDisabled : hartSupports extension.Ext_Zihintntl = false)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled : hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding :
      initial.regs.get? Register.mseccfg = some mseccfgValue) :
    GeneratedDecodeCertificateAt
      (encodeAdmittedBaseRType op rs2 rs1 rd)
      (admittedBaseRTypeInstruction op rs2 rs1 rd)
      initial := by
  constructor
  rw [ext_decode_admitted_base_rtype_branch
    op rs2 rs1 rd ntlDisabled pauseDisabled]
  simp [
    generatedUtypeDecodeProgram,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
    generatedUtypeDecodePreamble_exact_at
      initial mseccfgValue pauseDisabled landingPadDisabled
      privilegeBinding mseccfgBinding,
  ]

end LeanRV32IM.Functions
