import DecodeAluSlli
import DecodeAluSrli
import DecodeAluSrai

open Sail

namespace LeanRV32IM.Functions

theorem decode_admitted_shift_itype_certificate
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false) :
    GeneratedDecodeCertificate
      (encodeAdmittedShiftIType op shamt rs1 rd)
      (admittedShiftITypeInstruction op shamt rs1 rd) := by
  cases op
  · exact decode_admitted_slli_certificate
      shamt rs1 rd pauseDisabled
  · exact decode_admitted_srli_certificate
      shamt rs1 rd pauseDisabled
  · exact decode_admitted_srai_certificate
      shamt rs1 rd pauseDisabled

theorem decode_admitted_shift_itype_certificate_at
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5)
    (initial : GeneratedState)
    (mseccfgValue : BitVec 64)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled : hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding :
      initial.regs.get? Register.mseccfg = some mseccfgValue) :
    GeneratedDecodeCertificateAt
      (encodeAdmittedShiftIType op shamt rs1 rd)
      (admittedShiftITypeInstruction op shamt rs1 rd)
      initial := by
  cases op
  · exact decode_admitted_slli_certificate_at shamt rs1 rd initial
      mseccfgValue pauseDisabled landingPadDisabled
      privilegeBinding mseccfgBinding
  · exact decode_admitted_srli_certificate_at shamt rs1 rd initial
      mseccfgValue pauseDisabled landingPadDisabled
      privilegeBinding mseccfgBinding
  · exact decode_admitted_srai_certificate_at shamt rs1 rd initial
      mseccfgValue pauseDisabled landingPadDisabled
      privilegeBinding mseccfgBinding

end LeanRV32IM.Functions
