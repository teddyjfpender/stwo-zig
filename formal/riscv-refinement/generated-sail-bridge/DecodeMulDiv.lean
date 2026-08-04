import DecodeMulDivMul
import DecodeMulDivMulh
import DecodeMulDivMulhsu
import DecodeMulDivMulhu
import DecodeMulDivDiv
import DecodeMulDivDivu
import DecodeMulDivRem
import DecodeMulDivRemu

open Sail

namespace LeanRV32IM.Functions

theorem decode_admitted_mtype_certificate_at
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5)
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
    GeneratedDecodeCertificateAt
      (encodeAdmittedMType op rs2 rs1 rd)
      (admittedMTypeInstruction op rs2 rs1 rd)
      initial := by
  cases op
  · exact decode_mul_certificate_at rs2 rs1 rd initial
      misaValue mseccfgValue multiplyEnabled pauseDisabled
      landingPadDisabled misaBinding misaMEnabled privilegeBinding
      mseccfgBinding
  · exact decode_mulh_certificate_at rs2 rs1 rd initial
      misaValue mseccfgValue multiplyEnabled pauseDisabled
      landingPadDisabled misaBinding misaMEnabled privilegeBinding
      mseccfgBinding
  · exact decode_mulhsu_certificate_at rs2 rs1 rd initial
      misaValue mseccfgValue multiplyEnabled pauseDisabled
      landingPadDisabled misaBinding misaMEnabled privilegeBinding
      mseccfgBinding
  · exact decode_mulhu_certificate_at rs2 rs1 rd initial
      misaValue mseccfgValue multiplyEnabled pauseDisabled
      landingPadDisabled misaBinding misaMEnabled privilegeBinding
      mseccfgBinding
  · exact decode_div_certificate_at rs2 rs1 rd initial
      misaValue mseccfgValue multiplyEnabled pauseDisabled
      landingPadDisabled misaBinding misaMEnabled privilegeBinding
      mseccfgBinding
  · exact decode_divu_certificate_at rs2 rs1 rd initial
      misaValue mseccfgValue multiplyEnabled pauseDisabled
      landingPadDisabled misaBinding misaMEnabled privilegeBinding
      mseccfgBinding
  · exact decode_rem_certificate_at rs2 rs1 rd initial
      misaValue mseccfgValue multiplyEnabled pauseDisabled
      landingPadDisabled misaBinding misaMEnabled privilegeBinding
      mseccfgBinding
  · exact decode_remu_certificate_at rs2 rs1 rd initial
      misaValue mseccfgValue multiplyEnabled pauseDisabled
      landingPadDisabled misaBinding misaMEnabled privilegeBinding
      mseccfgBinding

theorem decode_admitted_mtype_exact
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5)
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
    ext_decode (encodeAdmittedMType op rs2 rs1 rd) initial =
      .ok (admittedMTypeInstruction op rs2 rs1 rd) initial :=
  (decode_admitted_mtype_certificate_at op rs2 rs1 rd initial
    misaValue mseccfgValue multiplyEnabled pauseDisabled
    landingPadDisabled misaBinding misaMEnabled privilegeBinding
    mseccfgBinding).exactOutcome

end LeanRV32IM.Functions
