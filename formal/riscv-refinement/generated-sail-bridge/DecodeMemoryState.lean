import DecodeMemory

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000

open Sail

namespace LeanRV32IM.Functions

/-!
State-indexed, constructive decoder certificates for the admitted RV32I load
and store encodings.  These close exact decode success from concrete profile
bindings; they do not accept a generated decoder outcome as a premise.
-/

private theorem generatedMemoryDecodeProgram_exact_at
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

theorem decode_load_memory_certificate_at
    (funct3 : BitVec 3) (imm : BitVec 12) (rs1 rd : BitVec 5)
    (valid :
      valid_load_encdec
        (width_enc_backwards (Sail.BitVec.extractLsb funct3 1 0))
        (bool_bit_backwards (Sail.BitVec.extractLsb funct3 2 2)) = true)
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
      (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd)
      (decodedLoadMemory funct3 imm rs1 rd) initial := by
  constructor
  rw [ext_decode_load_memory funct3 imm rs1 rd valid]
  exact generatedMemoryDecodeProgram_exact_at
    _ initial mseccfgValue pauseDisabled landingPadDisabled
    privilegeBinding mseccfgBinding

theorem decode_store_memory_certificate_at
    (funct3 : BitVec 3) (imm : BitVec 12) (rs2 rs1 : BitVec 5)
    (zeroBit :
      Sail.BitVec.extractLsb funct3 2 2 = (0#1 : BitVec 1))
    (widthFits :
      ((width_enc_backwards
        (Sail.BitVec.extractLsb funct3 1 0) ≤b xlen_bytes) : Bool) = true)
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
      (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3)
      (decodedStoreMemory funct3 imm rs2 rs1) initial := by
  constructor
  rw [ext_decode_store_memory funct3 imm rs2 rs1 zeroBit widthFits]
  exact generatedMemoryDecodeProgram_exact_at
    _ initial mseccfgValue pauseDisabled landingPadDisabled
    privilegeBinding mseccfgBinding

theorem decode_lb_memory_certificate_at
    (imm : BitVec 12) (rs1 rd : BitVec 5)
    (initial : GeneratedState) (mseccfgValue : BitVec 64)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled : hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding : initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding : initial.regs.get? Register.mseccfg = some mseccfgValue) :
    GeneratedDecodeCertificateAt
      (RiscvRefinement.Decode.encodeLb imm rs1 rd)
      (decodedLbMemory imm rs1 rd) initial := by
  simpa [
    RiscvRefinement.Decode.encodeLb,
    RiscvRefinement.Decode.funct3Lb,
    decodedLoadMemory,
    decodedLbMemory,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using decode_load_memory_certificate_at
    RiscvRefinement.Decode.funct3Lb imm rs1 rd (by decide)
    initial mseccfgValue pauseDisabled landingPadDisabled
    privilegeBinding mseccfgBinding

theorem decode_lh_memory_certificate_at
    (imm : BitVec 12) (rs1 rd : BitVec 5)
    (initial : GeneratedState) (mseccfgValue : BitVec 64)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled : hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding : initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding : initial.regs.get? Register.mseccfg = some mseccfgValue) :
    GeneratedDecodeCertificateAt
      (RiscvRefinement.Decode.encodeLh imm rs1 rd)
      (decodedLhMemory imm rs1 rd) initial := by
  simpa [
    RiscvRefinement.Decode.encodeLh,
    RiscvRefinement.Decode.funct3Lh,
    decodedLoadMemory,
    decodedLhMemory,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using decode_load_memory_certificate_at
    RiscvRefinement.Decode.funct3Lh imm rs1 rd (by decide)
    initial mseccfgValue pauseDisabled landingPadDisabled
    privilegeBinding mseccfgBinding

theorem decode_lw_memory_certificate_at
    (imm : BitVec 12) (rs1 rd : BitVec 5)
    (initial : GeneratedState) (mseccfgValue : BitVec 64)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled : hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding : initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding : initial.regs.get? Register.mseccfg = some mseccfgValue) :
    GeneratedDecodeCertificateAt
      (RiscvRefinement.Decode.encodeLw imm rs1 rd)
      (decodedLwMemory imm rs1 rd) initial := by
  simpa [
    RiscvRefinement.Decode.encodeLw,
    RiscvRefinement.Decode.funct3Lw,
    decodedLoadMemory,
    decodedLwMemory,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using decode_load_memory_certificate_at
    RiscvRefinement.Decode.funct3Lw imm rs1 rd (by decide)
    initial mseccfgValue pauseDisabled landingPadDisabled
    privilegeBinding mseccfgBinding

theorem decode_lbu_memory_certificate_at
    (imm : BitVec 12) (rs1 rd : BitVec 5)
    (initial : GeneratedState) (mseccfgValue : BitVec 64)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled : hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding : initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding : initial.regs.get? Register.mseccfg = some mseccfgValue) :
    GeneratedDecodeCertificateAt
      (RiscvRefinement.Decode.encodeLbu imm rs1 rd)
      (decodedLbuMemory imm rs1 rd) initial := by
  simpa [
    RiscvRefinement.Decode.encodeLbu,
    RiscvRefinement.Decode.funct3Lbu,
    decodedLoadMemory,
    decodedLbuMemory,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using decode_load_memory_certificate_at
    RiscvRefinement.Decode.funct3Lbu imm rs1 rd (by decide)
    initial mseccfgValue pauseDisabled landingPadDisabled
    privilegeBinding mseccfgBinding

theorem decode_lhu_memory_certificate_at
    (imm : BitVec 12) (rs1 rd : BitVec 5)
    (initial : GeneratedState) (mseccfgValue : BitVec 64)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled : hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding : initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding : initial.regs.get? Register.mseccfg = some mseccfgValue) :
    GeneratedDecodeCertificateAt
      (RiscvRefinement.Decode.encodeLhu imm rs1 rd)
      (decodedLhuMemory imm rs1 rd) initial := by
  simpa [
    RiscvRefinement.Decode.encodeLhu,
    RiscvRefinement.Decode.funct3Lhu,
    decodedLoadMemory,
    decodedLhuMemory,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using decode_load_memory_certificate_at
    RiscvRefinement.Decode.funct3Lhu imm rs1 rd (by decide)
    initial mseccfgValue pauseDisabled landingPadDisabled
    privilegeBinding mseccfgBinding

theorem decode_sb_memory_certificate_at
    (imm : BitVec 12) (rs2 rs1 : BitVec 5)
    (initial : GeneratedState) (mseccfgValue : BitVec 64)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled : hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding : initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding : initial.regs.get? Register.mseccfg = some mseccfgValue) :
    GeneratedDecodeCertificateAt
      (RiscvRefinement.Decode.encodeSb imm rs2 rs1)
      (decodedSbMemory imm rs2 rs1) initial := by
  simpa [
    RiscvRefinement.Decode.encodeSb,
    RiscvRefinement.Decode.funct3Sb,
    decodedStoreMemory,
    decodedSbMemory,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    xlen_bytes,
  ] using decode_store_memory_certificate_at
    RiscvRefinement.Decode.funct3Sb imm rs2 rs1 (by decide) (by decide)
    initial mseccfgValue pauseDisabled landingPadDisabled
    privilegeBinding mseccfgBinding

theorem decode_sh_memory_certificate_at
    (imm : BitVec 12) (rs2 rs1 : BitVec 5)
    (initial : GeneratedState) (mseccfgValue : BitVec 64)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled : hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding : initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding : initial.regs.get? Register.mseccfg = some mseccfgValue) :
    GeneratedDecodeCertificateAt
      (RiscvRefinement.Decode.encodeSh imm rs2 rs1)
      (decodedShMemory imm rs2 rs1) initial := by
  simpa [
    RiscvRefinement.Decode.encodeSh,
    RiscvRefinement.Decode.funct3Sh,
    decodedStoreMemory,
    decodedShMemory,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    xlen_bytes,
  ] using decode_store_memory_certificate_at
    RiscvRefinement.Decode.funct3Sh imm rs2 rs1 (by decide) (by decide)
    initial mseccfgValue pauseDisabled landingPadDisabled
    privilegeBinding mseccfgBinding

theorem decode_sw_memory_certificate_at
    (imm : BitVec 12) (rs2 rs1 : BitVec 5)
    (initial : GeneratedState) (mseccfgValue : BitVec 64)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled : hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding : initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding : initial.regs.get? Register.mseccfg = some mseccfgValue) :
    GeneratedDecodeCertificateAt
      (RiscvRefinement.Decode.encodeSw imm rs2 rs1)
      (decodedSwMemory imm rs2 rs1) initial := by
  simpa [
    RiscvRefinement.Decode.encodeSw,
    RiscvRefinement.Decode.funct3Sw,
    decodedStoreMemory,
    decodedSwMemory,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    xlen_bytes,
  ] using decode_store_memory_certificate_at
    RiscvRefinement.Decode.funct3Sw imm rs2 rs1 (by decide) (by decide)
    initial mseccfgValue pauseDisabled landingPadDisabled
    privilegeBinding mseccfgBinding

end LeanRV32IM.Functions
