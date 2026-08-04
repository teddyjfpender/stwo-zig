import DecodeMulDivGate

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000

open Sail

namespace LeanRV32IM.Functions

private theorem ext_decode_div_gate
    (rs2 rs1 rd : BitVec 5) :
    ∃ fallback : SailM instruction,
      ext_decode (encodeAdmittedMType .div rs2 rs1 rd) =
        generatedDivisionMTypeGate
          (admittedMTypeInstruction .div rs2 rs1 rd) fallback := by
  rw [ext_decode.eq_1, encdec_backwards.eq_def]
  simp only [
    encodeAdmittedMType_not_zicbop,
    Bool.false_eq_true,
    if_false,
    pure_bind,
  ]
  rw [
    generatedNtlProbeMType_raw,
    generatedNtlProbeMType_dead,
  ]
  rw [
    encodeAdmittedMType_not_pause,
    encodeAdmittedMType_not_lpad,
    encodeAdmittedMType_not_utype,
    encodeAdmittedMType_not_jal,
    encodeAdmittedMType_not_jalr,
    encodeAdmittedMType_not_branch,
    encodeAdmittedMType_not_itype,
    encodeAdmittedMType_not_load,
    encodeAdmittedMType_not_store,
    encodeAdmittedMType_not_itypew,
    encodeAdmittedMType_not_rtypew,
    encodeAdmittedMType_not_fence,
    encodeAdmittedMType_not_sfence,
    encodeAdmittedMType_not_atomic,
    encodeAdmittedMType_is_rtype,
    encodeAdmittedMType_not_base_funct7,
    encodeAdmittedMType_not_alt_funct7,
    encodeAdmittedMType_is_muldiv_funct7,
    encodeAdmittedDivMType_not_multiply,
    encodeAdmittedDivMType_unsignedBit,
    encodeAdmittedDivMType_class,
    mtypeClass2_is_div,
    mtypeClass2_not_rem,
    mtypeUnsignedBit0_matches,
    mtypeUnsignedBit0_value,
    encodeAdmittedMType_not_fence_tso,
    encodeAdmittedMType_not_ecall,
    encodeAdmittedMType_not_mret,
    encodeAdmittedMType_not_sret,
    encodeAdmittedMType_not_ebreak,
    encodeAdmittedMType_not_wfi,
  ]
  simp only [
    encodeAdmittedMType_not_pause,
    encodeAdmittedMType_not_fence_tso,
    encodeAdmittedMType_not_ecall,
    encodeAdmittedMType_not_mret,
    encodeAdmittedMType_not_sret,
    encodeAdmittedMType_not_ebreak,
    encodeAdmittedMType_not_wfi,
    encodeAdmittedMType_ne_fence_tso,
    encodeAdmittedMType_ne_ecall,
    encodeAdmittedMType_ne_mret,
    encodeAdmittedMType_ne_sret,
    encodeAdmittedMType_ne_ebreak,
    encodeAdmittedMType_ne_wfi,
    encodeAdmittedMType_not_lpad,
    encodeAdmittedMType_not_utype,
    encodeAdmittedMType_not_jal,
    encodeAdmittedMType_not_jalr,
    encodeAdmittedMType_not_branch,
    encodeAdmittedMType_not_itype,
    encodeAdmittedMType_not_load,
    encodeAdmittedMType_not_store,
    encodeAdmittedMType_not_itypew,
    encodeAdmittedMType_not_rtypew,
    encodeAdmittedMType_not_fence,
    encodeAdmittedMType_not_sfence,
    encodeAdmittedMType_not_atomic,
    encodeAdmittedMType_is_rtype,
    encodeAdmittedMType_opcode,
    encodeAdmittedMType_not_base_funct7,
    encodeAdmittedMType_not_alt_funct7,
    encodeAdmittedMType_is_muldiv_funct7,
    encodeAdmittedMType_funct7,
    encodeAdmittedMType_funct3,
    encodeAdmittedMType_rs2,
    encodeAdmittedMType_rs1,
    encodeAdmittedMType_rd,
    encdec_reg_backwards_matches_all_alu,
    encdec_reg_backwards_all_alu,
    encdec_uop_backwards_matches,
    encdec_iop_backwards_matches,
    encdec_mul_op_backwards_matches,
    encdec_mul_op_backwards,
    bool_bit_backwards_matches,
    bool_bit_backwards,
    admittedMTypeFunct3,
    admittedMTypeInstruction,
    RiscvRefinement.Decode.funct3Mul,
    RiscvRefinement.Decode.funct3Mulh,
    RiscvRefinement.Decode.funct3Mulhsu,
    RiscvRefinement.Decode.funct3Mulhu,
    RiscvRefinement.Decode.funct3Div,
    RiscvRefinement.Decode.funct3Divu,
    RiscvRefinement.Decode.funct3Rem,
    RiscvRefinement.Decode.funct3Remu,
    Bool.false_and,
    Bool.and_false,
    Bool.true_and,
    Bool.and_true,
    Bool.false_eq_true,
    eq_self,
    if_false,
    if_true,
    pure_bind,
    bind_assoc,
  ]
  apply Exists.intro
  exact generatedDivisionMTypeGate_factor _ _

theorem decode_div_certificate_at
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
      (encodeAdmittedMType .div rs2 rs1 rd)
      (admittedMTypeInstruction .div rs2 rs1 rd)
      initial := by
  rcases ext_decode_div_gate rs2 rs1 rd with ⟨fallback, gateEq⟩
  constructor
  rw [gateEq]
  exact generatedDivisionMTypeGate_exact_at
    (admittedMTypeInstruction .div rs2 rs1 rd)
    fallback initial misaValue mseccfgValue multiplyEnabled
    pauseDisabled landingPadDisabled misaBinding misaMEnabled
    privilegeBinding mseccfgBinding

end LeanRV32IM.Functions
