import DecodeAluShift

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000

open Sail

namespace LeanRV32IM.Functions

private theorem generated_srli_probe_facts
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    generatedSlliProbe (encodeAdmittedShiftIType .srli shamt rs1 rd) =
        pure none ∧
      generatedSrliProbe (encodeAdmittedShiftIType .srli shamt rs1 rd) =
        pure (some (admittedShiftITypeInstruction .srli shamt rs1 rd)) := by
  have topBit : ((0#1 : BitVec 1) +++ shamt)[5] = false := by
    rw [BitVec.getElem_append]
    rfl
  refine ⟨?_, ?_⟩ <;> simp only [
    generatedSlliProbe,
    generatedSrliProbe,
    encodeAdmittedShiftIType_opcode,
    encodeAdmittedShiftIType_funct3,
    encodeAdmittedShiftIType_top6,
    encodeAdmittedShiftIType_shamt6,
    encodeAdmittedShiftIType_rs1,
    encodeAdmittedShiftIType_rd,
    encdec_reg_backwards_matches_all_alu,
    encdec_reg_backwards_all_alu,
    admittedShiftITypeFunct7,
    admittedShiftITypeFunct3,
    admittedShiftITypeGeneratedOp,
    admittedShiftITypeInstruction,
    RiscvRefinement.Decode.funct7Base,
    RiscvRefinement.Decode.funct7Alt,
    RiscvRefinement.Decode.funct3Sll,
    RiscvRefinement.Decode.funct3Srl,
    RiscvRefinement.Decode.funct3Sra,
    xlen,
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
  ] <;> simp [
    topBit,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.access,
  ]

private theorem generated_srli_body_exact
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5)
    (fallback : SailM instruction) :
    generatedShiftITypeBody
        (encodeAdmittedShiftIType .srli shamt rs1 rd) fallback =
      pure (admittedShiftITypeInstruction .srli shamt rs1 rd) :=
  generatedShiftITypeBody_srli _ fallback _
    (generated_srli_probe_facts shamt rs1 rd).1
    (generated_srli_probe_facts shamt rs1 rd).2

private theorem ext_decode_admitted_srli_branch
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false) :
    ∃ fallback : SailM instruction,
      ext_decode (encodeAdmittedShiftIType .srli shamt rs1 rd) =
        generatedShiftITypeGate
          (encodeAdmittedShiftIType .srli shamt rs1 rd) fallback := by
  rw [ext_decode.eq_1, encdec_backwards.eq_def]
  simp only [
    encodeAdmittedShiftIType_not_zicbop,
    Bool.false_eq_true,
    if_false,
    pure_bind,
  ]
  rw [
    generatedNtlProbeShift_raw,
    generatedNtlProbeShift_dead,
  ]
  simp only [pure_bind]
  rw [
    currentlyEnabled_pause_disabled_alu pauseDisabled,
    encodeAdmittedShiftIType_not_lpad,
    encodeAdmittedShiftIType_not_utype,
    encodeAdmittedShiftIType_not_jal,
    encodeAdmittedShiftIType_not_jalr,
    encodeAdmittedShiftIType_not_branch,
    encodeAdmittedShiftIType_not_itype,
  ]
  simp only [
    Bool.false_and,
    Bool.and_false,
    Bool.false_eq_true,
    if_false,
    pure_bind,
  ]
  rw [
    generatedSlliProbe_raw,
    generatedSrliProbe_raw,
    generatedSraiProbe_raw,
  ]
  simp only [
    generatedShiftITypeGate,
    generatedUtypeDecodePreamble,
    currentlyEnabled_pause_disabled_alu pauseDisabled,
    pure_bind,
    bind_assoc,
  ]
  apply Exists.intro
  exact generatedShiftITypeBody_factor_after_zicfilp _ _

theorem decode_admitted_srli_certificate
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false) :
    GeneratedDecodeCertificate
      (encodeAdmittedShiftIType .srli shamt rs1 rd)
      (admittedShiftITypeInstruction .srli shamt rs1 rd) := by
  constructor
  intro initial final actual outcome
  rcases ext_decode_admitted_srli_branch shamt rs1 rd pauseDisabled with
    ⟨fallback, gateEq⟩
  rw [gateEq] at outcome
  exact generatedShiftITypeGate_success _ fallback
    (admittedShiftITypeInstruction .srli shamt rs1 rd)
    actual initial final
    (generated_srli_body_exact shamt rs1 rd fallback) outcome

theorem decode_admitted_srli_certificate_at
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
      (encodeAdmittedShiftIType .srli shamt rs1 rd)
      (admittedShiftITypeInstruction .srli shamt rs1 rd)
      initial := by
  rcases ext_decode_admitted_srli_branch shamt rs1 rd pauseDisabled with
    ⟨fallback, gateEq⟩
  constructor
  rw [gateEq]
  exact generatedShiftITypeGate_exact_at _ fallback _ initial mseccfgValue
    pauseDisabled landingPadDisabled privilegeBinding mseccfgBinding
    (generated_srli_body_exact shamt rs1 rd fallback)

end LeanRV32IM.Functions
