import DecodeAluBase

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000

open Sail

namespace LeanRV32IM.Functions

inductive AdmittedITypeOp where
  | addi | slti | sltiu | xori | ori | andi
deriving DecidableEq, Repr

def admittedITypeFunct3 : AdmittedITypeOp → BitVec 3
  | .addi => 0b000#3
  | .slti => 0b010#3
  | .sltiu => 0b011#3
  | .xori => 0b100#3
  | .ori => 0b110#3
  | .andi => 0b111#3

def admittedITypeGeneratedOp : AdmittedITypeOp → iop
  | .addi => .ADDI
  | .slti => .SLTI
  | .sltiu => .SLTIU
  | .xori => .XORI
  | .ori => .ORI
  | .andi => .ANDI

def encodeAdmittedIType
    (op : AdmittedITypeOp)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) : BitVec 32 :=
  imm.append
    (rs1.append
      ((admittedITypeFunct3 op).append
        (rd.append RiscvRefinement.Decode.opImmOpcode)))

def admittedITypeInstruction
    (op : AdmittedITypeOp)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) : instruction :=
  .ITYPE (imm, .Regidx rs1, .Regidx rd, admittedITypeGeneratedOp op)

private theorem encodeAdmittedIType_opcode
    (op : AdmittedITypeOp)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedIType op imm rs1 rd) 6 0 =
      (0b0010011#7 : BitVec 7) := by
  simp only [
    encodeAdmittedIType,
    RiscvRefinement.Decode.opImmOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 0) (len := 7) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 0) (len := 7) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 0) (len := 7) (by decide)]
  exact BitVec.extractLsb'_append_eq_right

private theorem encodeAdmittedIType_funct3
    (op : AdmittedITypeOp)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedIType op imm rs1 rd) 14 12 =
      admittedITypeFunct3 op := by
  simp only [
    encodeAdmittedIType,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 12) (len := 3) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 12) (len := 3) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 12) (len := 3) (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeAdmittedIType_imm
    (op : AdmittedITypeOp)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedIType op imm rs1 rd) 31 20 = imm := by
  simp only [
    encodeAdmittedIType,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 20) (len := 12) (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeAdmittedIType_rs1
    (op : AdmittedITypeOp)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedIType op imm rs1 rd) 19 15 = rs1 := by
  simp only [
    encodeAdmittedIType,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 15) (len := 5) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 15) (len := 5) (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeAdmittedIType_rd
    (op : AdmittedITypeOp)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedIType op imm rs1 rd) 11 7 = rd := by
  simp only [
    encodeAdmittedIType,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 7) (len := 5) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 7) (len := 5) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 7) (len := 5) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 7) (len := 5) (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeAdmittedIType_not_ntl
    (op : AdmittedITypeOp)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    ((let word := encodeAdmittedIType op imm rs1 rd
      let mapping : BitVec 5 := Sail.BitVec.extractLsb word 24 20
      encdec_ntl_backwards_matches mapping &&
        ((Sail.BitVec.extractLsb word 31 25 ==
          (0b0000000#7 : BitVec 7)) &&
         (Sail.BitVec.extractLsb word 19 0 ==
          (0x00033#20 : BitVec 20)))) : Bool) = false := by
  have lowBits :
      (Sail.BitVec.extractLsb
          (encodeAdmittedIType op imm rs1 rd) 19 0 ==
        (0x00033#20 : BitVec 20)) = false := by
    simpa only [Sail.BitVec.extractLsb, BitVec.extractLsb] using
      lowSlice_beq_false_of_subfield_ne_alu
        (width := 20) (start := 0) (len := 7)
        (encodeAdmittedIType op imm rs1 rd)
        (0x00033#20 : BitVec 20)
        (by decide)
        (0b0010011#7 : BitVec 7)
        (by
          simpa only [Sail.BitVec.extractLsb, BitVec.extractLsb] using
            encodeAdmittedIType_opcode op imm rs1 rd)
        (by decide)
  simp [lowBits]

private theorem encodeAdmittedIType_not_lpad
    (op : AdmittedITypeOp)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb (encodeAdmittedIType op imm rs1 rd) 11 0 ==
      (0x017#12 : BitVec 12)) = false := by
  simpa only [Sail.BitVec.extractLsb, BitVec.extractLsb] using
    lowSlice_beq_false_of_subfield_ne_alu
      (width := 12) (start := 0) (len := 7)
      (encodeAdmittedIType op imm rs1 rd)
      (0x017#12 : BitVec 12)
      (by decide)
      (0b0010011#7 : BitVec 7)
      (by
        simpa only [Sail.BitVec.extractLsb, BitVec.extractLsb] using
          encodeAdmittedIType_opcode op imm rs1 rd)
      (by decide)

private theorem ext_decode_admitted_itype_branch
    (op : AdmittedITypeOp)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5)
    (zicbopDisabled : hartSupports extension.Ext_Zicbop = false)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false) :
    ext_decode (encodeAdmittedIType op imm rs1 rd) =
      generatedUtypeDecodeProgram
        (admittedITypeInstruction op imm rs1 rd) := by
  cases op <;>
    rw [ext_decode.eq_1, encdec_backwards.eq_def] <;>
    dsimp only <;>
    rw [
      generatedZicbopProbeAlu_raw,
      generatedZicbopProbeAlu_disabled _ zicbopDisabled,
    ] <;>
    simp only [
      encodeAdmittedIType_not_ntl,
      currentlyEnabled_pause_disabled_alu pauseDisabled,
      encodeAdmittedIType_not_lpad,
      encodeAdmittedIType_opcode,
      encodeAdmittedIType_funct3,
      encodeAdmittedIType_imm,
      encodeAdmittedIType_rs1,
      encodeAdmittedIType_rd,
      encdec_reg_backwards_matches_all_alu,
      encdec_reg_backwards_all_alu,
      encdec_iop_backwards_matches,
      encdec_iop_backwards,
      encdec_uop_backwards_matches,
      generatedUtypeDecodePreamble,
      generatedUtypeDecodeProgram,
      admittedITypeFunct3,
      admittedITypeGeneratedOp,
      admittedITypeInstruction,
      Bool.false_and,
      Bool.and_false,
      Bool.false_eq_true,
      if_false,
      pure_bind,
      bind_assoc,
    ] <;> simp

theorem decode_admitted_itype_certificate
    (op : AdmittedITypeOp)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5)
    (zicbopDisabled : hartSupports extension.Ext_Zicbop = false)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false) :
    GeneratedDecodeCertificate
      (encodeAdmittedIType op imm rs1 rd)
      (admittedITypeInstruction op imm rs1 rd) := by
  constructor
  intro initial final actual outcome
  rw [
    ext_decode_admitted_itype_branch
      op imm rs1 rd zicbopDisabled pauseDisabled,
  ] at outcome
  exact
    generatedUtypeDecodeProgram_success
      (admittedITypeInstruction op imm rs1 rd)
      actual initial final outcome

/-- Constructive generated decode for one admitted ordinary I-type opcode. -/
theorem decode_admitted_itype_certificate_at
    (op : AdmittedITypeOp)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5)
    (initial : GeneratedState)
    (mseccfgValue : BitVec 64)
    (zicbopDisabled : hartSupports extension.Ext_Zicbop = false)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled : hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding :
      initial.regs.get? Register.mseccfg = some mseccfgValue) :
    GeneratedDecodeCertificateAt
      (encodeAdmittedIType op imm rs1 rd)
      (admittedITypeInstruction op imm rs1 rd)
      initial := by
  constructor
  rw [ext_decode_admitted_itype_branch
    op imm rs1 rd zicbopDisabled pauseDisabled]
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
