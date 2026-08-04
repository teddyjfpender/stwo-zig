import DecodeAluBase

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000

open Sail

namespace LeanRV32IM.Functions

inductive AdmittedMTypeOp where
  | mul | mulh | mulhsu | mulhu | div | divu | rem | remu
deriving DecidableEq, Repr

def admittedMTypeFunct3 : AdmittedMTypeOp → BitVec 3
  | .mul => RiscvRefinement.Decode.funct3Mul
  | .mulh => RiscvRefinement.Decode.funct3Mulh
  | .mulhsu => RiscvRefinement.Decode.funct3Mulhsu
  | .mulhu => RiscvRefinement.Decode.funct3Mulhu
  | .div => RiscvRefinement.Decode.funct3Div
  | .divu => RiscvRefinement.Decode.funct3Divu
  | .rem => RiscvRefinement.Decode.funct3Rem
  | .remu => RiscvRefinement.Decode.funct3Remu

def admittedMTypeInstruction
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5) : instruction :=
  match op with
  | .mul =>
    .MUL
      (.Regidx rs2, .Regidx rs1, .Regidx rd,
        { result_part := .Low
          signed_rs1 := .Signed
          signed_rs2 := .Signed })
  | .mulh =>
    .MUL
      (.Regidx rs2, .Regidx rs1, .Regidx rd,
        { result_part := .High
          signed_rs1 := .Signed
          signed_rs2 := .Signed })
  | .mulhsu =>
    .MUL
      (.Regidx rs2, .Regidx rs1, .Regidx rd,
        { result_part := .High
          signed_rs1 := .Signed
          signed_rs2 := .Unsigned })
  | .mulhu =>
    .MUL
      (.Regidx rs2, .Regidx rs1, .Regidx rd,
        { result_part := .High
          signed_rs1 := .Unsigned
          signed_rs2 := .Unsigned })
  | .div => .DIV (.Regidx rs2, .Regidx rs1, .Regidx rd, false)
  | .divu => .DIV (.Regidx rs2, .Regidx rs1, .Regidx rd, true)
  | .rem => .REM (.Regidx rs2, .Regidx rs1, .Regidx rd, false)
  | .remu => .REM (.Regidx rs2, .Regidx rs1, .Regidx rd, true)

def encodeAdmittedMType
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5) : BitVec 32 :=
  RiscvRefinement.Decode.encodeRType
    RiscvRefinement.Decode.funct7MulDiv
    rs2 rs1 (admittedMTypeFunct3 op) rd

private theorem encodeRTypeOpcodeField
    (funct7 : BitVec 7)
    (rs2 rs1 : BitVec 5)
    (funct3 : BitVec 3)
    (rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeRType funct7 rs2 rs1 funct3 rd)
        6 0 = RiscvRefinement.Decode.opOpcode := by
  simp only [
    RiscvRefinement.Decode.encodeRType,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeRTypeRdField
    (funct7 : BitVec 7)
    (rs2 rs1 : BitVec 5)
    (funct3 : BitVec 3)
    (rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeRType funct7 rs2 rs1 funct3 rd)
        11 7 = rd := by
  simp only [
    RiscvRefinement.Decode.encodeRType,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeRTypeFunct3Field
    (funct7 : BitVec 7)
    (rs2 rs1 : BitVec 5)
    (funct3 : BitVec 3)
    (rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeRType funct7 rs2 rs1 funct3 rd)
        14 12 = funct3 := by
  simp only [
    RiscvRefinement.Decode.encodeRType,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeRTypeFunct3LowField
    (funct7 : BitVec 7)
    (rs2 rs1 : BitVec 5)
    (funct3 : BitVec 3)
    (rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeRType funct7 rs2 rs1 funct3 rd)
        12 12 = Sail.BitVec.extractLsb funct3 0 0 := by
  simp only [
    RiscvRefinement.Decode.encodeRType,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le (by decide)]

private theorem encodeRTypeFunct3HighField
    (funct7 : BitVec 7)
    (rs2 rs1 : BitVec 5)
    (funct3 : BitVec 3)
    (rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeRType funct7 rs2 rs1 funct3 rd)
        14 13 = Sail.BitVec.extractLsb funct3 2 1 := by
  simp only [
    RiscvRefinement.Decode.encodeRType,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le (by decide)]

private theorem encodeRTypeRs1Field
    (funct7 : BitVec 7)
    (rs2 rs1 : BitVec 5)
    (funct3 : BitVec 3)
    (rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeRType funct7 rs2 rs1 funct3 rd)
        19 15 = rs1 := by
  simp only [
    RiscvRefinement.Decode.encodeRType,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeRTypeRs2Field
    (funct7 : BitVec 7)
    (rs2 rs1 : BitVec 5)
    (funct3 : BitVec 3)
    (rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeRType funct7 rs2 rs1 funct3 rd)
        24 20 = rs2 := by
  simp only [
    RiscvRefinement.Decode.encodeRType,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeRTypeFunct7Field
    (funct7 : BitVec 7)
    (rs2 rs1 : BitVec 5)
    (funct3 : BitVec 3)
    (rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeRType funct7 rs2 rs1 funct3 rd)
        31 25 = funct7 := by
  simp only [
    RiscvRefinement.Decode.encodeRType,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_le (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeRTypeLow12
    (funct7 : BitVec 7)
    (rs2 rs1 : BitVec 5)
    (funct3 : BitVec 3)
    (rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeRType funct7 rs2 rs1 funct3 rd)
        11 0 = rd.append RiscvRefinement.Decode.opOpcode := by
  simp only [
    RiscvRefinement.Decode.encodeRType,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeRTypeLow15
    (funct7 : BitVec 7)
    (rs2 rs1 : BitVec 5)
    (funct3 : BitVec 3)
    (rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeRType funct7 rs2 rs1 funct3 rd)
        14 0 = funct3.append (rd.append RiscvRefinement.Decode.opOpcode) := by
  simp only [
    RiscvRefinement.Decode.encodeRType,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeRTypeLow12Mismatch
    (funct7 : BitVec 7)
    (rs2 rs1 : BitVec 5)
    (funct3 : BitVec 3)
    (rd : BitVec 5)
    (target : BitVec 12)
    (mismatch : RiscvRefinement.Decode.opOpcode ≠
      Sail.BitVec.extractLsb target 6 0) :
    (Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeRType funct7 rs2 rs1 funct3 rd)
        11 0 == target) = false := by
  apply beq_eq_false_iff_ne.mpr
  intro equality
  rw [encodeRTypeLow12] at equality
  have opcodeEquality := congrArg
    (fun value : BitVec 12 => Sail.BitVec.extractLsb value 6 0)
    equality
  simp only [
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ] at opcodeEquality
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)] at opcodeEquality
  exact mismatch opcodeEquality

private theorem encodeRTypeLow15Mismatch
    (funct7 : BitVec 7)
    (rs2 rs1 : BitVec 5)
    (funct3 : BitVec 3)
    (rd : BitVec 5)
    (target : BitVec 15)
    (mismatch : RiscvRefinement.Decode.opOpcode ≠
      Sail.BitVec.extractLsb target 6 0) :
    (Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeRType funct7 rs2 rs1 funct3 rd)
        14 0 == target) = false := by
  apply beq_eq_false_iff_ne.mpr
  intro equality
  rw [encodeRTypeLow15] at equality
  have opcodeEquality := congrArg
    (fun value : BitVec 15 => Sail.BitVec.extractLsb value 6 0)
    equality
  simp only [
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ] at opcodeEquality
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)] at opcodeEquality
  rw [BitVec.extractLsb'_append_eq_of_add_le (by decide)] at opcodeEquality
  exact mismatch opcodeEquality

private theorem encodeRTypeWordMismatch
    (funct7 : BitVec 7)
    (rs2 rs1 : BitVec 5)
    (funct3 : BitVec 3)
    (rd : BitVec 5)
    (target : BitVec 32)
    (mismatch : RiscvRefinement.Decode.opOpcode ≠
      Sail.BitVec.extractLsb target 6 0) :
    (RiscvRefinement.Decode.encodeRType funct7 rs2 rs1 funct3 rd ==
      target) = false := by
  apply beq_eq_false_iff_ne.mpr
  intro equality
  have opcodeEquality := congrArg
    (fun word : BitVec 32 => Sail.BitVec.extractLsb word 6 0)
    equality
  change
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeRType funct7 rs2 rs1 funct3 rd)
        6 0 = Sail.BitVec.extractLsb target 6 0 at opcodeEquality
  rw [encodeRTypeOpcodeField] at opcodeEquality
  exact mismatch opcodeEquality

theorem encodeAdmittedMType_not_zicbop
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    ((let word := encodeAdmittedMType op rs2 rs1 rd
      let mapping1 : BitVec 5 := Sail.BitVec.extractLsb word 19 15
      let mapping0 : BitVec 5 := Sail.BitVec.extractLsb word 24 20
      (encdec_cbop_zicbop_backwards_matches mapping0 &&
          encdec_reg_backwards_matches mapping1) &&
        Sail.BitVec.extractLsb word 14 0 ==
          (0b110000000010011#15 : BitVec 15)) : Bool) = false := by
  have mismatch :
      (Sail.BitVec.extractLsb
          (encodeAdmittedMType op rs2 rs1 rd) 14 0 ==
        (0b110000000010011#15 : BitVec 15)) = false := by
    unfold encodeAdmittedMType
    exact encodeRTypeLow15Mismatch
      RiscvRefinement.Decode.funct7MulDiv rs2 rs1
      (admittedMTypeFunct3 op) rd _ (by decide)
  simp only [mismatch, Bool.and_false]

theorem encodeAdmittedMType_not_ntl
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    ((let word := encodeAdmittedMType op rs2 rs1 rd
      let mapping : BitVec 5 := Sail.BitVec.extractLsb word 24 20
      encdec_ntl_backwards_matches mapping &&
        ((Sail.BitVec.extractLsb word 31 25 ==
          (0b0000000#7 : BitVec 7)) &&
         (Sail.BitVec.extractLsb word 19 0 ==
          (0x00033#20 : BitVec 20)))) : Bool) = false := by
  have topField :
      Sail.BitVec.extractLsb
          (encodeAdmittedMType op rs2 rs1 rd) 31 25 =
        RiscvRefinement.Decode.funct7MulDiv := by
    unfold encodeAdmittedMType
    exact encodeRTypeFunct7Field
      RiscvRefinement.Decode.funct7MulDiv rs2 rs1
      (admittedMTypeFunct3 op) rd
  have topMismatch :
      (Sail.BitVec.extractLsb
          (encodeAdmittedMType op rs2 rs1 rd) 31 25 ==
        (0b0000000#7 : BitVec 7)) = false := by
    rw [topField]
    decide
  simp only [topMismatch, Bool.false_and, Bool.and_false]

theorem encodeAdmittedMType_not_lpad
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb (encodeAdmittedMType op rs2 rs1 rd) 11 0 ==
      (0x017#12 : BitVec 12)) = false := by
  unfold encodeAdmittedMType
  exact encodeRTypeLow12Mismatch
    RiscvRefinement.Decode.funct7MulDiv rs2 rs1
    (admittedMTypeFunct3 op) rd _ (by decide)

theorem encodeAdmittedMType_opcode
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedMType op rs2 rs1 rd) 6 0 =
      (0b0110011#7 : BitVec 7) := by
  unfold encodeAdmittedMType
  simpa only [RiscvRefinement.Decode.opOpcode] using
    encodeRTypeOpcodeField
      RiscvRefinement.Decode.funct7MulDiv rs2 rs1
      (admittedMTypeFunct3 op) rd

theorem encodeAdmittedMType_opcode_mismatch
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5)
    (opcode : BitVec 7)
    (mismatch : (0b0110011#7 : BitVec 7) ≠ opcode) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedMType op rs2 rs1 rd) 6 0 == opcode) = false := by
  rw [encodeAdmittedMType_opcode]
  exact beq_eq_false_iff_ne.mpr mismatch

theorem encodeAdmittedMType_not_jal
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedMType op rs2 rs1 rd) 6 0 == 0b1101111#7) = false :=
  encodeAdmittedMType_opcode_mismatch op rs2 rs1 rd _ (by decide)

theorem encodeAdmittedMType_not_jalr
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedMType op rs2 rs1 rd) 6 0 == 0b1100111#7) = false :=
  encodeAdmittedMType_opcode_mismatch op rs2 rs1 rd _ (by decide)

theorem encodeAdmittedMType_not_branch
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedMType op rs2 rs1 rd) 6 0 == 0b1100011#7) = false :=
  encodeAdmittedMType_opcode_mismatch op rs2 rs1 rd _ (by decide)

theorem encodeAdmittedMType_not_itype
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedMType op rs2 rs1 rd) 6 0 == 0b0010011#7) = false :=
  encodeAdmittedMType_opcode_mismatch op rs2 rs1 rd _ (by decide)

theorem encodeAdmittedMType_not_load
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedMType op rs2 rs1 rd) 6 0 == 0b0000011#7) = false :=
  encodeAdmittedMType_opcode_mismatch op rs2 rs1 rd _ (by decide)

theorem encodeAdmittedMType_not_store
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedMType op rs2 rs1 rd) 6 0 == 0b0100011#7) = false :=
  encodeAdmittedMType_opcode_mismatch op rs2 rs1 rd _ (by decide)

theorem encodeAdmittedMType_not_itypew
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedMType op rs2 rs1 rd) 6 0 == 0b0011011#7) = false :=
  encodeAdmittedMType_opcode_mismatch op rs2 rs1 rd _ (by decide)

theorem encodeAdmittedMType_not_rtypew
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedMType op rs2 rs1 rd) 6 0 == 0b0111011#7) = false :=
  encodeAdmittedMType_opcode_mismatch op rs2 rs1 rd _ (by decide)

theorem encodeAdmittedMType_not_fence
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedMType op rs2 rs1 rd) 6 0 == 0b0001111#7) = false :=
  encodeAdmittedMType_opcode_mismatch op rs2 rs1 rd _ (by decide)

theorem encodeAdmittedMType_not_atomic
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedMType op rs2 rs1 rd) 6 0 == 0b0101111#7) = false :=
  encodeAdmittedMType_opcode_mismatch op rs2 rs1 rd _ (by decide)

theorem encodeAdmittedMType_is_rtype
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedMType op rs2 rs1 rd) 6 0 == 0b0110011#7) = true := by
  rw [encodeAdmittedMType_opcode]
  decide

theorem encodeAdmittedMType_not_pause
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (encodeAdmittedMType op rs2 rs1 rd == 0x0100000F#32) = false := by
  unfold encodeAdmittedMType
  exact encodeRTypeWordMismatch
    RiscvRefinement.Decode.funct7MulDiv rs2 rs1
    (admittedMTypeFunct3 op) rd _ (by decide)

theorem encodeAdmittedMType_not_sfence
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedMType op rs2 rs1 rd) 14 0 ==
      (0b000000001110011#15 : BitVec 15)) = false := by
  unfold encodeAdmittedMType
  exact encodeRTypeLow15Mismatch
    RiscvRefinement.Decode.funct7MulDiv rs2 rs1
    (admittedMTypeFunct3 op) rd _ (by decide)

theorem encodeAdmittedMType_word_mismatch
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5)
    (target : BitVec 32)
    (opcodeMismatch :
      (0b0110011#7 : BitVec 7) ≠
        Sail.BitVec.extractLsb target 6 0) :
    (encodeAdmittedMType op rs2 rs1 rd == target) = false := by
  unfold encodeAdmittedMType
  apply encodeRTypeWordMismatch
  simpa only [RiscvRefinement.Decode.opOpcode] using opcodeMismatch

theorem encodeAdmittedMType_not_fence_tso
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (encodeAdmittedMType op rs2 rs1 rd == 2200961039#32) = false :=
  encodeAdmittedMType_word_mismatch op rs2 rs1 rd _ (by decide)

theorem encodeAdmittedMType_ne_fence_tso
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    encodeAdmittedMType op rs2 rs1 rd ≠ 2200961039#32 :=
  beq_eq_false_iff_ne.mp
    (encodeAdmittedMType_not_fence_tso op rs2 rs1 rd)

theorem encodeAdmittedMType_not_ecall
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (encodeAdmittedMType op rs2 rs1 rd == 115#32) = false :=
  encodeAdmittedMType_word_mismatch op rs2 rs1 rd _ (by decide)

theorem encodeAdmittedMType_ne_ecall
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    encodeAdmittedMType op rs2 rs1 rd ≠ 115#32 :=
  beq_eq_false_iff_ne.mp
    (encodeAdmittedMType_not_ecall op rs2 rs1 rd)

theorem encodeAdmittedMType_not_mret
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (encodeAdmittedMType op rs2 rs1 rd == 807403635#32) = false :=
  encodeAdmittedMType_word_mismatch op rs2 rs1 rd _ (by decide)

theorem encodeAdmittedMType_ne_mret
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    encodeAdmittedMType op rs2 rs1 rd ≠ 807403635#32 :=
  beq_eq_false_iff_ne.mp
    (encodeAdmittedMType_not_mret op rs2 rs1 rd)

theorem encodeAdmittedMType_not_sret
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (encodeAdmittedMType op rs2 rs1 rd == 270532723#32) = false :=
  encodeAdmittedMType_word_mismatch op rs2 rs1 rd _ (by decide)

theorem encodeAdmittedMType_ne_sret
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    encodeAdmittedMType op rs2 rs1 rd ≠ 270532723#32 :=
  beq_eq_false_iff_ne.mp
    (encodeAdmittedMType_not_sret op rs2 rs1 rd)

theorem encodeAdmittedMType_not_ebreak
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (encodeAdmittedMType op rs2 rs1 rd == 1048691#32) = false :=
  encodeAdmittedMType_word_mismatch op rs2 rs1 rd _ (by decide)

theorem encodeAdmittedMType_ne_ebreak
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    encodeAdmittedMType op rs2 rs1 rd ≠ 1048691#32 :=
  beq_eq_false_iff_ne.mp
    (encodeAdmittedMType_not_ebreak op rs2 rs1 rd)

theorem encodeAdmittedMType_not_wfi
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (encodeAdmittedMType op rs2 rs1 rd == 273678451#32) = false :=
  encodeAdmittedMType_word_mismatch op rs2 rs1 rd _ (by decide)

theorem encodeAdmittedMType_ne_wfi
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    encodeAdmittedMType op rs2 rs1 rd ≠ 273678451#32 :=
  beq_eq_false_iff_ne.mp
    (encodeAdmittedMType_not_wfi op rs2 rs1 rd)

theorem encodeAdmittedMType_not_utype
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    ((let word := encodeAdmittedMType op rs2 rs1 rd
      let opcode : BitVec 7 := Sail.BitVec.extractLsb word 6 0
      let destination : BitVec 5 := Sail.BitVec.extractLsb word 11 7
      encdec_reg_backwards_matches destination &&
        encdec_uop_backwards_matches opcode) : Bool) = false := by
  simp [
    encodeAdmittedMType_opcode,
    encdec_uop_backwards_matches,
  ]

theorem encodeAdmittedMType_funct7
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedMType op rs2 rs1 rd) 31 25 =
      (0b0000001#7 : BitVec 7) := by
  unfold encodeAdmittedMType
  simpa only [RiscvRefinement.Decode.funct7MulDiv] using
    encodeRTypeFunct7Field
      RiscvRefinement.Decode.funct7MulDiv rs2 rs1
      (admittedMTypeFunct3 op) rd

theorem encodeAdmittedMType_funct7_mismatch
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5)
    (funct7 : BitVec 7)
    (mismatch : (0b0000001#7 : BitVec 7) ≠ funct7) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedMType op rs2 rs1 rd) 31 25 == funct7) = false := by
  rw [encodeAdmittedMType_funct7]
  exact beq_eq_false_iff_ne.mpr mismatch

theorem encodeAdmittedMType_not_base_funct7
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedMType op rs2 rs1 rd) 31 25 == 0b0000000#7) = false :=
  encodeAdmittedMType_funct7_mismatch op rs2 rs1 rd _ (by decide)

theorem encodeAdmittedMType_not_alt_funct7
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedMType op rs2 rs1 rd) 31 25 == 0b0100000#7) = false :=
  encodeAdmittedMType_funct7_mismatch op rs2 rs1 rd _ (by decide)

theorem encodeAdmittedMType_is_muldiv_funct7
    (op : AdmittedMTypeOp) (rs2 rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedMType op rs2 rs1 rd) 31 25 == 0b0000001#7) = true := by
  rw [encodeAdmittedMType_funct7]
  decide

theorem encodeAdmittedMType_funct3
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedMType op rs2 rs1 rd) 14 12 =
      admittedMTypeFunct3 op := by
  unfold encodeAdmittedMType
  exact encodeRTypeFunct3Field
    RiscvRefinement.Decode.funct7MulDiv rs2 rs1
    (admittedMTypeFunct3 op) rd

theorem encodeAdmittedMType_funct3_low
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedMType op rs2 rs1 rd) 12 12 =
      Sail.BitVec.extractLsb (admittedMTypeFunct3 op) 0 0 := by
  unfold encodeAdmittedMType
  exact encodeRTypeFunct3LowField
    RiscvRefinement.Decode.funct7MulDiv rs2 rs1
    (admittedMTypeFunct3 op) rd

theorem encodeAdmittedMType_funct3_high
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedMType op rs2 rs1 rd) 14 13 =
      Sail.BitVec.extractLsb (admittedMTypeFunct3 op) 2 1 := by
  unfold encodeAdmittedMType
  exact encodeRTypeFunct3HighField
    RiscvRefinement.Decode.funct7MulDiv rs2 rs1
    (admittedMTypeFunct3 op) rd

theorem encodeAdmittedDivMType_unsignedBit
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (encodeAdmittedMType .div rs2 rs1 rd) 12 12 = 0#1 := by
  rw [encodeAdmittedMType_funct3_low]
  decide

theorem encodeAdmittedDivMType_class
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (encodeAdmittedMType .div rs2 rs1 rd) 14 13 = 2#2 := by
  rw [encodeAdmittedMType_funct3_high]
  decide

theorem encodeAdmittedDivuMType_unsignedBit
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (encodeAdmittedMType .divu rs2 rs1 rd) 12 12 = 1#1 := by
  rw [encodeAdmittedMType_funct3_low]
  decide

theorem encodeAdmittedDivuMType_class
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (encodeAdmittedMType .divu rs2 rs1 rd) 14 13 = 2#2 := by
  rw [encodeAdmittedMType_funct3_high]
  decide

theorem encodeAdmittedRemMType_unsignedBit
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (encodeAdmittedMType .rem rs2 rs1 rd) 12 12 = 0#1 := by
  rw [encodeAdmittedMType_funct3_low]
  decide

theorem encodeAdmittedRemMType_class
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (encodeAdmittedMType .rem rs2 rs1 rd) 14 13 = 3#2 := by
  rw [encodeAdmittedMType_funct3_high]
  decide

theorem encodeAdmittedRemuMType_unsignedBit
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (encodeAdmittedMType .remu rs2 rs1 rd) 12 12 = 1#1 := by
  rw [encodeAdmittedMType_funct3_low]
  decide

theorem encodeAdmittedRemuMType_class
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (encodeAdmittedMType .remu rs2 rs1 rd) 14 13 = 3#2 := by
  rw [encodeAdmittedMType_funct3_high]
  decide

theorem mtypeClass2_is_div :
    (((2#2 : BitVec 2) == 2#2) : Bool) = true := by
  decide

theorem mtypeClass2_not_rem :
    (((2#2 : BitVec 2) == 3#2) : Bool) = false := by
  decide

theorem mtypeClass3_not_div :
    (((3#2 : BitVec 2) == 2#2) : Bool) = false := by
  decide

theorem mtypeClass3_is_rem :
    (((3#2 : BitVec 2) == 3#2) : Bool) = true := by
  decide

theorem mtypeUnsignedBit0_matches :
    bool_bit_backwards_matches (0#1 : BitVec 1) = true := by
  decide

theorem mtypeUnsignedBit1_matches :
    bool_bit_backwards_matches (1#1 : BitVec 1) = true := by
  decide

theorem mtypeUnsignedBit0_value :
    bool_bit_backwards (0#1 : BitVec 1) = false := by
  decide

theorem mtypeUnsignedBit1_value :
    bool_bit_backwards (1#1 : BitVec 1) = true := by
  decide

theorem encodeAdmittedDivMType_not_multiply
    (rs2 rs1 rd : BitVec 5) :
    encdec_mul_op_backwards_matches
        (Sail.BitVec.extractLsb
          (encodeAdmittedMType .div rs2 rs1 rd) 14 12) = false := by
  rw [encodeAdmittedMType_funct3]
  decide

theorem encodeAdmittedDivuMType_not_multiply
    (rs2 rs1 rd : BitVec 5) :
    encdec_mul_op_backwards_matches
        (Sail.BitVec.extractLsb
          (encodeAdmittedMType .divu rs2 rs1 rd) 14 12) = false := by
  rw [encodeAdmittedMType_funct3]
  decide

theorem encodeAdmittedRemMType_not_multiply
    (rs2 rs1 rd : BitVec 5) :
    encdec_mul_op_backwards_matches
        (Sail.BitVec.extractLsb
          (encodeAdmittedMType .rem rs2 rs1 rd) 14 12) = false := by
  rw [encodeAdmittedMType_funct3]
  decide

theorem encodeAdmittedRemuMType_not_multiply
    (rs2 rs1 rd : BitVec 5) :
    encdec_mul_op_backwards_matches
        (Sail.BitVec.extractLsb
          (encodeAdmittedMType .remu rs2 rs1 rd) 14 12) = false := by
  rw [encodeAdmittedMType_funct3]
  decide

theorem encodeAdmittedMType_rs2
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedMType op rs2 rs1 rd) 24 20 = rs2 := by
  unfold encodeAdmittedMType
  exact encodeRTypeRs2Field
    RiscvRefinement.Decode.funct7MulDiv rs2 rs1
    (admittedMTypeFunct3 op) rd

theorem encodeAdmittedMType_rs1
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedMType op rs2 rs1 rd) 19 15 = rs1 := by
  unfold encodeAdmittedMType
  exact encodeRTypeRs1Field
    RiscvRefinement.Decode.funct7MulDiv rs2 rs1
    (admittedMTypeFunct3 op) rd

theorem encodeAdmittedMType_rd
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedMType op rs2 rs1 rd) 11 7 = rd := by
  unfold encodeAdmittedMType
  exact encodeRTypeRdField
    RiscvRefinement.Decode.funct7MulDiv rs2 rs1
    (admittedMTypeFunct3 op) rd

theorem generatedNtlProbeMType_raw
    (word : BitVec 32) :
    (do
      let mapping : BitVec 5 := Sail.BitVec.extractLsb word 24 20
      if encdec_ntl_backwards_matches mapping &&
          ((Sail.BitVec.extractLsb word 31 25 == (0b0000000#7 : BitVec 7)) &&
           (Sail.BitVec.extractLsb word 19 0 == (0x00033#20 : BitVec 20)))
      then
        let op ← encdec_ntl_backwards mapping
        if (← currentlyEnabled extension.Ext_Zihintntl)
        then pure (some (.NTL op))
        else pure none
      else pure none) = generatedNtlProbeAlu word := by
  rfl

theorem encodeAdmittedMType_ntl_dead
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    generatedNtlMatchesAlu (encodeAdmittedMType op rs2 rs1 rd) = false := by
  simpa only [generatedNtlMatchesAlu] using
    encodeAdmittedMType_not_ntl op rs2 rs1 rd

theorem generatedNtlProbeMType_dead
    (op : AdmittedMTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    generatedNtlProbeAlu (encodeAdmittedMType op rs2 rs1 rd) =
      pure none := by
  unfold generatedNtlProbeAlu
  simp only [
    encodeAdmittedMType_ntl_dead,
    Bool.false_eq_true,
    if_false,
  ]

end LeanRV32IM.Functions
