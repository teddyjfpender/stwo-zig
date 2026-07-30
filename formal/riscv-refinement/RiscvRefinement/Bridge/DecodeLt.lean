import RiscvRefinement.Bridge.DecodeTeamB

/-!
# Canonical decode for the RV32I less-than family

The four comparison instructions share the ordinary R- and I-type encodings.
This module keeps their discriminators and canonical encode/decode theorems
separate from the shared Team A file so the family can be reviewed in
isolation.
-/

namespace RiscvRefinement.Decode

open RiscvRefinement

def funct3Slt : BitVec 3 := BitVec.ofNat 3 0b010
def funct3Sltu : BitVec 3 := BitVec.ofNat 3 0b011
def funct3Slti : BitVec 3 := BitVec.ofNat 3 0b010
def funct3Sltiu : BitVec 3 := BitVec.ofNat 3 0b011

def encodeSlt (rs2 rs1 rd : RegisterIndex) : InstructionWord :=
  encodeRType funct7Base rs2 rs1 funct3Slt rd

def encodeSltu (rs2 rs1 rd : RegisterIndex) : InstructionWord :=
  encodeRType funct7Base rs2 rs1 funct3Sltu rd

def encodeSlti
    (imm : BitVec 12)
    (rs1 rd : RegisterIndex) :
    InstructionWord :=
  imm.append (rs1.append (funct3Slti.append (rd.append opImmOpcode)))

def encodeSltiu
    (imm : BitVec 12)
    (rs1 rd : RegisterIndex) :
    InstructionWord :=
  imm.append (rs1.append (funct3Sltiu.append (rd.append opImmOpcode)))

def isSlt (word : InstructionWord) : Bool :=
  isRType funct7Base funct3Slt word

def isSltu (word : InstructionWord) : Bool :=
  isRType funct7Base funct3Sltu word

def isSlti (word : InstructionWord) : Bool :=
  decodeOpcodeField word == opImmOpcode &&
    decodeFunct3 word == funct3Slti

def isSltiu (word : InstructionWord) : Bool :=
  decodeOpcodeField word == opImmOpcode &&
    decodeFunct3 word == funct3Sltiu

theorem encode_slt_is_canonical (rs2 rs1 rd : RegisterIndex) :
    isSlt (encodeSlt rs2 rs1 rd) = true ∧
      decodeRs2 (encodeSlt rs2 rs1 rd) = rs2 ∧
      decodeRs1 (encodeSlt rs2 rs1 rd) = rs1 ∧
      decodeRd (encodeSlt rs2 rs1 rd) = rd :=
  encode_rtype_is_canonical funct7Base funct3Slt rs2 rs1 rd

theorem encode_sltu_is_canonical (rs2 rs1 rd : RegisterIndex) :
    isSltu (encodeSltu rs2 rs1 rd) = true ∧
      decodeRs2 (encodeSltu rs2 rs1 rd) = rs2 ∧
      decodeRs1 (encodeSltu rs2 rs1 rd) = rs1 ∧
      decodeRd (encodeSltu rs2 rs1 rd) = rd :=
  encode_rtype_is_canonical funct7Base funct3Sltu rs2 rs1 rd

theorem encode_slti_is_canonical
    (imm : BitVec 12)
    (rs1 rd : RegisterIndex) :
    isSlti (encodeSlti imm rs1 rd) = true ∧
      decodeIImmediate (encodeSlti imm rs1 rd) = imm ∧
      decodeRs1 (encodeSlti imm rs1 rd) = rs1 ∧
      decodeRd (encodeSlti imm rs1 rd) = rd := by
  simp only [
    isSlti,
    encodeSlti,
    decodeOpcodeField,
    decodeFunct3,
    decodeIImmediate,
    decodeRs1,
    decodeRd,
    opImmOpcode,
    funct3Slti,
  ]
  bv_decide

theorem encode_sltiu_is_canonical
    (imm : BitVec 12)
    (rs1 rd : RegisterIndex) :
    isSltiu (encodeSltiu imm rs1 rd) = true ∧
      decodeIImmediate (encodeSltiu imm rs1 rd) = imm ∧
      decodeRs1 (encodeSltiu imm rs1 rd) = rs1 ∧
      decodeRd (encodeSltiu imm rs1 rd) = rd := by
  simp only [
    isSltiu,
    encodeSltiu,
    decodeOpcodeField,
    decodeFunct3,
    decodeIImmediate,
    decodeRs1,
    decodeRd,
    opImmOpcode,
    funct3Sltiu,
  ]
  bv_decide

theorem comparison_selectors_pairwise_disjoint (word : InstructionWord) :
    ¬ (isSlt word = true ∧ isSltu word = true) ∧
      ¬ (isSlti word = true ∧ isSltiu word = true) := by
  constructor
  · rintro ⟨left, right⟩
    exact absurd (((isRType_fields left).2.1).symm.trans
      (isRType_fields right).2.1) (by decide)
  · rintro ⟨left, right⟩
    simp only [isSlti, isSltiu, Bool.and_eq_true, beq_iff_eq] at left right
    exact absurd (left.2.symm.trans right.2) (by decide)

end RiscvRefinement.Decode
