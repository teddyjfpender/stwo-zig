import RiscvRefinement.Common

namespace RiscvRefinement.Decode

open RiscvRefinement

def luiOpcode : BitVec 7 := BitVec.ofNat 7 0x37

def addiOpcode : BitVec 7 := BitVec.ofNat 7 0x13

def addiFunct3 : BitVec 3 := BitVec.ofNat 3 0

def encodeLui (imm : BitVec 20) (rd : RegisterIndex) : InstructionWord :=
  imm.append (rd.append luiOpcode)

def encodeAddi
    (imm : BitVec 12)
    (rs1 rd : RegisterIndex) :
    InstructionWord :=
  imm.append (rs1.append (addiFunct3.append (rd.append addiOpcode)))

def decodeLuiImmediate (word : InstructionWord) : BitVec 20 :=
  BitVec.extractLsb 31 12 word

def decodeIImmediate (word : InstructionWord) : BitVec 12 :=
  BitVec.extractLsb 31 20 word

def decodeRs1 (word : InstructionWord) : RegisterIndex :=
  BitVec.extractLsb 19 15 word

def decodeRd (word : InstructionWord) : RegisterIndex :=
  BitVec.extractLsb 11 7 word

def isLui (word : InstructionWord) : Bool :=
  BitVec.extractLsb 6 0 word == luiOpcode

def isAddi (word : InstructionWord) : Bool :=
  BitVec.extractLsb 6 0 word == addiOpcode &&
    BitVec.extractLsb 14 12 word == addiFunct3

theorem encode_lui_is_canonical (imm : BitVec 20) (rd : RegisterIndex) :
    isLui (encodeLui imm rd) = true ∧
      decodeLuiImmediate (encodeLui imm rd) = imm ∧
      decodeRd (encodeLui imm rd) = rd := by
  simp only [
    isLui,
    encodeLui,
    decodeLuiImmediate,
    decodeRd,
    luiOpcode,
  ]
  bv_decide

theorem encode_addi_is_canonical
    (imm : BitVec 12)
    (rs1 rd : RegisterIndex) :
    isAddi (encodeAddi imm rs1 rd) = true ∧
      decodeIImmediate (encodeAddi imm rs1 rd) = imm ∧
      decodeRs1 (encodeAddi imm rs1 rd) = rs1 ∧
      decodeRd (encodeAddi imm rs1 rd) = rd := by
  simp only [
    isAddi,
    encodeAddi,
    decodeIImmediate,
    decodeRs1,
    decodeRd,
    addiOpcode,
    addiFunct3,
  ]
  bv_decide

end RiscvRefinement.Decode
