import RiscvRefinement.Bridge.DecodeTeamB

/-!
# Decode and admission for Team A opcodes

This module extends the shared RV32I field projections with the instruction
shapes owned by Team A. Each encoder theorem proves both selector admission
and exact recovery of every program-tuple operand.
-/

namespace RiscvRefinement.Decode

open RiscvRefinement

def miscMemOpcode : BitVec 7 := BitVec.ofNat 7 0x0f
def funct3Fence : BitVec 3 := BitVec.ofNat 3 0
def jalOpcode : BitVec 7 := BitVec.ofNat 7 0x6f
def auipcOpcode : BitVec 7 := BitVec.ofNat 7 0x17
def jalrOpcode : BitVec 7 := BitVec.ofNat 7 0x67
def funct3Jalr : BitVec 3 := BitVec.ofNat 3 0

def encodeFence
    (imm : BitVec 12)
    (rs1 rd : RegisterIndex) :
    InstructionWord :=
  imm.append
    (rs1.append (funct3Fence.append (rd.append miscMemOpcode)))

def isFence (word : InstructionWord) : Bool :=
  decodeOpcodeField word == miscMemOpcode &&
    decodeFunct3 word == funct3Fence

def jalImmediate (encoded : BitVec 20) : BitVec 21 :=
  encoded.append (BitVec.ofNat 1 0)

def encodeJal
    (encoded : BitVec 20)
    (rd : RegisterIndex) :
    InstructionWord :=
  let immediate := jalImmediate encoded
  (BitVec.extractLsb 20 20 immediate).append
    ((BitVec.extractLsb 10 1 immediate).append
      ((BitVec.extractLsb 11 11 immediate).append
        ((BitVec.extractLsb 19 12 immediate).append
          (rd.append jalOpcode))))

def decodeJImmediate (word : InstructionWord) : BitVec 21 :=
  (BitVec.extractLsb 31 31 word).append
    ((BitVec.extractLsb 19 12 word).append
      ((BitVec.extractLsb 20 20 word).append
        ((BitVec.extractLsb 30 21 word).append
          (BitVec.ofNat 1 0))))

def isJal (word : InstructionWord) : Bool :=
  decodeOpcodeField word == jalOpcode

def auipcImmediate (encoded : BitVec 20) : Word :=
  encoded.append (BitVec.ofNat 12 0)

def encodeAuipc
    (encoded : BitVec 20)
    (rd : RegisterIndex) :
    InstructionWord :=
  encoded.append (rd.append auipcOpcode)

def isAuipc (word : InstructionWord) : Bool :=
  decodeOpcodeField word == auipcOpcode

def encodeJalr
    (immediate : BitVec 12)
    (rs1 rd : RegisterIndex) :
    InstructionWord :=
  immediate.append
    (rs1.append (funct3Jalr.append (rd.append jalrOpcode)))

def isJalr (word : InstructionWord) : Bool :=
  decodeOpcodeField word == jalrOpcode &&
    decodeFunct3 word == funct3Jalr

theorem encode_fence_is_canonical
    (imm : BitVec 12)
    (rs1 rd : RegisterIndex) :
    isFence (encodeFence imm rs1 rd) = true ∧
      decodeIImmediate (encodeFence imm rs1 rd) = imm ∧
      decodeRs1 (encodeFence imm rs1 rd) = rs1 ∧
      decodeRd (encodeFence imm rs1 rd) = rd := by
  simp only [
    isFence,
    encodeFence,
    decodeOpcodeField,
    decodeFunct3,
    decodeIImmediate,
    decodeRs1,
    decodeRd,
    miscMemOpcode,
    funct3Fence,
  ]
  bv_decide

theorem encode_jal_is_canonical
    (encoded : BitVec 20)
    (rd : RegisterIndex) :
    isJal (encodeJal encoded rd) = true ∧
      decodeJImmediate (encodeJal encoded rd) =
        jalImmediate encoded ∧
      decodeRd (encodeJal encoded rd) = rd := by
  simp only [
    isJal,
    encodeJal,
    decodeJImmediate,
    decodeOpcodeField,
    decodeRd,
    jalImmediate,
    jalOpcode,
  ]
  bv_decide

theorem encode_auipc_is_canonical
    (encoded : BitVec 20)
    (rd : RegisterIndex) :
    isAuipc (encodeAuipc encoded rd) = true ∧
      decodeLuiImmediate (encodeAuipc encoded rd) = encoded ∧
      decodeRd (encodeAuipc encoded rd) = rd := by
  simp only [
    isAuipc,
    encodeAuipc,
    decodeOpcodeField,
    decodeLuiImmediate,
    decodeRd,
    auipcOpcode,
  ]
  bv_decide

theorem encode_jalr_is_canonical
    (immediate : BitVec 12)
    (rs1 rd : RegisterIndex) :
    isJalr (encodeJalr immediate rs1 rd) = true ∧
      decodeIImmediate (encodeJalr immediate rs1 rd) = immediate ∧
      decodeRs1 (encodeJalr immediate rs1 rd) = rs1 ∧
      decodeRd (encodeJalr immediate rs1 rd) = rd := by
  simp only [
    isJalr,
    encodeJalr,
    decodeOpcodeField,
    decodeFunct3,
    decodeIImmediate,
    decodeRs1,
    decodeRd,
    jalrOpcode,
    funct3Jalr,
  ]
  bv_decide

end RiscvRefinement.Decode
