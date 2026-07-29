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

def encodeFence
    (imm : BitVec 12)
    (rs1 rd : RegisterIndex) :
    InstructionWord :=
  imm.append
    (rs1.append (funct3Fence.append (rd.append miscMemOpcode)))

def isFence (word : InstructionWord) : Bool :=
  decodeOpcodeField word == miscMemOpcode &&
    decodeFunct3 word == funct3Fence

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

end RiscvRefinement.Decode
