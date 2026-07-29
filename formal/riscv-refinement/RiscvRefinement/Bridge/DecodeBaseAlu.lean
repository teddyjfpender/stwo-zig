import RiscvRefinement.Bridge.DecodeTeamB

/-!
# Canonical decode for the Team A base-ALU selectors

The production base-ALU families share the ordinary RV32I R- and I-type
layouts.  The opcode-specific functions below instantiate those layouts with
the architectural `funct7`/`funct3` discriminators and prove exact recovery of
every field published by the production program lookup.
-/

namespace RiscvRefinement.Decode

open RiscvRefinement

inductive BaseAluRegOp where
  | add | sub | xor | or | and
deriving DecidableEq, Repr

inductive BaseAluImmOp where
  | xori | ori | andi
deriving DecidableEq, Repr

def baseAluRegFunct7 : BaseAluRegOp → BitVec 7
  | .sub => funct7Alt
  | _ => funct7Base

def baseAluRegFunct3 : BaseAluRegOp → BitVec 3
  | .add | .sub => BitVec.ofNat 3 0b000
  | .xor => BitVec.ofNat 3 0b100
  | .or => BitVec.ofNat 3 0b110
  | .and => BitVec.ofNat 3 0b111

def baseAluRegOpcodeId : BaseAluRegOp → Nat
  | .add => 0
  | .sub => 1
  | .xor => 5
  | .or => 8
  | .and => 9

def encodeBaseAluReg
    (op : BaseAluRegOp)
    (rs2 rs1 rd : RegisterIndex) :
    InstructionWord :=
  encodeRType
    (baseAluRegFunct7 op) rs2 rs1 (baseAluRegFunct3 op) rd

def isBaseAluReg (op : BaseAluRegOp) (word : InstructionWord) : Bool :=
  isRType (baseAluRegFunct7 op) (baseAluRegFunct3 op) word

theorem encode_base_alu_reg_is_canonical
    (op : BaseAluRegOp)
    (rs2 rs1 rd : RegisterIndex) :
    isBaseAluReg op (encodeBaseAluReg op rs2 rs1 rd) = true ∧
      decodeRs2 (encodeBaseAluReg op rs2 rs1 rd) = rs2 ∧
      decodeRs1 (encodeBaseAluReg op rs2 rs1 rd) = rs1 ∧
      decodeRd (encodeBaseAluReg op rs2 rs1 rd) = rd := by
  exact
    encode_rtype_is_canonical
      (baseAluRegFunct7 op) (baseAluRegFunct3 op) rs2 rs1 rd

def baseAluImmFunct3 : BaseAluImmOp → BitVec 3
  | .xori => BitVec.ofNat 3 0b100
  | .ori => BitVec.ofNat 3 0b110
  | .andi => BitVec.ofNat 3 0b111

def baseAluImmOpcodeId : BaseAluImmOp → Nat
  | .xori => 13
  | .ori => 14
  | .andi => 15

def encodeBaseAluImm
    (op : BaseAluImmOp)
    (imm : BitVec 12)
    (rs1 rd : RegisterIndex) :
    InstructionWord :=
  imm.append
    (rs1.append
      ((baseAluImmFunct3 op).append (rd.append opImmOpcode)))

def isBaseAluImm (op : BaseAluImmOp) (word : InstructionWord) : Bool :=
  decodeOpcodeField word == opImmOpcode &&
    decodeFunct3 word == baseAluImmFunct3 op

theorem encode_base_alu_imm_is_canonical
    (op : BaseAluImmOp)
    (imm : BitVec 12)
    (rs1 rd : RegisterIndex) :
    isBaseAluImm op (encodeBaseAluImm op imm rs1 rd) = true ∧
      decodeIImmediate (encodeBaseAluImm op imm rs1 rd) = imm ∧
      decodeRs1 (encodeBaseAluImm op imm rs1 rd) = rs1 ∧
      decodeRd (encodeBaseAluImm op imm rs1 rd) = rd := by
  cases op <;>
    simp only [
      isBaseAluImm,
      encodeBaseAluImm,
      baseAluImmFunct3,
      decodeOpcodeField,
      decodeFunct3,
      decodeIImmediate,
      decodeRs1,
      decodeRd,
      opImmOpcode,
    ] <;>
    bv_decide

end RiscvRefinement.Decode
