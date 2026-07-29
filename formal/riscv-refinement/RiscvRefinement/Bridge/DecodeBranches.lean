import RiscvRefinement.Bridge.DecodeTeamB

/-!
# Canonical RV32I branch decode

The branch immediate is represented by the twelve encoded bits above its
architectural low zero.  `branchImmediate` restores that zero, while
`encodeBranch` places the resulting thirteen bits in the split B-type fields.
-/

namespace RiscvRefinement.Decode

open RiscvRefinement

inductive BranchKind where
  | beq
  | bne
  | blt
  | bge
  | bltu
  | bgeu
deriving DecidableEq, Repr

def branchOpcode : BitVec 7 := BitVec.ofNat 7 0x63

def BranchKind.funct3 : BranchKind → BitVec 3
  | .beq => BitVec.ofNat 3 0
  | .bne => BitVec.ofNat 3 1
  | .blt => BitVec.ofNat 3 4
  | .bge => BitVec.ofNat 3 5
  | .bltu => BitVec.ofNat 3 6
  | .bgeu => BitVec.ofNat 3 7

def BranchKind.manifestId : BranchKind → Nat
  | .beq => 27
  | .bne => 28
  | .blt => 29
  | .bge => 30
  | .bltu => 31
  | .bgeu => 32

def BranchKind.isEquality : BranchKind → Bool
  | .beq | .bne => true
  | _ => false

def BranchKind.isSigned : BranchKind → Bool
  | .blt | .bge => true
  | _ => false

def BranchKind.isLess : BranchKind → Bool
  | .blt | .bltu => true
  | _ => false

def branchImmediate (encoded : BitVec 12) : BitVec 13 :=
  encoded.append (BitVec.ofNat 1 0)

def encodeBranch
    (kind : BranchKind)
    (encoded : BitVec 12)
    (rs2 rs1 : RegisterIndex) :
    InstructionWord :=
  let immediate := branchImmediate encoded
  (BitVec.extractLsb 12 12 immediate).append
    ((BitVec.extractLsb 10 5 immediate).append
      (rs2.append
        (rs1.append
          (kind.funct3.append
            ((BitVec.extractLsb 4 1 immediate).append
              ((BitVec.extractLsb 11 11 immediate).append
                branchOpcode))))))

def decodeBImmediate (word : InstructionWord) : BitVec 13 :=
  (BitVec.extractLsb 31 31 word).append
    ((BitVec.extractLsb 7 7 word).append
      ((BitVec.extractLsb 30 25 word).append
        ((BitVec.extractLsb 11 8 word).append
          (BitVec.ofNat 1 0))))

def isBranch (kind : BranchKind) (word : InstructionWord) : Bool :=
  decodeOpcodeField word == branchOpcode &&
    decodeFunct3 word == kind.funct3

theorem encode_branch_is_canonical
    (kind : BranchKind)
    (encoded : BitVec 12)
    (rs2 rs1 : RegisterIndex) :
    isBranch kind (encodeBranch kind encoded rs2 rs1) = true ∧
      decodeBImmediate (encodeBranch kind encoded rs2 rs1) =
        branchImmediate encoded ∧
      decodeRs2 (encodeBranch kind encoded rs2 rs1) = rs2 ∧
      decodeRs1 (encodeBranch kind encoded rs2 rs1) = rs1 := by
  cases kind <;>
    simp only [
      isBranch,
      encodeBranch,
      decodeBImmediate,
      decodeRs2,
      decodeRs1,
      decodeOpcodeField,
      decodeFunct3,
      branchImmediate,
      branchOpcode,
      BranchKind.funct3,
    ] <;>
    bv_decide

end RiscvRefinement.Decode
