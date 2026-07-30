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

private theorem encodeBranchOpcode
    (kind : BranchKind)
    (encoded : BitVec 12)
    (rs2 rs1 : RegisterIndex) :
    decodeOpcodeField (encodeBranch kind encoded rs2 rs1) =
      branchOpcode := by
  simp only [
    decodeOpcodeField,
    encodeBranch,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 0) (len := 7) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 0) (len := 7) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 0) (len := 7) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 0) (len := 7) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 0) (len := 7) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 0) (len := 7) (by decide)]
  exact BitVec.extractLsb'_append_eq_right

private theorem encodeBranchFunct3
    (kind : BranchKind)
    (encoded : BitVec 12)
    (rs2 rs1 : RegisterIndex) :
    decodeFunct3 (encodeBranch kind encoded rs2 rs1) =
      kind.funct3 := by
  simp only [
    decodeFunct3,
    encodeBranch,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 12) (len := 3) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 12) (len := 3) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 12) (len := 3) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 12) (len := 3) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 12) (len := 3) (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeBranchRs1
    (kind : BranchKind)
    (encoded : BitVec 12)
    (rs2 rs1 : RegisterIndex) :
    decodeRs1 (encodeBranch kind encoded rs2 rs1) = rs1 := by
  simp only [
    decodeRs1,
    encodeBranch,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 15) (len := 5) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 15) (len := 5) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 15) (len := 5) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 15) (len := 5) (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeBranchRs2
    (kind : BranchKind)
    (encoded : BitVec 12)
    (rs2 rs1 : RegisterIndex) :
    decodeRs2 (encodeBranch kind encoded rs2 rs1) = rs2 := by
  simp only [
    decodeRs2,
    encodeBranch,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 20) (len := 5) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 20) (len := 5) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 20) (len := 5) (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeBranchSlice31
    (kind : BranchKind)
    (encoded : BitVec 12)
    (rs2 rs1 : RegisterIndex) :
    (encodeBranch kind encoded rs2 rs1).extractLsb' 31 1 =
      (branchImmediate encoded).extractLsb' 12 1 := by
  simp only [encodeBranch, BitVec.extractLsb, BitVec.append_eq]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 31) (len := 1) (by decide)]
  simp

private theorem encodeBranchSlice7
    (kind : BranchKind)
    (encoded : BitVec 12)
    (rs2 rs1 : RegisterIndex) :
    (encodeBranch kind encoded rs2 rs1).extractLsb' 7 1 =
      (branchImmediate encoded).extractLsb' 11 1 := by
  simp only [encodeBranch, BitVec.extractLsb, BitVec.append_eq]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 7) (len := 1) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 7) (len := 1) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 7) (len := 1) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 7) (len := 1) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 7) (len := 1) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 7) (len := 1) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 7) (len := 1) (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeBranchSlice25
    (kind : BranchKind)
    (encoded : BitVec 12)
    (rs2 rs1 : RegisterIndex) :
    (encodeBranch kind encoded rs2 rs1).extractLsb' 25 6 =
      (branchImmediate encoded).extractLsb' 5 6 := by
  simp only [encodeBranch, BitVec.extractLsb, BitVec.append_eq]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 25) (len := 6) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 25) (len := 6) (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeBranchSlice8
    (kind : BranchKind)
    (encoded : BitVec 12)
    (rs2 rs1 : RegisterIndex) :
    (encodeBranch kind encoded rs2 rs1).extractLsb' 8 4 =
      (branchImmediate encoded).extractLsb' 1 4 := by
  simp only [encodeBranch, BitVec.extractLsb, BitVec.append_eq]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 8) (len := 4) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 8) (len := 4) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 8) (len := 4) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 8) (len := 4) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 8) (len := 4) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 8) (len := 4) (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem branchImmediateReassemble (immediate : BitVec 13) :
    immediate.extractLsb' 12 1 ++
        (immediate.extractLsb' 11 1 ++
          (immediate.extractLsb' 5 6 ++
            (immediate.extractLsb' 1 4 ++
              immediate.extractLsb' 0 1))) =
      immediate := by
  rw [BitVec.extractLsb'_append_extractLsb'_eq_extractLsb'
    (start₁ := 0) (len₁ := 1)
    (start₂ := 1) (len₂ := 4) (by decide)]
  rw [BitVec.extractLsb'_append_extractLsb'_eq_extractLsb'
    (start₁ := 0) (len₁ := 5)
    (start₂ := 5) (len₂ := 6) (by decide)]
  rw [BitVec.extractLsb'_append_extractLsb'_eq_extractLsb'
    (start₁ := 0) (len₁ := 11)
    (start₂ := 11) (len₂ := 1) (by decide)]
  rw [BitVec.extractLsb'_append_extractLsb'_eq_extractLsb'
    (start₁ := 0) (len₁ := 12)
    (start₂ := 12) (len₂ := 1) (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem decodeBImmediateEncodeBranch
    (kind : BranchKind)
    (encoded : BitVec 12)
    (rs2 rs1 : RegisterIndex) :
    decodeBImmediate (encodeBranch kind encoded rs2 rs1) =
      branchImmediate encoded := by
  simp only [decodeBImmediate, BitVec.extractLsb, BitVec.append_eq]
  rw [
    encodeBranchSlice31,
    encodeBranchSlice7,
    encodeBranchSlice25,
    encodeBranchSlice8,
  ]
  have low :
      (branchImmediate encoded).extractLsb' 0 1 = 0#1 := by
    simp only [branchImmediate, BitVec.append_eq]
    exact BitVec.extractLsb'_append_eq_right
  rw [← low]
  exact branchImmediateReassemble (branchImmediate encoded)

theorem encode_branch_is_canonical
    (kind : BranchKind)
    (encoded : BitVec 12)
    (rs2 rs1 : RegisterIndex) :
    isBranch kind (encodeBranch kind encoded rs2 rs1) = true ∧
      decodeBImmediate (encodeBranch kind encoded rs2 rs1) =
        branchImmediate encoded ∧
      decodeRs2 (encodeBranch kind encoded rs2 rs1) = rs2 ∧
      decodeRs1 (encodeBranch kind encoded rs2 rs1) = rs1 := by
  constructor
  · simp [
      isBranch,
      encodeBranchOpcode,
      encodeBranchFunct3,
    ]
  exact ⟨decodeBImmediateEncodeBranch kind encoded rs2 rs1,
    encodeBranchRs2 kind encoded rs2 rs1,
    encodeBranchRs1 kind encoded rs2 rs1⟩

end RiscvRefinement.Decode
