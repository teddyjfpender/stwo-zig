import RiscvRefinement.Bridge.Decode

/-!
# Decode and admission for the 22 Team B opcodes

Canonical encode/decode for the register-register, shift-immediate, load and
store shapes, plus a per-selector admission predicate for each of the 22 opcodes
Team B owns.

Each shape is proved canonical once, generically in its `funct7`/`funct3`
discriminators, and each opcode's canonicity is an instance of that theorem. That
is what makes the rollout a family framework rather than 22 unrelated proofs.

Admission narrows: `isSll w = true` means "this word is in the zkVM language and
is SLL". It never asserts anything about words outside the admitted subset.
-/

namespace RiscvRefinement.Decode

open RiscvRefinement

/-! ## Base opcodes -/

def opOpcode : BitVec 7 := BitVec.ofNat 7 0x33

def opImmOpcode : BitVec 7 := BitVec.ofNat 7 0x13

def loadOpcode : BitVec 7 := BitVec.ofNat 7 0x03

def storeOpcode : BitVec 7 := BitVec.ofNat 7 0x23

/-! ## Field projections -/

def decodeOpcodeField (word : InstructionWord) : BitVec 7 :=
  BitVec.extractLsb 6 0 word

def decodeFunct3 (word : InstructionWord) : BitVec 3 :=
  BitVec.extractLsb 14 12 word

def decodeFunct7 (word : InstructionWord) : BitVec 7 :=
  BitVec.extractLsb 31 25 word

def decodeRs2 (word : InstructionWord) : RegisterIndex :=
  BitVec.extractLsb 24 20 word

/-- Shift amount of a shift-immediate instruction: bits 24:20. -/
def decodeShamt (word : InstructionWord) : BitVec 5 :=
  BitVec.extractLsb 24 20 word

/-- S-type immediate: bits 31:25 concatenated with bits 11:7. -/
def decodeSImmediate (word : InstructionWord) : BitVec 12 :=
  (BitVec.extractLsb 31 25 word).append (BitVec.extractLsb 11 7 word)

/-! ## Register-register shape -/

def encodeRType
    (funct7 : BitVec 7)
    (rs2 rs1 : RegisterIndex)
    (funct3 : BitVec 3)
    (rd : RegisterIndex) :
    InstructionWord :=
  funct7.append (rs2.append (rs1.append (funct3.append (rd.append opOpcode))))

def isRType
    (funct7 : BitVec 7)
    (funct3 : BitVec 3)
    (word : InstructionWord) :
    Bool :=
  decodeOpcodeField word == opOpcode &&
    decodeFunct3 word == funct3 &&
    decodeFunct7 word == funct7

theorem encode_rtype_is_canonical
    (funct7 : BitVec 7)
    (funct3 : BitVec 3)
    (rs2 rs1 rd : RegisterIndex) :
    isRType funct7 funct3 (encodeRType funct7 rs2 rs1 funct3 rd) = true ∧
      decodeRs2 (encodeRType funct7 rs2 rs1 funct3 rd) = rs2 ∧
      decodeRs1 (encodeRType funct7 rs2 rs1 funct3 rd) = rs1 ∧
      decodeRd (encodeRType funct7 rs2 rs1 funct3 rd) = rd := by
  simp only [
    isRType,
    encodeRType,
    decodeOpcodeField,
    decodeFunct3,
    decodeFunct7,
    decodeRs2,
    decodeRs1,
    decodeRd,
  ]
  bv_decide

/-! ## Shift-immediate shape -/

def encodeShiftImm
    (funct7 : BitVec 7)
    (shamt : BitVec 5)
    (rs1 : RegisterIndex)
    (funct3 : BitVec 3)
    (rd : RegisterIndex) :
    InstructionWord :=
  funct7.append (shamt.append (rs1.append (funct3.append (rd.append opImmOpcode))))

def isShiftImm
    (funct7 : BitVec 7)
    (funct3 : BitVec 3)
    (word : InstructionWord) :
    Bool :=
  decodeOpcodeField word == opImmOpcode &&
    decodeFunct3 word == funct3 &&
    decodeFunct7 word == funct7

theorem encode_shift_imm_is_canonical
    (funct7 : BitVec 7)
    (funct3 : BitVec 3)
    (shamt : BitVec 5)
    (rs1 rd : RegisterIndex) :
    isShiftImm funct7 funct3 (encodeShiftImm funct7 shamt rs1 funct3 rd) = true ∧
      decodeShamt (encodeShiftImm funct7 shamt rs1 funct3 rd) = shamt ∧
      decodeRs1 (encodeShiftImm funct7 shamt rs1 funct3 rd) = rs1 ∧
      decodeRd (encodeShiftImm funct7 shamt rs1 funct3 rd) = rd := by
  simp only [
    isShiftImm,
    encodeShiftImm,
    decodeOpcodeField,
    decodeFunct3,
    decodeFunct7,
    decodeShamt,
    decodeRs1,
    decodeRd,
  ]
  bv_decide

/-! ## Load shape -/

def encodeLoad
    (imm : BitVec 12)
    (rs1 : RegisterIndex)
    (funct3 : BitVec 3)
    (rd : RegisterIndex) :
    InstructionWord :=
  imm.append (rs1.append (funct3.append (rd.append loadOpcode)))

def isLoad (funct3 : BitVec 3) (word : InstructionWord) : Bool :=
  decodeOpcodeField word == loadOpcode && decodeFunct3 word == funct3

theorem encode_load_is_canonical
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs1 rd : RegisterIndex) :
    isLoad funct3 (encodeLoad imm rs1 funct3 rd) = true ∧
      decodeIImmediate (encodeLoad imm rs1 funct3 rd) = imm ∧
      decodeRs1 (encodeLoad imm rs1 funct3 rd) = rs1 ∧
      decodeRd (encodeLoad imm rs1 funct3 rd) = rd := by
  simp only [
    isLoad,
    encodeLoad,
    decodeOpcodeField,
    decodeFunct3,
    decodeIImmediate,
    decodeRs1,
    decodeRd,
  ]
  bv_decide

/-! ## Store shape -/

def encodeStore
    (imm : BitVec 12)
    (rs2 rs1 : RegisterIndex)
    (funct3 : BitVec 3) :
    InstructionWord :=
  (BitVec.extractLsb 11 5 imm).append
    (rs2.append
      (rs1.append
        (funct3.append
          ((BitVec.extractLsb 4 0 imm).append storeOpcode))))

def isStore (funct3 : BitVec 3) (word : InstructionWord) : Bool :=
  decodeOpcodeField word == storeOpcode && decodeFunct3 word == funct3

theorem encode_store_is_canonical
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs2 rs1 : RegisterIndex) :
    isStore funct3 (encodeStore imm rs2 rs1 funct3) = true ∧
      decodeSImmediate (encodeStore imm rs2 rs1 funct3) = imm ∧
      decodeRs2 (encodeStore imm rs2 rs1 funct3) = rs2 ∧
      decodeRs1 (encodeStore imm rs2 rs1 funct3) = rs1 := by
  simp only [
    isStore,
    encodeStore,
    decodeOpcodeField,
    decodeFunct3,
    decodeSImmediate,
    decodeRs2,
    decodeRs1,
  ]
  bv_decide

/-! ## Discriminators -/

def funct7Base : BitVec 7 := BitVec.ofNat 7 0b0000000
def funct7Alt : BitVec 7 := BitVec.ofNat 7 0b0100000
def funct7MulDiv : BitVec 7 := BitVec.ofNat 7 0b0000001

def funct3Sll : BitVec 3 := BitVec.ofNat 3 0b001
def funct3Srl : BitVec 3 := BitVec.ofNat 3 0b101
def funct3Sra : BitVec 3 := BitVec.ofNat 3 0b101

def funct3Mul : BitVec 3 := BitVec.ofNat 3 0b000
def funct3Mulh : BitVec 3 := BitVec.ofNat 3 0b001
def funct3Mulhsu : BitVec 3 := BitVec.ofNat 3 0b010
def funct3Mulhu : BitVec 3 := BitVec.ofNat 3 0b011
def funct3Div : BitVec 3 := BitVec.ofNat 3 0b100
def funct3Divu : BitVec 3 := BitVec.ofNat 3 0b101
def funct3Rem : BitVec 3 := BitVec.ofNat 3 0b110
def funct3Remu : BitVec 3 := BitVec.ofNat 3 0b111

def funct3Lb : BitVec 3 := BitVec.ofNat 3 0b000
def funct3Lh : BitVec 3 := BitVec.ofNat 3 0b001
def funct3Lw : BitVec 3 := BitVec.ofNat 3 0b010
def funct3Lbu : BitVec 3 := BitVec.ofNat 3 0b100
def funct3Lhu : BitVec 3 := BitVec.ofNat 3 0b101

def funct3Sb : BitVec 3 := BitVec.ofNat 3 0b000
def funct3Sh : BitVec 3 := BitVec.ofNat 3 0b001
def funct3Sw : BitVec 3 := BitVec.ofNat 3 0b010

/-! ## Per-opcode admission predicates -/

def isSll (word : InstructionWord) : Bool := isRType funct7Base funct3Sll word
def isSrl (word : InstructionWord) : Bool := isRType funct7Base funct3Srl word
def isSra (word : InstructionWord) : Bool := isRType funct7Alt funct3Sra word

def isSlli (word : InstructionWord) : Bool := isShiftImm funct7Base funct3Sll word
def isSrli (word : InstructionWord) : Bool := isShiftImm funct7Base funct3Srl word
def isSrai (word : InstructionWord) : Bool := isShiftImm funct7Alt funct3Sra word

def isMul (word : InstructionWord) : Bool := isRType funct7MulDiv funct3Mul word
def isMulh (word : InstructionWord) : Bool := isRType funct7MulDiv funct3Mulh word
def isMulhsu (word : InstructionWord) : Bool :=
  isRType funct7MulDiv funct3Mulhsu word
def isMulhu (word : InstructionWord) : Bool := isRType funct7MulDiv funct3Mulhu word

def isDiv (word : InstructionWord) : Bool := isRType funct7MulDiv funct3Div word
def isDivu (word : InstructionWord) : Bool := isRType funct7MulDiv funct3Divu word
def isRem (word : InstructionWord) : Bool := isRType funct7MulDiv funct3Rem word
def isRemu (word : InstructionWord) : Bool := isRType funct7MulDiv funct3Remu word

def isLb (word : InstructionWord) : Bool := isLoad funct3Lb word
def isLh (word : InstructionWord) : Bool := isLoad funct3Lh word
def isLw (word : InstructionWord) : Bool := isLoad funct3Lw word
def isLbu (word : InstructionWord) : Bool := isLoad funct3Lbu word
def isLhu (word : InstructionWord) : Bool := isLoad funct3Lhu word

def isSb (word : InstructionWord) : Bool := isStore funct3Sb word
def isSh (word : InstructionWord) : Bool := isStore funct3Sh word
def isSw (word : InstructionWord) : Bool := isStore funct3Sw word

/-! ## Encoders -/

def encodeSll (rs2 rs1 rd : RegisterIndex) : InstructionWord :=
  encodeRType funct7Base rs2 rs1 funct3Sll rd
def encodeSrl (rs2 rs1 rd : RegisterIndex) : InstructionWord :=
  encodeRType funct7Base rs2 rs1 funct3Srl rd
def encodeSra (rs2 rs1 rd : RegisterIndex) : InstructionWord :=
  encodeRType funct7Alt rs2 rs1 funct3Sra rd

def encodeSlli (shamt : BitVec 5) (rs1 rd : RegisterIndex) : InstructionWord :=
  encodeShiftImm funct7Base shamt rs1 funct3Sll rd
def encodeSrli (shamt : BitVec 5) (rs1 rd : RegisterIndex) : InstructionWord :=
  encodeShiftImm funct7Base shamt rs1 funct3Srl rd
def encodeSrai (shamt : BitVec 5) (rs1 rd : RegisterIndex) : InstructionWord :=
  encodeShiftImm funct7Alt shamt rs1 funct3Sra rd

def encodeMul (rs2 rs1 rd : RegisterIndex) : InstructionWord :=
  encodeRType funct7MulDiv rs2 rs1 funct3Mul rd
def encodeMulh (rs2 rs1 rd : RegisterIndex) : InstructionWord :=
  encodeRType funct7MulDiv rs2 rs1 funct3Mulh rd
def encodeMulhsu (rs2 rs1 rd : RegisterIndex) : InstructionWord :=
  encodeRType funct7MulDiv rs2 rs1 funct3Mulhsu rd
def encodeMulhu (rs2 rs1 rd : RegisterIndex) : InstructionWord :=
  encodeRType funct7MulDiv rs2 rs1 funct3Mulhu rd

def encodeDiv (rs2 rs1 rd : RegisterIndex) : InstructionWord :=
  encodeRType funct7MulDiv rs2 rs1 funct3Div rd
def encodeDivu (rs2 rs1 rd : RegisterIndex) : InstructionWord :=
  encodeRType funct7MulDiv rs2 rs1 funct3Divu rd
def encodeRem (rs2 rs1 rd : RegisterIndex) : InstructionWord :=
  encodeRType funct7MulDiv rs2 rs1 funct3Rem rd
def encodeRemu (rs2 rs1 rd : RegisterIndex) : InstructionWord :=
  encodeRType funct7MulDiv rs2 rs1 funct3Remu rd

def encodeLb (imm : BitVec 12) (rs1 rd : RegisterIndex) : InstructionWord :=
  encodeLoad imm rs1 funct3Lb rd
def encodeLh (imm : BitVec 12) (rs1 rd : RegisterIndex) : InstructionWord :=
  encodeLoad imm rs1 funct3Lh rd
def encodeLw (imm : BitVec 12) (rs1 rd : RegisterIndex) : InstructionWord :=
  encodeLoad imm rs1 funct3Lw rd
def encodeLbu (imm : BitVec 12) (rs1 rd : RegisterIndex) : InstructionWord :=
  encodeLoad imm rs1 funct3Lbu rd
def encodeLhu (imm : BitVec 12) (rs1 rd : RegisterIndex) : InstructionWord :=
  encodeLoad imm rs1 funct3Lhu rd

def encodeSb (imm : BitVec 12) (rs2 rs1 : RegisterIndex) : InstructionWord :=
  encodeStore imm rs2 rs1 funct3Sb
def encodeSh (imm : BitVec 12) (rs2 rs1 : RegisterIndex) : InstructionWord :=
  encodeStore imm rs2 rs1 funct3Sh
def encodeSw (imm : BitVec 12) (rs2 rs1 : RegisterIndex) : InstructionWord :=
  encodeStore imm rs2 rs1 funct3Sw

/-! ## Per-opcode canonicity, each an instance of its shape theorem -/

theorem encode_sll_is_canonical (rs2 rs1 rd : RegisterIndex) :
    isSll (encodeSll rs2 rs1 rd) = true ∧
      decodeRs2 (encodeSll rs2 rs1 rd) = rs2 ∧
      decodeRs1 (encodeSll rs2 rs1 rd) = rs1 ∧
      decodeRd (encodeSll rs2 rs1 rd) = rd :=
  encode_rtype_is_canonical funct7Base funct3Sll rs2 rs1 rd

theorem encode_srl_is_canonical (rs2 rs1 rd : RegisterIndex) :
    isSrl (encodeSrl rs2 rs1 rd) = true ∧
      decodeRs2 (encodeSrl rs2 rs1 rd) = rs2 ∧
      decodeRs1 (encodeSrl rs2 rs1 rd) = rs1 ∧
      decodeRd (encodeSrl rs2 rs1 rd) = rd :=
  encode_rtype_is_canonical funct7Base funct3Srl rs2 rs1 rd

theorem encode_sra_is_canonical (rs2 rs1 rd : RegisterIndex) :
    isSra (encodeSra rs2 rs1 rd) = true ∧
      decodeRs2 (encodeSra rs2 rs1 rd) = rs2 ∧
      decodeRs1 (encodeSra rs2 rs1 rd) = rs1 ∧
      decodeRd (encodeSra rs2 rs1 rd) = rd :=
  encode_rtype_is_canonical funct7Alt funct3Sra rs2 rs1 rd

theorem encode_slli_is_canonical
    (shamt : BitVec 5) (rs1 rd : RegisterIndex) :
    isSlli (encodeSlli shamt rs1 rd) = true ∧
      decodeShamt (encodeSlli shamt rs1 rd) = shamt ∧
      decodeRs1 (encodeSlli shamt rs1 rd) = rs1 ∧
      decodeRd (encodeSlli shamt rs1 rd) = rd :=
  encode_shift_imm_is_canonical funct7Base funct3Sll shamt rs1 rd

theorem encode_srli_is_canonical
    (shamt : BitVec 5) (rs1 rd : RegisterIndex) :
    isSrli (encodeSrli shamt rs1 rd) = true ∧
      decodeShamt (encodeSrli shamt rs1 rd) = shamt ∧
      decodeRs1 (encodeSrli shamt rs1 rd) = rs1 ∧
      decodeRd (encodeSrli shamt rs1 rd) = rd :=
  encode_shift_imm_is_canonical funct7Base funct3Srl shamt rs1 rd

theorem encode_srai_is_canonical
    (shamt : BitVec 5) (rs1 rd : RegisterIndex) :
    isSrai (encodeSrai shamt rs1 rd) = true ∧
      decodeShamt (encodeSrai shamt rs1 rd) = shamt ∧
      decodeRs1 (encodeSrai shamt rs1 rd) = rs1 ∧
      decodeRd (encodeSrai shamt rs1 rd) = rd :=
  encode_shift_imm_is_canonical funct7Alt funct3Sra shamt rs1 rd

theorem encode_mul_is_canonical (rs2 rs1 rd : RegisterIndex) :
    isMul (encodeMul rs2 rs1 rd) = true ∧
      decodeRs2 (encodeMul rs2 rs1 rd) = rs2 ∧
      decodeRs1 (encodeMul rs2 rs1 rd) = rs1 ∧
      decodeRd (encodeMul rs2 rs1 rd) = rd :=
  encode_rtype_is_canonical funct7MulDiv funct3Mul rs2 rs1 rd

theorem encode_mulh_is_canonical (rs2 rs1 rd : RegisterIndex) :
    isMulh (encodeMulh rs2 rs1 rd) = true ∧
      decodeRs2 (encodeMulh rs2 rs1 rd) = rs2 ∧
      decodeRs1 (encodeMulh rs2 rs1 rd) = rs1 ∧
      decodeRd (encodeMulh rs2 rs1 rd) = rd :=
  encode_rtype_is_canonical funct7MulDiv funct3Mulh rs2 rs1 rd

theorem encode_mulhsu_is_canonical (rs2 rs1 rd : RegisterIndex) :
    isMulhsu (encodeMulhsu rs2 rs1 rd) = true ∧
      decodeRs2 (encodeMulhsu rs2 rs1 rd) = rs2 ∧
      decodeRs1 (encodeMulhsu rs2 rs1 rd) = rs1 ∧
      decodeRd (encodeMulhsu rs2 rs1 rd) = rd :=
  encode_rtype_is_canonical funct7MulDiv funct3Mulhsu rs2 rs1 rd

theorem encode_mulhu_is_canonical (rs2 rs1 rd : RegisterIndex) :
    isMulhu (encodeMulhu rs2 rs1 rd) = true ∧
      decodeRs2 (encodeMulhu rs2 rs1 rd) = rs2 ∧
      decodeRs1 (encodeMulhu rs2 rs1 rd) = rs1 ∧
      decodeRd (encodeMulhu rs2 rs1 rd) = rd :=
  encode_rtype_is_canonical funct7MulDiv funct3Mulhu rs2 rs1 rd

theorem encode_div_is_canonical (rs2 rs1 rd : RegisterIndex) :
    isDiv (encodeDiv rs2 rs1 rd) = true ∧
      decodeRs2 (encodeDiv rs2 rs1 rd) = rs2 ∧
      decodeRs1 (encodeDiv rs2 rs1 rd) = rs1 ∧
      decodeRd (encodeDiv rs2 rs1 rd) = rd :=
  encode_rtype_is_canonical funct7MulDiv funct3Div rs2 rs1 rd

theorem encode_divu_is_canonical (rs2 rs1 rd : RegisterIndex) :
    isDivu (encodeDivu rs2 rs1 rd) = true ∧
      decodeRs2 (encodeDivu rs2 rs1 rd) = rs2 ∧
      decodeRs1 (encodeDivu rs2 rs1 rd) = rs1 ∧
      decodeRd (encodeDivu rs2 rs1 rd) = rd :=
  encode_rtype_is_canonical funct7MulDiv funct3Divu rs2 rs1 rd

theorem encode_rem_is_canonical (rs2 rs1 rd : RegisterIndex) :
    isRem (encodeRem rs2 rs1 rd) = true ∧
      decodeRs2 (encodeRem rs2 rs1 rd) = rs2 ∧
      decodeRs1 (encodeRem rs2 rs1 rd) = rs1 ∧
      decodeRd (encodeRem rs2 rs1 rd) = rd :=
  encode_rtype_is_canonical funct7MulDiv funct3Rem rs2 rs1 rd

theorem encode_remu_is_canonical (rs2 rs1 rd : RegisterIndex) :
    isRemu (encodeRemu rs2 rs1 rd) = true ∧
      decodeRs2 (encodeRemu rs2 rs1 rd) = rs2 ∧
      decodeRs1 (encodeRemu rs2 rs1 rd) = rs1 ∧
      decodeRd (encodeRemu rs2 rs1 rd) = rd :=
  encode_rtype_is_canonical funct7MulDiv funct3Remu rs2 rs1 rd

theorem encode_lb_is_canonical
    (imm : BitVec 12) (rs1 rd : RegisterIndex) :
    isLb (encodeLb imm rs1 rd) = true ∧
      decodeIImmediate (encodeLb imm rs1 rd) = imm ∧
      decodeRs1 (encodeLb imm rs1 rd) = rs1 ∧
      decodeRd (encodeLb imm rs1 rd) = rd :=
  encode_load_is_canonical funct3Lb imm rs1 rd

theorem encode_lh_is_canonical
    (imm : BitVec 12) (rs1 rd : RegisterIndex) :
    isLh (encodeLh imm rs1 rd) = true ∧
      decodeIImmediate (encodeLh imm rs1 rd) = imm ∧
      decodeRs1 (encodeLh imm rs1 rd) = rs1 ∧
      decodeRd (encodeLh imm rs1 rd) = rd :=
  encode_load_is_canonical funct3Lh imm rs1 rd

theorem encode_lw_is_canonical
    (imm : BitVec 12) (rs1 rd : RegisterIndex) :
    isLw (encodeLw imm rs1 rd) = true ∧
      decodeIImmediate (encodeLw imm rs1 rd) = imm ∧
      decodeRs1 (encodeLw imm rs1 rd) = rs1 ∧
      decodeRd (encodeLw imm rs1 rd) = rd :=
  encode_load_is_canonical funct3Lw imm rs1 rd

theorem encode_lbu_is_canonical
    (imm : BitVec 12) (rs1 rd : RegisterIndex) :
    isLbu (encodeLbu imm rs1 rd) = true ∧
      decodeIImmediate (encodeLbu imm rs1 rd) = imm ∧
      decodeRs1 (encodeLbu imm rs1 rd) = rs1 ∧
      decodeRd (encodeLbu imm rs1 rd) = rd :=
  encode_load_is_canonical funct3Lbu imm rs1 rd

theorem encode_lhu_is_canonical
    (imm : BitVec 12) (rs1 rd : RegisterIndex) :
    isLhu (encodeLhu imm rs1 rd) = true ∧
      decodeIImmediate (encodeLhu imm rs1 rd) = imm ∧
      decodeRs1 (encodeLhu imm rs1 rd) = rs1 ∧
      decodeRd (encodeLhu imm rs1 rd) = rd :=
  encode_load_is_canonical funct3Lhu imm rs1 rd

theorem encode_sb_is_canonical
    (imm : BitVec 12) (rs2 rs1 : RegisterIndex) :
    isSb (encodeSb imm rs2 rs1) = true ∧
      decodeSImmediate (encodeSb imm rs2 rs1) = imm ∧
      decodeRs2 (encodeSb imm rs2 rs1) = rs2 ∧
      decodeRs1 (encodeSb imm rs2 rs1) = rs1 :=
  encode_store_is_canonical funct3Sb imm rs2 rs1

theorem encode_sh_is_canonical
    (imm : BitVec 12) (rs2 rs1 : RegisterIndex) :
    isSh (encodeSh imm rs2 rs1) = true ∧
      decodeSImmediate (encodeSh imm rs2 rs1) = imm ∧
      decodeRs2 (encodeSh imm rs2 rs1) = rs2 ∧
      decodeRs1 (encodeSh imm rs2 rs1) = rs1 :=
  encode_store_is_canonical funct3Sh imm rs2 rs1

theorem encode_sw_is_canonical
    (imm : BitVec 12) (rs2 rs1 : RegisterIndex) :
    isSw (encodeSw imm rs2 rs1) = true ∧
      decodeSImmediate (encodeSw imm rs2 rs1) = imm ∧
      decodeRs2 (encodeSw imm rs2 rs1) = rs2 ∧
      decodeRs1 (encodeSw imm rs2 rs1) = rs1 :=
  encode_store_is_canonical funct3Sw imm rs2 rs1

/-! ## Admission is exclusive

The shapes are pairwise disjoint, and within a shape the discriminators separate
the selectors. Together with the exclusion of `FENCE.I` this is what makes the
zkVM language a conservative subset rather than a reinterpretation.

Each disjointness result is a contradiction between two *concrete* field
constants, so it is settled by `decide` on a pair of small bit vectors. Asking a
bit-blasting decision procedure to refute the conjunction directly would work
too, but it would attach a solver certificate as a per-theorem dependency, and this
development admits only `propext`, `Classical.choice` and `Quot.sound`. -/

theorem isRType_fields
    {funct7 : BitVec 7} {funct3 : BitVec 3} {word : InstructionWord}
    (admitted : isRType funct7 funct3 word = true) :
    decodeOpcodeField word = opOpcode ∧
      decodeFunct3 word = funct3 ∧ decodeFunct7 word = funct7 := by
  simp only [isRType, Bool.and_eq_true, beq_iff_eq] at admitted
  exact ⟨admitted.1.1, admitted.1.2, admitted.2⟩

theorem isShiftImm_fields
    {funct7 : BitVec 7} {funct3 : BitVec 3} {word : InstructionWord}
    (admitted : isShiftImm funct7 funct3 word = true) :
    decodeOpcodeField word = opImmOpcode ∧
      decodeFunct3 word = funct3 ∧ decodeFunct7 word = funct7 := by
  simp only [isShiftImm, Bool.and_eq_true, beq_iff_eq] at admitted
  exact ⟨admitted.1.1, admitted.1.2, admitted.2⟩

theorem isLoad_fields
    {funct3 : BitVec 3} {word : InstructionWord}
    (admitted : isLoad funct3 word = true) :
    decodeOpcodeField word = loadOpcode ∧ decodeFunct3 word = funct3 := by
  simp only [isLoad, Bool.and_eq_true, beq_iff_eq] at admitted
  exact admitted

theorem isStore_fields
    {funct3 : BitVec 3} {word : InstructionWord}
    (admitted : isStore funct3 word = true) :
    decodeOpcodeField word = storeOpcode ∧ decodeFunct3 word = funct3 := by
  simp only [isStore, Bool.and_eq_true, beq_iff_eq] at admitted
  exact admitted

/-- The four instruction shapes carry four different base opcodes. -/
theorem shapes_are_disjoint (word : InstructionWord) :
    ¬(isSll word = true ∧ isSlli word = true) ∧
      ¬(isSll word = true ∧ isLb word = true) ∧
      ¬(isSll word = true ∧ isSb word = true) ∧
      ¬(isSlli word = true ∧ isLb word = true) ∧
      ¬(isSlli word = true ∧ isSb word = true) ∧
      ¬(isLb word = true ∧ isSb word = true) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩ <;> rintro ⟨left, right⟩
  · exact absurd (((isRType_fields left).1).symm.trans
      (isShiftImm_fields right).1) (by decide)
  · exact absurd (((isRType_fields left).1).symm.trans
      (isLoad_fields right).1) (by decide)
  · exact absurd (((isRType_fields left).1).symm.trans
      (isStore_fields right).1) (by decide)
  · exact absurd (((isShiftImm_fields left).1).symm.trans
      (isLoad_fields right).1) (by decide)
  · exact absurd (((isShiftImm_fields left).1).symm.trans
      (isStore_fields right).1) (by decide)
  · exact absurd (((isLoad_fields left).1).symm.trans
      (isStore_fields right).1) (by decide)

/-- Within the shift-immediate shape the selectors differ in `funct3` or, for
`SRLI` against `SRAI`, only in `funct7`. -/
theorem shift_selectors_are_disjoint (word : InstructionWord) :
    ¬(isSrli word = true ∧ isSrai word = true) ∧
      ¬(isSlli word = true ∧ isSrli word = true) ∧
      ¬(isSlli word = true ∧ isSrai word = true) := by
  refine ⟨?_, ?_, ?_⟩ <;> rintro ⟨left, right⟩
  · exact absurd (((isShiftImm_fields left).2.2).symm.trans
      (isShiftImm_fields right).2.2) (by decide)
  · exact absurd (((isShiftImm_fields left).2.1).symm.trans
      (isShiftImm_fields right).2.1) (by decide)
  · exact absurd (((isShiftImm_fields left).2.1).symm.trans
      (isShiftImm_fields right).2.1) (by decide)

theorem load_selectors_are_disjoint (word : InstructionWord) :
    ¬(isLb word = true ∧ isLh word = true) ∧
      ¬(isLb word = true ∧ isLw word = true) ∧
      ¬(isLh word = true ∧ isLhu word = true) ∧
      ¬(isLbu word = true ∧ isLhu word = true) := by
  refine ⟨?_, ?_, ?_, ?_⟩ <;> rintro ⟨left, right⟩ <;>
    exact absurd (((isLoad_fields left).2).symm.trans
      (isLoad_fields right).2) (by decide)

theorem multiply_and_divide_selectors_are_disjoint (word : InstructionWord) :
    ¬(isMul word = true ∧ isMulh word = true) ∧
      ¬(isMulhsu word = true ∧ isMulhu word = true) ∧
      ¬(isDiv word = true ∧ isDivu word = true) ∧
      ¬(isRem word = true ∧ isRemu word = true) ∧
      ¬(isMul word = true ∧ isDiv word = true) := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> rintro ⟨left, right⟩ <;>
    exact absurd (((isRType_fields left).2.1).symm.trans
      (isRType_fields right).2.1) (by decide)

/-- `SLL` and `MUL` share the register-register shape and are separated only by
`funct7`, so the M-extension discriminator is load-bearing. -/
theorem base_and_m_extension_are_disjoint (word : InstructionWord) :
    ¬(isSll word = true ∧ isMulh word = true) ∧
      ¬(isSrl word = true ∧ isDivu word = true) ∧
      ¬(isSra word = true ∧ isDivu word = true) := by
  refine ⟨?_, ?_, ?_⟩ <;> rintro ⟨left, right⟩ <;>
    exact absurd (((isRType_fields left).2.2).symm.trans
      (isRType_fields right).2.2) (by decide)

/-- `FENCE.I` is outside every Team B admission predicate. The pinned model
retires it despite `Zifencei` being unsupported; the zkVM rejects it, and this
theorem is the ingress half of that narrowing. -/
theorem fence_i_is_not_admitted :
    isSll (BitVec.ofNat 32 0x0000100F) = false ∧
      isSlli (BitVec.ofNat 32 0x0000100F) = false ∧
      isLb (BitVec.ofNat 32 0x0000100F) = false ∧
      isLh (BitVec.ofNat 32 0x0000100F) = false ∧
      isLw (BitVec.ofNat 32 0x0000100F) = false ∧
      isSb (BitVec.ofNat 32 0x0000100F) = false ∧
      isMul (BitVec.ofNat 32 0x0000100F) = false ∧
      isDiv (BitVec.ofNat 32 0x0000100F) = false := by
  decide

end RiscvRefinement.Decode
