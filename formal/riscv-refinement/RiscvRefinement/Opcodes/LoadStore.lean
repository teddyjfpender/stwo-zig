import RiscvRefinement.Air.Family.LoadStore
import RiscvRefinement.Sail.Reviewed.LoadStore

/-!
# `load_store` refinement: `LB`, `LH`, `LW`, `LBU`, `LHU`, `SB`, `SH`, `SW`

Each theorem derives the reviewed architectural retirement of
`RiscvRefinement.Sail.Reviewed` **from** the transcribed production AIR
constraints of `RiscvRefinement.Air.Family`. No theorem assumes its own
conclusion: the only hypotheses are `LoadStoreHolds` (the AIR), the decoding
environment, and the opcode's own selector flag.

The architectural side is a reviewed capsule, not a generated-Sail theorem; see
the header of `RiscvRefinement/Sail/Reviewed/LoadStore.lean`.
-/

namespace RiscvRefinement.Opcodes

open RiscvRefinement
open RiscvRefinement.Air.Family
open RiscvRefinement.Sail.Reviewed

/-! ## Decoding bridge

`Bridge/Decode.lean` covers only the pilot's `LUI`/`ADDI`; the I-type load and
S-type store encodings live here in their own namespace. -/

namespace LoadStoreDecode

def loadOpcode : BitVec 7 := BitVec.ofNat 7 0x03

def storeOpcode : BitVec 7 := BitVec.ofNat 7 0x23

def funct3Lb : BitVec 3 := BitVec.ofNat 3 0
def funct3Lh : BitVec 3 := BitVec.ofNat 3 1
def funct3Lw : BitVec 3 := BitVec.ofNat 3 2
def funct3Lbu : BitVec 3 := BitVec.ofNat 3 4
def funct3Lhu : BitVec 3 := BitVec.ofNat 3 5
def funct3Sb : BitVec 3 := BitVec.ofNat 3 0
def funct3Sh : BitVec 3 := BitVec.ofNat 3 1
def funct3Sw : BitVec 3 := BitVec.ofNat 3 2

/-- I-type: `imm[11:0] | rs1 | funct3 | rd | opcode`. -/
def encodeLoad
    (imm : BitVec 12)
    (rs1 rd : RegisterIndex)
    (funct3 : BitVec 3) :
    InstructionWord :=
  imm.append (rs1.append (funct3.append (rd.append loadOpcode)))

/-- S-type: `imm[11:5] | rs2 | rs1 | funct3 | imm[4:0] | opcode`. -/
def encodeStore
    (imm : BitVec 12)
    (rs2 rs1 : RegisterIndex)
    (funct3 : BitVec 3) :
    InstructionWord :=
  (BitVec.extractLsb 11 5 imm).append
    (rs2.append
      (rs1.append
        (funct3.append ((BitVec.extractLsb 4 0 imm).append storeOpcode))))

def decodeOpcode (word : InstructionWord) : BitVec 7 :=
  BitVec.extractLsb 6 0 word

def decodeFunct3 (word : InstructionWord) : BitVec 3 :=
  BitVec.extractLsb 14 12 word

def decodeRd (word : InstructionWord) : RegisterIndex :=
  BitVec.extractLsb 11 7 word

def decodeRs1 (word : InstructionWord) : RegisterIndex :=
  BitVec.extractLsb 19 15 word

def decodeRs2 (word : InstructionWord) : RegisterIndex :=
  BitVec.extractLsb 24 20 word

def decodeIImmediate (word : InstructionWord) : BitVec 12 :=
  BitVec.extractLsb 31 20 word

def decodeSImmediate (word : InstructionWord) : BitVec 12 :=
  (BitVec.extractLsb 31 25 word).append (BitVec.extractLsb 11 7 word)

def isLoadOf (word : InstructionWord) (funct3 : BitVec 3) : Bool :=
  decodeOpcode word == loadOpcode && decodeFunct3 word == funct3

def isStoreOf (word : InstructionWord) (funct3 : BitVec 3) : Bool :=
  decodeOpcode word == storeOpcode && decodeFunct3 word == funct3

theorem encode_load_is_canonical
    (imm : BitVec 12)
    (rs1 rd : RegisterIndex)
    (funct3 : BitVec 3) :
    isLoadOf (encodeLoad imm rs1 rd funct3) funct3 = true ∧
      decodeIImmediate (encodeLoad imm rs1 rd funct3) = imm ∧
      decodeRs1 (encodeLoad imm rs1 rd funct3) = rs1 ∧
      decodeRd (encodeLoad imm rs1 rd funct3) = rd := by
  simp only [
    isLoadOf, encodeLoad, decodeOpcode, decodeFunct3, decodeIImmediate,
    decodeRs1, decodeRd, loadOpcode,
  ]
  bv_decide

theorem encode_store_is_canonical
    (imm : BitVec 12)
    (rs2 rs1 : RegisterIndex)
    (funct3 : BitVec 3) :
    isStoreOf (encodeStore imm rs2 rs1 funct3) funct3 = true ∧
      decodeSImmediate (encodeStore imm rs2 rs1 funct3) = imm ∧
      decodeRs1 (encodeStore imm rs2 rs1 funct3) = rs1 ∧
      decodeRs2 (encodeStore imm rs2 rs1 funct3) = rs2 := by
  simp only [
    isStoreOf, encodeStore, decodeOpcode, decodeFunct3, decodeSImmediate,
    decodeRs1, decodeRs2, storeOpcode,
  ]
  bv_decide

/-- The instruction word a row claims, dispatched on the committed selector.
`r2_idx` is `rd` for a load and `rs2` for a store, exactly as the production
program relation reads it. -/
def encoding (row : LoadStoreRow) (imm : BitVec 12) : InstructionWord :=
  if row.isLb then encodeLoad imm row.rs1Addr row.r2Idx funct3Lb
  else if row.isLh then encodeLoad imm row.rs1Addr row.r2Idx funct3Lh
  else if row.isLw then encodeLoad imm row.rs1Addr row.r2Idx funct3Lw
  else if row.isLbu then encodeLoad imm row.rs1Addr row.r2Idx funct3Lbu
  else if row.isLhu then encodeLoad imm row.rs1Addr row.r2Idx funct3Lhu
  else if row.isSb then encodeStore imm row.r2Idx row.rs1Addr funct3Sb
  else if row.isSh then encodeStore imm row.r2Idx row.rs1Addr funct3Sh
  else encodeStore imm row.r2Idx row.rs1Addr funct3Sw

end LoadStoreDecode

/-! ## Selector and marker combinatorics

C00/C69 make the eight opcode flags an exact one-hot vector, and C18-C20 pin
the marker set of a byte or halfword access. These are the finite facts every
opcode theorem starts from. -/

/-- The one-hot decomposition forced by C00 together with C69. -/
theorem selector_cases (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    (row.isLb = true ∧ row.isLh = false ∧ row.isLbu = false ∧
        row.isLhu = false ∧ row.isLw = false ∧ row.isSb = false ∧
        row.isSh = false ∧ row.isSw = false) ∨
      (row.isLb = false ∧ row.isLh = true ∧ row.isLbu = false ∧
        row.isLhu = false ∧ row.isLw = false ∧ row.isSb = false ∧
        row.isSh = false ∧ row.isSw = false) ∨
      (row.isLb = false ∧ row.isLh = false ∧ row.isLbu = true ∧
        row.isLhu = false ∧ row.isLw = false ∧ row.isSb = false ∧
        row.isSh = false ∧ row.isSw = false) ∨
      (row.isLb = false ∧ row.isLh = false ∧ row.isLbu = false ∧
        row.isLhu = true ∧ row.isLw = false ∧ row.isSb = false ∧
        row.isSh = false ∧ row.isSw = false) ∨
      (row.isLb = false ∧ row.isLh = false ∧ row.isLbu = false ∧
        row.isLhu = false ∧ row.isLw = true ∧ row.isSb = false ∧
        row.isSh = false ∧ row.isSw = false) ∨
      (row.isLb = false ∧ row.isLh = false ∧ row.isLbu = false ∧
        row.isLhu = false ∧ row.isLw = false ∧ row.isSb = true ∧
        row.isSh = false ∧ row.isSw = false) ∨
      (row.isLb = false ∧ row.isLh = false ∧ row.isLbu = false ∧
        row.isLhu = false ∧ row.isLw = false ∧ row.isSb = false ∧
        row.isSh = true ∧ row.isSw = false) ∨
      (row.isLb = false ∧ row.isLh = false ∧ row.isLbu = false ∧
        row.isLhu = false ∧ row.isLw = false ∧ row.isSb = false ∧
        row.isSh = false ∧ row.isSw = true) := by
  have sum := holds.selectorSum
  simp only [LoadStoreRow.selectorSum] at sum
  revert sum
  cases row.isLb <;> cases row.isLh <;> cases row.isLbu <;> cases row.isLhu <;>
    cases row.isLw <;> cases row.isSb <;> cases row.isSh <;> cases row.isSw <;>
    simp [bitValue]

/-- C18 with the marker bit constraints: a byte access marks exactly one limb,
and its index is the shift identifier. -/
theorem byte_marker_cases
    (m0 m1 m2 m3 : Bool)
    (sum : bitValue m0 + bitValue m1 + bitValue m2 + bitValue m3 = 1) :
    (m0 = true ∧ m1 = false ∧ m2 = false ∧ m3 = false ∧
        bitValue m1 + 2 * bitValue m2 + 3 * bitValue m3 = 0) ∨
      (m0 = false ∧ m1 = true ∧ m2 = false ∧ m3 = false ∧
        bitValue m1 + 2 * bitValue m2 + 3 * bitValue m3 = 1) ∨
      (m0 = false ∧ m1 = false ∧ m2 = true ∧ m3 = false ∧
        bitValue m1 + 2 * bitValue m2 + 3 * bitValue m3 = 2) ∨
      (m0 = false ∧ m1 = false ∧ m2 = false ∧ m3 = true ∧
        bitValue m1 + 2 * bitValue m2 + 3 * bitValue m3 = 3) := by
  revert sum
  cases m0 <;> cases m1 <;> cases m2 <;> cases m3 <;> simp [bitValue]

/-- C19 with C20: a halfword access marks exactly the low pair or exactly the
high pair. -/
theorem half_marker_cases
    (m0 m1 m2 m3 : Bool)
    (sum : bitValue m0 + bitValue m1 + bitValue m2 + bitValue m3 = 2)
    (identifier :
      bitValue m1 + 2 * bitValue m2 + 3 * bitValue m3 = 1 ∨
        bitValue m1 + 2 * bitValue m2 + 3 * bitValue m3 = 5) :
    (m0 = true ∧ m1 = true ∧ m2 = false ∧ m3 = false) ∨
      (m0 = false ∧ m1 = false ∧ m2 = true ∧ m3 = true) := by
  revert sum identifier
  cases m0 <;> cases m1 <;> cases m2 <;> cases m3 <;> simp [bitValue]

/-- The access never straddles its aligned word: the shift amount is a byte
offset. -/
theorem shift_amount_lt_four
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    row.shiftAmount < 4 := by
  have byteBranch : row.isByte = true → row.shiftAmount < 4 := by
    intro isByte
    have sum := holds.byteMarkerSum isByte
    have amount := holds.byteShiftAmount isByte
    simp only [LoadStoreRow.markerSum] at sum
    simp only [LoadStoreRow.shiftId] at amount
    rcases byte_marker_cases row.marker0 row.marker1 row.marker2 row.marker3 sum
      with ⟨_, _, _, _, h⟩ | ⟨_, _, _, _, h⟩ | ⟨_, _, _, _, h⟩ | ⟨_, _, _, _, h⟩ <;>
      omega
  have halfBranch : row.isHalf = true → row.shiftAmount < 4 := by
    intro isHalf
    have amount := holds.halfShiftAmount isHalf
    rcases holds.halfShiftId isHalf with h | h <;> omega
  have wordBranch : row.isWord = true → row.shiftAmount < 4 := by
    intro isWord
    simp [holds.wordShiftAmount isWord]
  rcases selector_cases row holds with
    ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
    ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
    ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
    ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩
  · exact byteBranch (by simp [LoadStoreRow.isByte, a])
  · exact halfBranch (by simp [LoadStoreRow.isHalf, b])
  · exact byteBranch (by simp [LoadStoreRow.isByte, c])
  · exact halfBranch (by simp [LoadStoreRow.isHalf, d])
  · exact wordBranch (by simp [LoadStoreRow.isWord, e])
  · exact byteBranch (by simp [LoadStoreRow.isByte, f])
  · exact halfBranch (by simp [LoadStoreRow.isHalf, g])
  · exact wordBranch (by simp [LoadStoreRow.isWord, h])

/-! ## The decoding environment

`imm_felt` is supplied by the decoded program ROM. Its contract is that it is
the canonical base-field encoding of the signed 12-bit displacement: a
non-negative displacement is itself, a negative one is `M31 + imm`. -/

/-- Canonical base-field encoding of a signed 12-bit displacement. -/
def immFieldValue (imm : BitVec 12) : Nat :=
  if imm.getLsbD 11 then m31Modulus + imm.toNat - 4096 else imm.toNat

/-- What binds one `load_store` row to an architectural pre-state. -/
structure LoadStoreEnvironment (row : LoadStoreRow) where
  /-- Architectural register file and program counter. -/
  pre : PreState
  /-- Architectural memory: a little-endian array of aligned 32-bit words,
  indexed by the aligned word bus address. -/
  memory : Word → WordBytes
  /-- The instruction's 12-bit displacement. -/
  imm : BitVec 12
  /-- The fetched instruction word. -/
  word : InstructionWord
  pcBinds : row.pc = pre.pc
  wordBinds : word = LoadStoreDecode.encoding row imm
  /-- The decoded program ROM supplies the canonical field encoding of the
  displacement in the program relation's `operand` slot. -/
  immBinds : row.immFelt = immFieldValue imm
  baseBinds : row.rs1Previous.word = pre.registers row.rs1Addr
  operandBinds : row.operandBefore.word = pre.registers row.r2Idx
  memoryBinds : row.memoryBefore = memory row.busAddress
  /-- Machine premise, **not** an AIR constraint. The production address
  arithmetic is base-field arithmetic modulo `2^31 - 1`, and the aligned-address
  range check `L06` bounds the modelled address space to `[0, 2^22)`. This
  premise says the base register plus its displacement does not leave the
  canonical field range, which every address inside the modelled memory
  satisfies with more than nine bits to spare. Without it the AIR would map a
  base register in the top 4 KiB of the field range onto a low address. -/
  baseInFieldRange : (pre.registers row.rs1Addr).toNat + 4096 < m31Modulus

namespace LoadStoreEnvironment

variable {row : LoadStoreRow}

/-- The architectural base register value. -/
def baseValue (env : LoadStoreEnvironment row) : Word :=
  env.pre.registers row.rs1Addr

/-- The architectural effective address `rs1 + signExtend(imm12)`. -/
def effectiveAddress (env : LoadStoreEnvironment row) : Word :=
  Memory.effectiveAddress env.baseValue env.imm

/-- The aligned word bus address the access names. -/
def busAddress (env : LoadStoreEnvironment row) : Word :=
  Memory.busAddress env.effectiveAddress

/-- The architectural memory word at the bus address. -/
def memoryWord (env : LoadStoreEnvironment row) : WordBytes :=
  env.memory env.busAddress

/-- The architectural value of the `r2_idx` register before the access. -/
def operandValue (env : LoadStoreEnvironment row) : Word :=
  env.pre.registers row.r2Idx

end LoadStoreEnvironment

/-! ## The address bridge

The production AIR computes the effective address in the base field. These
lemmas move that computation to the architectural 32-bit modular address and
project the aligned bus address, the byte offset and the halfword selector. -/

/-- A base-field sum of two canonical residues wraps at most once. -/
theorem m31_sum_cases
    (base displacement target : Nat)
    (baseRange : base < m31Modulus)
    (displacementRange : displacement < m31Modulus)
    (reduced : (base + displacement) % m31Modulus = target) :
    base + displacement = target ∨
      base + displacement = target + m31Modulus := by
  simp only [m31Modulus] at baseRange displacementRange reduced ⊢
  omega

/-- L07 keeps the base register inside the canonical field range. -/
theorem base_lt_modulus
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    row.rs1Next.value < m31Modulus := by
  have limb0 := row.rs1Next.limb0.isLt
  have limb1 := row.rs1Next.limb1.isLt
  have limb2 := row.rs1Next.limb2.isLt
  have limb3 := holds.baseHighLimbRange
  have canonical := holds.baseLimbsCanonical
  simp only [Nat.reducePow] at limb0 limb1 limb2
  simp only [WordBytes.value, m31Modulus]
  rcases canonical with h | h <;> omega

/-- The sign extension of a non-negative 12-bit displacement. -/
theorem signExtend_toNat_nonneg
    (imm : BitVec 12)
    (sign : imm.getLsbD 11 = false) :
    (BitVec.signExtend 32 imm).toNat = imm.toNat := by
  have expand : BitVec.signExtend 32 imm = (BitVec.ofNat 20 0).append imm := by
    bv_decide
  rw [expand]
  simp only [BitVec.append_eq, toNat_append_arith, BitVec.toNat_ofNat]
  simp

/-- The sign extension of a negative 12-bit displacement. -/
theorem signExtend_toNat_neg
    (imm : BitVec 12)
    (sign : imm.getLsbD 11 = true) :
    (BitVec.signExtend 32 imm).toNat = imm.toNat + 4294963200 := by
  have expand :
      BitVec.signExtend 32 imm = (BitVec.ofNat 20 1048575).append imm := by
    bv_decide
  rw [expand]
  simp only [BitVec.append_eq, toNat_append_arith, BitVec.toNat_ofNat,
    Nat.reducePow]
  omega

theorem immFieldValue_nonneg
    (imm : BitVec 12)
    (sign : imm.getLsbD 11 = false) :
    immFieldValue imm = imm.toNat := by
  unfold immFieldValue
  rw [sign]
  simp

theorem immFieldValue_neg
    (imm : BitVec 12)
    (sign : imm.getLsbD 11 = true) :
    immFieldValue imm = m31Modulus + imm.toNat - 4096 := by
  unfold immFieldValue
  rw [sign]
  simp

/-- **The address bridge.** The architectural effective address of the row, as a
32-bit modular sum of the base register and the sign-extended displacement, is
exactly the aligned word address the AIR range-checks plus the byte offset the
marker set pins. Both signs of the displacement and the 32-bit wrap are
covered. -/
theorem effective_address_toNat
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row) :
    env.effectiveAddress.toNat = row.alignedAddress + row.shiftAmount := by
  have baseWord : row.rs1Next.word = env.pre.registers row.rs1Addr := by
    rw [holds.baseReadOnly, env.baseBinds]
  have baseNat : (env.pre.registers row.rs1Addr).toNat = row.rs1Next.value := by
    rw [← baseWord, WordBytes.word_toNat]
  have baseRange := base_lt_modulus row holds
  have offsetRange := shift_amount_lt_four row holds
  have quarterRange := holds.alignedQuarterRange
  have addressRange : row.alignedAddress < 4194304 := by
    simp only [LoadStoreRow.alignedAddress]
    simp only [Nat.reducePow] at quarterRange
    omega
  have field := holds.memoryAddress
  have headRoom := env.baseInFieldRange
  rw [baseNat] at headRoom
  have immRange := env.imm.isLt
  simp only [Nat.reducePow] at immRange
  rcases Bool.eq_false_or_eq_true (env.imm.getLsbD 11) with sign | sign
  · have immValue : row.immFelt = m31Modulus + env.imm.toNat - 4096 := by
      rw [env.immBinds, immFieldValue_neg env.imm sign]
    have displacementRange : row.immFelt < m31Modulus := by
      simp only [immValue, m31Modulus]; omega
    simp only [LoadStoreEnvironment.effectiveAddress,
      LoadStoreEnvironment.baseValue, Memory.effectiveAddress_toNat,
      signExtend_toNat_neg env.imm sign, baseNat, Nat.reducePow]
    rcases m31_sum_cases row.rs1Next.value row.immFelt
        (row.alignedAddress + row.shiftAmount) baseRange displacementRange field
      with wrapFree | wrapped
    · simp only [immValue, m31Modulus] at wrapFree
      omega
    · simp only [immValue, m31Modulus] at wrapped
      omega
  · have immValue : row.immFelt = env.imm.toNat := by
      rw [env.immBinds, immFieldValue_nonneg env.imm sign]
    rw [immValue] at field
    simp only [LoadStoreEnvironment.effectiveAddress,
      LoadStoreEnvironment.baseValue, Memory.effectiveAddress_toNat,
      signExtend_toNat_nonneg env.imm sign, baseNat, Nat.reducePow]
    simp only [m31Modulus] at headRoom field
    omega

/-! ## Bit projections of the aligned address -/

theorem busAddress_toNat (address : Word) :
    (Memory.busAddress address).toNat = 4 * (address.toNat / 4) := by
  simp only [Memory.busAddress, BitVec.append_eq, toNat_append_arith,
    BitVec.toNat_ofNat, BitVec.extractLsb, BitVec.extractLsb'_toNat,
    Nat.shiftRight_eq_div_pow, Nat.reducePow]
  have bound := address.isLt
  simp only [Nat.reducePow] at bound
  omega

theorem byteOffset_toNat (address : Word) :
    (Memory.byteOffset address).toNat = address.toNat % 4 := by
  simp only [Memory.byteOffset, BitVec.extractLsb, BitVec.extractLsb'_toNat,
    Nat.shiftRight_eq_div_pow, Nat.reducePow]
  omega

theorem halfSelector_toNat (address : Word) :
    (Memory.halfSelector address).toNat = address.toNat / 2 % 2 := by
  simp only [Memory.halfSelector, BitVec.extractLsb, BitVec.extractLsb'_toNat,
    Nat.shiftRight_eq_div_pow, Nat.reducePow]

theorem lowBit_toNat (address : Word) :
    (BitVec.extractLsb 0 0 address).toNat = address.toNat % 2 := by
  simp only [BitVec.extractLsb, BitVec.extractLsb'_toNat,
    Nat.shiftRight_eq_div_pow, Nat.reducePow]
  omega

/-- The architectural aligned word bus address is the address the AIR
range-checks. -/
theorem row_busAddress
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row) :
    Memory.busAddress env.effectiveAddress = row.busAddress := by
  have address := effective_address_toNat row env holds
  have offsetRange := shift_amount_lt_four row holds
  have quarterRange := holds.alignedQuarterRange
  simp only [Nat.reducePow] at quarterRange
  apply BitVec.eq_of_toNat_eq
  rw [busAddress_toNat, address]
  simp only [LoadStoreRow.busAddress, LoadStoreRow.alignedAddress,
    BitVec.toNat_ofNat, Nat.reducePow]
  omega

/-- The architectural byte offset inside the aligned word is the AIR's shift
amount. -/
theorem row_byteOffset
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row) :
    Memory.byteOffset env.effectiveAddress = row.byteOffset := by
  have address := effective_address_toNat row env holds
  have offsetRange := shift_amount_lt_four row holds
  apply BitVec.eq_of_toNat_eq
  rw [byteOffset_toNat, address]
  simp only [LoadStoreRow.byteOffset, LoadStoreRow.alignedAddress,
    BitVec.toNat_ofNat, Nat.reducePow]
  omega

/-- The architectural halfword selector is the AIR's shift amount over two. -/
theorem row_halfSelector
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row) :
    Memory.halfSelector env.effectiveAddress = row.halfSelector := by
  have address := effective_address_toNat row env holds
  have offsetRange := shift_amount_lt_four row holds
  apply BitVec.eq_of_toNat_eq
  rw [halfSelector_toNat, address]
  simp only [LoadStoreRow.halfSelector, LoadStoreRow.alignedAddress,
    BitVec.toNat_ofNat, Nat.reducePow]
  omega

/-! ## Load and store projections of the row -/

theorem memoryBefore_load (row : LoadStoreRow) (isStore : row.isStore = false) :
    row.memoryBefore = row.srcPrevious := by
  simp [LoadStoreRow.memoryBefore, isStore]

theorem memoryAfter_load (row : LoadStoreRow) (isStore : row.isStore = false) :
    row.memoryAfter = row.srcNext := by
  simp [LoadStoreRow.memoryAfter, isStore]

theorem operandBefore_load (row : LoadStoreRow) (isStore : row.isStore = false) :
    row.operandBefore = row.dstPrevious := by
  simp [LoadStoreRow.operandBefore, isStore]

theorem operandAfter_load (row : LoadStoreRow) (isStore : row.isStore = false) :
    row.operandAfter = row.dstNext := by
  simp [LoadStoreRow.operandAfter, isStore]

theorem memoryPreviousClock_load
    (row : LoadStoreRow) (isStore : row.isStore = false) :
    row.memoryPreviousClock = row.srcPreviousClock := by
  simp [LoadStoreRow.memoryPreviousClock, isStore]

theorem operandPreviousClock_load
    (row : LoadStoreRow) (isStore : row.isStore = false) :
    row.operandPreviousClock = row.dstPreviousClock := by
  simp [LoadStoreRow.operandPreviousClock, isStore]

theorem memoryBefore_store (row : LoadStoreRow) (isStore : row.isStore = true) :
    row.memoryBefore = row.dstPrevious := by
  simp [LoadStoreRow.memoryBefore, isStore]

theorem memoryAfter_store (row : LoadStoreRow) (isStore : row.isStore = true) :
    row.memoryAfter = row.dstNext := by
  simp [LoadStoreRow.memoryAfter, isStore]

theorem operandBefore_store (row : LoadStoreRow) (isStore : row.isStore = true) :
    row.operandBefore = row.srcPrevious := by
  simp [LoadStoreRow.operandBefore, isStore]

theorem operandAfter_store (row : LoadStoreRow) (isStore : row.isStore = true) :
    row.operandAfter = row.srcNext := by
  simp [LoadStoreRow.operandAfter, isStore]

theorem memoryPreviousClock_store
    (row : LoadStoreRow) (isStore : row.isStore = true) :
    row.memoryPreviousClock = row.dstPreviousClock := by
  simp [LoadStoreRow.memoryPreviousClock, isStore]

theorem operandPreviousClock_store
    (row : LoadStoreRow) (isStore : row.isStore = true) :
    row.operandPreviousClock = row.srcPreviousClock := by
  simp [LoadStoreRow.operandPreviousClock, isStore]

theorem loadStoreRetirement_load
    (row : LoadStoreRow) (isStore : row.isStore = false) :
    loadStoreRetirement row = {
      nextPc := row.claimedNextPc
      write := architecturalWrite row.r2Idx row.dstNext.word
      read := some { address := row.busAddress, value := row.srcNext.word }
      store := none
    } := by
  simp [loadStoreRetirement, isStore]

theorem loadStoreRetirement_store
    (row : LoadStoreRow) (isStore : row.isStore = true) :
    loadStoreRetirement row = {
      nextPc := row.claimedNextPc
      write := none
      read := none
      store := some {
        address := row.busAddress
        mask := row.mask
        value := row.dstNext.word
      }
    } := by
  simp [loadStoreRetirement, isStore]

/-- The architectural memory word a load observes is the row's source block. -/
theorem load_memory_word
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (isStore : row.isStore = false) :
    env.memoryWord = row.srcNext := by
  simp only [LoadStoreEnvironment.memoryWord, LoadStoreEnvironment.busAddress,
    row_busAddress row env holds, ← env.memoryBinds,
    memoryBefore_load row isStore, holds.sourceReadOnly]

/-- The architectural memory word a store updates is the row's destination
block before the write. -/
theorem store_memory_word
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (isStore : row.isStore = true) :
    env.memoryWord = row.dstPrevious := by
  simp only [LoadStoreEnvironment.memoryWord, LoadStoreEnvironment.busAddress,
    row_busAddress row env holds, ← env.memoryBinds,
    memoryBefore_store row isStore]

/-- C61-C64 with C58-C60: the committed `rd` cell is the architectural value of
the load result, `x0` included. -/
theorem load_destination_value
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row)
    (isLoad : row.isLoad = true) :
    row.dstNext.word = architecturalValue row.r2Idx row.result.word := by
  by_cases isZero : row.r2Idx = zeroRegister
  · have flag : row.destinationNonzero = false := by
      rw [holds.destinationFlag]; simp [isZero]
    rw [holds.loadDestination isLoad, flag, isZero, architecturalValue_zero]
    simp
  · have flag : row.destinationNonzero = true := by
      rw [holds.destinationFlag]; simp [isZero]
    rw [holds.loadDestination isLoad, flag, architecturalValue]
    simp [isZero]

/-- The guarded register write a load claims is the write of its result. -/
theorem load_write_value
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row)
    (isLoad : row.isLoad = true) :
    architecturalWrite row.r2Idx row.dstNext.word =
      architecturalWrite row.r2Idx row.result.word := by
  rw [load_destination_value row holds isLoad, architecturalWrite_value]

/-! ## Width extension of the result limbs -/

theorem word_of_negative_half
    (bytes : WordBytes)
    (negative : bytes.limb1.getLsbD 7 = true)
    (high : bytes.limb2 = BitVec.ofNat 8 255)
    (top : bytes.limb3 = BitVec.ofNat 8 255) :
    bytes.word = Memory.signExtendHalf (bytes.limb1.append bytes.limb0) := by
  rw [WordBytes.word_append, high, top]
  simp only [Memory.signExtendHalf]
  bv_decide

theorem word_of_nonnegative_half
    (bytes : WordBytes)
    (nonnegative : bytes.limb1.getLsbD 7 = false)
    (high : bytes.limb2 = BitVec.ofNat 8 0)
    (top : bytes.limb3 = BitVec.ofNat 8 0) :
    bytes.word = Memory.signExtendHalf (bytes.limb1.append bytes.limb0) := by
  rw [WordBytes.word_append, high, top]
  simp only [Memory.signExtendHalf]
  bv_decide

theorem word_of_zero_extended_half
    (bytes : WordBytes)
    (high : bytes.limb2 = BitVec.ofNat 8 0)
    (top : bytes.limb3 = BitVec.ofNat 8 0) :
    bytes.word = Memory.zeroExtendHalf (bytes.limb1.append bytes.limb0) := by
  rw [WordBytes.word_append, high, top]
  simp only [Memory.zeroExtendHalf]
  bv_decide

theorem word_of_negative_byte
    (bytes : WordBytes)
    (negative : bytes.limb0.getLsbD 7 = true)
    (one : bytes.limb1 = BitVec.ofNat 8 255)
    (high : bytes.limb2 = BitVec.ofNat 8 255)
    (top : bytes.limb3 = BitVec.ofNat 8 255) :
    bytes.word = Memory.signExtendByte bytes.limb0 := by
  rw [WordBytes.word_append, one, high, top]
  simp only [Memory.signExtendByte]
  bv_decide

theorem word_of_nonnegative_byte
    (bytes : WordBytes)
    (nonnegative : bytes.limb0.getLsbD 7 = false)
    (one : bytes.limb1 = BitVec.ofNat 8 0)
    (high : bytes.limb2 = BitVec.ofNat 8 0)
    (top : bytes.limb3 = BitVec.ofNat 8 0) :
    bytes.word = Memory.signExtendByte bytes.limb0 := by
  rw [WordBytes.word_append, one, high, top]
  simp only [Memory.signExtendByte]
  bv_decide

theorem word_of_zero_extended_byte
    (bytes : WordBytes)
    (one : bytes.limb1 = BitVec.ofNat 8 0)
    (high : bytes.limb2 = BitVec.ofNat 8 0)
    (top : bytes.limb3 = BitVec.ofNat 8 0) :
    bytes.word = Memory.zeroExtendByte bytes.limb0 := by
  rw [WordBytes.word_append, one, high, top]
  simp only [Memory.zeroExtendByte]
  bv_decide

/-! ## Per-opcode flag extraction -/

theorem lb_flags (row : LoadStoreRow) (holds : LoadStoreHolds row)
    (selector : row.isLb = true) :
    row.isLh = false ∧ row.isLbu = false ∧ row.isLhu = false ∧
      row.isLw = false ∧ row.isSb = false ∧ row.isSh = false ∧
      row.isSw = false := by
  rcases selector_cases row holds with c|c|c|c|c|c|c|c <;> simp_all

theorem lh_flags (row : LoadStoreRow) (holds : LoadStoreHolds row)
    (selector : row.isLh = true) :
    row.isLb = false ∧ row.isLbu = false ∧ row.isLhu = false ∧
      row.isLw = false ∧ row.isSb = false ∧ row.isSh = false ∧
      row.isSw = false := by
  rcases selector_cases row holds with c|c|c|c|c|c|c|c <;> simp_all

theorem lbu_flags (row : LoadStoreRow) (holds : LoadStoreHolds row)
    (selector : row.isLbu = true) :
    row.isLb = false ∧ row.isLh = false ∧ row.isLhu = false ∧
      row.isLw = false ∧ row.isSb = false ∧ row.isSh = false ∧
      row.isSw = false := by
  rcases selector_cases row holds with c|c|c|c|c|c|c|c <;> simp_all

theorem lhu_flags (row : LoadStoreRow) (holds : LoadStoreHolds row)
    (selector : row.isLhu = true) :
    row.isLb = false ∧ row.isLh = false ∧ row.isLbu = false ∧
      row.isLw = false ∧ row.isSb = false ∧ row.isSh = false ∧
      row.isSw = false := by
  rcases selector_cases row holds with c|c|c|c|c|c|c|c <;> simp_all

theorem lw_flags (row : LoadStoreRow) (holds : LoadStoreHolds row)
    (selector : row.isLw = true) :
    row.isLb = false ∧ row.isLh = false ∧ row.isLbu = false ∧
      row.isLhu = false ∧ row.isSb = false ∧ row.isSh = false ∧
      row.isSw = false := by
  rcases selector_cases row holds with c|c|c|c|c|c|c|c <;> simp_all

theorem sb_flags (row : LoadStoreRow) (holds : LoadStoreHolds row)
    (selector : row.isSb = true) :
    row.isLb = false ∧ row.isLh = false ∧ row.isLbu = false ∧
      row.isLhu = false ∧ row.isLw = false ∧ row.isSh = false ∧
      row.isSw = false := by
  rcases selector_cases row holds with c|c|c|c|c|c|c|c <;> simp_all

theorem sh_flags (row : LoadStoreRow) (holds : LoadStoreHolds row)
    (selector : row.isSh = true) :
    row.isLb = false ∧ row.isLh = false ∧ row.isLbu = false ∧
      row.isLhu = false ∧ row.isLw = false ∧ row.isSb = false ∧
      row.isSw = false := by
  rcases selector_cases row holds with c|c|c|c|c|c|c|c <;> simp_all

theorem sw_flags (row : LoadStoreRow) (holds : LoadStoreHolds row)
    (selector : row.isSw = true) :
    row.isLb = false ∧ row.isLh = false ∧ row.isLbu = false ∧
      row.isLhu = false ∧ row.isLw = false ∧ row.isSb = false ∧
      row.isSh = false := by
  rcases selector_cases row holds with c|c|c|c|c|c|c|c <;> simp_all

/-! ## Folding lemmas for the environment abbreviations -/

theorem LoadStoreEnvironment.effectiveAddress_eq
    {row : LoadStoreRow} (env : LoadStoreEnvironment row) :
    Memory.effectiveAddress env.baseValue env.imm = env.effectiveAddress := rfl

theorem LoadStoreEnvironment.busAddress_eq
    {row : LoadStoreRow} (env : LoadStoreEnvironment row) :
    Memory.busAddress env.effectiveAddress = env.busAddress := rfl

theorem LoadStoreEnvironment.memoryWord_eq
    {row : LoadStoreRow} (env : LoadStoreEnvironment row) :
    env.memory env.busAddress = env.memoryWord := rfl

/-! ## `LH` — the halfword memory stress gate

`LH` is the mandatory Level-2 memory test: it exercises the effective-address
computation, natural halfword alignment, the aligned word bus projection,
little-endian half selection on both halves, sign extension on both signs, the
`rd = x0` discard, the `rd = rs1` alias, and read-only memory preservation. -/

/-- C15/C19/C20: a halfword access sits at byte offset zero or two, so it never
straddles its aligned word. Alignment is *derived* from the AIR here, not
assumed. -/
theorem lh_shift
    (row : LoadStoreRow)
    (holds : LoadStoreHolds row)
    (selector : row.isHalf = true) :
    (row.shiftId = 1 ∧ row.shiftAmount = 0) ∨
      (row.shiftId = 5 ∧ row.shiftAmount = 2) := by
  have amount := holds.halfShiftAmount selector
  rcases holds.halfShiftId selector with identifier | identifier
  · exact Or.inl ⟨identifier, by omega⟩
  · exact Or.inr ⟨identifier, by omega⟩

/-- The effective address of any halfword access is naturally aligned. -/
theorem half_access_aligned
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isHalf = true) :
    Memory.isHalfAligned env.effectiveAddress := by
  have address := effective_address_toNat row env holds
  simp only [Memory.isHalfAligned]
  apply BitVec.eq_of_toNat_eq
  rw [lowBit_toNat, address]
  simp only [LoadStoreRow.alignedAddress, BitVec.toNat_ofNat]
  rcases lh_shift row holds selector with ⟨_, amount⟩ | ⟨_, amount⟩ <;>
    rw [amount] <;> omega

/-- C34-C37: the two result limbs of a halfword load are the little-endian
halfword the address selects out of the aligned memory word. -/
theorem half_selected
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isHalfLoad = true)
    (isHalf : row.isHalf = true) :
    Memory.selectHalf row.srcNext (Memory.halfSelector env.effectiveAddress) =
      row.result.limb1.append row.result.limb0 := by
  rw [row_halfSelector row env holds]
  rcases lh_shift row holds isHalf with ⟨identifier, amount⟩ | ⟨identifier, amount⟩
  · obtain ⟨low, high⟩ := holds.halfLoadLow selector identifier
    simp only [LoadStoreRow.halfSelector, amount, Nat.reduceDiv,
      Memory.selectHalf_low, WordBytes.lowHalf, low, high]
  · obtain ⟨low, high⟩ := holds.halfLoadHigh selector identifier
    simp only [LoadStoreRow.halfSelector, amount, Nat.reduceDiv,
      Memory.selectHalf_high, WordBytes.highHalf, low, high]

/-- C32/C33 with L15: the `LH` result word is the sign extension of the
selected halfword, on both signs. -/
theorem lh_result_value
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isLh = true) :
    row.result.word = loadHalfSignedValue env.baseValue env.imm env.memoryWord := by
  obtain ⟨_, _, _, _, isSb, isSh, isSw⟩ := lh_flags row holds selector
  have isStore : row.isStore = false := by
    simp [LoadStoreRow.isStore, isSb, isSh, isSw]
  have isHalfLoad : row.isHalfLoad = true := by
    simp [LoadStoreRow.isHalfLoad, selector]
  have isHalf : row.isHalf = true := by simp [LoadStoreRow.isHalf, selector]
  have isSigned : row.isSigned = true := by
    simp [LoadStoreRow.isSigned, selector]
  have memory := load_memory_word row env holds isStore
  obtain ⟨limb2, limb3⟩ := holds.halfLoadExtension isHalfLoad
  have sign := holds.halfSignWitness selector
  simp only [loadHalfSignedValue, LoadStoreEnvironment.effectiveAddress_eq,
    memory, half_selected row env holds isHalfLoad isHalf]
  cases msb : row.srcMsb
  · refine word_of_nonnegative_half row.result ?_ ?_ ?_
    · rw [← sign, msb]
    · rw [limb2]; simp [LoadStoreRow.signMask, msb]
    · rw [limb3]; simp [LoadStoreRow.signMask, msb]
  · refine word_of_negative_half row.result ?_ ?_ ?_
    · rw [← sign, msb]
    · rw [limb2]; simp [LoadStoreRow.signMask, msb, isSigned]
    · rw [limb3]; simp [LoadStoreRow.signMask, msb, isSigned]

/-- The complete `LH` refinement obligation. -/
structure LhRefinement
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row) :
    Prop where
  /-- The fetched word decodes to `LH rd, imm(rs1)` with the row's operands. -/
  decode :
    LoadStoreDecode.isLoadOf env.word LoadStoreDecode.funct3Lh = true ∧
      LoadStoreDecode.decodeIImmediate env.word = env.imm ∧
      LoadStoreDecode.decodeRs1 env.word = row.rs1Addr ∧
      LoadStoreDecode.decodeRd env.word = row.r2Idx
  /-- The 32-bit modular effective address, wrap included. -/
  effectiveAddress :
    env.effectiveAddress.toNat = row.alignedAddress + row.shiftAmount
  /-- Natural halfword alignment, derived from the AIR marker constraints. -/
  aligned : halfAccessAligned env.baseValue env.imm
  /-- The aligned word bus address the memory relation names. -/
  busAddress : Memory.busAddress env.effectiveAddress = row.busAddress
  /-- The normalized retirement, including the memory read observation and the
  guarded `rd` write. -/
  retirement :
    loadStoreRetirement row =
      executeLh env.pre.pc env.baseValue env.imm row.r2Idx env.memoryWord
  /-- A load leaves memory untouched. -/
  memoryPreserved : row.memoryAfter = row.memoryBefore
  /-- A load leaves its base register untouched. -/
  basePreserved : row.rs1Next = row.rs1Previous
  programTuple :
    (loadStoreRelations row).program = {
      pc := env.pre.pc
      opcodeId := 20
      rd := row.rs1Addr.toNat
      rs1 := row.r2Idx.toNat
      operand := immFieldValue env.imm
    }
  stateConsume :
    (loadStoreRelations row).stateConsume = {
      pc := env.pre.pc
      clock := row.clock
    }
  stateEmit :
    (loadStoreRelations row).stateEmit = {
      pc := nextPc env.pre.pc
      clock := row.clock + 1
    }
  baseConsume :
    (loadStoreRelations row).baseConsume = {
      addr := row.rs1Addr
      clock := row.rs1PreviousClock
      value := env.pre.registers row.rs1Addr
    }
  baseEmit :
    (loadStoreRelations row).baseEmit = {
      addr := row.rs1Addr
      clock := accessClock row.clock 1
      value := env.pre.registers row.rs1Addr
    }
  operandConsume :
    (loadStoreRelations row).operandConsume = {
      addr := row.r2Idx
      clock := row.dstPreviousClock
      value := env.pre.registers row.r2Idx
    }
  operandEmit :
    (loadStoreRelations row).operandEmit = {
      addr := row.r2Idx
      clock := accessClock row.clock 2
      value :=
        architecturalValue row.r2Idx
          (loadHalfSignedValue env.baseValue env.imm env.memoryWord)
    }
  memoryConsume :
    (loadStoreRelations row).memoryConsume = {
      addr := env.busAddress
      clock := row.srcPreviousClock
      value := env.memoryWord.word
    }
  memoryEmit :
    (loadStoreRelations row).memoryEmit = {
      addr := env.busAddress
      clock := accessClock row.clock 3
      value := env.memoryWord.word
    }

/-- **`LH` refines the architectural halfword load.** -/
theorem lh_refines
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isLh = true) :
    LhRefinement row env := by
  obtain ⟨isLb, isLbu, isLhu, isLw, isSb, isSh, isSw⟩ := lh_flags row holds selector
  have isStore : row.isStore = false := by
    simp [LoadStoreRow.isStore, isSb, isSh, isSw]
  have isLoad : row.isLoad = true := by simp [LoadStoreRow.isLoad, isStore]
  have isHalf : row.isHalf = true := by simp [LoadStoreRow.isHalf, selector]
  have memory := load_memory_word row env holds isStore
  have address := effective_address_toNat row env holds
  have bus := row_busAddress row env holds
  have value := lh_result_value row env holds selector
  have pcValue : row.claimedNextPc = nextPc env.pre.pc := by
    rw [holds.nextPcResult, env.pcBinds]
  refine {
    decode := ?_
    effectiveAddress := address
    aligned := half_access_aligned row env holds isHalf
    busAddress := bus
    retirement := ?_
    memoryPreserved := ?_
    basePreserved := holds.baseReadOnly
    programTuple := ?_
    stateConsume := ?_
    stateEmit := ?_
    baseConsume := ?_
    baseEmit := ?_
    operandConsume := ?_
    operandEmit := ?_
    memoryConsume := ?_
    memoryEmit := ?_
  }
  · rw [env.wordBinds]
    simp only [LoadStoreDecode.encoding, isLb, selector, Bool.false_eq_true,
      if_false, if_true]
    exact LoadStoreDecode.encode_load_is_canonical env.imm row.rs1Addr row.r2Idx
      LoadStoreDecode.funct3Lh
  · rw [loadStoreRetirement_load row isStore]
    have write :
        architecturalWrite row.r2Idx row.dstNext.word =
          architecturalWrite row.r2Idx
            (loadHalfSignedValue env.baseValue env.imm env.memoryWord) := by
      rw [load_write_value row holds isLoad, value]
    simp only [executeLh, executeLoad, LoadStoreEnvironment.effectiveAddress_eq,
      LoadStoreEnvironment.busAddress_eq, pcValue, write, ← bus, memory]
  · rw [memoryAfter_load row isStore, memoryBefore_load row isStore,
      holds.sourceReadOnly]
  · simp only [loadStoreRelations, loadStoreProgramTuple, env.pcBinds,
      env.immBinds, LoadStoreRow.opcodeId, isLb, selector, isLbu, isLhu, isLw,
      isSb, isSh, isSw, bitValue_true, bitValue_false]
  · simp [loadStoreRelations, env.pcBinds]
  · simp [loadStoreRelations, env.pcBinds]
  · simp [loadStoreRelations, env.baseBinds]
  · simp [loadStoreRelations, holds.baseReadOnly, env.baseBinds]
  · simp [loadStoreRelations, operandPreviousClock_load row isStore,
      ← env.operandBinds, operandBefore_load row isStore]
  · simp only [loadStoreRelations, operandAfter_load row isStore,
      load_destination_value row holds isLoad, value]
  · simp only [loadStoreRelations, memoryPreviousClock_load row isStore,
      memoryBefore_load row isStore, ← bus, LoadStoreEnvironment.busAddress_eq,
      memory, holds.sourceReadOnly]
  · simp only [loadStoreRelations, memoryAfter_load row isStore, ← bus,
      LoadStoreEnvironment.busAddress_eq, memory]

/-! ## The shared load interface

`LH` above fixes the interface; this is the same obligation with the opcode
identifier, the architectural retirement and the loaded value abstracted, so
`LB`, `LW`, `LBU` and `LHU` reuse it verbatim. Stage B2's exit condition is
exactly that the interface generalizes without change. -/

/-- The complete refinement obligation of any of the five loads. -/
structure LoadRefinement
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (funct3 : BitVec 3)
    (opcodeId : Nat)
    (architectural : Retirement)
    (value : Word) :
    Prop where
  decode :
    LoadStoreDecode.isLoadOf env.word funct3 = true ∧
      LoadStoreDecode.decodeIImmediate env.word = env.imm ∧
      LoadStoreDecode.decodeRs1 env.word = row.rs1Addr ∧
      LoadStoreDecode.decodeRd env.word = row.r2Idx
  effectiveAddress :
    env.effectiveAddress.toNat = row.alignedAddress + row.shiftAmount
  busAddress : Memory.busAddress env.effectiveAddress = row.busAddress
  retirement : loadStoreRetirement row = architectural
  memoryPreserved : row.memoryAfter = row.memoryBefore
  basePreserved : row.rs1Next = row.rs1Previous
  programTuple :
    (loadStoreRelations row).program = {
      pc := env.pre.pc
      opcodeId := opcodeId
      rd := row.rs1Addr.toNat
      rs1 := row.r2Idx.toNat
      operand := immFieldValue env.imm
    }
  stateConsume :
    (loadStoreRelations row).stateConsume = {
      pc := env.pre.pc
      clock := row.clock
    }
  stateEmit :
    (loadStoreRelations row).stateEmit = {
      pc := nextPc env.pre.pc
      clock := row.clock + 1
    }
  baseConsume :
    (loadStoreRelations row).baseConsume = {
      addr := row.rs1Addr
      clock := row.rs1PreviousClock
      value := env.pre.registers row.rs1Addr
    }
  baseEmit :
    (loadStoreRelations row).baseEmit = {
      addr := row.rs1Addr
      clock := accessClock row.clock 1
      value := env.pre.registers row.rs1Addr
    }
  operandConsume :
    (loadStoreRelations row).operandConsume = {
      addr := row.r2Idx
      clock := row.dstPreviousClock
      value := env.pre.registers row.r2Idx
    }
  operandEmit :
    (loadStoreRelations row).operandEmit = {
      addr := row.r2Idx
      clock := accessClock row.clock 2
      value := architecturalValue row.r2Idx value
    }
  memoryConsume :
    (loadStoreRelations row).memoryConsume = {
      addr := env.busAddress
      clock := row.srcPreviousClock
      value := env.memoryWord.word
    }
  memoryEmit :
    (loadStoreRelations row).memoryEmit = {
      addr := env.busAddress
      clock := accessClock row.clock 3
      value := env.memoryWord.word
    }

/-- The shared load theorem. Everything except the loaded value and the opcode
identifier is derived once from the AIR. -/
theorem load_refines
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (isStore : row.isStore = false)
    {funct3 : BitVec 3}
    (encoding :
      LoadStoreDecode.encoding row env.imm =
        LoadStoreDecode.encodeLoad env.imm row.rs1Addr row.r2Idx funct3)
    {opcodeId : Nat}
    (identifier : row.opcodeId = opcodeId)
    {value : Word}
    (result : row.result.word = value)
    {architectural : Retirement}
    (retire : architectural = {
      nextPc := nextPc env.pre.pc
      write := architecturalWrite row.r2Idx value
      read := some { address := env.busAddress, value := env.memoryWord.word }
      store := none
    }) :
    LoadRefinement row env funct3 opcodeId architectural value := by
  have isLoad : row.isLoad = true := by simp [LoadStoreRow.isLoad, isStore]
  have memory := load_memory_word row env holds isStore
  have bus := row_busAddress row env holds
  have pcValue : row.claimedNextPc = nextPc env.pre.pc := by
    rw [holds.nextPcResult, env.pcBinds]
  refine {
    decode := ?_
    effectiveAddress := effective_address_toNat row env holds
    busAddress := bus
    retirement := ?_
    memoryPreserved := ?_
    basePreserved := holds.baseReadOnly
    programTuple := ?_
    stateConsume := ?_
    stateEmit := ?_
    baseConsume := ?_
    baseEmit := ?_
    operandConsume := ?_
    operandEmit := ?_
    memoryConsume := ?_
    memoryEmit := ?_
  }
  · rw [env.wordBinds, encoding]
    exact LoadStoreDecode.encode_load_is_canonical env.imm row.rs1Addr row.r2Idx
      funct3
  · rw [loadStoreRetirement_load row isStore, retire]
    have write :
        architecturalWrite row.r2Idx row.dstNext.word =
          architecturalWrite row.r2Idx value := by
      rw [load_write_value row holds isLoad, result]
    simp only [LoadStoreEnvironment.busAddress_eq, write, ← bus, memory,
      pcValue]
  · rw [memoryAfter_load row isStore, memoryBefore_load row isStore,
      holds.sourceReadOnly]
  · simp [loadStoreRelations, loadStoreProgramTuple, env.pcBinds, env.immBinds,
      identifier]
  · simp [loadStoreRelations, env.pcBinds]
  · simp [loadStoreRelations, env.pcBinds]
  · simp [loadStoreRelations, env.baseBinds]
  · simp [loadStoreRelations, holds.baseReadOnly, env.baseBinds]
  · simp [loadStoreRelations, operandPreviousClock_load row isStore,
      ← env.operandBinds, operandBefore_load row isStore]
  · simp only [loadStoreRelations, operandAfter_load row isStore,
      load_destination_value row holds isLoad, result]
  · simp only [loadStoreRelations, memoryPreviousClock_load row isStore,
      memoryBefore_load row isStore, ← bus, LoadStoreEnvironment.busAddress_eq,
      memory, holds.sourceReadOnly]
  · simp only [loadStoreRelations, memoryAfter_load row isStore, ← bus,
      LoadStoreEnvironment.busAddress_eq, memory]

/-- `LH` satisfies the shared interface too: the Stage B2 exit gate. -/
theorem lh_satisfies_load_interface
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isLh = true) :
    LoadRefinement row env LoadStoreDecode.funct3Lh 20
      (executeLh env.pre.pc env.baseValue env.imm row.r2Idx env.memoryWord)
      (loadHalfSignedValue env.baseValue env.imm env.memoryWord) := by
  obtain ⟨isLb, isLbu, isLhu, isLw, isSb, isSh, isSw⟩ := lh_flags row holds selector
  have isStore : row.isStore = false := by
    simp [LoadStoreRow.isStore, isSb, isSh, isSw]
  refine load_refines row env holds isStore ?_ ?_
    (lh_result_value row env holds selector) ?_
  · simp [LoadStoreDecode.encoding, isLb, selector]
  · simp [LoadStoreRow.opcodeId, isLb, selector, isLbu, isLhu, isLw, isSb, isSh,
      isSw, bitValue]
  · simp [executeLh, executeLoad, LoadStoreEnvironment.effectiveAddress_eq,
      LoadStoreEnvironment.busAddress_eq]

/-! ## Byte selection -/

/-- C24-C30: the `result_0` limb of a byte load is the little-endian byte the
address selects out of the aligned memory word. -/
theorem byte_selected
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isByteLoad = true)
    (isByte : row.isByte = true) :
    Memory.selectByte row.srcNext (Memory.byteOffset env.effectiveAddress) =
      row.result.limb0 := by
  rw [row_byteOffset row env holds]
  have sum := holds.byteMarkerSum isByte
  have amount := holds.byteShiftAmount isByte
  obtain ⟨limb0, limb1, limb2, limb3⟩ := holds.byteLoadSelect selector
  simp only [LoadStoreRow.markerSum] at sum
  simp only [LoadStoreRow.shiftId] at amount
  rcases byte_marker_cases row.marker0 row.marker1 row.marker2 row.marker3 sum
    with ⟨m0, _, _, _, sid⟩ | ⟨_, m1, _, _, sid⟩ | ⟨_, _, m2, _, sid⟩ |
      ⟨_, _, _, m3, sid⟩
  · have offset : row.shiftAmount = 0 := by omega
    simp only [LoadStoreRow.byteOffset, offset]
    simp only [Memory.selectByte]
    norm_cast
    exact (limb0 m0).symm
  · have offset : row.shiftAmount = 1 := by omega
    simp only [LoadStoreRow.byteOffset, offset]
    simp only [Memory.selectByte]
    norm_cast
    exact (limb1 m1).symm
  · have offset : row.shiftAmount = 2 := by omega
    simp only [LoadStoreRow.byteOffset, offset]
    simp only [Memory.selectByte]
    norm_cast
    exact (limb2 m2).symm
  · have offset : row.shiftAmount = 3 := by omega
    simp only [LoadStoreRow.byteOffset, offset]
    simp only [Memory.selectByte]
    norm_cast
    exact (limb3 m3).symm

/-! ## `LB`, `LBU`, `LHU`, `LW` through the shared interface -/

theorem lb_result_value
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isLb = true) :
    row.result.word = loadByteSignedValue env.baseValue env.imm env.memoryWord := by
  obtain ⟨_, _, _, _, isSb, isSh, isSw⟩ := lb_flags row holds selector
  have isStore : row.isStore = false := by
    simp [LoadStoreRow.isStore, isSb, isSh, isSw]
  have isByteLoad : row.isByteLoad = true := by
    simp [LoadStoreRow.isByteLoad, selector]
  have isByte : row.isByte = true := by simp [LoadStoreRow.isByte, selector]
  have isSigned : row.isSigned = true := by
    simp [LoadStoreRow.isSigned, selector]
  have memory := load_memory_word row env holds isStore
  obtain ⟨limb1, limb2, limb3⟩ := holds.byteLoadExtension isByteLoad
  have sign := holds.byteSignWitness selector
  simp only [loadByteSignedValue, LoadStoreEnvironment.effectiveAddress_eq,
    memory, byte_selected row env holds isByteLoad isByte]
  cases msb : row.srcMsb
  · refine word_of_nonnegative_byte row.result ?_ ?_ ?_ ?_
    · rw [← sign, msb]
    · rw [limb1]; simp [LoadStoreRow.signMask, msb]
    · rw [limb2]; simp [LoadStoreRow.signMask, msb]
    · rw [limb3]; simp [LoadStoreRow.signMask, msb]
  · refine word_of_negative_byte row.result ?_ ?_ ?_ ?_
    · rw [← sign, msb]
    · rw [limb1]; simp [LoadStoreRow.signMask, msb, isSigned]
    · rw [limb2]; simp [LoadStoreRow.signMask, msb, isSigned]
    · rw [limb3]; simp [LoadStoreRow.signMask, msb, isSigned]

theorem lbu_result_value
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isLbu = true) :
    row.result.word =
      loadByteUnsignedValue env.baseValue env.imm env.memoryWord := by
  obtain ⟨isLb, isLh, _, _, isSb, isSh, isSw⟩ := lbu_flags row holds selector
  have isStore : row.isStore = false := by
    simp [LoadStoreRow.isStore, isSb, isSh, isSw]
  have isByteLoad : row.isByteLoad = true := by
    simp [LoadStoreRow.isByteLoad, selector]
  have isByte : row.isByte = true := by simp [LoadStoreRow.isByte, selector]
  have isSigned : row.isSigned = false := by
    simp [LoadStoreRow.isSigned, isLb, isLh]
  have memory := load_memory_word row env holds isStore
  obtain ⟨limb1, limb2, limb3⟩ := holds.byteLoadExtension isByteLoad
  simp only [loadByteUnsignedValue, LoadStoreEnvironment.effectiveAddress_eq,
    memory, byte_selected row env holds isByteLoad isByte]
  refine word_of_zero_extended_byte row.result ?_ ?_ ?_
  · rw [limb1]; simp [LoadStoreRow.signMask, isSigned]
  · rw [limb2]; simp [LoadStoreRow.signMask, isSigned]
  · rw [limb3]; simp [LoadStoreRow.signMask, isSigned]

theorem lhu_result_value
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isLhu = true) :
    row.result.word =
      loadHalfUnsignedValue env.baseValue env.imm env.memoryWord := by
  obtain ⟨isLb, isLh, _, _, isSb, isSh, isSw⟩ := lhu_flags row holds selector
  have isStore : row.isStore = false := by
    simp [LoadStoreRow.isStore, isSb, isSh, isSw]
  have isHalfLoad : row.isHalfLoad = true := by
    simp [LoadStoreRow.isHalfLoad, selector]
  have isHalf : row.isHalf = true := by simp [LoadStoreRow.isHalf, selector]
  have isSigned : row.isSigned = false := by
    simp [LoadStoreRow.isSigned, isLb, isLh]
  have memory := load_memory_word row env holds isStore
  obtain ⟨limb2, limb3⟩ := holds.halfLoadExtension isHalfLoad
  simp only [loadHalfUnsignedValue, LoadStoreEnvironment.effectiveAddress_eq,
    memory, half_selected row env holds isHalfLoad isHalf]
  refine word_of_zero_extended_half row.result ?_ ?_
  · rw [limb2]; simp [LoadStoreRow.signMask, isSigned]
  · rw [limb3]; simp [LoadStoreRow.signMask, isSigned]

theorem lw_result_value
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isLw = true) :
    row.result.word = loadWordValue env.memoryWord := by
  obtain ⟨_, _, _, _, isSb, isSh, isSw⟩ := lw_flags row holds selector
  have isStore : row.isStore = false := by
    simp [LoadStoreRow.isStore, isSb, isSh, isSw]
  rw [holds.wordLoad selector, load_memory_word row env holds isStore]
  rfl

/-- `LW` and `SW` name a word-aligned effective address. -/
theorem word_access_aligned
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (isWord : row.isWord = true) :
    Memory.isWordAligned env.effectiveAddress := by
  simp only [Memory.isWordAligned, row_byteOffset row env holds,
    LoadStoreRow.byteOffset, holds.wordShiftAmount isWord]

theorem lb_refines
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isLb = true) :
    LoadRefinement row env LoadStoreDecode.funct3Lb 19
      (executeLb env.pre.pc env.baseValue env.imm row.r2Idx env.memoryWord)
      (loadByteSignedValue env.baseValue env.imm env.memoryWord) := by
  obtain ⟨isLh, isLbu, isLhu, isLw, isSb, isSh, isSw⟩ := lb_flags row holds selector
  have isStore : row.isStore = false := by
    simp [LoadStoreRow.isStore, isSb, isSh, isSw]
  refine load_refines row env holds isStore ?_ ?_
    (lb_result_value row env holds selector) ?_
  · simp [LoadStoreDecode.encoding, selector]
  · simp [LoadStoreRow.opcodeId, selector, isLh, isLbu, isLhu, isLw, isSb, isSh,
      isSw, bitValue]
  · simp [executeLb, executeLoad, LoadStoreEnvironment.effectiveAddress_eq,
      LoadStoreEnvironment.busAddress_eq]

theorem lbu_refines
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isLbu = true) :
    LoadRefinement row env LoadStoreDecode.funct3Lbu 22
      (executeLbu env.pre.pc env.baseValue env.imm row.r2Idx env.memoryWord)
      (loadByteUnsignedValue env.baseValue env.imm env.memoryWord) := by
  obtain ⟨isLb, isLh, isLhu, isLw, isSb, isSh, isSw⟩ := lbu_flags row holds selector
  have isStore : row.isStore = false := by
    simp [LoadStoreRow.isStore, isSb, isSh, isSw]
  refine load_refines row env holds isStore ?_ ?_
    (lbu_result_value row env holds selector) ?_
  · simp [LoadStoreDecode.encoding, selector, isLb, isLh, isLw]
  · simp [LoadStoreRow.opcodeId, selector, isLb, isLh, isLhu, isLw, isSb, isSh,
      isSw, bitValue]
  · simp [executeLbu, executeLoad, LoadStoreEnvironment.effectiveAddress_eq,
      LoadStoreEnvironment.busAddress_eq]

theorem lhu_refines
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isLhu = true) :
    LoadRefinement row env LoadStoreDecode.funct3Lhu 23
      (executeLhu env.pre.pc env.baseValue env.imm row.r2Idx env.memoryWord)
      (loadHalfUnsignedValue env.baseValue env.imm env.memoryWord) := by
  obtain ⟨isLb, isLh, isLbu, isLw, isSb, isSh, isSw⟩ := lhu_flags row holds selector
  have isStore : row.isStore = false := by
    simp [LoadStoreRow.isStore, isSb, isSh, isSw]
  refine load_refines row env holds isStore ?_ ?_
    (lhu_result_value row env holds selector) ?_
  · simp [LoadStoreDecode.encoding, selector, isLb, isLh, isLbu, isLw]
  · simp [LoadStoreRow.opcodeId, selector, isLb, isLh, isLbu, isLw, isSb, isSh,
      isSw, bitValue]
  · simp [executeLhu, executeLoad, LoadStoreEnvironment.effectiveAddress_eq,
      LoadStoreEnvironment.busAddress_eq]

theorem lw_refines
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isLw = true) :
    LoadRefinement row env LoadStoreDecode.funct3Lw 21
      (executeLw env.pre.pc env.baseValue env.imm row.r2Idx env.memoryWord)
      (loadWordValue env.memoryWord) := by
  obtain ⟨isLb, isLh, isLbu, isLhu, isSb, isSh, isSw⟩ := lw_flags row holds selector
  have isStore : row.isStore = false := by
    simp [LoadStoreRow.isStore, isSb, isSh, isSw]
  refine load_refines row env holds isStore ?_ ?_
    (lw_result_value row env holds selector) ?_
  · simp [LoadStoreDecode.encoding, selector, isLb, isLh]
  · simp [LoadStoreRow.opcodeId, selector, isLb, isLh, isLbu, isLhu, isSb, isSh,
      isSw, bitValue]
  · simp [executeLw, executeLoad, LoadStoreEnvironment.effectiveAddress_eq,
      LoadStoreEnvironment.busAddress_eq]

/-! ## Stores

A store commits the aligned word under a byte-enable mask, preserves every byte
outside the mask, preserves its data register, and performs no register write. -/

theorem extract_limb0 (bytes : WordBytes) :
    BitVec.extractLsb 7 0 bytes.word = bytes.limb0 := by
  rw [WordBytes.word_append]; bv_decide

theorem extract_limb1 (bytes : WordBytes) :
    BitVec.extractLsb 15 8 bytes.word = bytes.limb1 := by
  rw [WordBytes.word_append]; bv_decide

theorem extract_limb2 (bytes : WordBytes) :
    BitVec.extractLsb 23 16 bytes.word = bytes.limb2 := by
  rw [WordBytes.word_append]; bv_decide

theorem extract_limb3 (bytes : WordBytes) :
    BitVec.extractLsb 31 24 bytes.word = bytes.limb3 := by
  rw [WordBytes.word_append]; bv_decide

theorem mask_sb (row : LoadStoreRow) (selector : row.isSb = true) :
    row.mask = Memory.byteMask row.byteOffset := by
  simp [LoadStoreRow.mask, selector]

theorem mask_sh
    (row : LoadStoreRow) (selector : row.isSh = true) (isSb : row.isSb = false) :
    row.mask = Memory.halfMask row.halfSelector := by
  simp [LoadStoreRow.mask, selector, isSb]

theorem mask_sw
    (row : LoadStoreRow) (isSb : row.isSb = false) (isSh : row.isSh = false) :
    row.mask = Memory.wordMask := by
  simp [LoadStoreRow.mask, isSb, isSh]

/-- C50-C53: the data register a store reads is preserved, so its architectural
value is the row's `src` block. -/
theorem store_operand_value
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (isStore : row.isStore = true) :
    env.operandValue = row.srcNext.word := by
  simp only [LoadStoreEnvironment.operandValue, ← env.operandBinds,
    operandBefore_store row isStore, holds.sourceReadOnly]

/-- C25-C31 with C54-C57: the committed post-state word of an `SB` is the
pre-state word with exactly the selected byte replaced. -/
theorem sb_memory_after
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isSb = true) :
    row.dstNext =
      Memory.applyMask env.memoryWord (storeBytePayload env.operandValue)
        row.mask := by
  have isStore : row.isStore = true := by simp [LoadStoreRow.isStore, selector]
  have isByte : row.isByte = true := by simp [LoadStoreRow.isByte, selector]
  have memory := store_memory_word row env holds isStore
  have source := store_operand_value row env holds isStore
  have sum := holds.byteMarkerSum isByte
  have amount := holds.byteShiftAmount isByte
  obtain ⟨s0, s1, s2, s3⟩ := holds.byteStoreSelect selector
  obtain ⟨p0, p1, p2, p3⟩ := holds.partialStorePreserve (Or.inl selector)
  simp only [LoadStoreRow.markerSum] at sum
  simp only [LoadStoreRow.shiftId] at amount
  rw [memory, source, mask_sb row selector]
  simp only [LoadStoreRow.byteOffset]
  rcases byte_marker_cases row.marker0 row.marker1 row.marker2 row.marker3 sum
    with ⟨m0, m1, m2, m3, sid⟩ | ⟨m0, m1, m2, m3, sid⟩ |
      ⟨m0, m1, m2, m3, sid⟩ | ⟨m0, m1, m2, m3, sid⟩
  · have offset : row.shiftAmount = 0 := by omega
    rw [offset]
    refine WordBytes.eq_of_limbs _ _ ?_ ?_ ?_ ?_ <;>
      simp [Memory.applyMask, Memory.byteMask, storeBytePayload, extract_limb0,
        s0 m0, p1 m1, p2 m2, p3 m3]
  · have offset : row.shiftAmount = 1 := by omega
    rw [offset]
    refine WordBytes.eq_of_limbs _ _ ?_ ?_ ?_ ?_ <;>
      simp [Memory.applyMask, Memory.byteMask, storeBytePayload, extract_limb0,
        s1 m1, p0 m0, p2 m2, p3 m3]
  · have offset : row.shiftAmount = 2 := by omega
    rw [offset]
    refine WordBytes.eq_of_limbs _ _ ?_ ?_ ?_ ?_ <;>
      simp [Memory.applyMask, Memory.byteMask, storeBytePayload, extract_limb0,
        s2 m2, p0 m0, p1 m1, p3 m3]
  · have offset : row.shiftAmount = 3 := by omega
    rw [offset]
    refine WordBytes.eq_of_limbs _ _ ?_ ?_ ?_ ?_ <;>
      simp [Memory.applyMask, Memory.byteMask, storeBytePayload, extract_limb0,
        s3 m3, p0 m0, p1 m1, p2 m2]

/-- C38-C41 with C54-C57: the committed post-state word of an `SH` is the
pre-state word with exactly the selected halfword replaced. -/
theorem sh_memory_after
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isSh = true) :
    row.dstNext =
      Memory.applyMask env.memoryWord (storeHalfPayload env.operandValue)
        row.mask := by
  obtain ⟨_, _, _, _, _, isSb, _⟩ := sh_flags row holds selector
  have isStore : row.isStore = true := by simp [LoadStoreRow.isStore, selector]
  have isHalf : row.isHalf = true := by simp [LoadStoreRow.isHalf, selector]
  have memory := store_memory_word row env holds isStore
  have source := store_operand_value row env holds isStore
  have sum := holds.halfMarkerSum isHalf
  have amount := holds.halfShiftAmount isHalf
  obtain ⟨p0, p1, p2, p3⟩ := holds.partialStorePreserve (Or.inr selector)
  simp only [LoadStoreRow.markerSum] at sum
  have identifiers := holds.halfShiftId isHalf
  simp only [LoadStoreRow.shiftId] at identifiers
  rw [memory, source, mask_sh row selector isSb]
  rcases half_marker_cases row.marker0 row.marker1 row.marker2 row.marker3 sum
      identifiers with ⟨m0, m1, m2, m3⟩ | ⟨m0, m1, m2, m3⟩
  · have sid : row.shiftId = 1 := by
      simp [LoadStoreRow.shiftId, m0, m1, m2, m3]
    obtain ⟨d0, d1⟩ := holds.halfStoreLow selector sid
    have offset : row.shiftAmount = 0 := by omega
    simp only [LoadStoreRow.halfSelector, offset, Nat.reduceDiv]
    refine WordBytes.eq_of_limbs _ _ ?_ ?_ ?_ ?_ <;>
      simp [Memory.applyMask, Memory.halfMask, storeHalfPayload, extract_limb0,
        extract_limb1, d0, d1, p2 m2, p3 m3]
  · have sid : row.shiftId = 5 := by
      simp [LoadStoreRow.shiftId, m0, m1, m2, m3]
    obtain ⟨d2, d3⟩ := holds.halfStoreHigh selector sid
    have offset : row.shiftAmount = 2 := by omega
    simp only [LoadStoreRow.halfSelector, offset, Nat.reduceDiv]
    refine WordBytes.eq_of_limbs _ _ ?_ ?_ ?_ ?_ <;>
      simp [Memory.applyMask, Memory.halfMask, storeHalfPayload, extract_limb0,
        extract_limb1, d2, d3, p0 m0, p1 m1]

/-- C42-C45: `SW` overwrites the whole aligned word with `rs2`. -/
theorem sw_memory_after
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isSw = true) :
    row.dstNext =
      Memory.applyMask env.memoryWord (storeWordPayload env.operandValue)
        row.mask := by
  obtain ⟨_, _, _, _, _, isSb, isSh⟩ := sw_flags row holds selector
  have isStore : row.isStore = true := by simp [LoadStoreRow.isStore, selector]
  have source := store_operand_value row env holds isStore
  rw [source, mask_sw row isSb isSh, Memory.applyMask_word,
    holds.wordStore selector]
  refine WordBytes.eq_of_limbs _ _ ?_ ?_ ?_ ?_ <;>
    simp [storeWordPayload, extract_limb0, extract_limb1, extract_limb2,
      extract_limb3]

/-- C54-C57: every byte a partial store does not select survives unchanged. -/
theorem store_preserves_unselected
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (isStore : row.isStore = true)
    (narrow : row.isSb = true ∨ row.isSh = true) :
    (row.marker0 = false → row.memoryAfter.limb0 = env.memoryWord.limb0) ∧
      (row.marker1 = false → row.memoryAfter.limb1 = env.memoryWord.limb1) ∧
      (row.marker2 = false → row.memoryAfter.limb2 = env.memoryWord.limb2) ∧
      (row.marker3 = false → row.memoryAfter.limb3 = env.memoryWord.limb3) := by
  obtain ⟨p0, p1, p2, p3⟩ := holds.partialStorePreserve narrow
  rw [memoryAfter_store row isStore, store_memory_word row env holds isStore]
  exact ⟨p0, p1, p2, p3⟩

/-- The complete refinement obligation of any of the three stores. -/
structure StoreRefinement
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (funct3 : BitVec 3)
    (opcodeId : Nat)
    (architectural : Retirement)
    (after : WordBytes) :
    Prop where
  decode :
    LoadStoreDecode.isStoreOf env.word funct3 = true ∧
      LoadStoreDecode.decodeSImmediate env.word = env.imm ∧
      LoadStoreDecode.decodeRs1 env.word = row.rs1Addr ∧
      LoadStoreDecode.decodeRs2 env.word = row.r2Idx
  effectiveAddress :
    env.effectiveAddress.toNat = row.alignedAddress + row.shiftAmount
  busAddress : Memory.busAddress env.effectiveAddress = row.busAddress
  retirement : loadStoreRetirement row = architectural
  /-- A store performs no architectural register write. -/
  noRegisterWrite : (loadStoreRetirement row).write = none
  /-- A store performs no architectural memory read observation. -/
  noRead : (loadStoreRetirement row).read = none
  /-- The data register is read-only. -/
  sourcePreserved : row.srcNext = row.srcPrevious
  basePreserved : row.rs1Next = row.rs1Previous
  memoryUpdated : row.memoryAfter = after
  programTuple :
    (loadStoreRelations row).program = {
      pc := env.pre.pc
      opcodeId := opcodeId
      rd := row.rs1Addr.toNat
      rs1 := row.r2Idx.toNat
      operand := immFieldValue env.imm
    }
  stateConsume :
    (loadStoreRelations row).stateConsume = {
      pc := env.pre.pc
      clock := row.clock
    }
  stateEmit :
    (loadStoreRelations row).stateEmit = {
      pc := nextPc env.pre.pc
      clock := row.clock + 1
    }
  baseConsume :
    (loadStoreRelations row).baseConsume = {
      addr := row.rs1Addr
      clock := row.rs1PreviousClock
      value := env.pre.registers row.rs1Addr
    }
  baseEmit :
    (loadStoreRelations row).baseEmit = {
      addr := row.rs1Addr
      clock := accessClock row.clock 1
      value := env.pre.registers row.rs1Addr
    }
  operandConsume :
    (loadStoreRelations row).operandConsume = {
      addr := row.r2Idx
      clock := row.srcPreviousClock
      value := env.pre.registers row.r2Idx
    }
  operandEmit :
    (loadStoreRelations row).operandEmit = {
      addr := row.r2Idx
      clock := accessClock row.clock 2
      value := env.pre.registers row.r2Idx
    }
  memoryConsume :
    (loadStoreRelations row).memoryConsume = {
      addr := env.busAddress
      clock := row.dstPreviousClock
      value := env.memoryWord.word
    }
  memoryEmit :
    (loadStoreRelations row).memoryEmit = {
      addr := env.busAddress
      clock := accessClock row.clock 3
      value := after.word
    }

/-- The shared store theorem. -/
theorem store_refines
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (isStore : row.isStore = true)
    {funct3 : BitVec 3}
    (encoding :
      LoadStoreDecode.encoding row env.imm =
        LoadStoreDecode.encodeStore env.imm row.r2Idx row.rs1Addr funct3)
    {opcodeId : Nat}
    (identifier : row.opcodeId = opcodeId)
    {mask : ByteMask}
    (maskValue : row.mask = mask)
    {after : WordBytes}
    (updated : row.dstNext = after)
    {architectural : Retirement}
    (retire : architectural = {
      nextPc := nextPc env.pre.pc
      write := none
      read := none
      store := some {
        address := env.busAddress
        mask := mask
        value := after.word
      }
    }) :
    StoreRefinement row env funct3 opcodeId architectural after := by
  have memory := store_memory_word row env holds isStore
  have bus := row_busAddress row env holds
  have pcValue : row.claimedNextPc = nextPc env.pre.pc := by
    rw [holds.nextPcResult, env.pcBinds]
  have operand : row.srcPrevious.word = env.pre.registers row.r2Idx := by
    rw [← env.operandBinds, operandBefore_store row isStore]
  refine {
    decode := ?_
    effectiveAddress := effective_address_toNat row env holds
    busAddress := bus
    retirement := ?_
    noRegisterWrite := ?_
    noRead := ?_
    sourcePreserved := holds.sourceReadOnly
    basePreserved := holds.baseReadOnly
    memoryUpdated := ?_
    programTuple := ?_
    stateConsume := ?_
    stateEmit := ?_
    baseConsume := ?_
    baseEmit := ?_
    operandConsume := ?_
    operandEmit := ?_
    memoryConsume := ?_
    memoryEmit := ?_
  }
  · rw [env.wordBinds, encoding]
    exact LoadStoreDecode.encode_store_is_canonical env.imm row.r2Idx row.rs1Addr
      funct3
  · rw [loadStoreRetirement_store row isStore, retire]
    simp only [LoadStoreEnvironment.busAddress_eq, ← bus, pcValue, maskValue,
      updated]
  · rw [loadStoreRetirement_store row isStore]
  · rw [loadStoreRetirement_store row isStore]
  · rw [memoryAfter_store row isStore, updated]
  · simp [loadStoreRelations, loadStoreProgramTuple, env.pcBinds, env.immBinds,
      identifier]
  · simp [loadStoreRelations, env.pcBinds]
  · simp [loadStoreRelations, env.pcBinds]
  · simp [loadStoreRelations, env.baseBinds]
  · simp [loadStoreRelations, holds.baseReadOnly, env.baseBinds]
  · simp [loadStoreRelations, operandPreviousClock_store row isStore,
      operandBefore_store row isStore, operand]
  · simp [loadStoreRelations, operandAfter_store row isStore,
      holds.sourceReadOnly, operand]
  · simp only [loadStoreRelations, memoryPreviousClock_store row isStore,
      memoryBefore_store row isStore, ← bus, LoadStoreEnvironment.busAddress_eq,
      memory]
  · simp only [loadStoreRelations, memoryAfter_store row isStore, ← bus,
      LoadStoreEnvironment.busAddress_eq, updated]

theorem sb_refines
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isSb = true) :
    StoreRefinement row env LoadStoreDecode.funct3Sb 24
      (executeSb env.pre.pc env.baseValue env.imm env.operandValue
        env.memoryWord)
      (Memory.applyMask env.memoryWord (storeBytePayload env.operandValue)
        row.mask) := by
  obtain ⟨isLb, isLh, isLbu, isLhu, isLw, isSh, isSw⟩ := sb_flags row holds selector
  have isStore : row.isStore = true := by simp [LoadStoreRow.isStore, selector]
  refine store_refines row env holds isStore ?_ ?_ rfl
    (sb_memory_after row env holds selector) ?_
  · simp [LoadStoreDecode.encoding, selector, isLb, isLh, isLbu, isLhu, isLw]
  · simp [LoadStoreRow.opcodeId, selector, isLb, isLh, isLbu, isLhu, isLw, isSh,
      isSw, bitValue]
  · simp only [executeSb, executeStore, LoadStoreEnvironment.effectiveAddress_eq,
      LoadStoreEnvironment.busAddress_eq, row_byteOffset row env holds,
      ← mask_sb row selector]

theorem sh_refines
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isSh = true) :
    StoreRefinement row env LoadStoreDecode.funct3Sh 25
      (executeSh env.pre.pc env.baseValue env.imm env.operandValue
        env.memoryWord)
      (Memory.applyMask env.memoryWord (storeHalfPayload env.operandValue)
        row.mask) := by
  obtain ⟨isLb, isLh, isLbu, isLhu, isLw, isSb, isSw⟩ := sh_flags row holds selector
  have isStore : row.isStore = true := by simp [LoadStoreRow.isStore, selector]
  refine store_refines row env holds isStore ?_ ?_ rfl
    (sh_memory_after row env holds selector) ?_
  · simp [LoadStoreDecode.encoding, selector, isLb, isLh, isLbu, isLhu, isLw,
      isSb]
  · simp [LoadStoreRow.opcodeId, selector, isLb, isLh, isLbu, isLhu, isLw, isSb,
      isSw, bitValue]
  · simp only [executeSh, executeStore, LoadStoreEnvironment.effectiveAddress_eq,
      LoadStoreEnvironment.busAddress_eq, row_halfSelector row env holds,
      ← mask_sh row selector isSb]

theorem sw_refines
    (row : LoadStoreRow)
    (env : LoadStoreEnvironment row)
    (holds : LoadStoreHolds row)
    (selector : row.isSw = true) :
    StoreRefinement row env LoadStoreDecode.funct3Sw 26
      (executeSw env.pre.pc env.baseValue env.imm env.operandValue
        env.memoryWord)
      (Memory.applyMask env.memoryWord (storeWordPayload env.operandValue)
        row.mask) := by
  obtain ⟨isLb, isLh, isLbu, isLhu, isLw, isSb, isSh⟩ := sw_flags row holds selector
  have isStore : row.isStore = true := by simp [LoadStoreRow.isStore, selector]
  refine store_refines row env holds isStore ?_ ?_ rfl
    (sw_memory_after row env holds selector) ?_
  · simp [LoadStoreDecode.encoding, selector, isLb, isLh, isLbu, isLhu, isLw,
      isSb, isSh]
  · simp [LoadStoreRow.opcodeId, selector, isLb, isLh, isLbu, isLhu, isLw, isSb,
      isSh, bitValue]
  · simp only [executeSw, executeStore, LoadStoreEnvironment.effectiveAddress_eq,
      LoadStoreEnvironment.busAddress_eq, ← mask_sw row isSb isSh]

end RiscvRefinement.Opcodes
