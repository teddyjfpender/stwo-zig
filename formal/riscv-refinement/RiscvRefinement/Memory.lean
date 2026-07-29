import RiscvRefinement.Common

/-!
# Architectural memory model

Team B owns the architectural half of the memory contract: byte addressing,
aligned word bus projection, little-endian selection, natural alignment, byte
masks, and the sign/zero extension of narrow loads.

Memory is a little-endian array of 32-bit words. Every access names an aligned
word bus address plus a byte-enable mask; a sub-word access is never a narrow
bus transaction. This is the shape the production AIR emits and the shape the
normalized `Retirement` records, so `LB`, `LH`, `LW`, `LBU`, `LHU`, `SB`, `SH`,
and `SW` all project through these definitions without a second interface.
-/

namespace RiscvRefinement.Memory

open RiscvRefinement

/-! ## Addressing -/

/-- Byte offset of an address inside its containing aligned word. -/
def byteOffset (address : Word) : BitVec 2 := BitVec.extractLsb 1 0 address

/-- Aligned word bus address: the address with both low bits cleared. -/
def busAddress (address : Word) : Word :=
  (BitVec.extractLsb 31 2 address).append (BitVec.ofNat 2 0)

/-- Halfword selector: `0` selects the low half of the aligned word, `1` the
high half. -/
def halfSelector (address : Word) : BitVec 1 := BitVec.extractLsb 1 1 address

/-- Effective address of a base-plus-displacement access, under 32-bit modular
arithmetic. Address wrap is architectural, not an error. -/
def effectiveAddress (base : Word) (imm : BitVec 12) : Word :=
  base + BitVec.signExtend 32 imm

def isWordAligned (address : Word) : Prop :=
  byteOffset address = BitVec.ofNat 2 0

def isHalfAligned (address : Word) : Prop :=
  BitVec.extractLsb 0 0 address = BitVec.ofNat 1 0

instance (address : Word) : Decidable (isWordAligned address) := by
  unfold isWordAligned; infer_instance

instance (address : Word) : Decidable (isHalfAligned address) := by
  unfold isHalfAligned; infer_instance

theorem busAddress_isWordAligned (address : Word) :
    isWordAligned (busAddress address) := by
  simp only [isWordAligned, busAddress, byteOffset]
  bv_decide

theorem busAddress_of_wordAligned
    (address : Word)
    (aligned : isWordAligned address) :
    busAddress address = address := by
  revert aligned
  simp only [isWordAligned, busAddress, byteOffset]
  bv_decide

/-- A halfword-aligned address has byte offset `0` or `2`, so its selector bit
determines the offset completely. -/
theorem halfAligned_byteOffset
    (address : Word)
    (aligned : isHalfAligned address) :
    byteOffset address =
      (halfSelector address).append (BitVec.ofNat 1 0) := by
  revert aligned
  simp only [isHalfAligned, byteOffset, halfSelector]
  bv_decide

/-- Effective-address computation is exactly 32-bit modular addition of the
base register and the sign-extended 12-bit displacement. -/
theorem effectiveAddress_toNat (base : Word) (imm : BitVec 12) :
    (effectiveAddress base imm).toNat =
      (base.toNat + (BitVec.signExtend 32 imm).toNat) % 2 ^ 32 := by
  simp [effectiveAddress, BitVec.toNat_add]

/-! ## Little-endian selection -/

/-- Little-endian halfword selection from an aligned memory word. -/
def selectHalf (bytes : WordBytes) (selector : BitVec 1) : BitVec 16 :=
  if selector = BitVec.ofNat 1 1 then bytes.highHalf else bytes.lowHalf

/-- Little-endian byte selection from an aligned memory word. -/
def selectByte (bytes : WordBytes) (offset : BitVec 2) : Byte :=
  if offset = BitVec.ofNat 2 0 then bytes.limb0
  else if offset = BitVec.ofNat 2 1 then bytes.limb1
  else if offset = BitVec.ofNat 2 2 then bytes.limb2
  else bytes.limb3

@[simp]
theorem selectHalf_low (bytes : WordBytes) :
    selectHalf bytes (BitVec.ofNat 1 0) = bytes.lowHalf := rfl

@[simp]
theorem selectHalf_high (bytes : WordBytes) :
    selectHalf bytes (BitVec.ofNat 1 1) = bytes.highHalf := rfl

/-- The low half of an aligned word is bits 15:0 of that word: the little-endian
byte order of `WordBytes` agrees with the bit order of `Word`. -/
theorem lowHalf_extract (bytes : WordBytes) :
    bytes.lowHalf = BitVec.extractLsb 15 0 bytes.word := by
  rw [WordBytes.word_append]
  simp only [WordBytes.lowHalf]
  bv_decide

/-- The high half of an aligned word is bits 31:16 of that word. -/
theorem highHalf_extract (bytes : WordBytes) :
    bytes.highHalf = BitVec.extractLsb 31 16 bytes.word := by
  rw [WordBytes.word_append]
  simp only [WordBytes.highHalf]
  bv_decide

/-! ## Width extension -/

def signExtendByte (value : Byte) : Word := BitVec.signExtend 32 value

def zeroExtendByte (value : Byte) : Word := BitVec.zeroExtend 32 value

def signExtendHalf (value : BitVec 16) : Word := BitVec.signExtend 32 value

def zeroExtendHalf (value : BitVec 16) : Word := BitVec.zeroExtend 32 value

/-- A negative halfword sign-extends with a one fill in bits 31:16. -/
theorem signExtendHalf_negative
    (value : BitVec 16)
    (negative : value.getLsbD 15 = true) :
    BitVec.extractLsb 31 16 (signExtendHalf value) = BitVec.ofNat 16 0xffff := by
  revert negative
  simp only [signExtendHalf]
  bv_decide

/-- A nonnegative halfword sign-extends with a zero fill in bits 31:16, so it
agrees with the unsigned extension. -/
theorem signExtendHalf_nonnegative
    (value : BitVec 16)
    (nonnegative : value.getLsbD 15 = false) :
    signExtendHalf value = zeroExtendHalf value := by
  revert nonnegative
  simp only [signExtendHalf, zeroExtendHalf]
  bv_decide

theorem signExtendHalf_low (value : BitVec 16) :
    BitVec.extractLsb 15 0 (signExtendHalf value) = value := by
  simp only [signExtendHalf]
  bv_decide

theorem signExtendByte_negative
    (value : Byte)
    (negative : value.getLsbD 7 = true) :
    BitVec.extractLsb 31 8 (signExtendByte value) =
      BitVec.ofNat 24 0xffffff := by
  revert negative
  simp only [signExtendByte]
  bv_decide

theorem signExtendByte_nonnegative
    (value : Byte)
    (nonnegative : value.getLsbD 7 = false) :
    signExtendByte value = zeroExtendByte value := by
  revert nonnegative
  simp only [signExtendByte, zeroExtendByte]
  bv_decide

/-! ## Byte masks and masked stores -/

def wordMask : ByteMask := BitVec.ofNat 4 0b1111

def halfMask (selector : BitVec 1) : ByteMask :=
  if selector = BitVec.ofNat 1 1
  then BitVec.ofNat 4 0b1100
  else BitVec.ofNat 4 0b0011

def byteMask (offset : BitVec 2) : ByteMask :=
  if offset = BitVec.ofNat 2 0 then BitVec.ofNat 4 0b0001
  else if offset = BitVec.ofNat 2 1 then BitVec.ofNat 4 0b0010
  else if offset = BitVec.ofNat 2 2 then BitVec.ofNat 4 0b0100
  else BitVec.ofNat 4 0b1000

/-- Commit `replacement` into `original` under a byte-enable mask. -/
def applyMask (original replacement : WordBytes) (mask : ByteMask) :
    WordBytes where
  limb0 := if mask.getLsbD 0 then replacement.limb0 else original.limb0
  limb1 := if mask.getLsbD 1 then replacement.limb1 else original.limb1
  limb2 := if mask.getLsbD 2 then replacement.limb2 else original.limb2
  limb3 := if mask.getLsbD 3 then replacement.limb3 else original.limb3

/-! Bytes outside the mask keep their pre-state value. This is the store
preservation obligation, stated once per limb and reused by every store
width. -/

theorem applyMask_limb0_preserved
    (original replacement : WordBytes)
    (mask : ByteMask)
    (disabled : mask.getLsbD 0 = false) :
    (applyMask original replacement mask).limb0 = original.limb0 := by
  simp only [applyMask, disabled, Bool.false_eq_true, if_false]

theorem applyMask_limb1_preserved
    (original replacement : WordBytes)
    (mask : ByteMask)
    (disabled : mask.getLsbD 1 = false) :
    (applyMask original replacement mask).limb1 = original.limb1 := by
  simp only [applyMask, disabled, Bool.false_eq_true, if_false]

theorem applyMask_limb2_preserved
    (original replacement : WordBytes)
    (mask : ByteMask)
    (disabled : mask.getLsbD 2 = false) :
    (applyMask original replacement mask).limb2 = original.limb2 := by
  simp only [applyMask, disabled, Bool.false_eq_true, if_false]

theorem applyMask_limb3_preserved
    (original replacement : WordBytes)
    (mask : ByteMask)
    (disabled : mask.getLsbD 3 = false) :
    (applyMask original replacement mask).limb3 = original.limb3 := by
  simp only [applyMask, disabled, Bool.false_eq_true, if_false]

/-- A full-word mask overwrites the entire word. -/
theorem applyMask_word (original replacement : WordBytes) :
    applyMask original replacement wordMask = replacement := by
  cases replacement
  simp [applyMask, wordMask]

/-- A halfword store never disturbs the other half. -/
theorem applyMask_half_preserves_other
    (original replacement : WordBytes)
    (selector : BitVec 1) :
    (selector = BitVec.ofNat 1 1 →
        (applyMask original replacement (halfMask selector)).lowHalf =
          original.lowHalf) ∧
      (selector = BitVec.ofNat 1 0 →
        (applyMask original replacement (halfMask selector)).highHalf =
          original.highHalf) := by
  constructor <;> intro selectorValue <;>
    simp [applyMask, halfMask, selectorValue,
      WordBytes.lowHalf, WordBytes.highHalf]

/-- A byte store disturbs exactly one limb. -/
theorem applyMask_byte_single
    (original replacement : WordBytes)
    (offset : BitVec 2) :
    applyMask original replacement (byteMask offset) =
      { original with
        limb0 :=
          if offset = BitVec.ofNat 2 0 then replacement.limb0
          else original.limb0
        limb1 :=
          if offset = BitVec.ofNat 2 1 then replacement.limb1
          else original.limb1
        limb2 :=
          if offset = BitVec.ofNat 2 2 then replacement.limb2
          else original.limb2
        limb3 :=
          if offset = BitVec.ofNat 2 3 then replacement.limb3
          else original.limb3 } := by
  have cases : offset = BitVec.ofNat 2 0 ∨ offset = BitVec.ofNat 2 1 ∨
      offset = BitVec.ofNat 2 2 ∨ offset = BitVec.ofNat 2 3 := by
    revert offset; decide
  rcases cases with h | h | h | h <;>
    cases original <;> simp [applyMask, byteMask, h]

end RiscvRefinement.Memory
