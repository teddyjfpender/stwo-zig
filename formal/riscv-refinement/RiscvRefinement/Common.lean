import Std.Tactic.BVDecide

namespace RiscvRefinement

abbrev Word := BitVec 32
abbrev Byte := BitVec 8
abbrev RegisterIndex := BitVec 5
abbrev InstructionWord := BitVec 32

def zeroWord : Word := BitVec.ofNat 32 0

def zeroRegister : RegisterIndex := BitVec.ofNat 5 0

structure WordBytes where
  limb0 : Byte
  limb1 : Byte
  limb2 : Byte
  limb3 : Byte
deriving DecidableEq, Repr

def WordBytes.value (bytes : WordBytes) : Nat :=
  bytes.limb0.toNat +
    256 * bytes.limb1.toNat +
    65536 * bytes.limb2.toNat +
    16777216 * bytes.limb3.toNat

def WordBytes.word (bytes : WordBytes) : Word :=
  BitVec.ofNat 32 bytes.value

def WordBytes.zero : WordBytes where
  limb0 := BitVec.ofNat 8 0
  limb1 := BitVec.ofNat 8 0
  limb2 := BitVec.ofNat 8 0
  limb3 := BitVec.ofNat 8 0

theorem WordBytes.value_lt (bytes : WordBytes) :
    bytes.value < 2 ^ 32 := by
  have h0 := bytes.limb0.isLt
  have h1 := bytes.limb1.isLt
  have h2 := bytes.limb2.isLt
  have h3 := bytes.limb3.isLt
  simp only [Nat.reducePow] at h0 h1 h2 h3 ⊢
  simp only [WordBytes.value]
  omega

@[simp]
theorem WordBytes.word_toNat (bytes : WordBytes) :
    bytes.word.toNat = bytes.value := by
  simp [WordBytes.word, Nat.mod_eq_of_lt bytes.value_lt]

@[simp]
theorem WordBytes.zero_word :
    WordBytes.zero.word = zeroWord := by
  rfl

theorem WordBytes.eq_of_limbs
    (left right : WordBytes)
    (limb0 : left.limb0 = right.limb0)
    (limb1 : left.limb1 = right.limb1)
    (limb2 : left.limb2 = right.limb2)
    (limb3 : left.limb3 = right.limb3) :
    left = right := by
  cases left
  cases right
  simp_all

theorem toNat_append_arith
    {highWidth lowWidth : Nat}
    (high : BitVec highWidth)
    (low : BitVec lowWidth) :
    (high ++ low).toNat =
      2 ^ lowWidth * high.toNat + low.toNat := by
  rw [
    BitVec.toNat_append,
    ← Nat.shiftLeft_add_eq_or_of_lt (by omega),
    Nat.shiftLeft_eq,
  ]
  simp [Nat.mul_comm]

def nextPc (pc : Word) : Word := pc + BitVec.ofNat 32 4

def accessClock (clock ordinal : Nat) : Nat :=
  (clock - 1) * 4 + ordinal

def validPreviousClock (previous current : Nat) : Prop :=
  previous < current ∧ current - previous - 1 < 2 ^ 20

structure RegisterWrite where
  rd : RegisterIndex
  value : Word
deriving DecidableEq, Repr

def architecturalWrite (rd : RegisterIndex) (value : Word) :
    Option RegisterWrite :=
  if rd = zeroRegister then none else some { rd, value }

def architecturalValue (rd : RegisterIndex) (value : Word) : Word :=
  if rd = zeroRegister then zeroWord else value

structure Retirement where
  nextPc : Word
  write : Option RegisterWrite
deriving DecidableEq, Repr

structure ProgramTuple where
  pc : Word
  opcodeId : Nat
  rd : Nat
  rs1 : Nat
  operand : Nat
deriving DecidableEq, Repr

structure StateTuple where
  pc : Word
  clock : Nat
deriving DecidableEq, Repr

structure RegisterTuple where
  addr : RegisterIndex
  clock : Nat
  value : Word
deriving DecidableEq, Repr

structure PreState where
  pc : Word
  registers : RegisterIndex → Word
  x0IsZero : registers zeroRegister = zeroWord

theorem architecturalWrite_zero (value : Word) :
    architecturalWrite zeroRegister value = none := by
  simp [architecturalWrite]

theorem architecturalValue_zero (value : Word) :
    architecturalValue zeroRegister value = zeroWord := by
  simp [architecturalValue]

theorem architecturalWrite_value
    (rd : RegisterIndex)
    (value : Word) :
    architecturalWrite rd (architecturalValue rd value) =
      architecturalWrite rd value := by
  by_cases isZero : rd = zeroRegister
  · simp [architecturalWrite, isZero]
  · simp [architecturalWrite, architecturalValue, isZero]

end RiscvRefinement
