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

/-- Little-endian low halfword of an aligned memory word. -/
def WordBytes.lowHalf (bytes : WordBytes) : BitVec 16 :=
  bytes.limb1.append bytes.limb0

/-- Little-endian high halfword of an aligned memory word. -/
def WordBytes.highHalf (bytes : WordBytes) : BitVec 16 :=
  bytes.limb3.append bytes.limb2

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

/-- The little-endian limb decomposition of a word is exactly its bit-vector
concatenation, most significant limb first. This is the bridge between the AIR's
`Nat`-valued byte equations and bit-level reasoning. -/
theorem WordBytes.word_append (bytes : WordBytes) :
    bytes.word =
      bytes.limb3.append (bytes.limb2.append (bytes.limb1.append bytes.limb0)) := by
  apply BitVec.eq_of_toNat_eq
  have h0 := bytes.limb0.isLt
  have h1 := bytes.limb1.isLt
  have h2 := bytes.limb2.isLt
  have h3 := bytes.limb3.isLt
  simp only [Nat.reducePow] at h0 h1 h2 h3
  simp only [
    WordBytes.word_toNat,
    WordBytes.value,
    BitVec.append_eq,
    toNat_append_arith,
    Nat.reducePow,
  ]
  omega

/-- The same decomposition split evenly into halfwords.

Stating it this way, rather than only as the four-limb concatenation above, is
what lets the halfword projections be settled structurally: `extractLsb 31 16`
of a balanced `a ++ b` is literally `a`. -/
theorem WordBytes.word_halves (bytes : WordBytes) :
    bytes.word =
      (bytes.limb3.append bytes.limb2).append
        (bytes.limb1.append bytes.limb0) := by
  apply BitVec.eq_of_toNat_eq
  have h0 := bytes.limb0.isLt
  have h1 := bytes.limb1.isLt
  have h2 := bytes.limb2.isLt
  have h3 := bytes.limb3.isLt
  simp only [Nat.reducePow] at h0 h1 h2 h3
  simp only [
    WordBytes.word_toNat,
    WordBytes.value,
    BitVec.append_eq,
    toNat_append_arith,
    Nat.reducePow,
  ]
  omega

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

/-! ## Complete normalized architectural retirement

The zkVM observes exactly four things about a successful transition: the next
program counter, at most one architectural register write, at most one memory
read observation, and at most one masked memory write. `Retirement` is the
frozen Team A / Team B interface for that observation; no other externally
visible state change may be claimed by any refinement theorem.

Memory is addressed as a little-endian array of aligned 32-bit words. A memory
observation and a memory write both name the *aligned word bus address*, so a
sub-word access is expressed as an aligned word plus a byte-enable mask rather
than as a narrow bus transaction. -/

/-- Byte-enable mask over an aligned 32-bit memory word, bit `i` selecting
little-endian byte `i`. -/
abbrev ByteMask := BitVec 4

/-- The observation a load places on the memory bus: the aligned word address
that was read and the complete word value observed there. -/
structure MemoryRead where
  address : Word
  value : Word
deriving DecidableEq, Repr

/-- The masked word a store commits: the aligned word address, the byte-enable
mask, and the complete post-state word. Bytes outside `mask` are required by
the store theorems to equal their pre-state values. -/
structure MemoryWrite where
  address : Word
  mask : ByteMask
  value : Word
deriving DecidableEq, Repr

/-- Complete normalized architectural retirement.

`read` and `store` default to `none`, which is the literal claim "this
transition has no memory effect". Register-only families therefore keep their
existing two-field syntax, and a memory family that forgets to populate the
field cannot prove its refinement theorem, because the theorem states the
field's value. -/
structure Retirement where
  nextPc : Word
  write : Option RegisterWrite
  read : Option MemoryRead := none
  store : Option MemoryWrite := none
deriving DecidableEq, Repr

/-- Classification of a normalized transition. The pinned Sail model may also
trap or diverge; the zkVM language admits only `retired`. -/
inductive Outcome where
  | retired (retirement : Retirement)
  | rejected
deriving DecidableEq, Repr

def Outcome.retirement? : Outcome → Option Retirement
  | .retired retirement => some retirement
  | .rejected => none

@[simp]
theorem Outcome.retirement?_retired (retirement : Retirement) :
    (Outcome.retired retirement).retirement? = some retirement := rfl

@[simp]
theorem Outcome.retirement?_rejected :
    Outcome.rejected.retirement? = none := rfl

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

/-- Relation tuple for one memory access. `addr` is the aligned word bus
address, matching the production memory lookup argument. -/
structure MemoryTuple where
  addr : Word
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
