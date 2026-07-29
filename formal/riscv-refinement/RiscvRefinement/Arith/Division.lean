-- Checked Nat/Int quotient-and-remainder library for the RISC-V M division
-- family. This file is pure arithmetic: it makes no claim about the pinned
-- Sail model and no claim about the production AIR. It fixes the exact
-- interpretation of a 32-bit word as an unsigned and as a two's complement
-- signed integer, states RISC-V's truncate-toward-zero convention with
-- `Int.tdiv` / `Int.tmod`, and proves the uniqueness facts the AIR refinement
-- proofs consume.

import RiscvRefinement.Common

namespace RiscvRefinement.Arith

open RiscvRefinement

/-! ## Word interpretations -/

/-- The unsigned 32-bit value of a machine word. -/
def unsignedValue (w : Word) : Nat := w.toNat

/-- The two's complement signed 32-bit value of a machine word. -/
def signedValue (w : Word) : Int :=
  if w.toNat < 2147483648 then (w.toNat : Int) else (w.toNat : Int) - 4294967296

theorem unsignedValue_lt (w : Word) : unsignedValue w < 4294967296 := by
  have h := w.isLt
  simpa [unsignedValue] using h

theorem signedValue_eq_sub (w : Word) :
    signedValue w =
      (w.toNat : Int) -
        4294967296 * (if 2147483648 ≤ w.toNat then 1 else 0) := by
  unfold signedValue
  by_cases h : w.toNat < 2147483648
  · simp [h, Nat.not_le.mpr h]
  · simp [h, Nat.le_of_not_lt h]

theorem signedValue_lower (w : Word) : -2147483648 ≤ signedValue w := by
  have h := unsignedValue_lt w
  simp only [unsignedValue] at h
  unfold signedValue
  split <;> omega

theorem signedValue_upper (w : Word) : signedValue w < 2147483648 := by
  have h := unsignedValue_lt w
  simp only [unsignedValue] at h
  unfold signedValue
  split <;> omega

theorem signedValue_nonneg_iff (w : Word) :
    0 ≤ signedValue w ↔ w.toNat < 2147483648 := by
  have bound := unsignedValue_lt w
  simp only [unsignedValue] at bound
  unfold signedValue
  split <;> omega

/-! ## Wrapping an integer back into a machine word -/

/-- The 32-bit machine word denoting an integer, truncated modulo `2 ^ 32`. -/
def wrapSigned (value : Int) : Word := BitVec.ofInt 32 value

theorem wrapSigned_ofNat (value : Nat) :
    wrapSigned (value : Int) = BitVec.ofNat 32 value := by
  apply BitVec.eq_of_toNat_eq
  simp only [wrapSigned, BitVec.toNat_ofInt, BitVec.toNat_ofNat, Nat.reducePow]
  omega

/-- Wrapping the signed reading of a limb pattern recovers the pattern. This is
the bridge from an integer result back to the committed destination word. -/
theorem wrapSigned_sub (value : Nat) (high : Bool) :
    wrapSigned ((value : Int) - 4294967296 * (if high then 1 else 0)) =
      BitVec.ofNat 32 value := by
  apply BitVec.eq_of_toNat_eq
  cases high with
  | false =>
    simp only [Bool.false_eq_true, ↓reduceIte, Int.mul_zero, Int.sub_zero,
      wrapSigned, BitVec.toNat_ofInt, BitVec.toNat_ofNat, Nat.reducePow]
    omega
  | true =>
    simp only [↓reduceIte, Int.mul_one, wrapSigned, BitVec.toNat_ofInt,
      BitVec.toNat_ofNat, Nat.reducePow]
    omega

theorem signedValue_wrapSigned (value : Int)
    (lower : -2147483648 ≤ value) (upper : value < 2147483648) :
    signedValue (wrapSigned value) = value := by
  have toNat :
      (wrapSigned value).toNat =
        (value % 4294967296).toNat := by
    simp [wrapSigned, BitVec.toNat_ofInt]
  unfold signedValue
  rw [toNat]
  have hmod : value % 4294967296 = if 0 ≤ value then value else value + 4294967296 := by
    split <;> omega
  rw [hmod]
  split <;> omega

/-! ## Truncation toward zero

RISC-V division truncates toward zero. That is `Int.tdiv` / `Int.tmod`, not the
Euclidean `Int.div` / `Int.emod`: `(-7).tdiv 3 = -2` while `(-7) / 3 = -3`. -/

example : ((-7 : Int).tdiv 3, (-7 : Int).tmod 3) = (-2, -1) := by decide

example : ((7 : Int).tdiv (-3), (7 : Int).tmod (-3)) = (-2, 1) := by decide

example : ((-7 : Int).tdiv (-3), (-7 : Int).tmod (-3)) = (2, -1) := by decide

/-- The division identity: `dividend = divisor * quotient + remainder`. -/
theorem tdiv_identity (dividend divisor : Int) :
    divisor * dividend.tdiv divisor + dividend.tmod divisor = dividend :=
  Int.mul_tdiv_add_tmod dividend divisor

/-- The remainder magnitude is strictly below the divisor magnitude. -/
theorem tmod_natAbs_lt (dividend : Int) {divisor : Int} (nonzero : divisor ≠ 0) :
    (dividend.tmod divisor).natAbs < divisor.natAbs := by
  rw [Int.natAbs_tmod]
  exact Nat.mod_lt _ (Int.natAbs_pos.mpr nonzero)

/-- The remainder sign matches the dividend sign (or the remainder is zero). -/
theorem tmod_nonneg_of_nonneg {dividend : Int} (divisor : Int)
    (h : 0 ≤ dividend) : 0 ≤ dividend.tmod divisor :=
  Int.tmod_nonneg divisor h

theorem tmod_nonpos_of_nonpos {dividend : Int} (divisor : Int)
    (h : dividend ≤ 0) : dividend.tmod divisor ≤ 0 := by
  have := Int.tmod_nonneg (a := -dividend) divisor (by omega)
  rw [Int.neg_tmod] at this
  omega

/-- Uniqueness of truncated quotient and remainder.

Any `(quotient, remainder)` pair satisfying the division identity, the
remainder magnitude bound, and the remainder-sign-follows-dividend rule *is*
the truncating pair. This is the only route by which the AIR refinement proofs
identify the committed limbs with the architectural result: it consumes the
row's own product recurrence and comparison witnesses, never an assumption
that the quotient is already correct. -/
theorem tdiv_tmod_unique
    {dividend divisor quotient remainder : Int}
    (nonzero : divisor ≠ 0)
    (identity : divisor * quotient + remainder = dividend)
    (lower : -(divisor.natAbs : Int) < remainder)
    (upper : remainder < (divisor.natAbs : Int))
    (signPos : 0 ≤ dividend → 0 ≤ remainder)
    (signNeg : dividend ≤ 0 → remainder ≤ 0) :
    quotient = dividend.tdiv divisor ∧ remainder = dividend.tmod divisor := by
  rcases (by omega : 0 ≤ dividend ∨ dividend < 0) with hd | hd
  · have := (Int.tdiv_tmod_unique (a := dividend) (b := divisor)
      (r := remainder) (q := quotient) hd nonzero).mpr
      ⟨by rw [Int.add_comm]; exact identity, signPos hd, upper⟩
    exact ⟨this.1.symm, this.2.symm⟩
  · have hle : dividend ≤ 0 := by omega
    have := (Int.tdiv_tmod_unique' (a := dividend) (b := divisor)
      (r := remainder) (q := quotient) hle nonzero).mpr
      ⟨by rw [Int.add_comm]; exact identity, lower, signNeg hle⟩
    exact ⟨this.1.symm, this.2.symm⟩

/-- Uniqueness of the unsigned quotient and remainder. -/
theorem div_mod_unique
    {dividend divisor quotient remainder : Nat}
    (identity : divisor * quotient + remainder = dividend)
    (bound : remainder < divisor) :
    quotient = dividend / divisor ∧ remainder = dividend % divisor := by
  have positive : 0 < divisor := Nat.lt_of_le_of_lt (Nat.zero_le _) bound
  constructor
  · rw [← identity, Nat.mul_add_div positive, Nat.div_eq_of_lt bound, Nat.add_zero]
  · rw [← identity, Nat.mul_add_mod, Nat.mod_eq_of_lt bound]

/-! ## The four RISC-V conventions -/

def allOnesWord : Word := BitVec.ofNat 32 4294967295

def intMinWord : Word := BitVec.ofNat 32 2147483648

def minusOneWord : Word := BitVec.ofNat 32 4294967295

/-- `DIV`: signed truncating quotient; a zero divisor yields all ones. -/
def divideSigned (dividend divisor : Word) : Word :=
  if divisor = zeroWord then allOnesWord
  else wrapSigned ((signedValue dividend).tdiv (signedValue divisor))

/-- `DIVU`: unsigned quotient; a zero divisor yields `2 ^ 32 - 1`. -/
def divideUnsigned (dividend divisor : Word) : Word :=
  if divisor = zeroWord then allOnesWord
  else BitVec.ofNat 32 (unsignedValue dividend / unsignedValue divisor)

/-- `REM`: signed truncating remainder; a zero divisor yields the dividend. -/
def remainderSigned (dividend divisor : Word) : Word :=
  if divisor = zeroWord then dividend
  else wrapSigned ((signedValue dividend).tmod (signedValue divisor))

/-- `REMU`: unsigned remainder; a zero divisor yields the dividend. -/
def remainderUnsigned (dividend divisor : Word) : Word :=
  if divisor = zeroWord then dividend
  else BitVec.ofNat 32 (unsignedValue dividend % unsignedValue divisor)

theorem divideSigned_zero (dividend : Word) :
    divideSigned dividend zeroWord = allOnesWord := by
  simp [divideSigned]

theorem divideUnsigned_zero (dividend : Word) :
    divideUnsigned dividend zeroWord = allOnesWord := by
  simp [divideUnsigned]

theorem remainderSigned_zero (dividend : Word) :
    remainderSigned dividend zeroWord = dividend := by
  simp [remainderSigned]

theorem remainderUnsigned_zero (dividend : Word) :
    remainderUnsigned dividend zeroWord = dividend := by
  simp [remainderUnsigned]

theorem allOnesWord_signedValue : signedValue allOnesWord = -1 := by decide

theorem allOnesWord_unsignedValue : unsignedValue allOnesWord = 4294967295 := by
  decide

/-! ## Signed overflow at `INT_MIN / -1` -/

theorem intMinWord_signedValue : signedValue intMinWord = -2147483648 := by
  decide

theorem minusOneWord_signedValue : signedValue minusOneWord = -1 := by decide

theorem divideSigned_overflow :
    divideSigned intMinWord minusOneWord = intMinWord := by
  decide

theorem remainderSigned_overflow :
    remainderSigned intMinWord minusOneWord = zeroWord := by
  decide

/-! ## High-bit unsigned behaviour -/

theorem divideUnsigned_high_bit :
    divideUnsigned (BitVec.ofNat 32 0x8abcdef1) (BitVec.ofNat 32 1) =
      BitVec.ofNat 32 0x8abcdef1 := by
  decide

theorem remainderUnsigned_high_bit :
    remainderUnsigned (BitVec.ofNat 32 0x8abcdef1) (BitVec.ofNat 32 1) =
      zeroWord := by
  decide

/-- The same bit pattern read as a signed dividend is negative, so `DIV` and
`DIVU` genuinely disagree on it. -/
theorem divideSigned_high_bit :
    divideSigned (BitVec.ofNat 32 0x8abcdef1) (BitVec.ofNat 32 1) =
      BitVec.ofNat 32 0x8abcdef1 := by
  decide

theorem divideUnsigned_high_bit_by_two :
    divideUnsigned (BitVec.ofNat 32 0x8abcdef1) (BitVec.ofNat 32 2) =
      BitVec.ofNat 32 0x455e6f78 := by
  decide

theorem divideSigned_high_bit_by_two :
    divideSigned (BitVec.ofNat 32 0x8abcdef1) (BitVec.ofNat 32 2) =
      BitVec.ofNat 32 0xc55e6f79 := by
  decide

end RiscvRefinement.Arith
