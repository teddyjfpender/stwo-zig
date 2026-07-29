namespace RiscvRefinement

/--
The Mersenne prime used by the production prover.

AIR constants use canonical representatives, so decoding uses `ofNat?` or
`ofInt?`.  `reduce` is deliberately separate: it is used only to implement
field arithmetic after the wire value has already been checked.
-/
private def m31Modulus : Nat := 2147483647

structure M31 where
  val : Nat
  isLt : val < m31Modulus
deriving DecidableEq, BEq, Repr

namespace M31

def modulus : Nat := m31Modulus

private theorem modulus_pos : 0 < modulus := by decide

def ofNat? (value : Nat) : Option M31 :=
  if h : value < modulus then some ⟨value, h⟩ else none

def ofInt? (value : Int) : Option M31 :=
  if 0 ≤ value then ofNat? value.toNat else none

def reduce (value : Nat) : M31 :=
  ⟨value % modulus, Nat.mod_lt _ modulus_pos⟩

def toNat (value : M31) : Nat :=
  value.val

def toInt (value : M31) : Int :=
  Int.ofNat value.val

/-- Lift only when the canonical representative satisfies the caller's bound. -/
def toNatBounded? (bound : Nat) (value : M31) : Option Nat :=
  if value.val < bound then some value.val else none

/-- Lift only when the canonical representative satisfies the caller's integer bound. -/
def toIntBounded? (bound : Int) (value : M31) : Option Int :=
  if toInt value < bound then some (toInt value) else none

def zero : M31 :=
  ⟨0, modulus_pos⟩

def one : M31 :=
  ⟨1, by decide⟩

def add (left right : M31) : M31 :=
  reduce (left.val + right.val)

def sub (left right : M31) : M31 :=
  reduce (left.val + modulus - right.val)

def mul (left right : M31) : M31 :=
  reduce (left.val * right.val)

def neg (value : M31) : M31 :=
  if h : value = zero then
    zero
  else
    ⟨modulus - value.val, by
      have canonical := value.isLt
      have nonzero : value.val ≠ 0 := by
        intro value_zero
        apply h
        cases value with
        | mk val isLt =>
            simp_all [zero]
      simp [modulus, m31Modulus] at canonical ⊢
      omega⟩

instance : Zero M31 := ⟨zero⟩
instance : One M31 := ⟨one⟩
instance : Add M31 := ⟨add⟩
instance : Sub M31 := ⟨sub⟩
instance : Mul M31 := ⟨mul⟩
instance : Neg M31 := ⟨neg⟩

@[simp] theorem zero_val : zero.val = 0 := rfl
@[simp] theorem one_val : one.val = 1 := rfl
@[simp] theorem reduce_val (value : Nat) :
    (reduce value).val = value % modulus := rfl

theorem ofNat?_isSome_iff (value : Nat) :
    (ofNat? value).isSome ↔ value < modulus := by
  simp [ofNat?]

@[simp] theorem ofNat?_toNat (value : M31) :
    ofNat? value.toNat = some value := by
  cases value with
  | mk val isLt =>
      have canonical : val < modulus := by
        simpa [modulus, m31Modulus] using isLt
      simp [ofNat?, toNat, canonical]

@[simp] theorem ofInt?_toInt (value : M31) :
    ofInt? value.toInt = some value := by
  cases value with
  | mk val isLt =>
      have canonical : val < modulus := by
        simpa [modulus, m31Modulus] using isLt
      simp [ofInt?, toInt, ofNat?, canonical]

@[simp] theorem toNatBounded?_eq_some
    (bound : Nat)
    (value : M31)
    (h : value.toNat < bound) :
    value.toNatBounded? bound = some value.toNat := by
  simp [toNatBounded?, toNat] at h ⊢
  simp [h]

end M31

end RiscvRefinement
