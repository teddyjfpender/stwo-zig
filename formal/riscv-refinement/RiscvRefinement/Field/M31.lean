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
deriving DecidableEq, Repr

instance : BEq M31 := ⟨fun left right => left.val == right.val⟩

instance : LawfulBEq M31 where
  eq_of_beq := by
    intro left right equality
    cases left
    cases right
    simp_all [BEq.beq]
  rfl := by
    intro value
    cases value
    simp [BEq.beq]

namespace M31

def modulus : Nat := m31Modulus

theorem modulus_eq : modulus = 2147483647 := rfl

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

theorem ext {left right : M31} (values : left.val = right.val) :
    left = right := by
  cases left
  cases right
  simp_all

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

@[simp] theorem reduce_zero : reduce 0 = 0 := rfl

@[simp] theorem reduce_one : reduce 1 = 1 := rfl

@[simp] theorem toNat_zero : (0 : M31).toNat = 0 := rfl

@[simp] theorem toNat_one : (1 : M31).toNat = 1 := rfl

theorem reduce_val_of_lt
    (value : Nat)
    (bound : value < modulus) :
    (reduce value).val = value := by
  simp [Nat.mod_eq_of_lt bound]

theorem reduce_injective_of_lt
    {left right : Nat}
    (leftBound : left < modulus)
    (rightBound : right < modulus) :
    reduce left = reduce right ↔ left = right := by
  constructor
  · intro equality
    have values := congrArg M31.toNat equality
    change (reduce left).val = (reduce right).val at values
    rw [
      reduce_val_of_lt left leftBound,
      reduce_val_of_lt right rightBound,
    ] at values
    exact values
  · intro equality
    simp [equality]

theorem reduce_eq_zero_of_lt
    {value : Nat}
    (bound : value < modulus) :
    reduce value = 0 ↔ value = 0 := by
  simpa using
    (reduce_injective_of_lt bound (by decide : 0 < modulus))

theorem reduce_eq_one_of_lt
    {value : Nat}
    (bound : value < modulus) :
    reduce value = 1 ↔ value = 1 := by
  simpa using
    (reduce_injective_of_lt bound (by decide : 1 < modulus))

theorem add_toNat_of_lt
    (left right : M31)
    (bound : left.toNat + right.toNat < modulus) :
    (left + right).toNat = left.toNat + right.toNat := by
  change
    (reduce (left.val + right.val)).val =
      left.val + right.val
  exact reduce_val_of_lt _ bound

theorem add_val_of_lt
    (left right : M31)
    (bound : left.val + right.val < modulus) :
    (left + right).val = left.val + right.val :=
  add_toNat_of_lt left right bound

theorem mul_toNat_of_lt
    (left right : M31)
    (bound : left.toNat * right.toNat < modulus) :
    (left * right).toNat = left.toNat * right.toNat := by
  change
    (reduce (left.val * right.val)).val =
      left.val * right.val
  exact reduce_val_of_lt _ bound

theorem mul_val_of_lt
    (left right : M31)
    (bound : left.val * right.val < modulus) :
    (left * right).val = left.val * right.val :=
  mul_toNat_of_lt left right bound

private theorem add_sub_rearrange
    {left right offset : Nat}
    (ordered : right ≤ left) :
    left + offset - right =
      offset + (left - right) := by
  omega

private theorem add_sub_lt_offset
    {left right offset : Nat}
    (ordered : left < right)
    (positive : 0 < offset) :
    left + offset - right < offset := by
  omega

theorem sub_val_of_le
    (left right : M31)
    (ordered : right.val ≤ left.val) :
    (left - right).val = left.val - right.val := by
  change
    (reduce (left.val + modulus - right.val)).val =
      left.val - right.val
  rw [reduce_val]
  have rearranged :
      left.val + modulus - right.val =
        modulus + (left.val - right.val) :=
    add_sub_rearrange ordered
  have differenceBound : left.val - right.val < modulus :=
    Nat.lt_of_le_of_lt (Nat.sub_le left.val right.val) left.isLt
  rw [
    rearranged,
    Nat.add_mod_left,
    Nat.mod_eq_of_lt differenceBound,
  ]

theorem sub_val_of_lt
    (left right : M31)
    (ordered : left.val < right.val) :
    (left - right).val =
      modulus + left.val - right.val := by
  change
    (reduce (left.val + modulus - right.val)).val =
      modulus + left.val - right.val
  have expressionBound :
      left.val + modulus - right.val < modulus :=
    add_sub_lt_offset ordered modulus_pos
  rw [reduce_val_of_lt _ expressionBound]
  rw [Nat.add_comm left.val modulus]

theorem sub_eq_zero_iff
    (left right : M31) :
    left - right = 0 ↔ left = right := by
  constructor
  · intro differenceZero
    have differenceVal := congrArg M31.val differenceZero
    by_cases ordered : right.val ≤ left.val
    · rw [sub_val_of_le left right ordered] at differenceVal
      apply ext
      change left.val - right.val = 0 at differenceVal
      omega
    · have reverse : left.val < right.val := Nat.lt_of_not_ge ordered
      rw [sub_val_of_lt left right reverse] at differenceVal
      change modulus + left.val - right.val = 0 at differenceVal
      have rightCanonical : right.val < modulus := by
        simpa [modulus, m31Modulus] using right.isLt
      have positive : 0 < modulus + left.val - right.val := by
        omega
      omega
  · intro equality
    subst right
    apply ext
    rw [sub_val_of_le left left (Nat.le_refl _)]
    change left.val - left.val = 0
    omega

@[simp] theorem reduce_toNat (value : M31) :
    reduce value.toNat = value := by
  apply ext
  have bound : value.val < modulus := by
    simpa [modulus, m31Modulus] using value.isLt
  exact reduce_val_of_lt value.val bound

@[simp] theorem zero_add (value : M31) : 0 + value = value := by
  change reduce (zero.val + value.val) = value
  simpa [zero, toNat] using reduce_toNat value

@[simp] theorem add_zero (value : M31) : value + 0 = value := by
  change reduce (value.val + zero.val) = value
  simpa [zero, toNat] using reduce_toNat value

@[simp] theorem zero_mul (value : M31) : 0 * value = 0 := by
  change reduce (zero.val * value.val) = zero
  apply ext
  simp [zero, reduce]

@[simp] theorem mul_zero (value : M31) : value * 0 = 0 := by
  change reduce (value.val * zero.val) = zero
  apply ext
  simp [zero, reduce]

@[simp] theorem one_mul (value : M31) : 1 * value = value := by
  change reduce (one.val * value.val) = value
  simpa [one, toNat] using reduce_toNat value

@[simp] theorem mul_one (value : M31) : value * 1 = value := by
  change reduce (value.val * one.val) = value
  simpa [one, toNat] using reduce_toNat value

@[simp] theorem sub_zero (value : M31) : value - 0 = value := by
  change reduce (value.val + modulus - zero.val) = value
  apply ext
  have bound : value.val < modulus := by
    simpa [modulus, m31Modulus] using value.isLt
  simp [zero, reduce_val, Nat.mod_eq_of_lt bound]

@[simp] theorem sub_self (value : M31) : value - value = 0 := by
  change reduce (value.val + modulus - value.val) = zero
  apply ext
  have canonical : value.val < modulus := by
    simpa [modulus, m31Modulus] using value.isLt
  simp only [reduce_val, zero_val]
  have sum : value.val + modulus - value.val = modulus := by omega
  rw [sum, Nat.mod_self]

theorem toNat_injective {left right : M31} :
    left.toNat = right.toNat ↔ left = right := by
  constructor
  · exact fun equality => ext equality
  · exact fun equality => congrArg toNat equality

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
