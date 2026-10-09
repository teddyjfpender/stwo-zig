import S31.Semantics.Field
import Mathlib.Tactic

namespace S31.Field

instance : Fact (Nat.Prime 2147483647) := ⟨by norm_num⟩

theorem toZMod_val (x : M31) : (toZMod x).val = x.val := by
  change x.val % 2147483647 = x.val
  exact Nat.mod_eq_of_lt x.isLt

theorem toZMod_injective : Function.Injective toZMod := by
  intro a b h
  apply RiscvRefinement.M31.ext
  simpa only [toZMod_val] using congrArg ZMod.val h

theorem from_to (x : M31) : fromZMod (toZMod x) = x := by
  apply RiscvRefinement.M31.ext
  change (toZMod x).val % RiscvRefinement.M31.modulus = x.val
  rw [toZMod_val]
  exact Nat.mod_eq_of_lt x.isLt

theorem to_from (x : F) : toZMod (fromZMod x) = x := by
  change ((x.val % 2147483647 : Nat) : F) = x
  rw [ZMod.natCast_mod, ZMod.natCast_zmod_val]

theorem toZMod_reduce (x : Nat) : toZMod (RiscvRefinement.M31.reduce x) = (x : F) := by
  change ((x % 2147483647 : Nat) : F) = (x : F)
  exact ZMod.natCast_mod x 2147483647

theorem toZMod_add (a b : M31) : toZMod (a + b) = toZMod a + toZMod b := by
  change toZMod (RiscvRefinement.M31.reduce (a.val + b.val)) = _
  rw [toZMod_reduce, Nat.cast_add]; rfl

theorem toZMod_mul (a b : M31) : toZMod (a * b) = toZMod a * toZMod b := by
  change toZMod (RiscvRefinement.M31.reduce (a.val * b.val)) = _
  rw [toZMod_reduce, Nat.cast_mul]; rfl

theorem toZMod_zero : toZMod (0 : M31) = 0 := rfl
theorem toZMod_one : toZMod (1 : M31) = 1 := rfl

theorem inverse_sound_complete (x y : M31) (hx : x ≠ 0) :
    x * y = 1 ↔ y = inverse x := by
  have hx' : toZMod x ≠ 0 := by
    intro h
    exact hx (toZMod_injective (h.trans toZMod_zero.symm))
  constructor
  · intro h
    apply toZMod_injective
    rw [inverse, to_from]
    have h' : toZMod x * toZMod y = 1 := by
      simpa only [toZMod_mul, toZMod_one] using congrArg toZMod h
    exact eq_inv_of_mul_eq_one_right h'
  · rintro rfl
    apply toZMod_injective
    simp [toZMod_mul, inverse, to_from, toZMod_one, hx']

/-- Bounded representatives, rather than an equation modulo p alone, permit
recovering an ordinary integer equation. This premise is used at carry gates. -/
theorem bounded_equation (a b : Nat) (ha : a < 2147483647) (hb : b < 2147483647) :
    (a : F) = (b : F) ↔ a = b := by
  constructor
  · intro h
    have := congrArg ZMod.val h
    simpa [ZMod.val_natCast, Nat.mod_eq_of_lt ha, Nat.mod_eq_of_lt hb] using this
  · exact congrArg (fun n : Nat => (n : F))

end S31.Field

namespace S31.Gadgets
variable {F : Type} [Field F]

def addConstraint (a b y : F) : Prop := y - a - b = 0
def mulConstraint (a b y : F) : Prop := y - a * b = 0
def zeroAnchor (anchor value : F) : Prop := anchor + value = anchor

theorem add_sound_complete (a b y : F) : addConstraint a b y ↔ y = a + b := by
  unfold addConstraint
  constructor <;> intro h <;> linear_combination h

theorem mul_sound_complete (a b y : F) : mulConstraint a b y ↔ y = a * b :=
  sub_eq_zero

theorem zero_anchor_sound_complete (anchor value : F) : zeroAnchor anchor value ↔ value = 0 := by
  simp [zeroAnchor]

theorem inverse_sound_complete (x y : F) : x * y = 1 ↔ x ≠ 0 ∧ y = x⁻¹ := by
  constructor
  · intro h
    have hx : x ≠ 0 := by intro hx; simp [hx] at h
    exact ⟨hx, eq_inv_of_mul_eq_one_right h⟩
  · rintro ⟨hx, rfl⟩; exact mul_inv_cancel₀ hx

end S31.Gadgets
