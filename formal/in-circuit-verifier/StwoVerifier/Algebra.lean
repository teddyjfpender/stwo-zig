/-
**Ring structure for the concrete field tower.** `CM31` and `QM31` from
`Fields.lean` are commutative rings under their coordinate operations;
every law reduces to polynomial identities over `F = ZMod P`, discharged
by `ext` + `ring`. (Fieldness — every nonzero element invertible — follows
from the irreducibility of `i² + 1` and `u² − (2 + i)` and is proven in
starked-bitcoin's `Spec/QM31.lean` for the same tower; it is not needed by
the gadget soundness theorems, which only use ring reasoning and explicit
`x · x⁻¹ = 1` gate facts.)
-/
import StwoVerifier.Fields

namespace StwoVerifier

@[ext] theorem CM31.ext' {x y : CM31} (ha : x.a = y.a) (hb : x.b = y.b) : x = y := by
  cases x; cases y; simp_all

@[ext] theorem QM31.ext' {x y : QM31} (h0 : x.c0 = y.c0) (h1 : x.c1 = y.c1) : x = y := by
  cases x; cases y; simp_all

namespace CM31

@[simp] theorem add_a (x y : CM31) : (x + y).a = x.a + y.a := rfl
@[simp] theorem add_b (x y : CM31) : (x + y).b = x.b + y.b := rfl
@[simp] theorem sub_a (x y : CM31) : (x - y).a = x.a - y.a := rfl
@[simp] theorem sub_b (x y : CM31) : (x - y).b = x.b - y.b := rfl
@[simp] theorem neg_a (x : CM31) : (-x).a = -x.a := rfl
@[simp] theorem neg_b (x : CM31) : (-x).b = -x.b := rfl
@[simp] theorem mul_a (x y : CM31) : (x * y).a = x.a * y.a - x.b * y.b := rfl
@[simp] theorem mul_b (x y : CM31) : (x * y).b = x.a * y.b + x.b * y.a := rfl
@[simp] theorem zero_a : (0 : CM31).a = 0 := rfl
@[simp] theorem zero_b : (0 : CM31).b = 0 := rfl
@[simp] theorem one_a : (1 : CM31).a = 1 := rfl
@[simp] theorem one_b : (1 : CM31).b = 0 := rfl
@[simp] theorem zero_def : CM31.zero = (0 : CM31) := rfl
@[simp] theorem one_def : CM31.one = (1 : CM31) := rfl

instance : CommRing CM31 where
  add := (· + ·)
  zero := 0
  mul := (· * ·)
  one := 1
  neg := (- ·)
  sub := (· - ·)
  nsmul := nsmulRec
  zsmul := zsmulRec
  add_assoc := by intros; ext <;> simp <;> ring
  zero_add := by intros; ext <;> simp
  add_zero := by intros; ext <;> simp
  add_comm := by intros; ext <;> simp <;> ring
  neg_add_cancel := by intros; ext <;> simp
  mul_assoc := by intros; ext <;> simp <;> ring
  one_mul := by intros; ext <;> simp
  mul_one := by intros; ext <;> simp
  left_distrib := by intros; ext <;> simp <;> ring
  right_distrib := by intros; ext <;> simp <;> ring
  mul_comm := by intros; ext <;> simp <;> ring
  zero_mul := by intros; ext <;> simp
  mul_zero := by intros; ext <;> simp
  sub_eq_add_neg := by intros; ext <;> simp <;> ring

end CM31

namespace QM31

@[simp] theorem add_c0 (x y : QM31) : (x + y).c0 = x.c0 + y.c0 := rfl
@[simp] theorem add_c1 (x y : QM31) : (x + y).c1 = x.c1 + y.c1 := rfl
@[simp] theorem sub_c0 (x y : QM31) : (x - y).c0 = x.c0 - y.c0 := rfl
@[simp] theorem sub_c1 (x y : QM31) : (x - y).c1 = x.c1 - y.c1 := rfl
@[simp] theorem neg_c0 (x : QM31) : (-x).c0 = -x.c0 := rfl
@[simp] theorem neg_c1 (x : QM31) : (-x).c1 = -x.c1 := rfl
@[simp] theorem mul_c0 (x y : QM31) : (x * y).c0 = x.c0 * y.c0 + R * (x.c1 * y.c1) := rfl
@[simp] theorem mul_c1 (x y : QM31) : (x * y).c1 = x.c0 * y.c1 + x.c1 * y.c0 := rfl
@[simp] theorem zero_c0 : (0 : QM31).c0 = 0 := rfl
@[simp] theorem zero_c1 : (0 : QM31).c1 = 0 := rfl
@[simp] theorem one_c0 : (1 : QM31).c0 = 1 := rfl
@[simp] theorem one_c1 : (1 : QM31).c1 = 0 := rfl

/-- `QM31.zero/one` agree with the instance literals. -/
@[simp] theorem zero_def : QM31.zero = (0 : QM31) := rfl
@[simp] theorem one_def : QM31.one = (1 : QM31) := rfl

instance : CommRing QM31 where
  add := (· + ·)
  zero := 0
  mul := (· * ·)
  one := 1
  neg := (- ·)
  sub := (· - ·)
  nsmul := nsmulRec
  zsmul := zsmulRec
  add_assoc := by intros; ext <;> simp <;> ring
  zero_add := by intros; ext <;> simp
  add_zero := by intros; ext <;> simp
  add_comm := by intros; ext <;> simp <;> ring
  neg_add_cancel := by intros; ext <;> simp
  mul_assoc := by intros; ext <;> simp <;> ring
  one_mul := by intros; ext <;> simp
  mul_one := by intros; ext <;> simp
  left_distrib := by intros; ext <;> simp <;> ring
  right_distrib := by intros; ext <;> simp <;> ring
  mul_comm := by intros; ext <;> simp <;> ring
  zero_mul := by intros; ext <;> simp
  mul_zero := by intros; ext <;> simp
  sub_eq_add_neg := by intros; ext <;> simp <;> ring

/-- A gate-level inverse fact pins the register: inverses are unique in a
commutative monoid. -/
theorem inv_unique {x o o' : QM31} (h : x * o = 1) (h' : x * o' = 1) : o = o' := by
  calc o = o * (x * o') := by rw [h', mul_one]
    _ = (x * o) * o' := by ring
    _ = o' := by rw [h, one_mul]

end QM31
end StwoVerifier
