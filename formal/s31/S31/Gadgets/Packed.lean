import S31.Gadgets.Boolean

/-! Algebra of the production `(a+bi)+(c+di)u` basis, with i²=-1 and
u²=2+i. This proves packed local equations and extraction identities; it does
not assume or claim that the circuit lookup argument is formally verified. -/
namespace S31.Gadgets.Packed
abbrev F := Field.F

structure Quad where
  a : F
  b : F
  c : F
  d : F
deriving DecidableEq

@[ext] theorem Quad.ext {x y : Quad} (ha : x.a = y.a) (hb : x.b = y.b)
    (hc : x.c = y.c) (hd : x.d = y.d) : x = y := by
  cases x; cases y; cases ha; cases hb; cases hc; cases hd; rfl

def base (x : F) : Quad := ⟨x, 0, 0, 0⟩
def add (x y : Quad) : Quad := ⟨x.a + y.a, x.b + y.b, x.c + y.c, x.d + y.d⟩
def pointwise (x y : Quad) : Quad := ⟨x.a * y.a, x.b * y.b, x.c * y.c, x.d * y.d⟩
def coord (x : Quad) (i : Fin 4) : F :=
  match i.val with | 0 => x.a | 1 => x.b | 2 => x.c | _ => x.d

def mul (x y : Quad) : Quad :=
  let p := x.c * y.c - x.d * y.d
  let q := x.c * y.d + x.d * y.c
  ⟨x.a * y.a - x.b * y.b + 2 * p - q,
   x.a * y.b + x.b * y.a + p + 2 * q,
   x.a * y.c - x.b * y.d + x.c * y.a - x.d * y.b,
   x.a * y.d + x.b * y.c + x.c * y.b + x.d * y.a⟩

def residual (x y : Quad) : Prop :=
  x.a - y.a = 0 ∧ x.b - y.b = 0 ∧ x.c - y.c = 0 ∧ x.d - y.d = 0

theorem residual_sound_complete (x y : Quad) : residual x y ↔ x = y := by
  constructor
  · rintro ⟨ha, hb, hc, hd⟩
    exact Quad.ext (sub_eq_zero.mp ha) (sub_eq_zero.mp hb) (sub_eq_zero.mp hc) (sub_eq_zero.mp hd)
  · rintro rfl; simp [residual]

theorem add_sound_complete (x y output : Quad) : residual output (add x y) ↔ output = add x y :=
  residual_sound_complete _ _

theorem mul_sound_complete (x y output : Quad) : residual output (mul x y) ↔ output = mul x y :=
  residual_sound_complete _ _

theorem pointwise_sound_complete (x y output : Quad) :
    residual output (pointwise x y) ↔ output = pointwise x y := residual_sound_complete _ _

theorem scalar_mul (x : Quad) (s : F) :
    mul x (base s) = ⟨x.a*s, x.b*s, x.c*s, x.d*s⟩ := by
  ext <;> simp [mul, base]

def mask (active : Nat) : Quad :=
  ⟨if 0 < active then 1 else 0, if 1 < active then 1 else 0,
   if 2 < active then 1 else 0, if 3 < active then 1 else 0⟩

theorem coord_pointwise (x y : Quad) (i : Fin 4) :
    coord (pointwise x y) i = coord x i * coord y i := by fin_cases i <;> rfl

theorem coord_mask (active : Nat) (i : Fin 4) :
    coord (mask active) i = if i.val < active then 1 else 0 := by fin_cases i <;> rfl

theorem mask_active_lanes (x : Quad) (active : Nat) (i : Fin 4) :
    coord (pointwise x (mask active)) i = if i.val < active then coord x i else 0 := by
  rw [coord_pointwise, coord_mask]
  split <;> simp

def unit (i : Fin 4) : Quad :=
  match i.val with | 0 => ⟨1,0,0,0⟩ | 1 => ⟨0,1,0,0⟩ | 2 => ⟨0,0,1,0⟩ | _ => ⟨0,0,0,1⟩

def unitInverse (i : Fin 4) : Quad :=
  match i.val with
  | 0 => ⟨1,0,0,0⟩ | 1 => ⟨0,-1,0,0⟩
  | 2 => ⟨0,0,2/5,-1/5⟩ | _ => ⟨0,0,-1/5,-2/5⟩

theorem unpack_coordinate (x : Quad) (i : Fin 4) :
    mul (pointwise x (unit i)) (unitInverse i) = base (coord x i) := by
  have hf : (5 : F) ≠ 0 := by decide
  fin_cases i <;> ext <;> simp [mul, pointwise, unit, unitInverse, base, coord] <;>
    field_simp <;> ring

def dual : Quad := ⟨1, -1, 1/5, -3/5⟩

theorem sum_projection (x : Quad) :
    pointwise (mul x dual) (base 1) = base (x.a + x.b + x.c + x.d) := by
  have hf : (5 : F) ≠ 0 := by decide
  ext <;> simp [pointwise, mul, dual, base] <;> field_simp <;> ring

/-- Match the literal dual coordinates used by `relation_compiler.sumLanes`. -/
theorem dual_literal : (⟨1, 2147483646, 858993459, 1717986917⟩ : Quad) = dual := by
  decide

theorem mix4_broadcast (x : Quad) :
    add x (mul (base (x.a+x.b+x.c+x.d)) ⟨1,1,1,1⟩) =
      ⟨x.a+(x.a+x.b+x.c+x.d), x.b+(x.a+x.b+x.c+x.d),
       x.c+(x.a+x.b+x.c+x.d), x.d+(x.a+x.b+x.c+x.d)⟩ := by
  ext <;> simp [add, mul, base]

def inverseConstraint (active : Nat) (x y : Quad) : Prop := pointwise x y = mask active

theorem inverse_active_sound (active : Nat) (x y : Quad) (i : Fin 4) (hi : i.val < active)
    (h : inverseConstraint active x y) : coord x i ≠ 0 ∧ coord y i = (coord x i)⁻¹ := by
  have hc := congrArg (fun q => coord q i) h
  have hp : coord x i * coord y i = 1 := by simpa [coord_pointwise, coord_mask, hi] using hc
  exact (Gadgets.inverse_sound_complete _ _).mp hp

def honestInverse (active : Nat) (x : Quad) : Quad :=
  ⟨if 0 < active then x.a⁻¹ else 0, if 1 < active then x.b⁻¹ else 0,
   if 2 < active then x.c⁻¹ else 0, if 3 < active then x.d⁻¹ else 0⟩

theorem inverse_active_complete (active : Nat) (x : Quad)
    (h : ∀ i : Fin 4, i.val < active → coord x i ≠ 0) :
    inverseConstraint active x (honestInverse active x) := by
  have ha := h ⟨0, by decide⟩
  have hb := h ⟨1, by decide⟩
  have hc := h ⟨2, by decide⟩
  have hd := h ⟨3, by decide⟩
  unfold inverseConstraint
  ext <;> simp only [pointwise, honestInverse, mask] <;> split <;>
    simp_all [coord]

theorem inverse_sound_complete (active : Nat) (x : Quad) :
    (∃ y, inverseConstraint active x y) ↔ ∀ i : Fin 4, i.val < active → coord x i ≠ 0 := by
  constructor
  · rintro ⟨y, h⟩ i hi; exact (inverse_active_sound active x y i hi h).1
  · intro h; exact ⟨_, inverse_active_complete active x h⟩

end S31.Gadgets.Packed
