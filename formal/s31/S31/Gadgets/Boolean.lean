import S31.Gadgets.Field

namespace S31.Gadgets
variable {F : Type} [Field F]

def bit (x : F) : Prop := x * x = x
def encodeBool (b : Bool) : F := if b then 1 else 0

theorem bit_sound_complete (x : F) : bit x ↔ x = 0 ∨ x = 1 := by
  unfold bit
  constructor
  · intro h
    have h' : x * (x - 1) = 0 := by linear_combination h
    rcases mul_eq_zero.mp h' with hx | hx
    · exact Or.inl hx
    · exact Or.inr (sub_eq_zero.mp hx)
  · rintro (rfl | rfl) <;> simp

theorem bit_encoded (b : Bool) : bit (encodeBool b : F) := by
  cases b <;> simp [bit, encodeBool]

theorem bit_has_bool (x : F) (h : bit x) : ∃ b : Bool, x = encodeBool b := by
  rcases (bit_sound_complete x).mp h with h | h
  · exact ⟨false, h⟩
  · exact ⟨true, h⟩

def notConstraint (a y : F) : Prop := bit a ∧ y - (1 - a) = 0
def andConstraint (a b y : F) : Prop := bit a ∧ bit b ∧ y - a * b = 0
def orConstraint (a b y : F) : Prop := bit a ∧ bit b ∧ y - (a + b - a * b) = 0
def xorConstraint (a b y : F) : Prop := bit a ∧ bit b ∧ y - (a + b - 2 * a * b) = 0
def selectConstraint (s a b y : F) : Prop := bit s ∧ y - ((1 - s) * a + s * b) = 0

theorem not_sound_complete (a : Bool) (y : F) :
    notConstraint (encodeBool a) y ↔ y = encodeBool (!a) := by
  cases a <;> simp [notConstraint, encodeBool, bit, sub_eq_zero]

theorem and_sound_complete (a b : Bool) (y : F) :
    andConstraint (encodeBool a) (encodeBool b) y ↔ y = encodeBool (a && b) := by
  cases a <;> cases b <;> simp [andConstraint, encodeBool, bit, sub_eq_zero]

theorem or_sound_complete (a b : Bool) (y : F) :
    orConstraint (encodeBool a) (encodeBool b) y ↔ y = encodeBool (a || b) := by
  cases a <;> cases b <;> simp [orConstraint, encodeBool, bit, sub_eq_zero]

theorem xor_sound_complete (a b : Bool) (y : F) :
    xorConstraint (encodeBool a) (encodeBool b) y ↔ y = encodeBool (a != b) := by
  cases a <;> cases b <;> simp [xorConstraint, encodeBool, bit, sub_eq_zero]
  ring_nf

theorem select_sound_complete (s : Bool) (a b y : F) :
    selectConstraint (encodeBool s) a b y ↔ y = if s then b else a := by
  cases s <;> simp [selectConstraint, encodeBool, bit, sub_eq_zero]

theorem boolean_select_sound_complete (s a b : Bool) (y : F) :
    bit (encodeBool a : F) ∧ bit (encodeBool b : F) ∧
      selectConstraint (encodeBool s) (encodeBool a) (encodeBool b) y ↔
        y = encodeBool (if s then b else a) := by
  simp only [bit_encoded, true_and, select_sound_complete]
  cases s <;> rfl

/-- The inverse witness at x=0 is intentionally unconstrained. Soundness must
hold for every satisfying witness, not just the witness generator's choice. -/
def zeroConstraint (x indicator inverse : F) : Prop :=
  x * indicator = 0 ∧ x * inverse = 1 - indicator

variable [DecidableEq F]

theorem is_zero_sound (x z w : F) (h : zeroConstraint x z w) :
    z = if x = 0 then 1 else 0 := by
  by_cases hx : x = 0
  · simp only [hx, if_pos, zeroConstraint, zero_mul] at *
    linear_combination h.2
  · simp only [hx]
    exact (mul_eq_zero.mp h.1).resolve_left hx

theorem is_zero_complete (x : F) :
    zeroConstraint x (if x = 0 then 1 else 0) (if x = 0 then 0 else x⁻¹) := by
  by_cases hx : x = 0 <;> simp [zeroConstraint, hx]

theorem is_zero_sound_complete (x z : F) :
    (∃ w, zeroConstraint x z w) ↔ z = if x = 0 then 1 else 0 := by
  constructor
  · rintro ⟨w, h⟩; exact is_zero_sound x z w h
  · rintro rfl; exact ⟨_, is_zero_complete x⟩

end S31.Gadgets
