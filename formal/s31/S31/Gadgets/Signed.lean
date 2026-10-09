import S31.Gadgets.SubChain
import S31.Gadgets.Boolean

namespace S31.Gadgets.Signed

def signConstraint (half scale word lower scaled : Nat) (sign : Field.F) : Prop :=
  word < 2 * half ∧ lower < 65536 ∧ scaled < 65536 ∧
    (lower : Field.F) * scale = (scaled : Field.F) ∧ bit sign ∧
    (word : Field.F) = lower + sign * half

theorem sign_sound (half scale word lower scaled : Nat) (sign : Field.F)
    (layout : (half = 128 ∧ scale = 512) ∨ (half = 32768 ∧ scale = 2))
    (h : signConstraint half scale word lower scaled sign) :
    sign = encodeBool (word ≥ half) := by
  obtain ⟨hw, hl, hs, heq, hbit, hout⟩ := h
  have hm : lower * scale = scaled := (Field.bounded_equation _ _
    (by rcases layout with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;> omega) (by omega)).mp
      (by simpa using heq)
  have hlow : lower < half := by
    rcases layout with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;> omega
  rcases (bit_sound_complete sign).mp hbit with rfl | rfl
  · simp only [zero_mul, add_zero] at hout
    have hv : word = lower := (Field.bounded_equation _ _
      (by rcases layout with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;> omega) (by omega)).mp hout
    simp [encodeBool, show ¬word ≥ half by omega]
  · simp only [one_mul] at hout
    have hv : word = lower + half := (Field.bounded_equation _ _
      (by rcases layout with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;> omega)
      (by rcases layout with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;> omega)).mp
      (by simpa only [Nat.cast_add] using hout)
    simp [encodeBool, show word ≥ half by omega]

theorem sign_complete (half scale word : Nat)
    (layout : (half = 128 ∧ scale = 512) ∨ (half = 32768 ∧ scale = 2))
    (hw : word < 2 * half) :
    ∃ lower scaled, signConstraint half scale word lower scaled (encodeBool (word ≥ half)) := by
  let lower := if word < half then word else word - half
  refine ⟨lower, lower * scale, hw, ?_, ?_, ?_, bit_encoded _, ?_⟩
  · rcases layout with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;>
      dsimp [lower] <;> split <;> omega
  · rcases layout with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;>
      dsimp [lower] <;> split <;> omega
  · simp
  · by_cases h : word < half
    · simp [encodeBool, show ¬word ≥ half by omega, lower, h]
    · have heq : word = (word - half) + half := by omega
      simpa [encodeBool, show word ≥ half by omega, lower, h] using
        congrArg (fun n : Nat => (n : Field.F)) heq

theorem sign_sound_complete (half scale word : Nat) (sign : Field.F)
    (layout : (half = 128 ∧ scale = 512) ∨ (half = 32768 ∧ scale = 2))
    (hw : word < 2 * half) :
    (∃ lower scaled, signConstraint half scale word lower scaled sign) ↔
      sign = encodeBool (word ≥ half) := by
  constructor
  · rintro ⟨lower, scaled, h⟩; exact sign_sound _ _ _ _ _ _ layout h
  · rintro rfl; exact sign_complete _ _ _ layout hw

def twos (half x : Nat) : Int := if x ≥ half then (x : Int) - 2 * half else x

theorem twos_range (half x : Nat) (_hh : 0 < half) (hx : x < 2 * half) :
    -(half : Int) ≤ twos half x ∧ twos half x < half := by
  unfold twos
  split <;> omega

theorem signed_le (half a b : Nat) (_hh : 0 < half) (ha : a < 2 * half) (hb : b < 2 * half) :
    twos half a ≤ twos half b ↔
      if (decide (a ≥ half)) != (decide (b ≥ half)) then a ≥ half else a ≤ b := by
  by_cases sa : a ≥ half <;> by_cases sb : b ≥ half <;> simp [twos, sa, sb] <;> omega

def leConstraint (sa sb unsignedLe output : Field.F) : Prop :=
  bit unsignedLe ∧ output -
    ((sa - sb)^2 * sa + (1 - (sa - sb)^2) * unsignedLe) = 0

theorem le_sound_complete (sa sb le : Bool) (output : Field.F) :
    leConstraint (encodeBool sa) (encodeBool sb) (encodeBool le) output ↔
      output = encodeBool (if sa != sb then sa else le) := by
  cases sa <;> cases sb <;> cases le <;>
    simp [leConstraint, encodeBool, bit, sub_eq_zero]

def addOverflow (sa sb sr : Field.F) : Prop := (1 - (sa - sb)^2) * (sa - sr)^2 = 0
def subOverflow (sa sb sr : Field.F) : Prop := (sa - sb)^2 * (sa - sr)^2 = 0

theorem add_overflow_sound_complete (sa sb sr : Bool) :
    addOverflow (encodeBool sa) (encodeBool sb) (encodeBool sr) ↔
      (sa = sb → sr = sa) := by
  cases sa <;> cases sb <;> cases sr <;> norm_num [addOverflow, encodeBool]

theorem sub_overflow_sound_complete (sa sb sr : Bool) :
    subOverflow (encodeBool sa) (encodeBool sb) (encodeBool sr) ↔
      (sa ≠ sb → sr = sa) := by
  cases sa <;> cases sb <;> cases sr <;> norm_num [subOverflow, encodeBool]

theorem checked_add_interpretation (half a b r carry : Nat) (hh : 0 < half)
    (ha : a < 2 * half) (hb : b < 2 * half) (hr : r < 2 * half) (hc : carry ≤ 1)
    (heq : a + b = r + 2 * half * carry) :
    addOverflow (encodeBool (a ≥ half)) (encodeBool (b ≥ half)) (encodeBool (r ≥ half)) ↔
      twos half r = twos half a + twos half b := by
  rw [add_overflow_sound_complete]
  have hz := congrArg (fun n : Nat => (n : Int)) heq
  push_cast at hz
  rcases (by omega : carry = 0 ∨ carry = 1) with rfl | rfl <;>
    by_cases sa : a ≥ half <;> by_cases sb : b ≥ half <;> by_cases sr : r ≥ half <;>
    simp [twos, sa, sb, sr] <;> omega

theorem checked_sub_interpretation (half a b r borrow : Nat) (hh : 0 < half)
    (ha : a < 2 * half) (hb : b < 2 * half) (hr : r < 2 * half) (hc : borrow ≤ 1)
    (heq : a + 2 * half * borrow = b + r) :
    subOverflow (encodeBool (a ≥ half)) (encodeBool (b ≥ half)) (encodeBool (r ≥ half)) ↔
      twos half r = twos half a - twos half b := by
  rw [sub_overflow_sound_complete]
  have hz := congrArg (fun n : Nat => (n : Int)) heq
  push_cast at hz
  rcases (by omega : borrow = 0 ∨ borrow = 1) with rfl | rfl <;>
    by_cases sa : a ≥ half <;> by_cases sb : b ≥ half <;> by_cases sr : r ≥ half <;>
    simp [twos, sa, sb, sr] <;> omega

end S31.Gadgets.Signed
