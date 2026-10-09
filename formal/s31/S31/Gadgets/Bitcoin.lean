import S31.Gadgets.Schoolbook
import S31.Gadgets.Signed
import S31.Semantics.Bitcoin

namespace S31.Gadgets.Bitcoin
open Words Radix

def divisionConstraint (n d q r : Nat) : Prop := n = q * d + r ∧ r < d

theorem division_sound_complete (n d q r : Nat) :
    divisionConstraint n d q r ↔ 0 < d ∧ q = n / d ∧ r = n % d := by
  constructor
  · rintro ⟨heq, hr⟩
    have hp : 0 < d := by omega
    refine ⟨hp, ?_, ?_⟩
    · rw [heq, Nat.add_comm, Nat.mul_comm q d,
        Nat.add_mul_div_left _ _ hp, Nat.div_eq_of_lt hr]
      simp
    · rw [heq, Nat.add_comm, Nat.mul_comm q d]
      simp [Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt hr]
  · rintro ⟨hp, rfl, rfl⟩
    exact ⟨by simpa [Nat.mul_comm, Nat.add_comm] using (Nat.div_add_mod n d).symm,
      Nat.mod_lt _ hp⟩

theorem division_honest (n d : Nat) (hd : 0 < d) :
    divisionConstraint n d (n / d) (n % d) :=
  (division_sound_complete _ _ _ _).mpr ⟨hd, rfl, rfl⟩

/-- The complement/divide/add-one formula used by the production gadget is
exactly floor(2^256/(target+1)); the two excluded targets are explicit. -/
theorem work_formula (limit target : Nat) (ht : target < limit) :
    (limit - 1 - target) / (target + 1) + 1 = limit / (target + 1) := by
  have heq : limit = (limit - 1 - target) + (target + 1) * 1 := by omega
  calc
    _ = ((limit - 1 - target) + (target + 1) * 1) / (target + 1) :=
      (Nat.add_mul_div_left _ _ (by omega)).symm
    _ = _ := (congrArg (· / (target + 1)) heq).symm

def workConstraint (target work : Nat) : Prop :=
  0 < target ∧ target < 2^256 - 1 ∧ ∃ q r,
    divisionConstraint (2^256 - 1 - target) (target + 1) q r ∧ work = q + 1

theorem work_sound_complete (target work : Nat) :
    workConstraint target work ↔ 0 < target ∧ target < 2^256 - 1 ∧ work = 2^256 / (target + 1) := by
  constructor
  · rintro ⟨hp, hl, q, r, hdiv, rfl⟩
    have hq := ((division_sound_complete _ _ _ _).mp hdiv).2.1
    exact ⟨hp, hl, by rw [hq]; exact work_formula _ _ (by omega)⟩
  · rintro ⟨hp, hl, h⟩
    refine ⟨hp, hl, _, _, division_honest _ _ (by omega), ?_⟩
    rw [h, work_formula _ _ (by omega)]

theorem sum_le_length (xs : List Nat) (h : ∀ x ∈ xs, x ≤ 1) : xs.sum ≤ xs.length := by
  induction xs with
  | nil => simp
  | cons x xs ih =>
    have hx := h x (by simp)
    have ht := ih (fun x hx => h x (by simp [hx]))
    simp only [List.sum_cons, List.length_cons]
    omega

def oneHot (selectors : List Nat) : Prop := selectors.length = 32 ∧
  (∀ x ∈ selectors, x ≤ 1) ∧ (selectors.sum : Field.F) = 1

theorem one_hot_sound_complete (selectors : List Nat) :
    oneHot selectors ↔ selectors.length = 32 ∧ (∀ x ∈ selectors, x ≤ 1) ∧ selectors.sum = 1 := by
  constructor
  · rintro ⟨hlen, hb, h⟩
    have hr := sum_le_length selectors hb
    exact ⟨hlen, hb, (Field.bounded_equation _ _ (by omega) (by decide)).mp h⟩
  · rintro ⟨hlen, hb, h⟩; exact ⟨hlen, hb, by rw [h]; rfl⟩

theorem sum_one_unique (selectors : List Nat) (h : selectors.sum = 1) :
    ∃ before after, selectors = List.replicate before 0 ++ [1] ++ List.replicate after 0 := by
  induction selectors with
  | nil => simp at h
  | cons x xs ih =>
    by_cases hx : x = 0
    · have ht : xs.sum = 1 := by simpa [hx] using h
      obtain ⟨before, after, heq⟩ := ih ht
      exact ⟨before + 1, after, by simp [hx, heq, List.replicate_succ]⟩
    · have hx1 : x = 1 := by simp only [List.sum_cons] at h; omega
      have ht : xs.sum = 0 := by simp only [List.sum_cons] at h; omega
      have hz : xs = List.replicate xs.length 0 := by
        clear ih h hx hx1
        induction xs with
        | nil => simp
        | cons a xs ih =>
          simp only [List.sum_cons] at ht
          have ha : a = 0 := by omega
          have hs : xs.sum = 0 := by omega
          simpa only [List.length_cons, List.replicate_succ] using
            congrArg₂ List.cons ha (ih hs)
      subst x
      exact ⟨0, xs.length, by
        simpa only [List.replicate_zero, List.nil_append, List.singleton_append] using
          congrArg (List.cons 1) hz⟩

def weighted (offset : Nat) : List Nat → Nat
  | [] => 0
  | x :: xs => offset * x + weighted (offset + 1) xs

theorem weighted_zeros (offset n : Nat) : weighted offset (List.replicate n 0) = 0 := by
  induction n generalizing offset <;> simp_all [weighted, List.replicate_succ]

theorem weighted_append (offset : Nat) (xs ys : List Nat) :
    weighted offset (xs ++ ys) = weighted offset xs + weighted (offset + xs.length) ys := by
  induction xs generalizing offset with
  | nil => simp [weighted]
  | cons x xs ih => simp [weighted, ih, Nat.add_assoc, Nat.add_comm, Nat.add_left_comm]

def exponentConstraint (exponent : Nat) (selectors : List Nat) : Prop :=
  exponent < 256 ∧ oneHot selectors ∧ (weighted 1 selectors : Field.F) = exponent

theorem exponent_sound (exponent : Nat) (selectors : List Nat)
    (h : exponentConstraint exponent selectors) : 1 ≤ exponent ∧ exponent ≤ 32 := by
  obtain ⟨he, hot, hw⟩ := h
  obtain ⟨hlen, hb, hs⟩ := (one_hot_sound_complete selectors).mp hot
  obtain ⟨before, after, rfl⟩ := sum_one_unique selectors hs
  simp only [List.length_append, List.length_replicate, List.length_cons, List.length_nil] at hlen
  have hv : weighted 1 (List.replicate before 0 ++ [1] ++ List.replicate after 0) = before + 1 := by
    simp [weighted_append, weighted_zeros, weighted, Nat.add_comm]
  have hg : before + 1 = exponent := (Field.bounded_equation _ _ (by omega) (by omega)).mp
    (by simpa only [hv] using hw)
  omega

theorem exponent_complete (exponent : Nat) (hp : 1 ≤ exponent) (hl : exponent ≤ 32) :
    ∃ selectors, exponentConstraint exponent selectors := by
  let selectors := List.replicate (exponent - 1) 0 ++ [1] ++ List.replicate (32 - exponent) 0
  refine ⟨selectors, by omega, ?_, ?_⟩
  · apply (one_hot_sound_complete selectors).mpr
    refine ⟨by simp [selectors]; omega, ?_, by simp [selectors]⟩
    intro x hx
    simp [selectors] at hx
    rcases hx with hx | hx | hx <;> simp_all
  · have hv : weighted 1 selectors = exponent := by
      simp [selectors, weighted_append, weighted_zeros, weighted]
      omega
    rw [hv]

theorem exponent_sound_complete (exponent : Nat) :
    (∃ selectors, exponentConstraint exponent selectors) ↔ 1 ≤ exponent ∧ exponent ≤ 32 :=
  ⟨fun ⟨_, h⟩ => exponent_sound _ _ h, fun ⟨hp, hl⟩ => exponent_complete _ hp hl⟩

def targetBytes (exponent mantissa : Nat) : List Nat :=
  if exponent ≤ 3 then (encode 256 3 mantissa).drop (3 - exponent) ++ List.replicate (32 - exponent) 0
  else List.replicate (exponent - 3) 0 ++ encode 256 3 mantissa ++ List.replicate (32 - exponent) 0

theorem target_byte_placement (exponent mantissa : Nat) (hm : mantissa < 2^23) :
    decode 256 (targetBytes exponent mantissa) =
      if exponent ≤ 3 then mantissa / 2^(8 * (3 - exponent))
      else mantissa * 2^(8 * (exponent - 3)) := by
  have hbound : mantissa < 256^3 := by omega
  have he := decode_encode 256 (by decide) 3 mantissa hbound
  have hp (n : Nat) : 256^n = 2^(8*n) := by
    change (2^8)^n = 2^(8*n)
    exact (Nat.pow_mul 2 8 n).symm
  unfold targetBytes
  split
  · rw [decode_append, decode_zeros, mul_zero, add_zero]
    rw [decode_drop 256 (by decide) _ (encode_bounded _ (by decide) _ _) _
      (by rw [Words.encode_length]; omega), he, hp]
  · simp [decode_append, decode_zeros, he, hp, mul_comm]

end S31.Gadgets.Bitcoin
