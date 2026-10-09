import S31.Gadgets.Bitcoin

namespace S31.Gadgets.CompactTarget
open Words Radix

theorem decode_zero (base : Nat) (hb : 0 < base) (xs : List Nat) :
    decode base xs = 0 ↔ ∀ x ∈ xs, x = 0 := by
  induction xs with
  | nil => simp [decode]
  | cons x xs ih =>
    simp only [decode, List.mem_cons, forall_eq_or_imp, Nat.add_eq_zero]
    rw [Nat.mul_eq_zero, or_iff_right (by omega), ih]

theorem bounded_sum (base : Nat) (xs : List Nat) (h : Bounded base xs) : xs.sum ≤ (base - 1) * xs.length := by
  induction xs with
  | nil => simp
  | cons x xs ih =>
    have hx := h x (by simp)
    have ht := ih (fun x hx => h x (by simp [hx]))
    simp only [List.sum_cons, List.length_cons, Nat.mul_add, Nat.mul_one]
    omega

theorem byte_sum_inverse_sound_complete (bytes : List Nat) (hb : Bounded 256 bytes)
    (hl : bytes.length ≤ 32) :
    (∃ inverse : Field.F, (bytes.sum : Field.F) * inverse = 1) ↔ 0 < decode 256 bytes := by
  have hs := bounded_sum 256 bytes hb
  have hp : bytes.sum < 2147483647 := by omega
  have zero : bytes.sum = 0 ↔ decode 256 bytes = 0 := by
    rw [decode_zero 256 (by decide)]
    exact List.sum_eq_zero_iff
  constructor
  · rintro ⟨inverse, h⟩
    have hn := ((Gadgets.inverse_sound_complete _ _).mp h).1
    have nz : bytes.sum ≠ 0 := by intro hz; simp [hz] at hn
    have : decode 256 bytes ≠ 0 := fun h => nz (zero.mpr h)
    omega
  · intro h
    have nz : (bytes.sum : Field.F) ≠ 0 := by
      intro hz
      have hs0 := (Field.bounded_equation _ _ hp (by decide)).mp hz
      have := zero.mp hs0
      omega
    exact ⟨_, mul_inv_cancel₀ nz⟩

theorem high_bytes_zero_sound_complete (bytes : List Nat) (hb : Bounded 256 bytes)
    (hl : bytes.length = 32) :
    (∀ x ∈ bytes.drop 28, x = 0) ↔ decode 256 bytes ≤ S31.Bitcoin.powLimit := by
  rw [← decode_zero 256 (by decide) (bytes.drop 28),
    decode_drop 256 (by decide) bytes hb 28 (by omega)]
  have hp : 0 < 256^28 := by decide
  have hv : 256^28 = 2^224 := by norm_num
  rw [Nat.div_eq_zero_iff_lt hp]
  unfold S31.Bitcoin.powLimit
  rw [hv]
  omega

theorem target_bytes_length (exponent mantissa : Nat) (he : 1 ≤ exponent) (hl : exponent ≤ 32) :
    (Bitcoin.targetBytes exponent mantissa).length = 32 := by
  unfold Bitcoin.targetBytes
  split <;> simp [List.length_append, List.length_drop, Words.encode_length] <;> omega

theorem target_bytes_bounded (exponent mantissa : Nat) : Bounded 256 (Bitcoin.targetBytes exponent mantissa) := by
  intro x hx
  unfold Bitcoin.targetBytes at hx
  split at hx
  · simp only [List.mem_append] at hx
    rcases hx with h | h
    · exact encode_bounded _ (by decide) _ _ _ (List.mem_of_mem_drop h)
    · have : x = 0 := (List.mem_replicate.mp h).2; omega
  · simp only [List.mem_append] at hx
    rcases hx with (h | h) | h
    · have : x = 0 := (List.mem_replicate.mp h).2; omega
    · exact encode_bounded _ (by decide) _ _ _ h
    · have : x = 0 := (List.mem_replicate.mp h).2; omega

/-- One-hot selection/byte placement is followed by a nonzero byte-sum inverse
and zero high bytes. These are the production target gadget's three guards. -/
def Accepts (exponent mantissa : Nat) (bytes : List Nat) : Prop :=
  mantissa < 2^23 ∧ (∃ selectors, Bitcoin.exponentConstraint exponent selectors) ∧
    bytes = Bitcoin.targetBytes exponent mantissa ∧
    (∃ inverse : Field.F, (bytes.sum : Field.F) * inverse = 1) ∧
    (∀ x ∈ bytes.drop 28, x = 0)

theorem target_sound_complete (exponent mantissa : Nat) (bytes : List Nat) :
    Accepts exponent mantissa bytes ↔ mantissa < 2^23 ∧ 1 ≤ exponent ∧ exponent ≤ 32 ∧
      bytes = Bitcoin.targetBytes exponent mantissa ∧
      0 < decode 256 bytes ∧ decode 256 bytes ≤ S31.Bitcoin.powLimit := by
  constructor
  · rintro ⟨hm, hexp, heq, hinv, hhigh⟩
    have he := (Bitcoin.exponent_sound_complete exponent).mp hexp
    have hb : Bounded 256 bytes := heq ▸ target_bytes_bounded _ _
    have hl : bytes.length = 32 := heq ▸ target_bytes_length _ _ he.1 he.2
    exact ⟨hm, he.1, he.2, heq,
      (byte_sum_inverse_sound_complete bytes hb (by omega)).mp hinv,
      (high_bytes_zero_sound_complete bytes hb hl).mp hhigh⟩
  · rintro ⟨hm, hep, hel, heq, hn, hh⟩
    have hb : Bounded 256 bytes := heq ▸ target_bytes_bounded _ _
    have hl : bytes.length = 32 := heq ▸ target_bytes_length _ _ hep hel
    exact ⟨hm, (Bitcoin.exponent_sound_complete exponent).mpr ⟨hep, hel⟩, heq,
      (byte_sum_inverse_sound_complete bytes hb (by omega)).mpr hn,
      (high_bytes_zero_sound_complete bytes hb hl).mpr hh⟩

end S31.Gadgets.CompactTarget
