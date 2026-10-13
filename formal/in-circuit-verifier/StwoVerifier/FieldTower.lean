/-
**CM31 and QM31 are fields.** The norms decide invertibility:
`‖a + bi‖ = a² + b²` vanishes only at 0 because −1 is not a square mod
`P` (`P ≡ 3 (mod 4)`), and `‖c0 + c1·u‖ = c0² − (2+i)·c1²` vanishes only
at 0 because `2 + i` is not a square in CM31 (else `5` would be a square
mod `P`, refuted by quadratic reciprocity). The non-square arguments
follow starked-bitcoin's `Spec/QM31.lean` for the same tower.

With the `Field` instances, every later gadget proof gets cancellation
and inverse reasoning (`div` gates, DEEP quotients, FRI folds) for free.
-/
import StwoVerifier.Algebra
import Mathlib.NumberTheory.LegendreSymbol.QuadraticReciprocity

namespace StwoVerifier

theorem P_mod4 : P % 4 = 3 := by unfold P; norm_num

theorem neg_one_not_square : ¬ IsSquare (-1 : F) := by
  rw [ZMod.exists_sq_eq_neg_one_iff]
  simp [P_mod4]

instance : Fact (Nat.Prime 5) := ⟨by norm_num⟩

theorem five_not_square : ¬ IsSquare (5 : F) := by
  have h := ZMod.exists_sq_eq_prime_iff_of_mod_four_eq_one (p := 5) (q := P)
    (by norm_num) (by unfold P; norm_num)
  have h5 : ((P : ℕ) : ZMod 5) = 2 := by unfold P; decide
  have hP : (((5 : ℕ) : F)) = 5 := by norm_num
  rw [h5, hP] at h
  rw [← h]
  decide

namespace CM31

/-- The norm `a² + b²`. -/
def norm2 (x : CM31) : F := x.a * x.a + x.b * x.b

theorem norm2_eq_zero {x : CM31} (h : norm2 x = 0) : x = 0 := by
  unfold norm2 at h
  by_cases hb : x.b = 0
  · have ha : x.a * x.a = 0 := by rw [hb] at h; linear_combination h
    have : x.a = 0 := by
      rcases mul_eq_zero.mp ha with h' | h' <;> exact h'
    ext <;> simp [this, hb]
  · exfalso
    apply neg_one_not_square
    refine ⟨x.a / x.b, ?_⟩
    field_simp
    linear_combination -h

/-- `conj / norm2` is a two-sided inverse away from zero. -/
theorem mul_inv_cancel' {x : CM31} (hx : x ≠ 0) :
    x * ⟨x.a / norm2 x, -x.b / norm2 x⟩ = 1 := by
  have hn : norm2 x ≠ 0 := fun h => hx (norm2_eq_zero h)
  ext
  · show x.a * (x.a / norm2 x) - x.b * (-x.b / norm2 x) = 1
    field_simp
    unfold norm2
    ring
  · show x.a * (-x.b / norm2 x) + x.b * (x.a / norm2 x) = 0
    field_simp
    ring

noncomputable instance : Field CM31 where
  inv x := ⟨x.a / norm2 x, -x.b / norm2 x⟩
  exists_pair_ne := ⟨0, 1, by
    intro h
    have : (0 : F) = 1 := congrArg CM31.a h
    exact absurd this (by norm_num)⟩
  mul_inv_cancel x hx := mul_inv_cancel' hx
  inv_zero := by
    show (⟨0 / norm2 0, -(0 : CM31).b / norm2 0⟩ : CM31) = 0
    unfold norm2
    ext <;> simp
  nnqsmul := _
  qsmul := _

/-- `2 + i` is not a square in CM31: its norm `5` would be a square in F. -/
theorem R_not_square : ¬ IsSquare (QM31.R) := by
  rintro ⟨s, hs⟩
  apply five_not_square
  refine ⟨norm2 s, ?_⟩
  have h2 : norm2 QM31.R = 5 := by
    unfold norm2 QM31.R
    show (2 : F) * 2 + 1 * 1 = 5
    norm_num
  have hmul : norm2 (s * s) = norm2 s * norm2 s := by
    unfold norm2
    show _ = _
    simp only [CM31.mul_a, CM31.mul_b]
    ring
  rw [hs, hmul] at h2
  rw [← h2]

end CM31

namespace QM31

/-- The tower norm `c0² − R·c1²`. -/
def normQ (x : QM31) : CM31 := x.c0 * x.c0 - R * (x.c1 * x.c1)

theorem normQ_eq_zero {x : QM31} (h : normQ x = 0) : x = 0 := by
  unfold normQ at h
  by_cases hc1 : x.c1 = 0
  · have hc0 : x.c0 * x.c0 = 0 := by rw [hc1] at h; linear_combination h
    have : x.c0 = 0 := by
      rcases mul_eq_zero.mp hc0 with h' | h' <;> exact h'
    ext <;> simp [this, hc1, CM31.zero_def]
  · exfalso
    apply CM31.R_not_square
    refine ⟨x.c0 / x.c1, ?_⟩
    field_simp
    linear_combination (-1 : CM31) * h

theorem mul_inv_cancel' {x : QM31} (hx : x ≠ 0) :
    x * ⟨x.c0 / normQ x, -x.c1 / normQ x⟩ = 1 := by
  have hn : normQ x ≠ 0 := fun h => hx (normQ_eq_zero h)
  refine QM31.ext' ?_ ?_
  · show x.c0 * (x.c0 / normQ x) + R * (x.c1 * (-x.c1 / normQ x)) = (1 : QM31).c0
    rw [QM31.one_c0]
    field_simp
    unfold normQ
    ring
  · show x.c0 * (-x.c1 / normQ x) + x.c1 * (x.c0 / normQ x) = (1 : QM31).c1
    rw [QM31.one_c1]
    field_simp
    ring

noncomputable instance : Field QM31 where
  inv x := ⟨x.c0 / normQ x, -x.c1 / normQ x⟩
  exists_pair_ne := ⟨0, 1, by
    intro h
    have h0 : (0 : QM31).c0 = (1 : QM31).c0 := congrArg QM31.c0 h
    have : (0 : F) = 1 := congrArg CM31.a h0
    exact absurd this (by norm_num)⟩
  mul_inv_cancel x hx := mul_inv_cancel' hx
  inv_zero := by
    show (⟨(0 : QM31).c0 / normQ 0, -(0 : QM31).c1 / normQ 0⟩ : QM31) = 0
    unfold normQ
    ext <;> simp
  nnqsmul := _
  qsmul := _

/-- The executable `inv?` agrees with the field inverse. -/
theorem inv?_eq_some {x y : QM31} (h : x.inv? = some y) : x ≠ 0 ∧ y = x⁻¹ := by
  cases hn : (x.c0 * x.c0 - R * (x.c1 * x.c1)).inv? with
  | none => simp [QM31.inv?, hn] at h
  | some di =>
    simp [QM31.inv?, hn] at h
    unfold CM31.inv? at hn
    by_cases h0 : CM31.norm (x.c0 * x.c0 - R * (x.c1 * x.c1)) = 0
    · rw [if_pos h0] at hn; simp at hn
    · rw [if_neg h0] at hn
      simp only [Option.some.injEq] at hn
      -- The norm of `normQ x` is nonzero, so `normQ x ≠ 0`, so `x ≠ 0`.
      have hnormQ : normQ x ≠ 0 := by
        intro hz
        apply h0
        unfold normQ at hz
        rw [hz]
        unfold CM31.norm
        simp
      have hx : x ≠ 0 := fun hz => hnormQ (by rw [hz]; unfold normQ; simp)
      refine ⟨hx, ?_⟩
      -- `di` is the CM31 field inverse of `normQ x`.
      have hdi : di = (normQ x)⁻¹ := by
        rw [← hn]
        show _ = (⟨(normQ x).a / CM31.norm2 (normQ x),
          -(normQ x).b / CM31.norm2 (normQ x)⟩ : CM31)
        unfold CM31.norm2 CM31.norm normQ
        ext <;> simp [div_eq_mul_inv] <;> rfl
      rw [← h, hdi]
      refine QM31.ext' ?_ ?_
      · show x.c0 * (normQ x)⁻¹ = x.c0 / normQ x
        rw [div_eq_mul_inv]
      · show -(x.c1 * (normQ x)⁻¹) = -x.c1 / normQ x
        rw [neg_div, div_eq_mul_inv]

end QM31
end StwoVerifier
