/-
**The DEEP denominator never vanishes at a domain point.**

The circuit's `inv(prod)` gate forces `im(P.y) ≠ 0` for every sample
point `P` (`prodChain_all_ne_zero`). This file supplies the mathematical
step from there to the capstone's `hden` hypothesis: the QM31 line
`d·X − e·Y − f` through an on-circle `P` and its conjugate meets the
circle in exactly those two points — a quadratic with three distinct
roots is identically zero — so it cannot vanish at a (real) M31 domain
point unless `im(P.y) = 0`. By `den_identity`, the line's value at the
domain point is `−u·embed(den)`, so the spec denominator is nonzero.
-/
import StwoVerifier.DeepIdentity
import StwoVerifier.OodsGadgets
import StwoVerifier.FriGadgets
import StwoVerifier.BitDecomp

namespace StwoVerifier.Deep

open StwoVerifier

theorem qtwo_ne_zero : (2 : QM31) ≠ 0 := by
  intro h
  rw [two_coords] at h
  have h0 : (⟨⟨2, 0⟩, 0⟩ : QM31).c0 = (0 : QM31).c0 := congrArg QM31.c0 h
  have h1 : (2 : F) = 0 := congrArg CM31.a h0
  exact absurd h1 BitDecomp.two_ne_zero

theorem conj_mul' (x y : QM31) :
    (x * y).complexConjugate = x.complexConjugate * y.complexConjugate := by
  unfold QM31.complexConjugate
  refine QM31.ext' ?_ ?_ <;> show _ = _ <;>
    simp [QM31.mul_c0, QM31.mul_c1] <;> ring

theorem conj_add' (x y : QM31) :
    (x + y).complexConjugate = x.complexConjugate + y.complexConjugate := by
  unfold QM31.complexConjugate
  refine QM31.ext' ?_ ?_ <;> simp <;> try ring

theorem conj_one' : (1 : QM31).complexConjugate = 1 := by
  unfold QM31.complexConjugate
  refine QM31.ext' ?_ ?_ <;> simp

theorem imQ_fromBase (v : F) : imQ (QM31.fromBase v) = 0 := by
  rw [imQ_eq]
  show embed (CM31.zero) * uu = 0
  rw [show CM31.zero = 0 from rfl, embed_zero, zero_mul]

theorem imQ_conj (x : QM31) :
    imQ x.complexConjugate = -imQ x := by
  rw [imQ_eq, imQ_eq]
  show embed (-x.c1) * uu = -(embed x.c1 * uu)
  rw [show embed (-x.c1) = -embed x.c1 from by
    unfold embed; refine QM31.ext' ?_ ?_ <;> simp]
  ring

/-- A quadratic with three distinct roots has all coefficients zero. -/
theorem quad_three_roots {a b c y1 y2 y3 : QM31}
    (h1 : a * (y1 * y1) + b * y1 + c = 0)
    (h2 : a * (y2 * y2) + b * y2 + c = 0)
    (h3 : a * (y3 * y3) + b * y3 + c = 0)
    (d12 : y1 ≠ y2) (d13 : y1 ≠ y3) (d23 : y2 ≠ y3) :
    a = 0 ∧ b = 0 ∧ c = 0 := by
  have k12 : (y1 - y2) * (a * (y1 + y2) + b) = 0 := by linear_combination h1 - h2
  have k13 : (y1 - y3) * (a * (y1 + y3) + b) = 0 := by linear_combination h1 - h3
  have e12 : a * (y1 + y2) + b = 0 := by
    rcases mul_eq_zero.mp k12 with h | h
    · exact absurd (sub_eq_zero.mp h) d12
    · exact h
  have e13 : a * (y1 + y3) + b = 0 := by
    rcases mul_eq_zero.mp k13 with h | h
    · exact absurd (sub_eq_zero.mp h) d13
    · exact h
  have ka : (y2 - y3) * a = 0 := by linear_combination e12 - e13
  have ha : a = 0 := by
    rcases mul_eq_zero.mp ka with h | h
    · exact absurd (sub_eq_zero.mp h) d23
    · exact h
  have hb : b = 0 := by
    rw [ha] at e12
    simpa using e12
  have hc : c = 0 := by
    rw [ha, hb] at h1
    simpa using h1
  exact ⟨ha, hb, hc⟩

/-- A circle point on the line `im(P.y)·X − im(P.x)·Y − f` is a root of
the eliminated quadratic in `Y`. -/
theorem line_circle_root (P : PointQ) (X Y : QM31)
    (hcirc : X * X + Y * Y = 1)
    (hline : imQ P.y * X - (imQ P.x * Y + (imQ P.y * P.x - imQ P.x * P.y)) = 0) :
    (imQ P.x * imQ P.x + imQ P.y * imQ P.y) * (Y * Y)
      + (2 * (imQ P.x * (imQ P.y * P.x - imQ P.x * P.y))) * Y
      + ((imQ P.y * P.x - imQ P.x * P.y) * (imQ P.y * P.x - imQ P.x * P.y)
          - imQ P.y * imQ P.y) = 0 := by
  have hdX : imQ P.y * X = imQ P.x * Y + (imQ P.y * P.x - imQ P.x * P.y) := by
    linear_combination hline
  have hsq : (imQ P.y * X) * (imQ P.y * X)
      = (imQ P.x * Y + (imQ P.y * P.x - imQ P.x * P.y))
        * (imQ P.x * Y + (imQ P.y * P.x - imQ P.x * P.y)) := by
    rw [hdX]
  linear_combination (imQ P.y * imQ P.y) * hcirc - hsq

/-- **The spec denominator is nonzero at every M31 domain point** when
the sample point is on the circle with `im(P.y) ≠ 0` — the gate-provided
guard (`prodChain_all_ne_zero` on the `d` registers) is sufficient. -/
theorem den_nonzero (P : PointQ) (q : PointF)
    (hP : Gadgets.OnCircleQ P) (hq : q.x * q.x + q.y * q.y = 1)
    (him : imQ P.y ≠ 0) :
    Quotients.denominator P ⟨q.x, q.y⟩ ≠ 0 := by
  intro hden
  -- The line vanishes at the real lift of `q`…
  have hlq : imQ P.y * QM31.fromBase q.x
      - (imQ P.x * QM31.fromBase q.y + (imQ P.y * P.x - imQ P.x * P.y)) = 0 := by
    have h := den_identity P q.x q.y
    rw [hden, embed_zero, mul_zero] at h
    exact h
  -- …at `P` itself…
  have hlP : imQ P.y * P.x
      - (imQ P.x * P.y + (imQ P.y * P.x - imQ P.x * P.y)) = 0 := by ring
  -- …and at the conjugate point.
  have hlPc : imQ P.y * P.x.complexConjugate
      - (imQ P.x * P.y.complexConjugate
        + (imQ P.y * P.x - imQ P.x * P.y)) = 0 := by
    rw [conj_eq_sub_two_im P.x, conj_eq_sub_two_im P.y]
    ring_nf
  -- The three circle memberships.
  have hcP : P.x * P.x + P.y * P.y = 1 := hP
  have hcPc : P.x.complexConjugate * P.x.complexConjugate
      + P.y.complexConjugate * P.y.complexConjugate = 1 := by
    rw [← conj_mul', ← conj_mul', ← conj_add', hcP, conj_one']
  have hcq : QM31.fromBase q.x * QM31.fromBase q.x
      + QM31.fromBase q.y * QM31.fromBase q.y = 1 := by
    have h := congrArg Gadgets.baseHom hq
    simp only [map_add, map_mul, map_one] at h
    exact h
  -- Three distinct Y-roots.
  have r1 := line_circle_root P P.x P.y hcP hlP
  have r2 := line_circle_root P P.x.complexConjugate P.y.complexConjugate hcPc hlPc
  have r3 := line_circle_root P (QM31.fromBase q.x) (QM31.fromBase q.y) hcq hlq
  have d12 : P.y ≠ P.y.complexConjugate := by
    intro h
    have h2 : (2 : QM31) * imQ P.y = 0 := by
      have := conj_eq_sub_two_im P.y
      rw [← h] at this
      linear_combination this
    rcases mul_eq_zero.mp h2 with h' | h'
    · exact qtwo_ne_zero h'
    · exact him h'
  have d13 : P.y ≠ QM31.fromBase q.y := by
    intro h
    exact him (by rw [h, imQ_fromBase])
  have d23 : P.y.complexConjugate ≠ QM31.fromBase q.y := by
    intro h
    have := imQ_conj P.y
    rw [h, imQ_fromBase] at this
    exact him (by rw [← neg_neg (imQ P.y), ← this, neg_zero])
  obtain ⟨ha, hb, hc⟩ := quad_three_roots r1 r2 r3 d12 d13 d23
  -- Coefficients zero force `im(P.y) = 0`.
  have hef : imQ P.x * (imQ P.y * P.x - imQ P.x * P.y) = 0 := by
    have h2 : (2 : QM31) * (imQ P.x * (imQ P.y * P.x - imQ P.x * P.y)) = 0 := by
      linear_combination hb
    rcases mul_eq_zero.mp h2 with h' | h'
    · exact absurd h' qtwo_ne_zero
    · exact h'
  rcases mul_eq_zero.mp hef with he | hf
  · -- e = 0: a = 0 gives d² = 0.
    rw [he] at ha
    have : imQ P.y * imQ P.y = 0 := by linear_combination ha
    rcases mul_eq_zero.mp this with h' | h' <;> exact him h'
  · -- f = 0: c = 0 gives d² = 0.
    rw [hf] at hc
    have : imQ P.y * imQ P.y = 0 := by linear_combination -hc
    rcases mul_eq_zero.mp this with h' | h' <;> exact him h'

end StwoVerifier.Deep
