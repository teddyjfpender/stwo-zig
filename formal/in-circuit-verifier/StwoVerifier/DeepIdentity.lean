/-
**The DEEP-quotient identity** behind `compute_fri_input`
(`src/frontends/circuit/stark_verifier/oods.zig`, stwo-zig `4afa09dbf`).

The circuit computes, per sampled point `P` and response `(V, α')` with
`α' = −2u·α`, the quotient

  `(α'·im V·y_q + (d·α'·V − α'·im V·P.y) − d·α'·val) / (d·x_q − e·y_q − f)`

with `d = im P.y`, `e = im P.x`, `f = d·P.x − e·P.y`. The native spec
(`Quotients`) uses the complex-conjugate line coefficients
`a = α(conj V − V)`, `c = α(conj P.y − P.y)`, `b = α(V·c/α − a/α·P.y)`
and the CM31 denominator. `deep_term_identity` shows the two agree:
numerator and denominator of the circuit form are both exactly `−u`
times the spec's, so the quotients coincide. Batched responses follow by
linearity of both numerators in `(V, α)`.
-/
import StwoVerifier.FieldTower
import StwoVerifier.Quotients
import StwoVerifier.Gates

namespace StwoVerifier.Deep

open StwoVerifier

/-- The CM31 scalar embedding. -/
def embed (c : CM31) : QM31 := ⟨c, 0⟩

theorem embed_add (a b : CM31) : embed (a + b) = embed a + embed b := by
  unfold embed; ext <;> simp
theorem embed_mul (a b : CM31) : embed (a * b) = embed a * embed b := by
  unfold embed
  refine QM31.ext' ?_ ?_ <;> show _ = _
  · simp [QM31.mul_c0]
  · simp [QM31.mul_c1]
theorem embed_one : embed 1 = 1 := by unfold embed; rfl
theorem embed_zero : embed 0 = 0 := by unfold embed; rfl

/-- `embed` as a ring homomorphism. -/
def embedHom : CM31 →+* QM31 where
  toFun := embed
  map_one' := embed_one
  map_mul' := embed_mul
  map_zero' := embed_zero
  map_add' := embed_add

theorem embed_inv (c : CM31) : embed c⁻¹ = (embed c)⁻¹ :=
  map_inv₀ embedHom c

/-- The generator `u` of the quadratic layer. -/
def uu : QM31 := ⟨0, 1⟩

theorem uu_ne_zero : uu ≠ 0 := by
  intro h
  have h1 : (uu.c1 : CM31) = (0 : QM31).c1 := congrArg QM31.c1 h
  have : (1 : CM31) = 0 := h1
  have ha : (1 : F) = 0 := congrArg CM31.a this
  exact absurd ha (by norm_num)

/-- `x = embed x.c0 + embed x.c1 · u`. -/
theorem decomp (x : QM31) : x = embed x.c0 + embed x.c1 * uu := by
  unfold embed uu
  refine QM31.ext' ?_ ?_ <;> show _ = _ <;>
    simp [QM31.mul_c0, QM31.mul_c1]

/-- Spec conjugation in the decomposition. -/
theorem conj_decomp (x : QM31) :
    x.complexConjugate = embed x.c0 - embed x.c1 * uu := by
  unfold QM31.complexConjugate embed uu
  refine QM31.ext' ?_ ?_ <;> show _ = _ <;>
    simp [QM31.mul_c0, QM31.mul_c1]

/-- The circuit's `im` (`ops.im`, a pointwise product by `(0,0,1,1)`). -/
def imQ (x : QM31) : QM31 := Gates.pmulQ x (QM31.fromM31s 0 0 1 1)

theorem imQ_eq (x : QM31) : imQ x = embed x.c1 * uu := by
  unfold imQ Gates.pmulQ embed uu QM31.fromM31s
  refine QM31.ext' ?_ ?_ <;> show _ = _ <;>
    simp [QM31.mul_c0, QM31.mul_c1] <;> ext <;> simp

theorem two_coords : (2 : QM31) = ⟨⟨2, 0⟩, 0⟩ := by
  rw [show (2 : QM31) = 1 + 1 from by norm_num]
  ext <;> simp <;> norm_num

/-- `conj x = x − 2·im x`. -/
theorem conj_eq_sub_two_im (x : QM31) :
    x.complexConjugate = x - 2 * imQ x := by
  rw [two_coords]
  ext <;> simp [QM31.complexConjugate, imQ, Gates.pmulQ, QM31.fromM31s] <;> ring

/-- The circuit's denominator is `−u` times the spec's (embedded). -/
theorem den_identity (P : PointQ) (xq yq : F) :
    imQ P.y * QM31.fromBase xq - (imQ P.x * QM31.fromBase yq
        + (imQ P.y * P.x - imQ P.x * P.y))
      = -uu * embed (Quotients.denominator P ⟨xq, yq⟩) := by
  ext <;>
    simp [Quotients.denominator, imQ, Gates.pmulQ, embed, uu,
      QM31.fromBase, CM31.fromBase, QM31.fromM31s, QM31.R] <;>
    ring

/-- The circuit's per-response numerator is `−u` times the spec's: with
`α' = −2u·α`, the circuit accumulates
`α'·(im V·y_q + d·V − im V·P.y − d·val)` while the spec's line
coefficients give `α·(c·val − a·y_q − b)`; the two differ by `−u`. -/
theorem num_identity (P : PointQ) (V alpha valQ Yq : QM31) :
    ((-2 : QM31) * uu * alpha) *
        (imQ V * Yq + (imQ P.y * V - imQ V * P.y)
          - imQ P.y * valQ)
      = -uu * (alpha * (P.y.complexConjugate - P.y) * valQ
          - (alpha * (V.complexConjugate - V) * Yq
            + (alpha * (V * (P.y.complexConjugate - P.y))
              - alpha * ((V.complexConjugate - V) * P.y)))) := by
  rw [conj_eq_sub_two_im P.y, conj_eq_sub_two_im V]
  ring

theorem mulCM31_eq (x : QM31) (c : CM31) : x.mulCM31 c = x * embed c := by
  unfold QM31.mulCM31 embed
  refine QM31.ext' ?_ ?_ <;> show _ = _ <;> simp [QM31.mul_c0, QM31.mul_c1]

theorem embed_ne_zero {c : CM31} (hc : c ≠ 0) : embed c ≠ 0 := by
  intro h
  exact hc (by
    have := congrArg QM31.c0 h
    simpa [embed] using this)

/-- **The DEEP term identity.** The circuit's per-response quotient equals
the spec's: numerator and denominator are both `−u` times the spec's,
and the factors cancel. (`friAnswers` applies the inverse via `mulCM31`;
batched responses follow by linearity of both numerators.) -/
theorem deep_term_eq (P : PointQ) (V alpha : QM31) (valM yq xq : F)
    (hden : Quotients.denominator P ⟨xq, yq⟩ ≠ 0) :
    (((-2 : QM31) * uu * alpha) *
        (imQ V * QM31.fromBase yq + (imQ P.y * V - imQ V * P.y)
          - imQ P.y * QM31.fromBase valM)) /
      (imQ P.y * QM31.fromBase xq - (imQ P.x * QM31.fromBase yq
          + (imQ P.y * P.x - imQ P.x * P.y)))
      = (alpha * (P.y.complexConjugate - P.y) * QM31.fromBase valM
          - (alpha * (V.complexConjugate - V) * QM31.fromBase yq
            + (alpha * (V * (P.y.complexConjugate - P.y))
              - alpha * ((V.complexConjugate - V) * P.y)))).mulCM31
          (Quotients.denominator P ⟨xq, yq⟩)⁻¹ := by
  rw [num_identity P V alpha (QM31.fromBase valM) (QM31.fromBase yq), den_identity P xq yq,
    mulCM31_eq, embed_inv]
  have hu : (-uu : QM31) ≠ 0 := neg_ne_zero.mpr uu_ne_zero
  rw [mul_div_mul_left _ _ hu, div_eq_mul_inv]

/-! ### Batched responses

The circuit accumulates `a_sum = Σ α'ᵢ·im Vᵢ`, `v_sum = Σ α'ᵢ·Vᵢ`,
`b = d·v_sum − a_sum·P.y` and subtracts `Σ (d·α'ᵢ)·valᵢ`; regrouping,
that is the sum of the per-response circuit numerators, so the batched
numerator is `−u` times the spec batch's by `num_identity` termwise. -/

/-- Regrouping the circuit's accumulated numerator into per-response
terms. `rs` carries `(α'ᵢ, Vᵢ, valᵢ)`. -/
theorem circuit_num_regroup (d Py Yq : QM31) (rs : List (QM31 × QM31 × QM31)) :
    (rs.map fun r => r.1 * imQ r.2.1).sum * Yq
      + (d * (rs.map fun r => r.1 * r.2.1).sum
        - (rs.map fun r => r.1 * imQ r.2.1).sum * Py)
      - (rs.map fun r => d * r.1 * r.2.2).sum
    = (rs.map fun r =>
        r.1 * (imQ r.2.1 * Yq + (d * r.2.1 - imQ r.2.1 * Py) - d * r.2.2)).sum := by
  induction rs with
  | nil => simp
  | cons r rs ih =>
    simp only [List.map_cons, List.sum_cons]
    linear_combination ih

/-- The batched numerator identity: with every `α'ᵢ = −2u·αᵢ`, the
accumulated circuit numerator is `−u` times the spec batch numerator. -/
theorem num_identity_batched (P : PointQ) (Yq : QM31)
    (rs : List (QM31 × QM31 × QM31)) :
    ((rs.map fun r => ((-2 : QM31) * uu * r.1) * imQ r.2.1).sum * Yq
      + (imQ P.y * (rs.map fun r => ((-2 : QM31) * uu * r.1) * r.2.1).sum
        - (rs.map fun r => ((-2 : QM31) * uu * r.1) * imQ r.2.1).sum * P.y)
      - (rs.map fun r => imQ P.y * ((-2 : QM31) * uu * r.1) * r.2.2).sum)
    = -uu * (rs.map fun r =>
        r.1 * (P.y.complexConjugate - P.y) * r.2.2
          - (r.1 * (r.2.1.complexConjugate - r.2.1) * Yq
            + (r.1 * (r.2.1 * (P.y.complexConjugate - P.y))
              - r.1 * ((r.2.1.complexConjugate - r.2.1) * P.y)))).sum := by
  induction rs with
  | nil => simp
  | cons r rs ih =>
    simp only [List.map_cons, List.sum_cons]
    have hhead := num_identity P r.2.1 r.1 r.2.2 Yq
    linear_combination hhead + ih

/-- **The batched DEEP quotient.** The circuit's accumulated per-point
quotient equals the spec batch's numerator times the inverse CM31
denominator — `deep_term_eq` at batch scale. -/
theorem deep_batch_eq (P : PointQ) (Yq : QM31) (xq yq : F)
    (hYq : Yq = QM31.fromBase yq)
    (rs : List (QM31 × QM31 × QM31))
    (hden : Quotients.denominator P ⟨xq, yq⟩ ≠ 0) :
    ((rs.map fun r => ((-2 : QM31) * uu * r.1) * imQ r.2.1).sum * Yq
      + (imQ P.y * (rs.map fun r => ((-2 : QM31) * uu * r.1) * r.2.1).sum
        - (rs.map fun r => ((-2 : QM31) * uu * r.1) * imQ r.2.1).sum * P.y)
      - (rs.map fun r => imQ P.y * ((-2 : QM31) * uu * r.1) * r.2.2).sum) /
      (imQ P.y * QM31.fromBase xq - (imQ P.x * QM31.fromBase yq
          + (imQ P.y * P.x - imQ P.x * P.y)))
      = ((rs.map fun r =>
          r.1 * (P.y.complexConjugate - P.y) * r.2.2
            - (r.1 * (r.2.1.complexConjugate - r.2.1) * Yq
              + (r.1 * (r.2.1 * (P.y.complexConjugate - P.y))
                - r.1 * ((r.2.1.complexConjugate - r.2.1) * P.y)))).sum).mulCM31
          (Quotients.denominator P ⟨xq, yq⟩)⁻¹ := by
  rw [num_identity_batched P Yq rs, den_identity P xq yq,
    mulCM31_eq, embed_inv]
  have hu : (-uu : QM31) ≠ 0 := neg_ne_zero.mpr uu_ne_zero
  rw [mul_div_mul_left _ _ hu, div_eq_mul_inv]

end StwoVerifier.Deep
