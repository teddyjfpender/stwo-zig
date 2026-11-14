/-
**Scope A / deliverable 3, first pieces: the OODS composition
reconstruction** (`src/frontends/circuit/stark_verifier/oods.zig` and
`builder/ops.zig`, stwo-zig `4afa09dbf`).

`from_partial_evals` recombines four wires on the extension basis
`1, i, u, iu`; `extract_expected_composition_eval` is
`left + doubleX^(k−2)(oods.x) · right` over the two composition halves.
Both are proven to compute the *spec's* functions:
`StwoVerifier.fromPartialEvals` and (via `reconstructChunks_two`) the
spec's `reconstructChunks` at the pinned `COMPOSITION_LOG_SPLIT = 1` —
the exact value `NativeAccepts` compares against the AIR evaluation.
-/
import StwoVerifier.CircleGadgets
import StwoVerifier.Verifier
import StwoVerifier.FieldTower

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-- `from_partial_evals`: interned basis constants, then the `eval!` chain
`((v0 + v1·i) + v2·u) + v3·iu`. -/
def fromPartialEvalsG (v0 v1 v2 v3 n : ℕ) : Out ℕ :=
  ⟨[.const n (QM31.fromM31s 0 1 0 0),
    .const (n + 1) (QM31.fromM31s 0 0 1 0),
    .const (n + 2) (QM31.fromM31s 0 0 0 1),
    .mul (n + 3) v1 n,
    .add (n + 4) v0 (n + 3),
    .mul (n + 5) v2 (n + 1),
    .add (n + 6) (n + 4) (n + 5),
    .mul (n + 7) v3 (n + 2),
    .add (n + 8) (n + 6) (n + 7)],
   n + 8, n + 9⟩

theorem fromPartialEvalsG_sound {ρ : ℕ → QM31} {v0 v1 v2 v3 n : ℕ}
    (h : AllHold ρ (fromPartialEvalsG v0 v1 v2 v3 n).ops) :
    ρ (fromPartialEvalsG v0 v1 v2 v3 n).res
      = fromPartialEvals [ρ v0, ρ v1, ρ v2, ρ v3] := by
  rw [show (fromPartialEvalsG v0 v1 v2 v3 n).ops =
    .const n (QM31.fromM31s 0 1 0 0) ::
    .const (n + 1) (QM31.fromM31s 0 0 1 0) ::
    .const (n + 2) (QM31.fromM31s 0 0 0 1) ::
    .mul (n + 3) v1 n ::
    .add (n + 4) v0 (n + 3) ::
    .mul (n + 5) v2 (n + 1) ::
    .add (n + 6) (n + 4) (n + 5) ::
    .mul (n + 7) v3 (n + 2) ::
    [.add (n + 8) (n + 6) (n + 7)] from rfl,
    allHold_cons, allHold_cons, allHold_cons, allHold_cons, allHold_cons,
    allHold_cons, allHold_cons, allHold_cons, allHold_cons] at h
  obtain ⟨hi, hu, hiu, hm1, ha1, hm2, ha2, hm3, ha3, -⟩ := h
  simp only [Holds] at hi hu hiu hm1 ha1 hm2 ha2 hm3 ha3
  show ρ (n + 8) = _
  rw [ha3, ha2, ha1, hm1, hm2, hm3, hi, hu, hiu]
  unfold fromPartialEvals
  simp only [List.getD_cons_zero, List.getD_cons_succ]
  try ring

/-- `extract_expected_composition_eval`:
`left + doubleX^(k−2)(oods.x) · right` (the loop reuses the
`cosetVanishing` emitter, which is exactly iterated `doubleX`). -/
def extractExpectedCompositionEvalG (one : ℕ) (evals : Fin 8 → ℕ)
    (oodsX : ℕ) (k n : ℕ) : Out ℕ :=
  let left := fromPartialEvalsG (evals 0) (evals 1) (evals 2) (evals 3) n
  let right := fromPartialEvalsG (evals 4) (evals 5) (evals 6) (evals 7) left.next
  let x := cosetVanishing one oodsX (k - 2) right.next
  ⟨left.ops ++ right.ops ++ x.ops ++
    [.mul x.next x.res right.res, .add (x.next + 1) left.res x.next],
   x.next + 1, x.next + 2⟩

theorem extractExpectedCompositionEvalG_sound {ρ : ℕ → QM31} {one : ℕ}
    {evals : Fin 8 → ℕ} {oodsX : ℕ} {k n : ℕ}
    (hone : ρ one = 1)
    (h : AllHold ρ (extractExpectedCompositionEvalG one evals oodsX k n).ops) :
    ρ (extractExpectedCompositionEvalG one evals oodsX k n).res
      = fromPartialEvals [ρ (evals 0), ρ (evals 1), ρ (evals 2), ρ (evals 3)]
        + CPoint.doubleX^[k - 2] (ρ oodsX) *
          fromPartialEvals [ρ (evals 4), ρ (evals 5), ρ (evals 6), ρ (evals 7)] := by
  unfold extractExpectedCompositionEvalG at h ⊢
  rw [allHold_append, allHold_append, allHold_append, allHold_cons,
    allHold_cons] at h
  obtain ⟨⟨⟨hleft, hright⟩, hx⟩, hmul, hadd, -⟩ := h
  simp only [Holds] at hmul hadd
  have hl := fromPartialEvalsG_sound hleft
  have hr := fromPartialEvalsG_sound hright
  have hxv := cosetVanishing_sound hone (k - 2) _ hx
  show ρ _ = _
  rw [hadd, hmul, hxv, hl, hr]

/-! ### Linking to the spec's chunk reconstruction

`reconstructChunks` at the pinned split 1 is exactly
`left + (repeatedDouble point (k−2)).x · right`; on the circle, the
point-doubling x-coordinate is iterated `doubleX`, and the OODS point
(the image of the rational map) is always on the circle. Together with
`extractExpectedCompositionEvalG_sound` this ties the gadget to the
value `NativeAccepts` checks. -/

/-- The split-1 chunk reconstruction, explicitly. -/
theorem reconstructChunks_two (l r : QM31) (p : PointQ) (k : ℕ) (hk : 2 ≤ k) :
    reconstructChunks [l, r] p k 1
      = some (l + (CPoint.repeatedDouble p (k - 1 + 1 - 2)).x * r) := by
  unfold reconstructChunks
  rw [if_neg (by simp; omega)]
  simp [reconstructChunks.go, reconstructChunks.pair]

/-- On-circle predicate for QM31 points. -/
def OnCircleQ (p : PointQ) : Prop := p.x * p.x + p.y * p.y = 1

theorem onCircleQ_double {p : PointQ} (hp : OnCircleQ p) : OnCircleQ p.double := by
  unfold OnCircleQ at *
  show (p.add p).x * (p.add p).x + (p.add p).y * (p.add p).y = 1
  unfold CPoint.add
  simp only
  linear_combination (p.x * p.x + p.y * p.y + 1) * hp

/-- On the circle, doubling's x-coordinate is `doubleX`. -/
theorem double_x_onCircle {p : PointQ} (hp : OnCircleQ p) :
    p.double.x = CPoint.doubleX p.x := by
  unfold OnCircleQ at hp
  show (p.add p).x = p.x * p.x + p.x * p.x - 1
  unfold CPoint.add
  simp only
  linear_combination -hp

theorem repeatedDouble_x_onCircle {p : PointQ} (hp : OnCircleQ p) :
    ∀ n, (CPoint.repeatedDouble p n).x = CPoint.doubleX^[n] p.x := by
  intro n
  induction n with
  | zero => rfl
  | succ n ih =>
    have hcirc : ∀ m, OnCircleQ (CPoint.repeatedDouble p m) := by
      intro m
      induction m with
      | zero => exact hp
      | succ m ihm => exact onCircleQ_double ihm
    show (CPoint.repeatedDouble p n).double.x = _
    rw [double_x_onCircle (hcirc n), ih,
      Function.iterate_succ_apply' CPoint.doubleX n p.x]

/-- The OODS seed map lands on the circle. -/
theorem securePoint_onCircle {t : QM31} {p : PointQ}
    (h : securePointFromSeed t = some p) : OnCircleQ p := by
  have h' : ((t.square + QM31.one).inv?).bind
      (fun d => some (⟨(QM31.one - t.square) * d, (t + t) * d⟩ : PointQ))
      = some p := h
  cases hinv : (t.square + QM31.one).inv? with
  | none => rw [hinv] at h'; simp at h'
  | some d =>
    rw [hinv] at h'
    have h : (⟨(QM31.one - t.square) * d, (t + t) * d⟩ : PointQ) = p :=
      Option.some.inj h'
    obtain ⟨hne, hd⟩ := QM31.inv?_eq_some hinv
    rw [← h]
    unfold OnCircleQ QM31.square
    show (QM31.one - t * t) * d * ((QM31.one - t * t) * d)
      + (t + t) * d * ((t + t) * d) = 1
    have hcancel : (t * t + 1) * d = 1 := by
      rw [hd]
      exact mul_inv_cancel₀ (by
        intro h0
        apply hne
        rw [show t.square + QM31.one = t * t + 1 from rfl, h0])
    calc (QM31.one - t * t) * d * ((QM31.one - t * t) * d)
        + (t + t) * d * ((t + t) * d)
        = ((t * t + 1) * d) * ((t * t + 1) * d) := by
          rw [show (QM31.one : QM31) = 1 from rfl]
          ring
      _ = 1 := by rw [hcancel, mul_one]

/-- **The OODS reconstruction corollary**: at an on-circle OODS point `P`
whose x-coordinate the gadget received, the gadget output is exactly the
spec's split-1 chunk reconstruction — the composition value
`NativeAccepts` compares against the AIR evaluation. -/
theorem extractExpected_matches_spec {ρ : ℕ → QM31} {one : ℕ}
    {evals : Fin 8 → ℕ} {oodsX : ℕ} {k n : ℕ} {P : PointQ}
    (hone : ρ one = 1) (hk : 2 ≤ k)
    (hP : OnCircleQ P) (hPx : P.x = ρ oodsX)
    (h : AllHold ρ (extractExpectedCompositionEvalG one evals oodsX k n).ops) :
    reconstructChunks
        [fromPartialEvals [ρ (evals 0), ρ (evals 1), ρ (evals 2), ρ (evals 3)],
         fromPartialEvals [ρ (evals 4), ρ (evals 5), ρ (evals 6), ρ (evals 7)]]
        P (k - 1 + 1) 1
      = some (ρ (extractExpectedCompositionEvalG one evals oodsX k n).res) := by
  rw [reconstructChunks_two _ _ _ _ (by omega),
    extractExpectedCompositionEvalG_sound hone h,
    repeatedDouble_x_onCircle hP, hPx,
    show k - 1 + 1 - 1 + 1 - 2 = k - 2 from by omega]

end StwoVerifier.Gadgets
