/-
LogUp-GKR for fraction sums: one layer reduction, and the composition over
layers (zero-dependency).

Model. Layer `k` of the fraction circuit has `k` variables; its numerator
and denominator are given by functions `PT k, QT k : List F → F` (their
multilinear extensions). The fraction layer is

    p_k(x) = p_(k+1)(0,x) q_(k+1)(1,x) + p_(k+1)(1,x) q_(k+1)(0,x),
    q_k(x) = q_(k+1)(0,x) q_(k+1)(1,x),

i.e. `p0/q0 + p1/q1 = (p0 q1 + p1 q0)/(q0 q1)` (`frac_combine`), so the
root `p_0/q_0` is the sum of the leaf fractions. As multilinear extensions
this is the *layer-consistency* hypothesis `LayerConsistent`:
`PT k r = Σ_x eq(r,x) (PT(k+1)(0x) QT(k+1)(1x) + PT(k+1)(1x) QT(k+1)(0x))`
(and the same for `QT`), plus linearity of `PT (k+1)` in its first variable.
Both are properties of the honest MLEs, stated (not derived) like `IndDeg`.

One layer (`layerOut`): the verifier holds claims `(cp, cq)` for layer `k`
at a point `r`; it draws `lam`, runs a degree-3 sumcheck of `k` rounds on
`eq(r,x) (p-part + lam q-part)` against `cp + lam cq`, receives the four
values `p0 q0 p1 q1` at the sumcheck point `rho`, checks the final round
claim against them, draws `mu` and outputs claims for layer `k + 1` at
`mu :: rho` on the line through the received values.

`layer_sound`: from a false claim, at most a `(3k + 2)/|F|` fraction of
`(lam, rho, mu)` yields a true claim (1 for `lam`, `3k` for the sumcheck,
1 for `mu`), for any prover. `gkr_sound`: composed over `N` layers
(Compose.chain_sound), a false root claim ends in true input-layer claims
with probability `<= Σ_(k<N) (3k + 2)/|F|`. The input-layer claims are
checked against the committed leaves by the PCS; modelled as an ideal
oracle, accepting means exactly "the final claims are true".

security.zig `accountGkr` charges per layer `(2·active + 1) + 3·rounds +
active` over `|F|` (instance batching, degree-3 rounds, mask fold). For one
instance (`active = 1`) that is `3k + 4 >= 3k + 2`.
-/
import TensorFrontend.Compose
import TensorFrontend.Sumcheck

namespace TensorFrontend.Gkr

open Lean.Grind TensorFrontend TensorFrontend.Compose

variable {F : Type} [Field F] [DecidableEq F]

/-- `eq(r, x) = Π (r_i x_i + (1 - r_i)(1 - x_i))`. -/
def eqP : List F → List F → F
  | r :: rs, x :: xs => (r * x + (1 - r) * (1 - x)) * eqP rs xs
  | _, _ => 1

/-- The fraction layer: `p0/q0 + p1/q1 = (p0 q1 + p1 q0)/(q0 q1)`. -/
theorem frac_combine (p0 q0 p1 q1 : F) (h0 : q0 ≠ 0) (h1 : q1 ≠ 0) :
    p0 * q0⁻¹ + p1 * q1⁻¹ = (p0 * q1 + p1 * q0) * (q0 * q1)⁻¹ := by
  grind

/-- The batched layer summand `eq(r,x) (p-part + lam q-part)`. -/
def summand (PT QT : List F → F) (r : List F) (lam : F) (x : List F) : F :=
  eqP r x * ((PT (0 :: x) * QT (1 :: x) + PT (1 :: x) * QT (0 :: x)) + lam * (QT (0 :: x) * QT (1 :: x)))

/-- True numerator claim of the layer below, at `r`. -/
def Vp (PT QT : List F → F) (n : Nat) (r : List F) : F :=
  hsum n (fun x => eqP r x * (PT (0 :: x) * QT (1 :: x) + PT (1 :: x) * QT (0 :: x)))

/-- True denominator claim of the layer below, at `r`. -/
def Vq (PT QT : List F → F) (n : Nat) (r : List F) : F :=
  hsum n (fun x => eqP r x * (QT (0 :: x) * QT (1 :: x)))

theorem hsum_lin (n : Nat) (f g : List F → F) (c : F) :
    hsum n (fun x => f x + c * g x) = hsum n f + c * hsum n g := by
  induction n generalizing f g with
  | zero => rfl
  | succ n ih =>
    simp only [hsum]
    rw [ih (fun r => f (0 :: r)) (fun r => g (0 :: r)), ih (fun r => f (1 :: r)) (fun r => g (1 :: r))]
    grind

theorem hsum_summand (PT QT : List F → F) (n : Nat) (r : List F) (lam : F) :
    hsum n (summand PT QT r lam) = Vp PT QT n r + lam * Vq PT QT n r := by
  have : summand PT QT r lam = fun x =>
      eqP r x * (PT (0 :: x) * QT (1 :: x) + PT (1 :: x) * QT (0 :: x)) +
        lam * (eqP r x * (QT (0 :: x) * QT (1 :: x))) := by
    funext x; simp only [summand]; grind
  rw [this, hsum_lin]; rfl

/-- The sumcheck verifier's rounds, returning the final claim (the oracle
check is replaced by the layer's own check). -/
def scFinal (d : Nat) : Nat → F → (List F → List F) → List F → Option F
  | 0, c, _, [] => some c
  | n + 1, c, P, r :: rs =>
    if (P []).length ≤ d + 1 ∧ eval (P []) 0 + eval (P []) 1 = c then
      scFinal d n (eval (P []) r) (fun pre => P (r :: pre)) rs
    else none
  | _, _, _, _ => none

theorem scFinal_accepts (d : Nat) [FinEnum F] :
    ∀ (n : Nat) (f : List F → F) (c : F) (P : List F → List F) (ρ : List F) (cf : F),
    scFinal d n c P ρ = some cf → cf = f ρ → accepts d n f c P ρ = true
  | 0, f, c, P, [], cf, h, hf => by
    simp only [scFinal, Option.some.injEq] at h
    simp only [accepts, decide_eq_true_eq]; rw [h, hf]
  | 0, _, _, _, _ :: _, _, h, _ => by simp [scFinal] at h
  | n + 1, _, _, _, [], _, h, _ => by simp [scFinal] at h
  | n + 1, f, c, P, r :: rs, cf, h, hf => by
    simp only [scFinal] at h
    split at h
    · rename_i hc
      have := scFinal_accepts d n (fun t => f (r :: t)) _ _ rs cf h hf
      simp only [accepts, Bool.and_eq_true, decide_eq_true_eq]
      exact ⟨⟨hc.1, hc.2⟩, this⟩
    · cases h

/-- A layer prover: sumcheck messages and the four opened values
`(p0, q0, p1, q1)`, as functions of the challenges. -/
structure LayerProver (F : Type) where
  sc : F → List F → List F
  opening : F → List F → F × F × F × F

/-- The layer verifier on challenges `lam :: mu :: rho`: the next claim
`(point, p, q)` or `none` (reject). -/
def layerOut (n : Nat) (r : List F) (cp cq : F) (P : LayerProver F) : List F → Option (List F × F × F)
  | lam :: mu :: rho =>
    match scFinal 3 n (cp + lam * cq) (P.sc lam) rho with
    | none => none
    | some cf =>
      match P.opening lam rho with
      | (p0, q0, p1, q1) =>
        if cf = eqP r rho * ((p0 * q1 + p1 * q0) + lam * (q0 * q1)) then
          some (mu :: rho, (1 - mu) * p0 + mu * p1, (1 - mu) * q0 + mu * q1)
        else none
  | _ => none

/-- The output claim is true for the layer functions `PT, QT`. -/
def goodOut (PT QT : List F → F) : Option (List F × F × F) → Bool
  | some (r', a, b) => decide (a = PT r' ∧ b = QT r')
  | none => false

variable [FinEnum F]

/-- The layer challenge space, iterated `lam`, `rho`, `mu`. -/
def layerΩ (F : Type) [FinEnum F] (n : Nat) : List (List F) :=
  (FinEnum.elems (F := F)).flatMap (fun lam =>
    (vecs F n).flatMap (fun rho => (FinEnum.elems (F := F)).map (fun mu => lam :: mu :: rho)))

omit [Field F] [DecidableEq F] in
theorem layerΩ_length (n : Nat) : (layerΩ F n).length = card F * (card F ^ n * card F) := by
  simp only [layerΩ, List.length_flatMap, List.length_map]
  rw [Compose.sum_map_const', Compose.sum_map_const', vecs_length]; rfl

/-- A nonzero linear function `a + x b` has at most one root. -/
theorem lin_count (a b : F) (h : ¬ (a = 0 ∧ b = 0)) :
    (FinEnum.elems (F := F)).countP (fun x => decide (a + x * b = 0)) ≤ 1 := by
  have hnz : ¬ AllZero [a, b] := fun hz =>
    h ⟨hz a (List.mem_cons_self ..), hz b (List.mem_cons_of_mem _ (List.mem_cons_self ..))⟩
  rw [List.countP_eq_length_filter]
  have := roots_le [a, b] hnz ((FinEnum.elems (F := F)).filter (fun x => decide (a + x * b = 0)))
    (List.Nodup.sublist List.filter_sublist FinEnum.nodup) (by
      intro x hx
      rw [List.mem_filter] at hx
      have := _root_.of_decide_eq_true hx.2
      simp only [eval]; grind)
  simpa using this

theorem countP_le_of_imp {α : Type} (l : List α) (p q : α → Bool) (h : ∀ x, p x = true → q x = true) :
    l.countP p ≤ l.countP q := by
  induction l with
  | nil => simp
  | cons y l ih =>
    simp only [List.countP_cons]
    cases hp : p y
    · simp only [Bool.false_eq_true, ite_false]; split <;> omega
    · simp only [h y hp, ite_true]; omega

/-- The `mu` level: with a false combined claim and a non-accepting
sumcheck point, at most one `mu` gives a true output claim. -/
theorem mu_level (n : Nat) (PT QT : List F → F) (r : List F) (cp cq : F) (P : LayerProver F)
    (lam : F) (rho : List F)
    (hlinP : ∀ mu, PT (mu :: rho) = (1 - mu) * PT (0 :: rho) + mu * PT (1 :: rho))
    (hlinQ : ∀ mu, QT (mu :: rho) = (1 - mu) * QT (0 :: rho) + mu * QT (1 :: rho))
    (hacc : accepts 3 n (summand PT QT r lam) (cp + lam * cq) (P.sc lam) rho = false) :
    (FinEnum.elems (F := F)).countP (fun mu => goodOut PT QT (layerOut n r cp cq P (lam :: mu :: rho))) ≤ 1 := by
  cases hsc : scFinal 3 n (cp + lam * cq) (P.sc lam) rho with
  | none =>
    have : ∀ mu, layerOut n r cp cq P (lam :: mu :: rho) = none := by
      intro mu; simp only [layerOut, hsc]
    simp only [this, goodOut]; simp
  | some cf =>
    match ho : P.opening lam rho with
    | (p0, q0, p1, q1) =>
    by_cases hchk : cf = eqP r rho * ((p0 * q1 + p1 * q0) + lam * (q0 * q1))
    · -- the opened values cannot all be the true ones (else the sumcheck accepts)
      have hne : ¬ (p0 = PT (0 :: rho) ∧ q0 = QT (0 :: rho) ∧ p1 = PT (1 :: rho) ∧ q1 = QT (1 :: rho)) := by
        rintro ⟨e1, e2, e3, e4⟩
        have := scFinal_accepts 3 n (summand PT QT r lam) _ _ rho cf hsc (by
          rw [hchk, e1, e2, e3, e4]; simp only [summand])
        rw [hacc] at this; cases this
      have hout : ∀ mu, layerOut n r cp cq P (lam :: mu :: rho) =
          some (mu :: rho, (1 - mu) * p0 + mu * p1, (1 - mu) * q0 + mu * q1) := by
        intro mu
        simp only [layerOut, hsc, ho, hchk, if_true]
      simp only [hout, goodOut]
      by_cases hp : p0 = PT (0 :: rho) ∧ p1 = PT (1 :: rho)
      · have hq : ¬ (q0 - QT (0 :: rho) = 0 ∧ (q1 - QT (1 :: rho)) - (q0 - QT (0 :: rho)) = 0) := by
          intro e; apply hne; refine ⟨hp.1, ?_, hp.2, ?_⟩ <;> grind
        refine Nat.le_trans (countP_le_of_imp _ _ _ ?_) (lin_count _ _ hq)
        intro mu h
        simp only [decide_eq_true_eq] at h ⊢
        have := hlinQ mu
        grind
      · have hp' : ¬ (p0 - PT (0 :: rho) = 0 ∧ (p1 - PT (1 :: rho)) - (p0 - PT (0 :: rho)) = 0) := by
          intro e; apply hp; constructor <;> grind
        refine Nat.le_trans (countP_le_of_imp _ _ _ ?_) (lin_count _ _ hp')
        intro mu h
        simp only [decide_eq_true_eq] at h ⊢
        have := hlinP mu
        grind
    · have : ∀ mu, layerOut n r cp cq P (lam :: mu :: rho) = none := by
        intro mu; simp only [layerOut, hsc, ho, hchk, if_false]
      simp only [this, goodOut]; simp

omit [Field F] [DecidableEq F] in
theorem sum_le_len {α : Type} (L : List α) (g : α → Nat) (c : Nat) (h : ∀ x ∈ L, g x ≤ c) :
    (L.map g).sum ≤ L.length * c := by
  have := sum_split L g (fun _ => false) 0 c (by intro x hx; simpa using h x hx)
  simpa using this

/-- **One GKR layer is sound.** From a false claim `(cp, cq)` about the
layer with `n` variables, for every prover at most `(3n + 2) |F|^(n+1)` of
the `|F|^(n+2)` challenge triples give a true claim about the layer below:
probability `<= (3n + 2)/|F|`. -/
theorem layer_sound (n : Nat) (PT QT : List F → F) (r : List F) (cp cq : F) (P : LayerProver F)
    (hlinP : ∀ mu rho, PT (mu :: rho) = (1 - mu) * PT (0 :: rho) + mu * PT (1 :: rho))
    (hlinQ : ∀ mu rho, QT (mu :: rho) = (1 - mu) * QT (0 :: rho) + mu * QT (1 :: rho))
    (hdeg : ∀ lam, IndDeg 3 n (summand PT QT r lam))
    (hbad : ¬ (cp = Vp PT QT n r ∧ cq = Vq PT QT n r)) :
    (layerΩ F n).countP (fun ω => goodOut PT QT (layerOut n r cp cq P ω)) * card F ≤
      (3 * n + 2) * (layerΩ F n).length := by
  have hsplit : (layerΩ F n).countP (fun ω => goodOut PT QT (layerOut n r cp cq P ω)) =
      ((FinEnum.elems (F := F)).map (fun lam => ((vecs F n).map (fun rho =>
        (FinEnum.elems (F := F)).countP (fun mu =>
          goodOut PT QT (layerOut n r cp cq P (lam :: mu :: rho))))).sum)).sum := by
    simp only [layerΩ, List.countP_flatMap, List.countP_map, Function.comp_def]
  rw [hsplit, layerΩ_length]
  have hL : (FinEnum.elems (F := F)).length = card F := rfl
  have hV : (vecs F n).length = card F ^ n := vecs_length n
  -- Y * C <= 3 n X
  have hYC : n * 3 * card F ^ (n - 1) * card F ≤ n * 3 * card F ^ n := by
    cases n with
    | zero => simp
    | succ k => simp only [Nat.add_sub_cancel, Nat.pow_succ, Nat.mul_assoc]; exact Nat.le_refl _
  have hout := sum_split (FinEnum.elems (F := F))
    (fun lam => ((vecs F n).map (fun rho =>
        (FinEnum.elems (F := F)).countP (fun mu =>
          goodOut PT QT (layerOut n r cp cq P (lam :: mu :: rho))))).sum)
    (fun lam => decide (cp + lam * cq = hsum n (summand PT QT r lam)))
    (card F ^ n * card F) (n * 3 * card F ^ n + card F ^ n) (by
      intro lam _
      by_cases hl : cp + lam * cq = hsum n (summand PT QT r lam)
      · simp only [hl, decide_true, ite_true]
        have := sum_le_len (vecs F n) (fun rho => (FinEnum.elems (F := F)).countP (fun mu =>
            goodOut PT QT (layerOut n r cp cq P (lam :: mu :: rho)))) (card F)
          (fun rho _ => by rw [← hL]; exact List.countP_le_length)
        rw [hV] at this; omega
      · simp only [hl, decide_false, Bool.false_eq_true, ite_false, Nat.zero_add]
        have hsc := sumcheck_sound 3 n (summand PT QT r lam) (hdeg lam) _ hl (P.sc lam)
        have hin := sum_split (vecs F n) (fun rho => (FinEnum.elems (F := F)).countP (fun mu =>
            goodOut PT QT (layerOut n r cp cq P (lam :: mu :: rho))))
          (accepts 3 n (summand PT QT r lam) (cp + lam * cq) (P.sc lam)) (card F) 1 (by
            intro rho _
            cases ha : accepts 3 n (summand PT QT r lam) (cp + lam * cq) (P.sc lam) rho
            · simp only [Bool.false_eq_true, ite_false, Nat.zero_add]
              exact mu_level n PT QT r cp cq P lam rho (fun mu => hlinP mu rho) (fun mu => hlinQ mu rho) ha
            · simp only [ite_true]; rw [← hL]
              exact Nat.le_trans List.countP_le_length (Nat.le_add_right _ _))
        rw [hV] at hin
        have h2 : (vecs F n).countP (accepts 3 n (summand PT QT r lam) (cp + lam * cq) (P.sc lam)) * card F ≤
            n * 3 * card F ^ (n - 1) * card F := Nat.mul_le_mul_right _ hsc
        omega)
  have hbadl : (FinEnum.elems (F := F)).countP
      (fun lam => decide (cp + lam * cq = hsum n (summand PT QT r lam))) ≤ 1 := by
    have hab : ¬ (cp - Vp PT QT n r = 0 ∧ cq - Vq PT QT n r = 0) := by
      intro e; apply hbad; constructor <;> grind
    refine Nat.le_trans (countP_le_of_imp _ _ _ ?_) (lin_count _ _ hab)
    intro lam h
    simp only [decide_eq_true_eq, hsum_summand] at h ⊢
    grind
  rw [hL] at hout
  have h3 : (FinEnum.elems (F := F)).countP
      (fun lam => decide (cp + lam * cq = hsum n (summand PT QT r lam))) * (card F ^ n * card F) ≤
      card F ^ n * card F := by
    have := Nat.mul_le_mul_right (card F ^ n * card F) hbadl; simpa using this
  have h4 : ((FinEnum.elems (F := F)).map (fun lam => ((vecs F n).map (fun rho =>
        (FinEnum.elems (F := F)).countP (fun mu =>
          goodOut PT QT (layerOut n r cp cq P (lam :: mu :: rho))))).sum)).sum ≤
      card F ^ n * card F + card F * (n * 3 * card F ^ n + card F ^ n) := by omega
  have h5 := Nat.mul_le_mul_right (card F) h4
  have e : (card F ^ n * card F + card F * (n * 3 * card F ^ n + card F ^ n)) * card F =
      (3 * n + 2) * (card F * (card F ^ n * card F)) := by grind
  omega

/-! ### Composition over layers -/

/-- Verifier state: the transcript so far and the current claim
(layer, point, numerator, denominator), `none` after a rejection. -/
abbrev GState (F : Type) := List (List F) × Option (Nat × List F × F × F)

/-- The claim is about layer `k` and true. -/
def good (PT QT : Nat → List F → F) (s : GState F) : Bool :=
  match s.2 with
  | some (k, r, a, b) => decide (a = PT k r ∧ b = QT k r)
  | none => false

/-- Layer `k` as a protocol step; the prover sees the whole transcript. -/
def gkrStep (Prov : Nat → List (List F) → LayerProver F) (k : Nat) : Step (GState F) (List F) where
  Ω := layerΩ F k
  next := fun s ω => (s.1 ++ [ω], match s.2 with
    | some (k', r, a, b) =>
      if k' = k then (layerOut k r a b (Prov k s.1) ω).map (fun t => (k + 1, t)) else none
    | none => none)
  err := 3 * k + 2

/-- The `N` layers, root (`k = 0`) first. -/
def gkrSteps (Prov : Nat → List (List F) → LayerProver F) (N : Nat) : List (Step (GState F) (List F)) :=
  (List.range N).map (gkrStep Prov)

theorem errSum_gkr (Prov : Nat → List (List F) → LayerProver F) (N : Nat) :
    errSum (gkrSteps Prov N) = ((List.range N).map (fun k => 3 * k + 2)).sum := by
  simp only [errSum, gkrSteps, List.map_map]; rfl

/-- The honest circuit's multilinear extensions are layer-consistent
(stated hypothesis; see the module header). -/
structure LayerConsistent (N : Nat) (PT QT : Nat → List F → F) : Prop where
  p : ∀ k, k < N → ∀ r, PT k r = Vp (PT (k + 1)) (QT (k + 1)) k r
  q : ∀ k, k < N → ∀ r, QT k r = Vq (PT (k + 1)) (QT (k + 1)) k r
  linP : ∀ k, k < N → ∀ mu rho, PT (k + 1) (mu :: rho) = (1 - mu) * PT (k + 1) (0 :: rho) + mu * PT (k + 1) (1 :: rho)
  linQ : ∀ k, k < N → ∀ mu rho, QT (k + 1) (mu :: rho) = (1 - mu) * QT (k + 1) (0 :: rho) + mu * QT (k + 1) (1 :: rho)
  deg : ∀ k, k < N → ∀ r lam, IndDeg 3 k (summand (PT (k + 1)) (QT (k + 1)) r lam)

/-- **LogUp-GKR soundness (N layers).** A false root claim `(cp, cq)` ends,
after the `N` layer reductions, in true claims about the input layer (what
an ideal input oracle accepts) for at most a `Σ_(k<N) (3k + 2) / |F|`
fraction of all challenge tuples, for every adaptive prover. -/
theorem gkr_sound (PT QT : Nat → List F → F) (N : Nat) (hc : LayerConsistent N PT QT)
    (Prov : Nat → List (List F) → LayerProver F) (cp cq : F)
    (hbad : ¬ (cp = PT 0 [] ∧ cq = QT 0 [])) :
    (space (gkrSteps Prov N)).countP
        (fun as => good PT QT (run (gkrSteps Prov N) ([], some (0, [], cp, cq)) as)) * card F ≤
      errSum (gkrSteps Prov N) * (space (gkrSteps Prov N)).length := by
  apply chain_sound
  · simp only [good, decide_eq_false_iff_not]; exact hbad
  · intro st hst s hs
    obtain ⟨k, hkN, rfl⟩ := List.mem_map.mp hst
    have hkN : k < N := List.mem_range.mp hkN
    obtain ⟨h, o⟩ := s
    cases o with
    | none => simp [gkrStep, good]
    | some c =>
      obtain ⟨k', r, a, b⟩ := c
      by_cases hk : k' = k
      · subst hk
        have hb : ¬ (a = Vp (PT (k' + 1)) (QT (k' + 1)) k' r ∧ b = Vq (PT (k' + 1)) (QT (k' + 1)) k' r) := by
          rw [← hc.p k' hkN, ← hc.q k' hkN]
          simpa [good] using hs
        have heq : (layerΩ F k').countP (fun ω => good PT QT ((gkrStep Prov k').next (h, some (k', r, a, b)) ω)) =
            (layerΩ F k').countP (fun ω => goodOut (PT (k' + 1)) (QT (k' + 1)) (layerOut k' r a b (Prov k' h) ω)) := by
          congr 1; funext ω
          simp only [gkrStep, ite_true]
          cases layerOut k' r a b (Prov k' h) ω with
          | none => rfl
          | some t => obtain ⟨r', x, y⟩ := t; rfl
        show (layerΩ F k').countP _ * card F ≤ (3 * k' + 2) * (layerΩ F k').length
        rw [heq]
        exact layer_sound k' (PT (k' + 1)) (QT (k' + 1)) r a b (Prov k' h)
          (hc.linP k' hkN) (hc.linQ k' hkN) (hc.deg k' hkN r) hb
      · simp [gkrStep, hk, good]

end TensorFrontend.Gkr
