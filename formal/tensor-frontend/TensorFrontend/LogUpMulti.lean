/-
Multi-column LogUp keys (zero-dependency).

security.zig `accountLogup`: a key of arity `a` (columns `v_0 .. v_(a-1)`)
enters LogUp as the denominator `alpha - (v_0 + beta v_1 + ... + beta^(a-1) v_(a-1))`
with two challenges: `beta` combines the columns, `alpha` is the LogUp point.
We model a key as a coefficient list `k` (low column first), so the combined
value is `eval k beta` (Horner), and a LogUp relation as a list of
(net coefficient, key) pairs.

Proven (sequential, not joint, Schwartz-Zippel):

* `isolated_coef`: if, at `beta`, the combined value of key `s` collides with
  no other key's, the grouped coefficient of the pole `eval s beta` is the
  key-level coefficient `coefKey L s`;
* `collision_count`: for fixed-arity keys, at most
  `#{entries with key != s} * (a - 1)` values of `beta` make some other key
  collide with `s` (each difference is a nonzero polynomial of degree
  `<= a - 1`);
* `logupMulti_count`: if some key has a nonzero coefficient, at most
  `((N - 1)(a - 1) + (2N - 1)) |F|` of the `|F|^2` pairs `(beta, alpha)`
  are poles or zeros of the fractional sum (`N` = number of fractions):
  probability `<= ((N - 1)(a - 1) + 2N - 1) / |F|`;
* `logupMulti_sound`: the same from a failing keyed multiset relation with
  all counts below the characteristic (`D < p`, `logup_below_p`);
* `logupMulti_charge`: for arity 1 or `>= 3` this is `<= 2 g N / |F|`
  with `g = max(a - 1, 1)`, exactly the term `accountLogup` charges
  (`2 g D / |F|`). For arity 2 the sequential bound is `3N - 2`, above the
  charged `2N` (the Zig comment's joint Schwartz-Zippel argument gives
  `2N - 1`; the joint form is not formalised): `logupMulti_charge_arity2`.
-/
import TensorFrontend.LogUp

namespace TensorFrontend.LogUpMulti

open Lean.Grind TensorFrontend TensorFrontend.LogUp

variable {F : Type} [Field F] [DecidableEq F]

/-- The univariate LogUp pair list at the column challenge `beta`:
pole `eval k beta = v_0 + beta v_1 + ...` per key. -/
def atBeta (L : List (F × List F)) (β : F) : List (F × F) :=
  L.map (fun ck => (ck.1, eval ck.2 β))

/-- Net coefficient of key `s` (key-level grouping). -/
def coefKey : List (F × List F) → List F → F
  | [], _ => 0
  | (c, k) :: t, s => (if k = s then c else 0) + coefKey t s

theorem isolated_coef (L : List (F × List F)) (s : List F) (β : F)
    (hiso : ∀ ck ∈ L, ck.2 = s ∨ eval ck.2 β ≠ eval s β) :
    coefSum (atBeta L β) (eval s β) = coefKey L s := by
  induction L with
  | nil => rfl
  | cons ck t ih =>
    obtain ⟨c, k⟩ := ck
    have ht := ih (fun y hy => hiso y (List.mem_cons_of_mem _ hy))
    simp only [atBeta, List.map_cons, coefSum, coefKey] at ht ⊢
    rw [ht]
    rcases hiso (c, k) (List.mem_cons_self ..) with h | h
    · simp only at h; subst h; simp
    · simp only at h
      have hk : k ≠ s := fun e => h (e ▸ rfl)
      simp [h, hk]

theorem coefKey_mem (L : List (F × List F)) (s : List F) (h : coefKey L s ≠ 0) :
    ∃ c, (c, s) ∈ L := by
  induction L with
  | nil => exact absurd rfl h
  | cons ck t ih =>
    obtain ⟨c, k⟩ := ck
    simp only [coefKey] at h
    by_cases e : k = s
    · subst e; exact ⟨c, List.mem_cons_self ..⟩
    · simp only [e, ite_false] at h
      obtain ⟨c', h'⟩ := ih (by intro z; apply h; rw [z]; grind)
      exact ⟨c', List.mem_cons_of_mem _ h'⟩

/-- A nonzero grouped coefficient at a pole makes the cleared numerator a
nonzero polynomial. -/
theorem num_nonzero (L : List (F × F)) (z : F) (hz : z ∈ poles L) (hc : coefSum L z ≠ 0) :
    ¬ AllZero (num (group L)) := by
  intro hall
  have hnd : (poles (group L)).Nodup := by rw [poles_group]; exact nodup_dd _
  have h := (num_allZero_iff _ hnd).mp hall
  exact hc (h (coefSum L z, z) (List.mem_map.mpr ⟨z, (mem_dd _ z).mpr hz, rfl⟩))

/-- Equal-length lists with all-zero difference are equal. -/
theorem sub_allZero_eq (p q : List F) (hl : p.length = q.length) (h : AllZero (sub p q)) : p = q := by
  match p, q with
  | [], [] => rfl
  | c :: p, d :: q =>
    simp only [sub] at h
    have h0 : c - d = 0 := h _ (List.mem_cons_self ..)
    have ih := sub_allZero_eq p q (by simpa using hl) (fun y hy => h y (List.mem_cons_of_mem _ hy))
    rw [ih, show c = d by grind]
  | [], _ :: _ => simp at hl
  | _ :: _, [] => simp at hl

variable [FinEnum F]

/-- Two distinct keys of arity `a` combine to the same value for at most
`a - 1` values of `beta`. -/
theorem pair_collision (a : Nat) (k s : List F) (hk : k.length = a) (hs : s.length = a) (hne : k ≠ s) :
    (FinEnum.elems (F := F)).countP (fun β => decide (eval k β = eval s β)) ≤ a - 1 := by
  have hnz : ¬ AllZero (sub k s) := fun hz => hne (sub_allZero_eq k s (by rw [hk, hs]) hz)
  rw [List.countP_eq_length_filter]
  have := roots_le (sub k s) hnz
    ((FinEnum.elems (F := F)).filter (fun β => decide (eval k β = eval s β)))
    (List.Nodup.sublist List.filter_sublist FinEnum.nodup) (by
    intro x hx
    rw [List.mem_filter] at hx
    rw [sub_eval]
    have := _root_.of_decide_eq_true hx.2
    grind)
  rw [sub_length, hk, hs, Nat.max_self] at this
  exact this

/-- Some key other than `s` collides with `s` at `beta`. -/
def collides (L : List (F × List F)) (s : List F) (β : F) : Bool :=
  L.any (fun ck => decide (ck.2 ≠ s) && decide (eval ck.2 β = eval s β))

theorem collision_count (a : Nat) (L : List (F × List F)) (s : List F)
    (hk : ∀ ck ∈ L, ck.2.length = a) (hs : s.length = a) :
    (FinEnum.elems (F := F)).countP (collides L s) ≤ L.countP (fun ck => decide (ck.2 ≠ s)) * (a - 1) := by
  induction L with
  | nil => simp [collides]
  | cons ck t ih =>
    have iht := ih (fun y hy => hk y (List.mem_cons_of_mem _ hy))
    have heq : collides (ck :: t) s =
        (fun β => (decide (ck.2 ≠ s) && decide (eval ck.2 β = eval s β)) || collides t s β) := by
      funext β; simp [collides]
    rw [heq]
    have hor := countP_or_le (FinEnum.elems (F := F))
      (fun β => decide (ck.2 ≠ s) && decide (eval ck.2 β = eval s β)) (collides t s)
    rw [List.countP_cons]
    by_cases hne : ck.2 = s
    · have hf : (fun β => (decide (ck.2 ≠ s) && decide (eval ck.2 β = eval s β)) || collides t s β)
          = collides t s := by funext β; simp [hne]
      rw [hf]
      have : decide (ck.2 ≠ s) = false := by simp [hne]
      rw [this]; simp only [Bool.false_eq_true, ite_false, Nat.add_zero]; exact iht
    · have h1 := pair_collision (F := F) a ck.2 s (hk ck (List.mem_cons_self ..)) hs hne
      have hdec : decide (ck.2 ≠ s) = true := by simp [hne]
      simp only [hdec, Bool.true_and, ite_true]
      have hor2 := countP_or_le (FinEnum.elems (F := F))
        (fun β => decide (eval ck.2 β = eval s β)) (collides t s)
      rw [Nat.add_mul, Nat.one_mul]
      omega

omit [Field F] [FinEnum F] in
theorem dd_length_le (l : List F) : (dd l).length ≤ l.length := by
  induction l with
  | nil => simp [dd]
  | cons x t ih => simp only [dd]; split <;> simp <;> omega

/-- All pairs `(beta, alpha) ∈ F × F`. -/
def pairsF (F : Type) [FinEnum F] : List (F × F) :=
  (FinEnum.elems (F := F)).flatMap (fun β => (FinEnum.elems (F := F)).map (fun α => (β, α)))

omit [Field F] [DecidableEq F] in
theorem pairsF_length : (pairsF F).length = card F * card F := by
  simp only [pairsF, List.length_flatMap, List.length_map]
  rw [sum_map_const]; rfl

/-- The bad event: `alpha` is a pole at `beta` or the fractional sum vanishes. -/
def badPair (L : List (F × List F)) (βα : F × F) : Bool :=
  decide (βα.2 ∈ poles (atBeta L βα.1)) || decide (fsum (atBeta L βα.1) βα.2 = 0)

/-- **Multi-column LogUp, counting form.** Keys of arity `a`; some key `s`
has a nonzero net coefficient. Then at most
`((N - 1)(a - 1) + (2N - 1)) |F|` of the `|F|^2` challenge pairs are bad. -/
theorem logupMulti_count (a : Nat) (L : List (F × List F)) (s : List F)
    (hk : ∀ ck ∈ L, ck.2.length = a) (hc : coefKey L s ≠ 0) :
    (pairsF F).countP (badPair L) ≤
      ((L.length - 1) * (a - 1)) * card F + card F * (2 * L.length - 1) := by
  obtain ⟨c0, hm⟩ := coefKey_mem L s hc
  have hs : s.length = a := hk _ hm
  have hsplit : (pairsF F).countP (badPair L) =
      ((FinEnum.elems (F := F)).map (fun β =>
        (FinEnum.elems (F := F)).countP (fun α => badPair L (β, α)))).sum := by
    simp only [pairsF, List.countP_flatMap]
    congr 1
    apply List.map_congr_left
    intro β _
    simp only [Function.comp, List.countP_map]
    rfl
  rw [hsplit]
  have hb := sum_split (FinEnum.elems (F := F))
    (fun β => (FinEnum.elems (F := F)).countP (fun α => badPair L (β, α)))
    (collides L s) (card F) (2 * L.length - 1) (by
      intro β _
      by_cases hcol : collides L s β = true
      · simp only [hcol, ite_true]
        have := List.countP_le_length (p := fun α => badPair L (β, α)) (l := FinEnum.elems (F := F))
        exact Nat.le_trans this (Nat.le_add_right _ _)
      · simp only [Bool.not_eq_true] at hcol
        simp only [hcol, Bool.false_eq_true, ite_false, Nat.zero_add]
        have hiso : ∀ ck ∈ L, ck.2 = s ∨ eval ck.2 β ≠ eval s β := by
          intro ck hck
          by_cases e : ck.2 = s
          · exact Or.inl e
          · refine Or.inr (fun h => ?_)
            have : collides L s β = true := by
              simp only [collides, List.any_eq_true, Bool.and_eq_true, decide_eq_true_eq]
              exact ⟨ck, hck, e, h⟩
            rw [hcol] at this; cases this
        have hcoef := isolated_coef L s β hiso
        have hpole : eval s β ∈ poles (atBeta L β) :=
          List.mem_map.mpr ⟨(c0, eval s β), List.mem_map.mpr ⟨(c0, s), hm, rfl⟩, rfl⟩
        have hnz := num_nonzero (atBeta L β) (eval s β) hpole (by rw [hcoef]; exact hc)
        have hcnt := fsum_random_count (atBeta L β) hnz
        have hdd := dd_length_le (poles (atBeta L β))
        have hpl : (poles (atBeta L β)).length = L.length := by simp [poles, atBeta]
        have : (FinEnum.elems (F := F)).countP (fun α => badPair L (β, α)) =
            (FinEnum.elems (F := F)).countP
              (fun x => decide (x ∈ poles (atBeta L β)) || decide (fsum (atBeta L β) x = 0)) := rfl
        omega)
  have hcol := collision_count a L s hk hs
  have hlt : L.countP (fun ck => decide (ck.2 ≠ s)) ≤ L.length - 1 := by
    have h1 : L.countP (fun ck => decide (ck.2 ≠ s)) ≠ L.length := by
      intro e
      have := (List.countP_eq_length).mp e (c0, s) hm
      simp at this
    have h2 := List.countP_le_length (p := fun ck => decide (ck.2 ≠ s)) (l := L)
    omega
  have hm2 : (FinEnum.elems (F := F)).countP (collides L s) * card F ≤
      ((L.length - 1) * (a - 1)) * card F :=
    Nat.mul_le_mul_right _ (Nat.le_trans hcol (Nat.mul_le_mul_right _ hlt))
  have hL : (FinEnum.elems (F := F)).length = card F := rfl
  rw [hL] at hb
  omega

/-! ### Keyed tables -/

/-- Multiplicity-weighted count of key `z` in a keyed table. -/
def tcountK : List (List F × Nat) → List F → Nat
  | [], _ => 0
  | (t, m) :: T, z => (if t = z then m else 0) + tcountK T z

/-- Occurrences of key `z` among the looked-up keys. -/
def acountK : List (List F) → List F → Nat
  | [], _ => 0
  | a :: A, z => (if a = z then 1 else 0) + acountK A z

/-- Keyed LogUp pair list: table rows with multiplicity, `-1` per lookup. -/
def pairsK (T : List (List F × Nat)) (A : List (List F)) : List (F × List F) :=
  T.map (fun tm => (ncast tm.2, tm.1)) ++ A.map (fun a => (0 - 1, a))

/-- The keyed multiset relation. -/
def MultisetOKK (T : List (List F × Nat)) (A : List (List F)) : Prop :=
  ∀ z, tcountK T z = acountK A z

omit [FinEnum F] in
theorem coefKey_append (L M : List (F × List F)) (z : List F) :
    coefKey (L ++ M) z = coefKey L z + coefKey M z := by
  induction L with
  | nil => simp [coefKey]; grind
  | cons cz t ih => obtain ⟨c, w⟩ := cz; simp only [List.cons_append, coefKey]; rw [ih]; grind

omit [FinEnum F] in
theorem coefKey_pairsK (T : List (List F × Nat)) (A : List (List F)) (z : List F) :
    coefKey (pairsK T A) z = ncast (tcountK T z) - ncast (acountK A z) := by
  unfold pairsK
  rw [coefKey_append]
  have h1 : coefKey (T.map (fun tm => ((ncast tm.2 : F), tm.1))) z = (ncast (tcountK T z) : F) := by
    induction T with
    | nil => simp [coefKey, tcountK, ncast]
    | cons tm T ih =>
      obtain ⟨t, m⟩ := tm
      simp only [List.map_cons, coefKey, tcountK]
      rw [ih, ncast_add]
      by_cases h : t = z
      · simp only [h, ite_true]
      · simp only [h, ite_false, ncast]; try grind
  have h2 : coefKey (A.map (fun a => ((0 : F) - 1, a))) z = 0 - (ncast (acountK A z) : F) := by
    induction A with
    | nil => simp [coefKey, acountK, ncast]; grind
    | cons a A ih =>
      simp only [List.map_cons, coefKey, acountK]
      rw [ih, ncast_add]
      by_cases h : a = z
      · simp only [h, ite_true, ncast]; grind
      · simp only [h, ite_false, ncast]; grind
  rw [h1, h2]; grind

/-- **Multi-column LogUp soundness.** If the keyed multiset relation fails,
all counts are below the characteristic and every key has arity `a`, at most
`((N - 1)(a - 1) + 2N - 1) |F|` of the `|F|^2` pairs `(beta, alpha)` make
the verifier's fractional-sum check pass (or hit a pole), `N = |T| + |A|`. -/
theorem logupMulti_sound (p a : Nat) (hchar : ∀ k, 0 < k → k < p → (ncast k : F) ≠ 0)
    (T : List (List F × Nat)) (A : List (List F))
    (hT : ∀ z, tcountK T z < p) (hA : ∀ z, acountK A z < p)
    (harity : ∀ ck ∈ pairsK T A, ck.2.length = a)
    (hbad : ¬ MultisetOKK T A) :
    (pairsF F).countP (badPair (pairsK T A)) ≤
      (((pairsK T A).length - 1) * (a - 1)) * card F + card F * (2 * (pairsK T A).length - 1) := by
  have : ∃ s, coefKey (pairsK T A) s ≠ 0 := by
    apply Classical.byContradiction
    intro hno
    apply hbad
    intro z
    have hz : coefKey (pairsK T A) z = 0 := Classical.byContradiction (fun h => hno ⟨z, h⟩)
    rw [coefKey_pairsK] at hz
    exact ncast_inj p hchar _ _ (hT z) (hA z) hz
  obtain ⟨s, hs⟩ := this
  exact logupMulti_count a _ s harity hs

/-- **The charged term.** For arity 1 or `>= 3`, the sequential bound is at
most `2 g N` with `g = max(a - 1, 1)`: security.zig `accountLogup` charges
`2 g D / |F|` (`D` = fractions = `N`). -/
theorem logupMulti_charge (a N : Nat) (ha : a = 1 ∨ 3 ≤ a) :
    (N - 1) * (a - 1) + (2 * N - 1) ≤ 2 * (max (a - 1) 1) * N := by
  rcases ha with h | h
  · subst h; simp
  · have hg : max (a - 1) 1 = a - 1 := by omega
    rw [hg]
    generalize hgg : a - 1 = g
    have hg2 : 2 ≤ g := by omega
    cases N with
    | zero => simp
    | succ m =>
      have h1 : 2 * m ≤ g * m := Nat.mul_le_mul_right m hg2
      have e1 : 2 * g * (m + 1) = 2 * (g * m) + 2 * g := by
        rw [Nat.mul_add, Nat.mul_one, Nat.mul_assoc]
      have e2 : (m + 1 - 1) * g = g * m := by rw [Nat.add_sub_cancel, Nat.mul_comm]
      rw [e1, e2]
      omega

/-- Arity 2: the sequential bound `3N - 2` (charged: `2N`). -/
theorem logupMulti_charge_arity2 (N : Nat) : (N - 1) * (2 - 1) + (2 * N - 1) ≤ 3 * N := by
  simp; omega

end TensorFrontend.LogUpMulti
