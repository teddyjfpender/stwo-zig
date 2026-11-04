/-
LogUp soundness (zero-dependency).

The LogUp relation checks, at a random `x`, the fractional-sum identity

    sum_i m_i / (x - t_i)  -  sum_j 1 / (x - a_j)  =  0

(table entries `t_i` with multiplicities `m_i`, looked-up values `a_j`).
We model it as a list `L` of (coefficient, pole) pairs and prove:

* `fsum_group`      : the sum regroups by distinct pole, the coefficient of
                      pole `z` being `coefSum L z`;
* `num_eval_pole`   : for distinct poles, the cleared numerator `num G`
                      (a coefficient list of length <= #poles) evaluated at a
                      pole `z_k` is `c_k * prod_(l != k) (z_k - z_l)`, so it is
                      the zero polynomial iff every coefficient is zero
                      (`num_allZero_iff`): the rational function is zero iff
                      all grouped coefficients are zero;
* `coef_table_witness` + `ncast_inj` : with the characteristic hypothesis
                      (`0 < k < p -> (k : F) != 0`) and every multiplicity sum
                      and count below `p`, a zero coefficient means
                      `sum_(t_i = z) m_i = #{j : a_j = z}` as natural numbers;
* `logup_identity_sound` : identically-zero fractional sum => the looked-up
                      multiset equals the multiplicity-weighted table
                      (in particular every a_j is a table entry);
* `logup_random_sound`   : if the multiset relation fails, at most
                      `2 U - 1` points `x` of `F` (U = number of distinct
                      poles <= |T| + |A|) are poles or make the sum vanish:
                      acceptance probability <= (2U - 1)/|F|.
-/
import TensorFrontend.Sumcheck

namespace TensorFrontend.LogUp

open Lean.Grind TensorFrontend

variable {F : Type} [Field F] [DecidableEq F]

/-! ### Polynomial helpers -/

def padd : List F → List F → List F
  | [], q => q
  | p, [] => p
  | c :: p, d :: q => (c + d) :: padd p q

def scale (c : F) (p : List F) : List F := p.map (c * ·)

/-- Coefficients of `(X - z) * p`. -/
def mulLin (z : F) (p : List F) : List F := padd (0 :: p) (scale (0 - z) p)

theorem padd_eval (p q : List F) (x : F) : eval (padd p q) x = eval p x + eval q x := by
  match p, q with
  | [], q => simp [padd, eval]; grind
  | c :: p, [] => simp [padd, eval]; grind
  | c :: p, d :: q =>
    have := padd_eval p q x
    simp only [padd, eval] at this ⊢; rw [this]; grind

theorem padd_length (p q : List F) : (padd p q).length = max p.length q.length := by
  match p, q with
  | [], q => simp [padd]
  | c :: p, [] => simp [padd]
  | c :: p, d :: q =>
    have := padd_length p q
    simp only [padd, List.length_cons] at this ⊢; omega

theorem scale_eval (c : F) (p : List F) (x : F) : eval (scale c p) x = c * eval p x := by
  induction p with
  | nil => simp [scale, eval]; grind
  | cons d p ih => simp only [scale, List.map_cons, eval] at ih ⊢; rw [ih]; grind

theorem mulLin_eval (z : F) (p : List F) (x : F) : eval (mulLin z p) x = (x - z) * eval p x := by
  simp only [mulLin, padd_eval, scale_eval, eval]; grind

theorem mulLin_length (z : F) (p : List F) : (mulLin z p).length = p.length + 1 := by
  simp only [mulLin, padd_length, scale, List.length_map, List.length_cons]; omega

/-! ### Fractional sums -/

/-- `sum c / (x - z)` over (coefficient, pole) pairs. -/
def fsum : List (F × F) → F → F
  | [], _ => 0
  | (c, z) :: t, x => c * (x - z)⁻¹ + fsum t x

/-- Cleared denominator `prod (X - z)`. -/
def den : List (F × F) → List F
  | [] => [1]
  | (_, z) :: t => mulLin z (den t)

/-- Cleared numerator: `sum_i c_i prod_(l != i) (X - z_l)`. -/
def num : List (F × F) → List F
  | [] => []
  | (c, z) :: t => padd (scale c (den t)) (mulLin z (num t))

def poles (L : List (F × F)) : List F := L.map (·.2)

theorem num_length (L : List (F × F)) : (num L).length ≤ L.length := by
  induction L with
  | nil => simp [num]
  | cons cz t ih =>
    obtain ⟨c, z⟩ := cz
    have hd : (den t).length = t.length + 1 := by
      clear ih
      induction t with
      | nil => rfl
      | cons y t ih2 => obtain ⟨_, w⟩ := y; simp only [den, mulLin_length, List.length_cons, ih2]
    simp only [num, padd_length, scale, List.length_map, mulLin_length, hd, List.length_cons]
    omega

theorem den_eval_pole (L : List (F × F)) (x : F) (h : x ∈ poles L) : eval (den L) x = 0 := by
  induction L with
  | nil => simp [poles] at h
  | cons cz t ih =>
    obtain ⟨c, z⟩ := cz
    simp only [den, mulLin_eval]
    simp only [poles, List.map_cons, List.mem_cons] at h
    rcases h with h | h
    · subst h; grind
    · rw [ih h]; grind

theorem den_eval_ne (L : List (F × F)) (x : F) (h : x ∉ poles L) : eval (den L) x ≠ 0 := by
  induction L with
  | nil => simp [den, eval]; grind
  | cons cz t ih =>
    obtain ⟨c, z⟩ := cz
    simp only [poles, List.map_cons, List.mem_cons, _root_.not_or] at h
    simp only [den, mulLin_eval]
    have h1 := ih h.2
    have h2 : x - z ≠ 0 := fun e => h.1 (by grind)
    grind

/-- Away from the poles, `fsum = num / den`. -/
theorem fsum_eq (L : List (F × F)) (x : F) (h : x ∉ poles L) :
    fsum L x * eval (den L) x = eval (num L) x := by
  induction L with
  | nil => simp [fsum, num, eval]; grind
  | cons cz t ih =>
    obtain ⟨c, z⟩ := cz
    simp only [poles, List.map_cons, List.mem_cons, _root_.not_or] at h
    have h1 := ih h.2
    have h2 : x - z ≠ 0 := fun e => h.1 (by grind)
    simp only [fsum, den, num, mulLin_eval, padd_eval, scale_eval]
    rw [← h1]
    grind

/-- At a pole `z_k` of a duplicate-free pole list, `num` is
`c_k * prod_(l != k) (z_k - z_l)`: zero iff `c_k = 0`. -/
theorem num_eval_pole (L : List (F × F)) (hnd : (poles L).Nodup) (c z : F) (hm : (c, z) ∈ L) :
    eval (num L) z = 0 ↔ c = 0 := by
  induction L with
  | nil => cases hm
  | cons cz t ih =>
    obtain ⟨c0, z0⟩ := cz
    simp only [poles, List.map_cons, List.nodup_cons] at hnd
    simp only [num, padd_eval, scale_eval, mulLin_eval]
    rcases List.mem_cons.mp hm with h | h
    · cases h
      have hz : z ∉ poles t := hnd.1
      have := den_eval_ne t z hz
      constructor
      · intro e; grind
      · intro e; rw [e]; grind
    · have hzt : z ∈ poles t := List.mem_map.mpr ⟨(c, z), h, rfl⟩
      have hd := den_eval_pole t z hzt
      have hne : z ≠ z0 := fun e => hnd.1 (e ▸ hzt)
      have hne' : z - z0 ≠ 0 := fun e => hne (by grind)
      rw [hd]
      have := ih hnd.2 h
      constructor
      · intro e; apply this.mp; grind
      · intro e; rw [this.mpr e]; grind

theorem num_allZero_iff (L : List (F × F)) (hnd : (poles L).Nodup) :
    AllZero (num L) ↔ ∀ cz ∈ L, cz.1 = 0 := by
  constructor
  · intro hz cz hm
    exact (num_eval_pole L hnd cz.1 cz.2 hm).mp (eval_allZero _ hz _)
  · intro hc
    induction L with
    | nil => intro x hx; cases hx
    | cons cz t ih =>
      obtain ⟨c, z⟩ := cz
      simp only [poles, List.map_cons, List.nodup_cons] at hnd
      have h0 : c = 0 := hc (c, z) (List.mem_cons_self ..)
      have iht := ih hnd.2 (fun y hy => hc y (List.mem_cons_of_mem _ hy))
      intro x hx
      simp only [num] at hx
      -- padd of an all-zero scale and an all-zero mulLin is all zero
      have hs : AllZero (scale c (den t)) := by
        intro y hy; simp only [scale, List.mem_map] at hy
        obtain ⟨w, _, hw⟩ := hy; rw [← hw, h0]; grind
      have hmz : AllZero (mulLin z (num t)) := by
        intro y hy
        simp only [mulLin] at hy
        have hz0 : AllZero (0 :: num t) := by
          intro u hu; rcases List.mem_cons.mp hu with hu | hu
          · exact hu
          · exact iht u hu
        have hz1 : AllZero (scale (0 - z) (num t)) := by
          intro u hu; simp only [scale, List.mem_map] at hu
          obtain ⟨w, hw1, hw⟩ := hu; rw [← hw, iht w hw1]; grind
        exact padd_allZero _ _ hz0 hz1 y hy
      exact padd_allZero _ _ hs hmz x hx
where
  padd_allZero (p q : List F) (hp : AllZero p) (hq : AllZero q) : AllZero (padd p q) := by
    match p, q with
    | [], q => simpa [padd] using hq
    | c :: p, [] => simpa [padd] using hp
    | c :: p, d :: q =>
      intro y hy
      simp only [padd] at hy
      rcases List.mem_cons.mp hy with h | h
      · rw [h, hp c (List.mem_cons_self ..), hq d (List.mem_cons_self ..)]; grind
      · exact padd_allZero p q (fun u hu => hp u (List.mem_cons_of_mem _ hu))
          (fun u hu => hq u (List.mem_cons_of_mem _ hu)) y h

/-! ### Grouping by pole -/

/-- Sum of the coefficients of pole `z`. -/
def coefSum : List (F × F) → F → F
  | [], _ => 0
  | (c, w) :: t, z => (if w = z then c else 0) + coefSum t z

/-- Duplicate-free list of the distinct poles. -/
def dd : List F → List F
  | [] => []
  | x :: t => if x ∈ dd t then dd t else x :: dd t

theorem mem_dd (l : List F) (x : F) : x ∈ dd l ↔ x ∈ l := by
  induction l with
  | nil => simp [dd]
  | cons y t ih =>
    simp only [dd]
    split
    · rw [ih]; simp only [List.mem_cons]; constructor
      · exact Or.inr
      · rintro (h | h)
        · subst h; rwa [← ih]
        · exact h
    · simp only [List.mem_cons, ih]

theorem nodup_dd (l : List F) : (dd l).Nodup := by
  induction l with
  | nil => simp [dd]
  | cons y t ih =>
    simp only [dd]; split
    · exact ih
    · exact List.nodup_cons.mpr ⟨by assumption, ih⟩

/-- Grouped form: one pair per distinct pole. -/
def group (L : List (F × F)) : List (F × F) := (dd (poles L)).map (fun z => (coefSum L z, z))

theorem poles_group (L : List (F × F)) : poles (group L) = dd (poles L) := by
  simp only [group, poles, List.map_map]; exact List.map_id' _

omit [DecidableEq F] in
theorem fsum_indicator_zero [DecidableEq F] (U : List F) (c z x : F) (hz : z ∉ U) :
    fsum (U.map (fun w => (if z = w then c else 0, w))) x = 0 := by
  induction U with
  | nil => rfl
  | cons v U ih =>
    simp only [List.map_cons, fsum]
    have hzv : z ≠ v := fun e => hz (e ▸ List.mem_cons_self ..)
    rw [if_neg hzv, ih (fun e => hz (List.mem_cons_of_mem _ e))]
    grind

/-- sum over a nodup list of an indicator. -/
theorem fsum_indicator (U : List F) (hU : U.Nodup) (c z x : F) (hz : z ∈ U) :
    fsum (U.map (fun w => (if z = w then c else 0, w))) x = c * (x - z)⁻¹ := by
  induction U with
  | nil => cases hz
  | cons w U ih =>
    simp only [List.map_cons, fsum]
    rw [List.nodup_cons] at hU
    by_cases h : z = w
    · subst h
      have : fsum (U.map (fun w => (if z = w then c else 0, w))) x = 0 :=
        fsum_indicator_zero U c z x hU.1
      rw [this, if_pos rfl]; grind
    · rw [if_neg h]
      rcases List.mem_cons.mp hz with e | e
      · exact absurd e h
      · rw [ih hU.2 e]; grind

theorem fsum_map_add (U : List F) (f g : F → F) (x : F) :
    fsum (U.map (fun w => (f w + g w, w))) x =
      fsum (U.map (fun w => (f w, w))) x + fsum (U.map (fun w => (g w, w))) x := by
  induction U with
  | nil => simp [fsum]; grind
  | cons w U ih => simp only [List.map_cons, fsum]; rw [ih]; grind

/-- **Regrouping.** For any duplicate-free `U` containing the poles of `L`. -/
theorem fsum_regroup (L : List (F × F)) (U : List F) (hU : U.Nodup)
    (hsub : ∀ z ∈ poles L, z ∈ U) (x : F) :
    fsum L x = fsum (U.map (fun z => (coefSum L z, z))) x := by
  induction L with
  | nil =>
    simp only [fsum, coefSum]
    clear hsub hU
    induction U with
    | nil => rfl
    | cons w U ih => simp only [List.map_cons, fsum]; rw [← ih]; grind
  | cons cz t ih =>
    obtain ⟨c, z⟩ := cz
    have hz : z ∈ U := hsub z (List.mem_cons_self ..)
    have ht := ih (fun w hw => hsub w (List.mem_cons_of_mem _ hw))
    simp only [fsum, coefSum]
    rw [fsum_map_add U (fun w => if z = w then c else 0) (fun w => coefSum t w), fsum_indicator U hU c z x hz, ht]

theorem fsum_group (L : List (F × F)) (x : F) : fsum L x = fsum (group L) x :=
  fsum_regroup L _ (nodup_dd _) (fun z hz => (mem_dd _ z).mpr hz) x

/-! ### Characteristic and multiplicities -/

/-- `k : F`, without a `NatCast` instance. -/
def ncast : Nat → F
  | 0 => 0
  | k + 1 => ncast k + 1

theorem ncast_add (m n : Nat) : (ncast (m + n) : F) = ncast m + ncast n := by
  induction n with
  | zero => simp [ncast]; grind
  | succ n ih => rw [← Nat.add_assoc]; simp only [ncast]; rw [ih]; grind

/-- With the characteristic hypothesis, `ncast` is injective below `p`. -/
theorem ncast_inj (p : Nat) (hchar : ∀ k, 0 < k → k < p → (ncast k : F) ≠ 0)
    (m n : Nat) (hm : m < p) (hn : n < p) (h : (ncast m : F) - ncast n = 0) : m = n := by
  rcases Nat.lt_trichotomy m n with hl | he | hg
  · have := hchar (n - m) (by omega) (by omega)
    have e := ncast_add (F := F) m (n - m)
    rw [Nat.add_sub_cancel' (Nat.le_of_lt hl)] at e
    exact absurd (by grind) this
  · exact he
  · have := hchar (m - n) (by omega) (by omega)
    have e := ncast_add (F := F) n (m - n)
    rw [Nat.add_sub_cancel' (Nat.le_of_lt hg)] at e
    exact absurd (by grind) this

/-- The LogUp pair list: table entries with multiplicity, then `-1` per
looked-up value. -/
def pairs (T : List (F × Nat)) (A : List F) : List (F × F) :=
  T.map (fun tm => (ncast tm.2, tm.1)) ++ A.map (fun a => (0 - 1, a))

/-- Multiplicity-weighted table count of `z`. -/
def tcount : List (F × Nat) → F → Nat
  | [], _ => 0
  | (t, m) :: T, z => (if t = z then m else 0) + tcount T z

/-- Occurrences of `z` among the looked-up values. -/
def acount : List F → F → Nat
  | [], _ => 0
  | a :: A, z => (if a = z then 1 else 0) + acount A z

theorem coefSum_append (L M : List (F × F)) (z : F) :
    coefSum (L ++ M) z = coefSum L z + coefSum M z := by
  induction L with
  | nil => simp [coefSum]; grind
  | cons cz t ih => obtain ⟨c, w⟩ := cz; simp only [List.cons_append, coefSum]; rw [ih]; grind

theorem coef_table_witness (T : List (F × Nat)) (A : List F) (z : F) :
    coefSum (pairs T A) z = ncast (tcount T z) - ncast (acount A z) := by
  unfold pairs
  rw [coefSum_append]
  have h1 : coefSum (T.map (fun tm => (ncast tm.2, tm.1))) z = (ncast (tcount T z) : F) := by
    induction T with
    | nil => simp [coefSum, tcount, ncast]
    | cons tm T ih =>
      obtain ⟨t, m⟩ := tm
      simp only [List.map_cons, coefSum, tcount]
      rw [ih, ncast_add]
      by_cases h : t = z
      · simp only [h, ite_true]
      · simp only [h, ite_false, ncast]; try grind
  have h2 : coefSum (A.map (fun a => ((0 : F) - 1, a))) z = 0 - (ncast (acount A z) : F) := by
    induction A with
    | nil => simp [coefSum, acount, ncast]; grind
    | cons a A ih =>
      simp only [List.map_cons, coefSum, acount]
      rw [ih, ncast_add]
      by_cases h : a = z
      · simp only [h, ite_true, ncast]; grind
      · simp only [h, ite_false, ncast]; grind
  rw [h1, h2]; grind

theorem tcount_zero (T : List (F × Nat)) (z : F) (h : ∀ tm ∈ T, tm.1 ≠ z) : tcount T z = 0 := by
  induction T with
  | nil => rfl
  | cons tm T ih =>
    obtain ⟨t, m⟩ := tm
    simp only [tcount, if_neg (h (t, m) (List.mem_cons_self ..)), Nat.zero_add]
    exact ih (fun y hy => h y (List.mem_cons_of_mem _ hy))

theorem acount_zero (A : List F) (z : F) (h : ∀ a ∈ A, a ≠ z) : acount A z = 0 := by
  induction A with
  | nil => rfl
  | cons a A ih =>
    simp only [acount, if_neg (h a (List.mem_cons_self ..)), Nat.zero_add]
    exact ih (fun y hy => h y (List.mem_cons_of_mem _ hy))

/-- The multiset relation LogUp is meant to prove: every value's
looked-up count equals its multiplicity-weighted table count. -/
def MultisetOK (T : List (F × Nat)) (A : List F) : Prop :=
  ∀ z, tcount T z = acount A z

/-- **LogUp, identity form.** If the fractional sum is the zero rational
function (its grouped cleared numerator is the zero polynomial) and all
counts are below the characteristic, the multiset relation holds; in
particular every looked-up value is a table entry. -/
theorem logup_identity_sound (p : Nat) (hchar : ∀ k, 0 < k → k < p → (ncast k : F) ≠ 0)
    (T : List (F × Nat)) (A : List F) (hT : ∀ z, tcount T z < p) (hA : ∀ z, acount A z < p)
    (hzero : AllZero (num (group (pairs T A)))) : MultisetOK T A := by
  intro z
  have hnd : (poles (group (pairs T A))).Nodup := by rw [poles_group]; exact nodup_dd _
  have hc := (num_allZero_iff _ hnd).mp hzero
  by_cases hz : z ∈ poles (pairs T A)
  · have hm : (coefSum (pairs T A) z, z) ∈ group (pairs T A) :=
      List.mem_map.mpr ⟨z, (mem_dd _ z).mpr hz, rfl⟩
    have := hc _ hm
    simp only at this
    rw [coef_table_witness] at this
    exact ncast_inj p hchar _ _ (hT z) (hA z) this
  · -- z is not a pole: it is neither a table entry nor looked up
    have ht : tcount T z = 0 := tcount_zero T z (fun tm htm e => hz (by
        simp only [pairs, poles, List.map_append, List.map_map, List.mem_append, List.mem_map]
        exact Or.inl ⟨tm, htm, e⟩))
    have ha : acount A z = 0 := acount_zero A z (fun a ha e => hz (by
        simp only [pairs, poles, List.map_append, List.map_map, List.mem_append, List.mem_map]
        exact Or.inr ⟨a, ha, e⟩))
    rw [ht, ha]

/-- Every looked-up value is in the table (for nonzero... any) once the
multiset relation holds. -/
theorem multisetOK_mem (T : List (F × Nat)) (A : List F) (h : MultisetOK T A) (a : F) (ha : a ∈ A) :
    ∃ m, (a, m) ∈ T ∧ 0 < m := by
  have hpos : 0 < acount A a := by
    clear h
    induction A with
    | nil => cases ha
    | cons b A ih =>
      simp only [acount]
      by_cases e : b = a
      · simp only [e, ite_true]; omega
      · rcases List.mem_cons.mp ha with h | h
        · exact absurd h.symm e
        · have := ih h; omega
  rw [← h a] at hpos
  clear h ha
  induction T with
  | nil => simp [tcount] at hpos
  | cons tm T ih =>
    obtain ⟨t, m⟩ := tm
    simp only [tcount] at hpos
    by_cases e : t = a
    · subst e
      by_cases hm : 0 < m
      · exact ⟨m, List.mem_cons_self .., hm⟩
      · simp only [ite_true] at hpos
        obtain ⟨m', h1, h2⟩ := ih (by omega)
        exact ⟨m', List.mem_cons_of_mem _ h1, h2⟩
    · simp only [if_neg e, Nat.zero_add] at hpos
      obtain ⟨m', h1, h2⟩ := ih hpos
      exact ⟨m', List.mem_cons_of_mem _ h1, h2⟩

/-! ### Random evaluation -/

variable [FinEnum F]

omit [Field F] in
theorem countP_or_le {α : Type} (l : List α) (p q : α → Bool) :
    l.countP (fun x => p x || q x) ≤ l.countP p + l.countP q := by
  induction l with
  | nil => simp
  | cons y l ih =>
    simp only [List.countP_cons]
    cases p y <;> cases q y <;> simp <;> omega

omit [Field F] in
theorem countP_eq_le_one (l : List F) (hnd : l.Nodup) (u : F) :
    l.countP (fun x => decide (x = u)) ≤ 1 := by
  induction l with
  | nil => simp
  | cons y l ih =>
    rw [List.nodup_cons] at hnd
    rw [List.countP_cons]
    by_cases a : y = u
    · subst a
      have : l.countP (fun x => decide (x = y)) = 0 :=
        List.countP_eq_zero.mpr (fun x hx e => hnd.1 (by
          have := _root_.of_decide_eq_true e; exact this ▸ hx))
      rw [this]; simp
    · have := ih hnd.2
      simp only [a, decide_false]; simpa using this

omit [Field F] in
theorem countP_mem_le (U : List F) :
    (FinEnum.elems (F := F)).countP (fun x => decide (x ∈ U)) ≤ U.length := by
  induction U with
  | nil => simp
  | cons u U ih =>
    have heq : (fun x => decide (x ∈ u :: U)) = (fun x => decide (x = u) || decide (x ∈ U)) := by
      funext x; simp
    rw [heq]
    have h1 := countP_or_le (FinEnum.elems (F := F)) (fun x => decide (x = u)) (fun x => decide (x ∈ U))
    have h2 := countP_eq_le_one _ FinEnum.nodup u
    simp only [List.length_cons]; omega

/-- **LogUp, random-evaluation form.** If the multiset relation fails (with
all counts below the characteristic), then among all `x ∈ F` at most
`2 U - 1` are poles or make the fractional sum vanish, where `U` is the
number of distinct poles (`<= |T| + |A|`). -/
theorem logup_random_sound (p : Nat) (hchar : ∀ k, 0 < k → k < p → (ncast k : F) ≠ 0)
    (T : List (F × Nat)) (A : List F) (hT : ∀ z, tcount T z < p) (hA : ∀ z, acount A z < p)
    (hbad : ¬ MultisetOK T A) :
    (FinEnum.elems (F := F)).countP
        (fun x => decide (x ∈ poles (pairs T A)) || decide (fsum (pairs T A) x = 0))
      ≤ 2 * (dd (poles (pairs T A))).length - 1 := by
  let G := group (pairs T A)
  have hnd : (poles G).Nodup := by rw [poles_group]; exact nodup_dd _
  have hnz : ¬ AllZero (num G) := fun hz => hbad (logup_identity_sound p hchar T A hT hA hz)
  have hU : (dd (poles (pairs T A))).length = G.length := by simp [G, group]
  -- the zero set of num G
  have hroots := roots_le (num G) hnz
    ((FinEnum.elems (F := F)).filter (fun x => decide (eval (num G) x = 0)))
    (List.Nodup.sublist List.filter_sublist FinEnum.nodup)
    (fun x hx => of_decide_eq_true (List.mem_filter.mp hx).2)
  have hlen := num_length G
  rw [← List.countP_eq_length_filter] at hroots
  -- split the count
  have hsplit : ∀ l : List F,
      l.countP (fun x => decide (x ∈ poles (pairs T A)) || decide (fsum (pairs T A) x = 0)) ≤
        l.countP (fun x => decide (x ∈ dd (poles (pairs T A)))) +
          l.countP (fun x => decide (eval (num G) x = 0)) := by
    intro l
    induction l with
    | nil => simp
    | cons y l ih =>
      simp only [List.countP_cons]
      by_cases hp : y ∈ poles (pairs T A)
      · have : y ∈ dd (poles (pairs T A)) := (mem_dd _ _).mpr hp
        simp [hp, this]; omega
      · have hp' : y ∉ dd (poles (pairs T A)) := fun e => hp ((mem_dd _ _).mp e)
        have hpG : y ∉ poles G := by rw [poles_group]; exact hp'
        by_cases hf : fsum (pairs T A) y = 0
        · have : eval (num G) y = 0 := by
            rw [← fsum_eq G y hpG, ← fsum_group, hf]; grind
          simp [hp, hp', hf, this]; omega
        · simp [hp, hp', hf]; omega
  have h1 := hsplit FinEnum.elems
  have h2 := countP_mem_le (F := F) (dd (poles (pairs T A)))
  have hpos : 0 < G.length := by
    cases hG : G with
    | nil => exact absurd (by rw [hG]; simp [num]; intro x hx; cases hx) hnz
    | cons _ _ => simp
  omega

end TensorFrontend.LogUp
