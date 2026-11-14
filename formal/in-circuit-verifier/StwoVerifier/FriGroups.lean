/-
**`compute_fri_input`'s grouping loop** (`oods.zig` `computeFriInput`,
phase 1, stwo-zig `4afa09dbf`).

The emitter walks the responses once with a single global power chain
(`α'ᵢ = −2u·αⁱ`), keying `OodsPointAuxiliary` groups by the point's
`(x, y)` wire pair: on first sight it inits the group's line
coefficients, then accumulates `c = d·α'`, `a += α'·im V`, `v += α'·V`
into that group. Different groups' steps interleave in response order,
so the walk is stateful; `GInv` is the preserved invariant — per group,
the register facts of **its** fiber of the indexed response prefix,
exactly the `Bound` shape over the filtered positions that
`zip_partition_perm` groups by.
-/
import StwoVerifier.DeepRowSpec
import StwoVerifier.ResponseOrder

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-- One response's registers: the point wires (the group key) and the
value wire. -/
structure RespReg where
  px : ℕ
  py : ℕ
  value : ℕ
  deriving Repr, DecidableEq

instance : Inhabited RespReg := ⟨⟨0, 0, 0⟩⟩

def respKey (r : RespReg) : ℕ × ℕ := (r.px, r.py)

/-- One group's partial registers during the walk. -/
structure PG where
  d : ℕ
  e : ℕ
  f : ℕ
  coeffs : List ℕ
  aReg : ℕ
  vReg : ℕ
  deriving Repr

/-- `AutoArrayHashMap.getOrPut`'s lookup. -/
def findG : List ((ℕ × ℕ) × PG) → (ℕ × ℕ) → Option PG
  | [], _ => none
  | (k', g) :: rest, k => if k' = k then some g else findG rest k

def updateG : List ((ℕ × ℕ) × PG) → (ℕ × ℕ) → PG → List ((ℕ × ℕ) × PG)
  | [], k, g => [(k, g)]
  | (k', g') :: rest, k, g =>
    if k' = k then (k, g) :: rest else (k', g') :: updateG rest k g

theorem findG_none_iff : ∀ (l : List ((ℕ × ℕ) × PG)) (k : ℕ × ℕ),
    findG l k = none ↔ k ∉ l.map Prod.fst
  | [], _ => by simp [findG]
  | (k', g) :: rest, k => by
    by_cases h : k' = k
    · simp [findG, h]
    · rw [show findG ((k', g) :: rest) k = findG rest k from by
        simp [findG, h], findG_none_iff rest k]
      simp [Ne.symm h]

theorem findG_some_mem : ∀ {l : List ((ℕ × ℕ) × PG)} {k : ℕ × ℕ} {g : PG},
    findG l k = some g → (k, g) ∈ l
  | [], _, _, h => by simp [findG] at h
  | (k', g') :: rest, k, g, h => by
    by_cases he : k' = k
    · subst he
      rw [show findG ((k', g') :: rest) k' = some g' from by simp [findG]] at h
      exact (Option.some.inj h) ▸ List.mem_cons_self
    · rw [show findG ((k', g') :: rest) k = findG rest k from by
        simp [findG, he]] at h
      exact List.mem_cons_of_mem _ (findG_some_mem h)

theorem updateG_map_fst : ∀ (l : List ((ℕ × ℕ) × PG)) (k : ℕ × ℕ) (g : PG),
    k ∈ l.map Prod.fst → (updateG l k g).map Prod.fst = l.map Prod.fst
  | [], k, g, h => by simp at h
  | (k', g') :: rest, k, g, h => by
    by_cases he : k' = k
    · simp [updateG, he]
    · rw [show updateG ((k', g') :: rest) k g
        = (k', g') :: updateG rest k g from by simp [updateG, he]]
      rw [List.map_cons] at h
      have hm : k ∈ rest.map Prod.fst := by
        rcases List.mem_cons.mp h with h1 | h1
        · exact absurd h1.symm he
        · exact h1
      simp [updateG_map_fst rest k g hm]

theorem mem_updateG : ∀ {l : List ((ℕ × ℕ) × PG)} {k : ℕ × ℕ} {g : PG}
    {pr : (ℕ × ℕ) × PG}, (l.map Prod.fst).Nodup → pr ∈ updateG l k g →
    pr = (k, g) ∨ (pr ∈ l ∧ pr.1 ≠ k)
  | [], k, g, pr, _, h => by
    rw [show updateG [] k g = [(k, g)] from rfl] at h
    exact Or.inl (List.mem_singleton.mp h)
  | (k', g') :: rest, k, g, pr, hnd, h => by
    by_cases he : k' = k
    · subst he
      rw [show updateG ((k', g') :: rest) k' g = (k', g) :: rest from by
        simp [updateG]] at h
      rcases List.mem_cons.mp h with h1 | h1
      · exact Or.inl h1
      · refine Or.inr ⟨List.mem_cons_of_mem _ h1, ?_⟩
        intro hk
        rw [List.map_cons] at hnd
        exact ((List.nodup_cons.mp hnd).1)
          (List.mem_map.mpr ⟨pr, h1, hk⟩)
    · rw [show updateG ((k', g') :: rest) k g
        = (k', g') :: updateG rest k g from by simp [updateG, he]] at h
      rcases List.mem_cons.mp h with h1 | h1
      · exact Or.inr ⟨h1 ▸ List.mem_cons_self, by rw [h1]; exact he⟩
      · rw [List.map_cons] at hnd
        rcases mem_updateG (List.nodup_cons.mp hnd).2 h1
          with h2 | h2
        · exact Or.inl h2
        · exact Or.inr ⟨List.mem_cons_of_mem _ h2.1, h2.2⟩

theorem updateG_mem_self : ∀ (l : List ((ℕ × ℕ) × PG)) (k : ℕ × ℕ) (g : PG),
    (k, g) ∈ updateG l k g
  | [], k, g => List.mem_singleton.mpr rfl
  | (k', g') :: rest, k, g => by
    by_cases he : k' = k
    · rw [show updateG ((k', g') :: rest) k g = (k, g) :: rest from by
        simp [updateG, he]]
      exact List.mem_cons_self
    · rw [show updateG ((k', g') :: rest) k g
        = (k', g') :: updateG rest k g from by simp [updateG, he]]
      exact List.mem_cons_of_mem _ (updateG_mem_self rest k g)

/-! ### The walk -/

/-- One response (`computeFriInput`'s loop body after the power
advance): init the group on first sight, then accumulate. -/
def friStep (imMask zero : ℕ) (groups : List ((ℕ × ℕ) × PG)) (r : RespReg)
    (apReg n : ℕ) : Out (List ((ℕ × ℕ) × PG)) :=
  match findG groups (respKey r) with
  | none =>
    let ini := auxInit imMask r.px r.py n
    let acc := auxAccum imMask ini.res.1 apReg r.value zero zero ini.next
    ⟨ini.ops ++ acc.ops,
     groups ++ [(respKey r,
       ⟨ini.res.1, ini.res.2.1, ini.res.2.2, [acc.res.1],
        acc.res.2.1, acc.res.2.2⟩)], acc.next⟩
  | some g =>
    let acc := auxAccum imMask g.d apReg r.value g.aReg g.vReg n
    ⟨acc.ops,
     updateG groups (respKey r)
       ⟨g.d, g.e, g.f, g.coeffs ++ [acc.res.1], acc.res.2.1, acc.res.2.2⟩,
     acc.next⟩

/-- The walk over the remaining responses: advance the global power,
then step. -/
def friWalk (imMask zero alpha : ℕ) :
    List RespReg → List ((ℕ × ℕ) × PG) → ℕ → ℕ →
    Out (List ((ℕ × ℕ) × PG) × ℕ × List ℕ)
  | [], groups, apReg, n => ⟨[], (groups, apReg, []), n⟩
  | r :: rest, groups, apReg, n =>
    let st := friStep imMask zero groups r n (n + 1)
    let tail := friWalk imMask zero alpha rest st.res n st.next
    ⟨.mul n apReg alpha :: (st.ops ++ tail.ops),
     (tail.res.1, tail.res.2.1, n :: tail.res.2.2), tail.next⟩

/-- The whole grouping loop: the interned `−2u` start power, the first
response at `α⁰`, the rest advancing. -/
noncomputable def friGroups (imMask zero alpha : ℕ) (rs : List RespReg) (n : ℕ) :
    Out (List ((ℕ × ℕ) × PG) × ℕ × List ℕ) :=
  match rs with
  | [] => ⟨[.const n ((-2 : QM31) * Deep.uu)], ([], n, []), n + 1⟩
  | r :: rest =>
    let st := friStep imMask zero [] r n (n + 1)
    let walk := friWalk imMask zero alpha rest st.res n st.next
    ⟨.const n ((-2 : QM31) * Deep.uu) :: (st.ops ++ walk.ops),
     (walk.res.1, walk.res.2.1, n :: walk.res.2.2), walk.next⟩

/-! ### The invariant -/

/-- One group's register facts over its fiber of the indexed responses:
the line coefficients of its point wires, and the coefficient, `a` and
`v` registers carrying the `α'`-weighted sums at the fiber's global
indices. -/
structure GFacts (ρ : ℕ → QM31) (α : QM31) (k : ℕ × ℕ) (g : PG)
    (fiber : List (RespReg × ℕ)) : Prop where
  hd : ρ g.d = Deep.imQ (ρ k.2)
  he : ρ g.e = Deep.imQ (ρ k.1)
  hf : ρ g.f = Deep.imQ (ρ k.2) * ρ k.1 - Deep.imQ (ρ k.1) * ρ k.2
  hclen : g.coeffs.length = fiber.length
  hcoeff : ∀ j, j < fiber.length →
    ρ (g.coeffs.getD j 0)
      = ρ g.d * ((-2 : QM31) * Deep.uu * α ^ (fiber.getD j default).2)
  ha : ρ g.aReg = (fiber.map fun p =>
    ((-2 : QM31) * Deep.uu * α ^ p.2) * Deep.imQ (ρ p.1.value)).sum
  hv : ρ g.vReg = (fiber.map fun p =>
    ((-2 : QM31) * Deep.uu * α ^ p.2) * ρ p.1.value).sum

/-- The walk's invariant: distinct keys, every processed response has
its group, and each group's facts hold over its fiber. -/
structure GInv (ρ : ℕ → QM31) (α : QM31) (groups : List ((ℕ × ℕ) × PG))
    (processed : List (RespReg × ℕ)) : Prop where
  nodup : (groups.map Prod.fst).Nodup
  cover : ∀ p ∈ processed, respKey p.1 ∈ groups.map Prod.fst
  facts : ∀ pr ∈ groups, GFacts ρ α pr.1 pr.2
    (processed.filter fun p => respKey p.1 = pr.1)
  fiber_ne : ∀ pr ∈ groups,
    (processed.filter fun p => respKey p.1 = pr.1) ≠ []

/-- Appending a response of a *different* key leaves a fiber alone. -/
private theorem filter_append_other {processed : List (RespReg × ℕ)}
    {r : RespReg} {i : ℕ} {k : ℕ × ℕ} (hne : respKey r ≠ k) :
    ((processed ++ [(r, i)]).filter fun p => respKey p.1 = k)
      = processed.filter fun p => respKey p.1 = k := by
  rw [List.filter_append]
  simp [hne]

/-- Appending a response of the *same* key extends its fiber. -/
private theorem filter_append_same {processed : List (RespReg × ℕ)}
    {r : RespReg} {i : ℕ} {k : ℕ × ℕ} (heq : respKey r = k) :
    ((processed ++ [(r, i)]).filter fun p => respKey p.1 = k)
      = (processed.filter fun p => respKey p.1 = k) ++ [(r, i)] := by
  rw [List.filter_append]
  simp [heq]

private theorem getD_concat_lt {l : List ℕ} {a : ℕ} {j : ℕ} (h : j < l.length) :
    (l ++ [a]).getD j 0 = l.getD j 0 := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_append_left h,
    List.getD_eq_getElem?_getD]

private theorem getD_concat_len {l : List ℕ} {a : ℕ} :
    (l ++ [a]).getD l.length 0 = a := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_concat_length]
  rfl

private theorem getD_concat_lt' {l : List (RespReg × ℕ)} {a : RespReg × ℕ}
    {j : ℕ} (h : j < l.length) : (l ++ [a]).getD j default = l.getD j default := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_append_left h,
    List.getD_eq_getElem?_getD]

private theorem getD_concat_len' {l : List (RespReg × ℕ)} {a : RespReg × ℕ} :
    (l ++ [a]).getD l.length default = a := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_concat_length]
  rfl

/-- **One step preserves the invariant**, the new response indexed at
the current power. -/
theorem friStep_sound {ρ : ℕ → QM31} {α : QM31} {imMask zero : ℕ}
    {groups : List ((ℕ × ℕ) × PG)} {processed : List (RespReg × ℕ)}
    {r : RespReg} {apReg n i : ℕ}
    (hmask : ρ imMask = QM31.fromM31s 0 0 1 1) (hzero : ρ zero = 0)
    (hinv : GInv ρ α groups processed)
    (hap : ρ apReg = (-2 : QM31) * Deep.uu * α ^ i)
    (h : AllHold ρ (friStep imMask zero groups r apReg n).ops) :
    GInv ρ α (friStep imMask zero groups r apReg n).res
      (processed ++ [(r, i)]) := by
  match hfind : findG groups (respKey r) with
  | none =>
    have hnotin := (findG_none_iff groups (respKey r)).mp hfind
    have heq : friStep imMask zero groups r apReg n
      = ⟨(auxInit imMask r.px r.py n).ops ++
          (auxAccum imMask (auxInit imMask r.px r.py n).res.1 apReg r.value
            zero zero (auxInit imMask r.px r.py n).next).ops,
        groups ++ [(respKey r,
          ⟨(auxInit imMask r.px r.py n).res.1,
           (auxInit imMask r.px r.py n).res.2.1,
           (auxInit imMask r.px r.py n).res.2.2,
           [(auxAccum imMask (auxInit imMask r.px r.py n).res.1 apReg r.value
              zero zero (auxInit imMask r.px r.py n).next).res.1],
           (auxAccum imMask (auxInit imMask r.px r.py n).res.1 apReg r.value
              zero zero (auxInit imMask r.px r.py n).next).res.2.1,
           (auxAccum imMask (auxInit imMask r.px r.py n).res.1 apReg r.value
              zero zero (auxInit imMask r.px r.py n).next).res.2.2⟩)],
        (auxAccum imMask (auxInit imMask r.px r.py n).res.1 apReg r.value
          zero zero (auxInit imMask r.px r.py n).next).next⟩ := by
      unfold friStep
      rw [hfind]
    rw [heq] at h ⊢
    rw [allHold_append] at h
    obtain ⟨hini, hacc⟩ := h
    obtain ⟨hid, hie, hif⟩ := auxInit_sound hmask hini
    obtain ⟨hc, ha, hv⟩ := auxAccum_sound hmask hacc
    -- No processed response carries the new key.
    have hfib : ∀ k : ℕ × ℕ, k = respKey r →
        (processed.filter fun p => respKey p.1 = k) = [] := by
      intro k hk
      rw [List.filter_eq_nil_iff]
      intro p hp hpk
      have hpk' : respKey p.1 = k := by simpa using hpk
      refine hnotin ?_
      rw [← hk, ← hpk']
      exact hinv.cover p hp
    refine ⟨?_, ?_, ?_, ?_⟩
    · rw [List.map_append]
      refine List.Nodup.append hinv.nodup (by simp) ?_
      intro k hk hk2
      simp only [List.map_cons, List.map_nil, List.mem_singleton] at hk2
      exact hnotin (hk2 ▸ hk)
    · intro p hp
      rcases List.mem_append.mp hp with h1 | h1
      · rw [List.map_append]
        exact List.mem_append_left _ (hinv.cover p h1)
      · rw [List.mem_singleton.mp h1, List.map_append]
        exact List.mem_append_right _ (by simp)
    · intro pr hpr
      rcases List.mem_append.mp hpr with h1 | h1
      · have hne : respKey r ≠ pr.1 := by
          intro hk
          exact hnotin (hk ▸ List.mem_map_of_mem h1)
        have hold := hinv.facts pr h1
        rw [filter_append_other hne]
        exact hold
      · rw [List.mem_singleton.mp h1]
        rw [filter_append_same rfl, hfib _ rfl, List.nil_append]
        dsimp only
        refine ⟨hid, hie, hif, rfl, ?_, ?_, ?_⟩
        · intro j hj
          have hj0 : j = 0 := by
            rw [List.length_cons, List.length_nil] at hj
            omega
          subst hj0
          show ρ (auxAccum _ _ _ _ _ _ _).res.1 = _
          rw [hc, hap]
          rfl
        · rw [ha, hzero, hap]
          simp
        · rw [hv, hzero, hap]
          simp
    · intro pr hpr
      rcases List.mem_append.mp hpr with h1 | h1
      · have hne : respKey r ≠ pr.1 := by
          intro hk
          exact hnotin (hk ▸ List.mem_map_of_mem h1)
        rw [filter_append_other hne]
        exact hinv.fiber_ne pr h1
      · rw [List.mem_singleton.mp h1, filter_append_same rfl]
        simp
  | some g =>
    have hgm := findG_some_mem hfind
    have heq : friStep imMask zero groups r apReg n
      = ⟨(auxAccum imMask g.d apReg r.value g.aReg g.vReg n).ops,
        updateG groups (respKey r)
          ⟨g.d, g.e, g.f,
           g.coeffs ++ [(auxAccum imMask g.d apReg r.value g.aReg g.vReg n).res.1],
           (auxAccum imMask g.d apReg r.value g.aReg g.vReg n).res.2.1,
           (auxAccum imMask g.d apReg r.value g.aReg g.vReg n).res.2.2⟩,
        (auxAccum imMask g.d apReg r.value g.aReg g.vReg n).next⟩ := by
      unfold friStep
      rw [hfind]
    rw [heq] at h ⊢
    obtain ⟨hc, ha, hv⟩ := auxAccum_sound hmask h
    have hgf := hinv.facts _ hgm
    have hkin : respKey r ∈ groups.map Prod.fst := List.mem_map_of_mem hgm
    refine ⟨?_, ?_, ?_, ?_⟩
    · rw [updateG_map_fst groups _ _ hkin]
      exact hinv.nodup
    · intro p hp
      rw [updateG_map_fst groups _ _ hkin]
      rcases List.mem_append.mp hp with h1 | h1
      · exact hinv.cover p h1
      · rw [List.mem_singleton.mp h1]
        exact hkin
    · intro pr hpr
      rcases mem_updateG hinv.nodup hpr with h1 | h1
      · subst h1
        rw [filter_append_same rfl]
        dsimp only
        obtain ⟨hd0, he0, hf0, hclen0, hcoeff0, ha0, hv0⟩ := hgf
        refine ⟨hd0, he0, hf0, by simp [hclen0], ?_, ?_, ?_⟩
        · intro j hj
          rw [List.length_append, List.length_cons, List.length_nil] at hj
          rcases Nat.lt_or_ge j (processed.filter fun p =>
              respKey p.1 = respKey r).length with hlt | hge
          · show ρ ((g.coeffs ++ [_]).getD j 0) = _
            rw [getD_concat_lt (hclen0 ▸ hlt), getD_concat_lt' hlt]
            exact hcoeff0 j hlt
          · have hj' : j = (processed.filter fun p =>
                respKey p.1 = respKey r).length := by omega
            subst hj'
            show ρ ((g.coeffs ++ [_]).getD _ 0) = _
            rw [← hclen0, getD_concat_len, hclen0, getD_concat_len']
            rw [hc, hap]
        · rw [ha, ha0, hap, List.map_append, List.sum_append]
          simp
        · rw [hv, hv0, hap, List.map_append, List.sum_append]
          simp
      · rw [filter_append_other (fun hk => h1.2 hk.symm)]
        exact hinv.facts _ h1.1
    · intro pr hpr
      rcases mem_updateG hinv.nodup hpr with h1 | h1
      · subst h1
        rw [filter_append_same rfl]
        simp
      · rw [filter_append_other (fun hk => h1.2 hk.symm)]
        exact hinv.fiber_ne _ h1.1

/-- **The walk preserves the invariant**, indexing the remaining
responses from `i + 1`, and leaves the final power register at the last
index. -/
theorem friWalk_sound {ρ : ℕ → QM31} {α : QM31} {imMask zero alpha : ℕ}
    (hmask : ρ imMask = QM31.fromM31s 0 0 1 1) (hzero : ρ zero = 0)
    (halpha : ρ alpha = α) :
    ∀ (rest : List RespReg) (groups : List ((ℕ × ℕ) × PG))
      (apReg n i : ℕ) (processed : List (RespReg × ℕ)),
      GInv ρ α groups processed →
      ρ apReg = (-2 : QM31) * Deep.uu * α ^ i →
      AllHold ρ (friWalk imMask zero alpha rest groups apReg n).ops →
      GInv ρ α (friWalk imMask zero alpha rest groups apReg n).res.1
        (processed ++ rest.zipIdx (i + 1)) ∧
      ρ (friWalk imMask zero alpha rest groups apReg n).res.2.1
        = (-2 : QM31) * Deep.uu * α ^ (i + rest.length) ∧
      ((friWalk imMask zero alpha rest groups apReg n).res.2.2.length
          = rest.length ∧
        ∀ j, j < rest.length →
          ρ ((friWalk imMask zero alpha rest groups apReg n).res.2.2.getD j 0)
            = (-2 : QM31) * Deep.uu * α ^ (i + 1 + j))
  | [], groups, apReg, n, i, processed, hinv, hap, _ => by
    refine ⟨?_, ?_, rfl, ?_⟩
    · show GInv ρ α groups (processed ++ ([] : List RespReg).zipIdx (i + 1))
      simpa using hinv
    · show ρ apReg = (-2 : QM31) * Deep.uu * α ^ (i + ([] : List RespReg).length)
      simpa using hap
    · intro j hj
      exact absurd hj (by simp)
  | r :: rest, groups, apReg, n, i, processed, hinv, hap, h => by
    rw [show (friWalk imMask zero alpha (r :: rest) groups apReg n).ops =
      .mul n apReg alpha ::
        ((friStep imMask zero groups r n (n + 1)).ops ++
          (friWalk imMask zero alpha rest
            (friStep imMask zero groups r n (n + 1)).res n
            (friStep imMask zero groups r n (n + 1)).next).ops) from rfl,
      allHold_cons, allHold_append] at h
    obtain ⟨hmul, hst, htail⟩ := h
    simp only [Holds] at hmul
    have hap' : ρ n = (-2 : QM31) * Deep.uu * α ^ (i + 1) := by
      rw [hmul, hap, halpha, pow_succ]
      ring
    have hstep := friStep_sound hmask hzero hinv hap' hst
    obtain ⟨hinv', hpow, hlen, hregs⟩ := friWalk_sound hmask hzero halpha rest
      (friStep imMask zero groups r n (n + 1)).res n
      (friStep imMask zero groups r n (n + 1)).next (i + 1)
      (processed ++ [(r, i + 1)]) hstep hap' htail
    refine ⟨?_, ?_, ?_, ?_⟩
    · show GInv ρ α (friWalk imMask zero alpha rest
        (friStep imMask zero groups r n (n + 1)).res n
        (friStep imMask zero groups r n (n + 1)).next).res.1 _
      rw [List.zipIdx_cons, show processed ++ (r, i + 1) :: rest.zipIdx (i + 1 + 1)
        = (processed ++ [(r, i + 1)]) ++ rest.zipIdx (i + 2) from by simp]
      exact hinv'
    · show ρ (friWalk imMask zero alpha rest
        (friStep imMask zero groups r n (n + 1)).res n
        (friStep imMask zero groups r n (n + 1)).next).res.2.1 = _
      rw [hpow, show i + 1 + rest.length = i + (r :: rest).length from by
        rw [List.length_cons]; omega]
    · show (friWalk imMask zero alpha rest
        (friStep imMask zero groups r n (n + 1)).res n
        (friStep imMask zero groups r n (n + 1)).next).res.2.2.length + 1 = _
      rw [hlen, List.length_cons]
    · intro j hj
      cases j with
      | zero =>
        show ρ n = _
        rw [hap']
      | succ j =>
        show ρ ((friWalk imMask zero alpha rest
          (friStep imMask zero groups r n (n + 1)).res n
          (friStep imMask zero groups r n (n + 1)).next).res.2.2.getD j 0) = _
        rw [hregs j (by rw [List.length_cons] at hj; omega),
          show i + 1 + 1 + j = i + 1 + (j + 1) from by omega]

/-- **The grouping loop's invariant at the end**: per wire-keyed group,
the line coefficients of its point and the `α'`-weighted sums over its
fiber of the indexed response list — with distinct keys covering every
response, each fiber nonempty. -/
theorem friGroups_sound {ρ : ℕ → QM31} {α : QM31} {imMask zero alpha : ℕ}
    {rs : List RespReg} {n : ℕ}
    (hmask : ρ imMask = QM31.fromM31s 0 0 1 1) (hzero : ρ zero = 0)
    (halpha : ρ alpha = α)
    (h : AllHold ρ (friGroups imMask zero alpha rs n).ops) :
    GInv ρ α (friGroups imMask zero alpha rs n).res.1 rs.zipIdx ∧
    ((friGroups imMask zero alpha rs n).res.2.2.length = rs.length ∧
      ∀ j, j < rs.length →
        ρ ((friGroups imMask zero alpha rs n).res.2.2.getD j 0)
          = (-2 : QM31) * Deep.uu * α ^ j) := by
  match rs with
  | [] =>
    refine ⟨?_, rfl, fun j hj => absurd hj (by simp)⟩
    show GInv ρ α [] (List.zipIdx [])
    rw [List.zipIdx_nil]
    exact ⟨by simp, by simp, by simp, by simp⟩
  | r :: rest =>
    rw [show (friGroups imMask zero alpha (r :: rest) n).ops =
      .const n ((-2 : QM31) * Deep.uu) ::
        ((friStep imMask zero [] r n (n + 1)).ops ++
          (friWalk imMask zero alpha rest
            (friStep imMask zero [] r n (n + 1)).res n
            (friStep imMask zero [] r n (n + 1)).next).ops) from rfl,
      allHold_cons, allHold_append] at h
    obtain ⟨hconst, hst, hwalk⟩ := h
    simp only [Holds] at hconst
    have hap : ρ n = (-2 : QM31) * Deep.uu * α ^ 0 := by
      rw [hconst, pow_zero, mul_one]
    have hempty : GInv ρ α [] [] := ⟨by simp, by simp, by simp, by simp⟩
    have hstep := friStep_sound hmask hzero hempty hap hst
    rw [List.nil_append] at hstep
    obtain ⟨hinv, -, hlen, hregs⟩ := friWalk_sound hmask hzero halpha rest
      (friStep imMask zero [] r n (n + 1)).res n
      (friStep imMask zero [] r n (n + 1)).next 0 [(r, 0)] hstep hap hwalk
    refine ⟨?_, ?_, ?_⟩
    · show GInv ρ α (friWalk imMask zero alpha rest
        (friStep imMask zero [] r n (n + 1)).res n
        (friStep imMask zero [] r n (n + 1)).next).res.1 _
      rw [List.zipIdx_cons]
      simpa using hinv
    · show (friWalk imMask zero alpha rest
        (friStep imMask zero [] r n (n + 1)).res n
        (friStep imMask zero [] r n (n + 1)).next).res.2.2.length + 1 = _
      rw [hlen, List.length_cons]
    · intro j hj
      cases j with
      | zero =>
        show ρ n = _
        rw [hap]
      | succ j =>
        show ρ ((friWalk imMask zero alpha rest
          (friStep imMask zero [] r n (n + 1)).res n
          (friStep imMask zero [] r n (n + 1)).next).res.2.2.getD j 0) = _
        rw [hregs j (by rw [List.length_cons] at hj; omega),
          show 0 + 1 + j = j + 1 from by omega]

/-! ### The finalize loop and the product guard -/

instance : Inhabited PG := ⟨⟨0, 0, 0, [], 0, 0⟩⟩

/-- A finalized group's registers against its walk entry: the shared
registers carry over, `b = d·v − a·P.y`. -/
def FinFacts (ρ : ℕ → QM31) (pr : (ℕ × ℕ) × PG) (gr : GroupRegs) : Prop :=
  gr.d = pr.2.d ∧ gr.e = pr.2.e ∧ gr.f = pr.2.f ∧ gr.coeffs = pr.2.coeffs ∧
  gr.aSum = pr.2.aReg ∧
  ρ gr.b = ρ pr.2.d * ρ pr.2.vReg - ρ pr.2.aReg * ρ pr.1.2

/-- The tail of the finalize loop: per group `finalize`, then the
product step `prod ← prod · d`. -/
def finChain (prod : ℕ) : List ((ℕ × ℕ) × PG) → ℕ →
    Out (List GroupRegs × ℕ)
  | [], n => ⟨[], ([], prod), n⟩
  | (k, g) :: rest, n =>
    let fin := auxFinalize g.d g.vReg g.aReg k.2 n
    let tail := finChain fin.next rest (fin.next + 1)
    ⟨fin.ops ++ .mul fin.next prod g.d :: tail.ops,
     (⟨g.d, g.e, g.f, g.coeffs, g.aReg, fin.res⟩ :: tail.res.1, tail.res.2),
     tail.next⟩

theorem finChain_sound {ρ : ℕ → QM31} :
    ∀ (groups : List ((ℕ × ℕ) × PG)) (prod n : ℕ),
      AllHold ρ (finChain prod groups n).ops →
      (finChain prod groups n).res.1.length = groups.length ∧
      ρ (finChain prod groups n).res.2
        = ρ prod * (groups.map fun pr => ρ pr.2.d).prod ∧
      ∀ idx, idx < groups.length →
        FinFacts ρ (groups.getD idx default)
          ((finChain prod groups n).res.1.getD idx default)
  | [], prod, n, _ =>
    ⟨rfl, by simp [finChain], fun idx hidx => absurd hidx (by simp)⟩
  | (k, g) :: rest, prod, n, h => by
    rw [show (finChain prod ((k, g) :: rest) n).ops =
      (auxFinalize g.d g.vReg g.aReg k.2 n).ops ++
        .mul (auxFinalize g.d g.vReg g.aReg k.2 n).next prod g.d ::
          (finChain (auxFinalize g.d g.vReg g.aReg k.2 n).next rest
            ((auxFinalize g.d g.vReg g.aReg k.2 n).next + 1)).ops from rfl,
      allHold_append, allHold_cons] at h
    obtain ⟨hfin, hmul, htail⟩ := h
    simp only [Holds] at hmul
    obtain ⟨ihlen, ihprod, ihfacts⟩ := finChain_sound rest
      (auxFinalize g.d g.vReg g.aReg k.2 n).next
      ((auxFinalize g.d g.vReg g.aReg k.2 n).next + 1) htail
    refine ⟨?_, ?_, fun idx hidx => ?_⟩
    · show (finChain _ rest _).res.1.length + 1 = rest.length + 1
      rw [ihlen]
    · show ρ (finChain _ rest _).res.2 = _
      rw [ihprod, hmul]
      simp only [List.map_cons, List.prod_cons]
      ring
    · cases idx with
      | zero =>
        refine ⟨rfl, rfl, rfl, rfl, rfl, ?_⟩
        show ρ (auxFinalize g.d g.vReg g.aReg k.2 n).res = _
        exact auxFinalize_sound hfin
      | succ idx =>
        exact ihfacts idx (by rw [List.length_cons] at hidx; omega)

/-- The whole finalize phase: the head group's `finalize` seeds the
product, the chain follows, the closing `inv` gate guards it. -/
def friFinalize (groups : List ((ℕ × ℕ) × PG)) (n : ℕ) :
    Out (List GroupRegs) :=
  match groups with
  | [] => ⟨[.inv n 1], [], n + 1⟩
  | (k, g) :: rest =>
    let fin := auxFinalize g.d g.vReg g.aReg k.2 n
    let tail := finChain g.d rest fin.next
    ⟨fin.ops ++ tail.ops ++ [.inv tail.next tail.res.2],
     ⟨g.d, g.e, g.f, g.coeffs, g.aReg, fin.res⟩ :: tail.res.1,
     tail.next + 1⟩

/-- **Finalize soundness**: each group's registers carry over with
`b = d·v − a·P.y`, and the product guard forces every group's `d`
nonzero. -/
theorem friFinalize_sound {ρ : ℕ → QM31}
    {groups : List ((ℕ × ℕ) × PG)} {n : ℕ}
    (h : AllHold ρ (friFinalize groups n).ops) :
    (friFinalize groups n).res.length = groups.length ∧
    (∀ idx, idx < groups.length →
      FinFacts ρ (groups.getD idx default)
        ((friFinalize groups n).res.getD idx default)) ∧
    ∀ pr ∈ groups, ρ pr.2.d ≠ 0 := by
  match groups with
  | [] =>
    exact ⟨rfl, fun idx hidx => absurd hidx (by simp),
      fun pr hpr => absurd hpr (by simp)⟩
  | (k, g) :: rest =>
    rw [show (friFinalize ((k, g) :: rest) n).ops =
      (auxFinalize g.d g.vReg g.aReg k.2 n).ops ++
        (finChain g.d rest (auxFinalize g.d g.vReg g.aReg k.2 n).next).ops ++
        [.inv (finChain g.d rest
            (auxFinalize g.d g.vReg g.aReg k.2 n).next).next
          (finChain g.d rest
            (auxFinalize g.d g.vReg g.aReg k.2 n).next).res.2]
      from rfl, allHold_append, allHold_append, allHold_cons] at h
    obtain ⟨⟨hfin, hchain⟩, hinv, -⟩ := h
    obtain ⟨clen, cprod, cfacts⟩ := finChain_sound rest g.d
      (auxFinalize g.d g.vReg g.aReg k.2 n).next hchain
    have hne : ρ (finChain g.d rest
        (auxFinalize g.d g.vReg g.aReg k.2 n).next).res.2 ≠ 0 :=
      inv_gate_ne_zero hinv
    rw [cprod] at hne
    refine ⟨?_, fun idx hidx => ?_, fun pr hpr => ?_⟩
    · show (finChain _ rest _).res.1.length + 1 = rest.length + 1
      rw [clen]
    · cases idx with
      | zero =>
        refine ⟨rfl, rfl, rfl, rfl, rfl, ?_⟩
        show ρ (auxFinalize g.d g.vReg g.aReg k.2 n).res = _
        exact auxFinalize_sound hfin
      | succ idx =>
        exact cfacts idx (by rw [List.length_cons] at hidx; omega)
    · rcases List.mem_cons.mp hpr with h1 | h1
      · rw [h1]
        exact left_ne_zero_of_mul hne
      · intro hzero
        apply right_ne_zero_of_mul hne
        exact List.prod_eq_zero (List.mem_map.mpr ⟨pr, h1, hzero⟩)

/-! ### `Bound` from the walk -/

/-- **A walked and finalized group is `Bound`** to the batch its fiber
describes: the response registers are the global power registers at the
fiber's indices paired with the response value registers. The batch
data (its point, and per entry the running power and sample value) must
match the fiber — that is the statement-level content `circuitPairs`
and `zip_partition_perm` provide. -/
theorem bound_of_walk {ρ : ℕ → QM31} {α : QM31} {k : ℕ × ℕ} {g : PG}
    {gr : GroupRegs} {fiber : List (RespReg × ℕ)} {apRegs : List ℕ}
    {b : Quotients.SampleBatch} {flatCols : List (List F)} {row : ℕ}
    {valRegs : List ℕ} {N : ℕ}
    (hgf : GFacts ρ α k g fiber)
    (hff : FinFacts ρ (k, g) gr)
    (hap : ∀ j, j < N →
      ρ (apRegs.getD j 0) = (-2 : QM31) * Deep.uu * α ^ j)
    (hidx : ∀ p ∈ fiber, p.2 < N)
    (hPx : ρ k.1 = b.point.x) (hPy : ρ k.2 = b.point.y)
    (hlenE : fiber.length = b.entries.length)
    (hrand : ∀ j, j < fiber.length →
      (b.entries.getD j default).randomCoeff
        = α ^ (fiber.getD j default).2)
    (hsv : ∀ j, j < fiber.length →
      (b.entries.getD j default).sampleValue
        = ρ (fiber.getD j default).1.value)
    (hlenV : valRegs.length = fiber.length)
    (hvals : ∀ j, j < fiber.length →
      ρ (valRegs.getD j 0) = QM31.fromBase ((flatCols.getD
        (b.entries.getD j default).columnIndex []).getD row 0)) :
    Bound ρ flatCols row
      ⟨gr, valRegs, fiber.map fun p => (apRegs.getD p.2 0, p.1.value), b⟩ := by
  have hgd : gr.d = g.d := hff.1
  have hge : gr.e = g.e := hff.2.1
  have hgfr : gr.f = g.f := hff.2.2.1
  have hgc : gr.coeffs = g.coeffs := hff.2.2.2.1
  have hga : gr.aSum = g.aReg := hff.2.2.2.2.1
  have hgb : ρ gr.b = ρ g.d * ρ g.vReg - ρ g.aReg * ρ k.2 := hff.2.2.2.2.2
  have hgetDmem : ∀ j, j < fiber.length → fiber.getD j default ∈ fiber := by
    intro j hj
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hj]
    exact List.getElem_mem hj
  have hrs : ∀ j, j < fiber.length →
      ((fiber.map fun p => (apRegs.getD p.2 0, p.1.value)).getD j (0, 0))
        = (apRegs.getD (fiber.getD j default).2 0,
           (fiber.getD j default).1.value) :=
    fun j hj => getD_map _ _ fiber j hj
  have hmapV : (fiber.map fun p =>
      ((-2 : QM31) * Deep.uu * α ^ p.2) * ρ p.1.value)
      = (fiber.map fun p => (apRegs.getD p.2 0, p.1.value)).map
          fun (a, v) => ρ a * ρ v := by
    rw [List.map_map]
    refine (List.map_congr_left fun p hp => ?_).symm
    show ρ (apRegs.getD p.2 0) * ρ p.1.value = _
    rw [hap p.2 (hidx p hp)]
  have hmapA : (fiber.map fun p =>
      ((-2 : QM31) * Deep.uu * α ^ p.2) * Deep.imQ (ρ p.1.value))
      = (fiber.map fun p => (apRegs.getD p.2 0, p.1.value)).map
          fun (a, v) => ρ a * Deep.imQ (ρ v) := by
    rw [List.map_map]
    refine (List.map_congr_left fun p hp => ?_).symm
    show ρ (apRegs.getD p.2 0) * Deep.imQ (ρ p.1.value) = _
    rw [hap p.2 (hidx p hp)]
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> dsimp only
  · rw [hgd, hgf.hd, hPy]
  · rw [hge, hgf.he, hPx]
  · rw [hgfr, hgf.hf, hPx, hPy]
  · rw [hgc, hgf.hclen, List.length_map]
  · intro i hi
    rw [List.length_map] at hi
    rw [hgc, hgf.hcoeff i hi, hrs i hi]
    dsimp only
    rw [hap (fiber.getD i default).2 (hidx _ (hgetDmem i hi)),
      hgf.hd, hPy]
  · rw [hga, hgf.ha, hmapA]
  · rw [hgb, hgf.hv, hgf.ha, hgf.hd, hPy, hmapV, hmapA]
  · rw [hlenV, List.length_map]
  · rw [List.length_map, hlenE]
  · intro i hi
    rw [List.length_map] at hi
    rw [hrs i hi]
    dsimp only
    rw [hrand i hi, hap (fiber.getD i default).2 (hidx _ (hgetDmem i hi))]
  · intro i hi
    rw [List.length_map] at hi
    rw [hrs i hi]
    dsimp only
    rw [hsv i hi]
  · intro i hi
    rw [List.length_map] at hi
    exact hvals i hi
end StwoVerifier.Gadgets