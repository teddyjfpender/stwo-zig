/-
**Phase 5 glue**: the spec's sample points/values/log sizes (circuitAir's
mask points, the read-off sampled values, the four trees' extended
column logs) in the shape `phase5G_sound` consumes; `buildSampleBatches`
succeeds on them; the response layout's column indices are in range.
-/
import StwoVerifier.ReadOff
import StwoVerifier.ResponseLayout

namespace StwoVerifier.Phase5Glue

open StwoVerifier StwoVerifier.Gadgets StwoVerifier.Gates StwoVerifier.ReadOff Quotients

/-! ### Triples -/

theorem zip3_self {A B C : Type} : ∀ T : List (A × B × C),
    (T.map (·.1)).zip ((T.map (·.2.1)).zip (T.map (·.2.2))) = T
  | [] => rfl
  | t :: rest => by simp [zip3_self rest]

/-- The interaction tree's per-column `(points, values, log)` triples. -/
def interT (cs : List (List QM31 × List (QM31 × QM31) × ℕ)) (P prev : PointQ) :
    List (List PointQ × List QM31 × ℕ) :=
  cs.flatMap fun c => (c.1.map fun v => ([P], [v], c.2.2)) ++ c.2.1.map fun p => ([prev, P], [p.1, p.2], c.2.2)

theorem map_const_rep {α β : Type} (l : List α) (b : β) : l.map (fun _ => b) = List.replicate l.length b := by
  induction l with
  | nil => rfl
  | cons x xs ih => rw [List.map_cons, ih, List.length_cons, List.replicate_succ]

theorem interT_fst (cs : List (List QM31 × List (QM31 × QM31) × ℕ)) (P prev : PointQ) :
    (interT cs P prev).map (·.1)
      = cs.flatMap fun c => List.replicate c.1.length [P] ++ List.replicate c.2.1.length [prev, P] := by
  unfold interT
  rw [List.map_flatMap]
  refine List.flatMap_congr fun c _ => ?_
  rw [List.map_append, List.map_map, List.map_map]
  exact congrArg₂ (· ++ ·) (map_const_rep _ _) (map_const_rep _ _)

theorem interT_snd (cs : List (List QM31 × List (QM31 × QM31) × ℕ)) (P prev : PointQ) :
    (interT cs P prev).map (·.2.1)
      = cs.flatMap fun c => (c.1.map fun v => [v]) ++ c.2.1.map fun p => [p.1, p.2] := by
  unfold interT
  rw [List.map_flatMap]
  refine List.flatMap_congr fun c _ => ?_
  rw [List.map_append, List.map_map, List.map_map]
  rfl

theorem interT_thd (cs : List (List QM31 × List (QM31 × QM31) × ℕ)) (P prev : PointQ) :
    (interT cs P prev).map (·.2.2)
      = cs.flatMap fun c => List.replicate c.1.length c.2.2 ++ List.replicate c.2.1.length c.2.2 := by
  unfold interT
  rw [List.map_flatMap]
  refine List.flatMap_congr fun c _ => ?_
  rw [List.map_append, List.map_map, List.map_map]
  exact congrArg₂ (· ++ ·) (map_const_rep _ _) (map_const_rep _ _)

/-! ### `buildSampleBatches` succeeds on matching shapes -/

theorem pushColumn_ok (step : PointF) (rc : QM31) (st : BatchState) (pts : List PointQ)
    (vals : List QM31) (L : ℕ) (h : pts.length = vals.length) :
    ∃ st', pushColumn step rc st pts vals L = .ok st' := by
  unfold pushColumn
  simp only [h, ne_eq, not_true_eq_false, if_false, bind, Except.bind, pure, Except.pure]
  split <;> exact ⟨_, rfl⟩

theorem pushTree_ok (step : PointF) (rc : QM31) :
    ∀ (cols : List (List PointQ × List QM31 × ℕ)) (st : BatchState),
      (∀ c ∈ cols, c.1.length = c.2.1.length) → ∃ st', pushTree step rc st cols = .ok st'
  | [], st, _ => ⟨st, rfl⟩
  | c :: rest, st, h => by
    obtain ⟨pts, vals, L⟩ := c
    obtain ⟨st1, h1⟩ := pushColumn_ok step rc st pts vals L (h _ List.mem_cons_self)
    obtain ⟨st2, h2⟩ := pushTree_ok step rc rest st1 fun c hc => h c (List.mem_cons_of_mem _ hc)
    exact ⟨st2, by rw [pushTree, h1]; exact h2⟩

theorem pushTrees_ok (step : PointF) (rc : QM31) :
    ∀ (trees : List (List (List PointQ) × List (List QM31) × List ℕ)) (st : BatchState),
      (∀ t ∈ trees, t.1.length = t.2.2.length ∧ t.1.length = t.2.1.length ∧
        ∀ c ∈ t.1.zip (t.2.1.zip t.2.2), c.1.length = c.2.1.length) →
      ∃ st', pushTrees step rc st trees = .ok st'
  | [], st, _ => ⟨st, rfl⟩
  | t :: rest, st, h => by
    obtain ⟨pts, vals, sizes⟩ := t
    obtain ⟨h1, h2, h3⟩ := h _ List.mem_cons_self
    obtain ⟨st1, e1⟩ := pushTree_ok step rc (pts.zip (vals.zip sizes)) st h3
    obtain ⟨st2, e2⟩ := pushTrees_ok step rc rest st1 fun t ht => h t (List.mem_cons_of_mem _ ht)
    refine ⟨st2, ?_⟩
    rw [pushTrees]
    simp only [show ¬ (pts.length ≠ sizes.length ∨ pts.length ≠ vals.length) by
      simp only [ne_eq, not_or, not_not]; exact ⟨h1, h2⟩, if_false, bind, Except.bind]
    rw [e1]
    exact e2

theorem buildSampleBatches_ok (sp : List (List (List PointQ))) (sv : List (List (List QM31)))
    (cls : List (List ℕ)) (L : ℕ) (rc : QM31) (h1 : sp.length = cls.length)
    (h2 : sp.length = sv.length)
    (h : ∀ t ∈ sp.zip (sv.zip cls), t.1.length = t.2.2.length ∧ t.1.length = t.2.1.length ∧
        ∀ c ∈ t.1.zip (t.2.1.zip t.2.2), c.1.length = c.2.1.length) :
    ∃ batches, buildSampleBatches sp sv cls L rc = .ok batches := by
  obtain ⟨st, hst⟩ := pushTrees_ok (canonicStep L) rc _ ⟨[], QM31.one, 0⟩ h
  refine ⟨st.batches, ?_⟩
  unfold buildSampleBatches
  simp only [show ¬ (sp.length ≠ cls.length ∨ sp.length ≠ sv.length) by
    simp only [ne_eq, not_or, not_not]; exact ⟨h1, h2⟩, if_false, bind, Except.bind]
  rw [hst]
  rfl

theorem single_cols_ok {k : ℕ} {P : PointQ} {vs : List QM31} {ls : List ℕ}
    (c : List PointQ × List QM31 × ℕ)
    (hc : c ∈ (List.replicate k [P]).zip ((vs.map fun v => [v]).zip ls)) :
    c.1.length = c.2.1.length := by
  have h1 := (List.of_mem_zip hc).1
  have h2 := (List.of_mem_zip (List.of_mem_zip hc).2).1
  rw [(List.mem_replicate.mp h1).2]
  obtain ⟨v, -, hv⟩ := List.mem_map.mp h2
  rw [← hv]
  rfl

theorem interT_cols_ok {cs : List (List QM31 × List (QM31 × QM31) × ℕ)} {P prev : PointQ}
    (c : List PointQ × List QM31 × ℕ) (hc : c ∈ interT cs P prev) : c.1.length = c.2.1.length := by
  unfold interT at hc
  obtain ⟨x, -, hx⟩ := List.mem_flatMap.mp hc
  rcases List.mem_append.mp hx with hx | hx
  · obtain ⟨v, -, rfl⟩ := List.mem_map.mp hx; rfl
  · obtain ⟨p, -, rfl⟩ := List.mem_map.mp hx; rfl

/-! ### Interaction-sample shapes -/

theorem range_kinds {n : ℕ} (hn : 4 ≤ n) :
    (List.range n).map (fun i => decide (i + 4 ≥ n))
      = List.replicate (n - 4) false ++ List.replicate 4 true := by
  refine List.ext_getElem (by simp; omega) fun i h1 h2 => ?_
  have hi : i < n := by simpa using h1
  rw [List.getElem_map, List.getElem_range]
  by_cases hlt : i < n - 4
  · rw [List.getElem_append_left (by simpa using hlt)]
    simp only [List.getElem_replicate]
    simp; omega
  · rw [List.getElem_append_right (by simp; omega)]
    simp only [List.getElem_replicate]
    simp; omega

theorem interShape_ge : ∀ m ∈ CircuitAirData.interShape.toList, 4 ≤ m := by decide

theorem comps_lens {comps : List (List ℕ × List (ℕ × ℕ))} (hl : comps.length = 11)
    (hs : ∀ j, j < 11 → (comps.getD j ([], [])).1.length = CircuitAirData.interShape.toList.getD j 0 - 4 ∧
      (comps.getD j ([], [])).2.length = 4) :
    comps.map (fun c => (c.1.length, c.2.length))
      = CircuitAirData.interShape.toList.map fun m => (m - 4, 4) := by
  have h11 : CircuitAirData.interShape.toList.length = 11 := by decide
  refine List.ext_getElem (by simp [hl, h11]) fun j h1 h2 => ?_
  have hj : j < 11 := by simpa [hl] using h1
  rw [List.getElem_map, List.getElem_map]
  obtain ⟨e1, e2⟩ := hs j hj
  rw [List.getD_eq_getElem _ _ (by rw [hl]; exact hj),
    List.getD_eq_getElem _ _ (by rw [h11]; exact hj)] at e1
  rw [List.getD_eq_getElem _ _ (by rw [hl]; exact hj)] at e2
  rw [e1, e2]

theorem map_eq_replicate' {α : Type} (l : List α) (b : Bool) (f : α → Bool) (h : ∀ x, f x = b) :
    l.map f = List.replicate l.length b := by
  induction l with
  | nil => rfl
  | cons x xs ih => rw [List.map_cons, h x, ih, List.length_cons, List.replicate_succ]

theorem interAtOf_kinds {comps : List (List ℕ × List (ℕ × ℕ))} (hl : comps.length = 11)
    (hs : ∀ j, j < 11 → (comps.getD j ([], [])).1.length = CircuitAirData.interShape.toList.getD j 0 - 4 ∧
      (comps.getD j ([], [])).2.length = 4) :
    (interAtOf comps).map (fun c => c.2.isSome) = CircuitAir.cumulativeKinds := by
  have e : (interAtOf comps).map (fun c => c.2.isSome)
      = (comps.map (fun c => (c.1.length, c.2.length))).flatMap
          (fun p => List.replicate p.1 false ++ List.replicate p.2 true) := by
    unfold interAtOf
    rw [List.map_flatMap, List.flatMap_map]
    refine List.flatMap_congr fun c _ => ?_
    rw [List.map_append, List.map_map, List.map_map]
    exact congrArg₂ (· ++ ·) (map_eq_replicate' _ _ _ (fun _ => rfl))
      (map_eq_replicate' _ _ _ (fun _ => rfl))
  rw [e, comps_lens hl hs, List.flatMap_map]
  unfold CircuitAir.cumulativeKinds
  exact List.flatMap_congr fun m hm => (range_kinds (interShape_ge m hm)).symm

theorem interAtOf_length {comps : List (List ℕ × List (ℕ × ℕ))} (hl : comps.length = 11)
    (hs : ∀ j, j < 11 → (comps.getD j ([], [])).1.length = CircuitAirData.interShape.toList.getD j 0 - 4 ∧
      (comps.getD j ([], [])).2.length = 4) :
    (interAtOf comps).length = CircuitAirData.nInter := by
  rw [← List.length_map (f := fun c => c.2.isSome), interAtOf_kinds hl hs]
  unfold CircuitAir.cumulativeKinds
  simp [CircuitAirData.interShape, CircuitAirData.nInter]

/-! ### The trees in phase 5's shape -/

/-- The spec sample points: circuitAir's mask points and the composition tree. -/
def spList (P : PointQ) (lt : ℕ) : List (List (List PointQ)) :=
  CircuitAir.maskPoints P lt ++ [List.replicate 8 [P]]

/-- The spec column logs of the four trees. -/
def clsList (S : Stmt) : List (List ℕ) := [treeLogs S 0, treeLogs S 1, treeLogs S 2, treeLogs S 3]

theorem prevPoint_eq (P : PointQ) (lt : ℕ) :
    CircuitAir.prevPoint P lt = P.add (PointF.intoQ (canonicStep lt).conjugate) := by
  unfold CircuitAir.prevPoint CircuitAir.embedPoint PointF.intoQ CPoint.neg CPoint.conjugate
  congr 2
  exact (map_neg baseHom _).symm

theorem flatMap_zip_fst {α β γ : Type} (l : List α) (m : List β) (f : α → List γ)
    (h : l.length ≤ m.length) : (l.zip m).flatMap (fun x => f x.1) = l.flatMap f := by
  have := List.flatMap_map (f := Prod.fst) (g := f) (l := l.zip m)
  rw [List.map_fst_zip h] at this
  exact this.symm

/-- The interaction components as `phase5G_sound` reads them. -/
def csOf (ρ : ℕ → QM31) (comps : List (List ℕ × List (ℕ × ℕ))) (Ls : List ℕ) :
    List (List QM31 × List (QM31 × QM31) × ℕ) :=
  (comps.zip Ls).map fun x => (x.1.1.map ρ, x.1.2.map fun d => (ρ d.1, ρ d.2), x.2)

theorem csOf_lens (ρ : ℕ → QM31) {comps : List (List ℕ × List (ℕ × ℕ))} {Ls : List ℕ}
    (hl : comps.length ≤ Ls.length) :
    (csOf ρ comps Ls).map (fun c => (c.1.length, c.2.1.length))
      = comps.map fun c => (c.1.length, c.2.length) := by
  unfold csOf
  rw [List.map_map]
  have := List.map_fst_zip hl
  conv_rhs => rw [← this, List.map_map]
  refine List.map_congr_left fun x _ => ?_
  simp

theorem tree2_points (ρ : ℕ → QM31) {comps : List (List ℕ × List (ℕ × ℕ))} {Ls : List ℕ}
    (hl : comps.length = 11) (hLs : Ls.length = 11)
    (hs : ∀ j, j < 11 → (comps.getD j ([], [])).1.length = CircuitAirData.interShape.toList.getD j 0 - 4 ∧
      (comps.getD j ([], [])).2.length = 4) (P prev : PointQ) :
    (CircuitAirData.interShape.toList.flatMap fun n =>
        List.replicate (n - 4) [P] ++ List.replicate 4 [prev, P])
      = (csOf ρ comps Ls).flatMap fun c =>
          List.replicate c.1.length [P] ++ List.replicate c.2.1.length [prev, P] := by
  have e := List.flatMap_map (f := fun c : List QM31 × List (QM31 × QM31) × ℕ => (c.1.length, c.2.1.length))
    (g := fun p : ℕ × ℕ => List.replicate p.1 [P] ++ List.replicate p.2 [prev, P]) (l := csOf ρ comps Ls)
  rw [← e, csOf_lens ρ (by omega), comps_lens hl hs, List.flatMap_map]

theorem tree2_values (ρ : ℕ → QM31) {comps : List (List ℕ × List (ℕ × ℕ))} {Ls : List ℕ}
    (hl : comps.length ≤ Ls.length) :
    (interAtOf comps).map (fun c => c.2.toList.map ρ ++ [ρ c.1])
      = (csOf ρ comps Ls).flatMap fun c => (c.1.map fun v => [v]) ++ c.2.1.map fun p => [p.1, p.2] := by
  unfold interAtOf csOf
  rw [List.map_flatMap, List.flatMap_map]
  rw [flatMap_zip_fst comps Ls (fun c => (c.1.map ρ).map (fun v => [v]) ++
    (c.2.map fun d => (ρ d.1, ρ d.2)).map fun p => [p.1, p.2]) hl]
  refine List.flatMap_congr fun c _ => ?_
  simp [List.map_map, Function.comp_def]

theorem tree2_logs (ρ : ℕ → QM31) {comps : List (List ℕ × List (ℕ × ℕ))} {ls : List ℕ}
    (hl : comps.length = 11) (hls : ls.length = 11)
    (hs : ∀ j, j < 11 → (comps.getD j ([], [])).1.length = CircuitAirData.interShape.toList.getD j 0 - 4 ∧
      (comps.getD j ([], [])).2.length = 4) :
    (CircuitVerify.interColumnLogSizes ls).map (· + 1)
      = (csOf ρ comps ((List.range 11).map fun j => ls.getD j 0 + 1)).flatMap fun c =>
          List.replicate c.1.length c.2.2 ++ List.replicate c.2.1.length c.2.2 := by
  have h11 : CircuitAirData.interShape.toList.length = 11 := by decide
  unfold CircuitVerify.interColumnLogSizes csOf
  rw [List.map_flatMap, List.flatMap_map]
  simp only [List.map_replicate, List.replicate_append_replicate, List.length_map]
  rw [List.flatMap_def, List.flatMap_def]
  congr 1
  refine List.ext_getElem (by simp [hl, hls, h11]) fun j h1 h2 => ?_
  have hj : j < 11 := by simpa [hls, h11] using h1
  simp only [List.getElem_map, List.getElem_zip, List.getElem_range]
  obtain ⟨e1, e2⟩ := hs j hj
  rw [List.getD_eq_getElem _ _ (by rw [hl]; exact hj),
    List.getD_eq_getElem _ _ (by rw [h11]; exact hj)] at e1
  rw [List.getD_eq_getElem _ _ (by rw [hl]; exact hj)] at e2
  rw [e1, e2, List.getD_eq_getElem _ _ (by rw [hls]; exact hj),
    Nat.sub_add_cancel (interShape_ge _ (List.getElem_mem _))]

/-- The interaction log column of phase 5 (`logs j + 1` per component). -/
def lsOf (S : Stmt) : List ℕ := (List.range 11).map fun j => S.logSizes.getD j 0 + 1

theorem htrees_ok (ρ : ℕ → QM31) (g : ProofRegs) (S : Stmt) (P : PointQ)
    (hpp : g.ppAt.length = CircuitAirData.nPp) (hlay : S.layout.length = CircuitAirData.nPp)
    (htr : g.traceAt.length = CircuitAirData.nTrace) (hcmp : g.compAt.length = 8)
    (hcl : g.comps.length = 11) (hls : S.logSizes.length = 11)
    (hs : ∀ j, j < 11 → (g.comps.getD j ([], [])).1.length = CircuitAirData.interShape.toList.getD j 0 - 4 ∧
      (g.comps.getD j ([], [])).2.length = 4) :
    (spList P S.logTrace).zip ((rdSampled ρ g).zip (clsList S)) =
      [(List.replicate (g.ppAt.map ρ).length [P], (g.ppAt.map ρ).map fun v => [v], treeLogs S 0),
       (List.replicate (g.traceAt.map ρ).length [P], (g.traceAt.map ρ).map fun v => [v], treeLogs S 1),
       ((csOf ρ g.comps (lsOf S)).flatMap fun c => List.replicate c.1.length [P]
          ++ List.replicate c.2.1.length [P.add (PointF.intoQ (canonicStep S.logTrace).conjugate), P],
        (csOf ρ g.comps (lsOf S)).flatMap fun c => (c.1.map fun v => [v]) ++ c.2.1.map fun p => [p.1, p.2],
        (csOf ρ g.comps (lsOf S)).flatMap fun c =>
          List.replicate c.1.length c.2.2 ++ List.replicate c.2.1.length c.2.2),
       (List.replicate (g.compAt.map ρ).length [P], (g.compAt.map ρ).map fun v => [v], treeLogs S 3)] := by
  have hLs : (lsOf S).length = 11 := by simp [lsOf]
  unfold spList CircuitAir.maskPoints rdSampled svOf clsList
  simp only [List.cons_append, List.nil_append, List.zip_cons_cons, List.zip_nil_left,
    List.cons.injEq, and_true]
  refine ⟨?_, ?_, ?_, ?_⟩
  · rw [List.length_map, hpp, List.map_map]; rfl
  · rw [List.length_map, htr, List.map_map]; rfl
  · rw [tree2_points ρ hcl hLs hs P, tree2_values ρ (by rw [hcl, hLs]), prevPoint_eq,
      show treeLogs S 2 = (CircuitVerify.interColumnLogSizes S.logSizes).map (· + 1) from rfl,
      tree2_logs ρ hcl hls hs]
    rfl
  · rw [List.length_map, hcmp, List.map_map]; rfl

theorem single_tree_ok {k : ℕ} {P : PointQ} {vs : List QM31} {ls : List ℕ} (hk : k = vs.length)
    (hl : ls.length = vs.length) :
    (List.replicate k [P]).length = ls.length ∧ (List.replicate k [P]).length = (vs.map fun v => [v]).length ∧
      ∀ c ∈ (List.replicate k [P]).zip ((vs.map fun v => [v]).zip ls), c.1.length = c.2.1.length :=
  ⟨by rw [List.length_replicate, hl, hk], by rw [List.length_replicate, List.length_map, hk],
   single_cols_ok⟩

theorem hbuild_ok (ρ : ℕ → QM31) (g : ProofRegs) (S : Stmt) (P : PointQ) (L : ℕ) (rc : QM31)
    (hpp : g.ppAt.length = CircuitAirData.nPp) (hlay : S.layout.length = CircuitAirData.nPp)
    (htr : g.traceAt.length = CircuitAirData.nTrace) (hcmp : g.compAt.length = 8)
    (hcl : g.comps.length = 11) (hls : S.logSizes.length = 11)
    (hs : ∀ j, j < 11 → (g.comps.getD j ([], [])).1.length = CircuitAirData.interShape.toList.getD j 0 - 4 ∧
      (g.comps.getD j ([], [])).2.length = 4) :
    ∃ batches, buildSampleBatches (spList P S.logTrace) (rdSampled ρ g) (clsList S) L rc = .ok batches := by
  refine buildSampleBatches_ok _ _ _ L rc rfl rfl ?_
  rw [htrees_ok ρ g S P hpp hlay htr hcmp hcl hls hs]
  intro t ht
  simp only [List.mem_cons, List.not_mem_nil, or_false] at ht
  rcases ht with rfl | rfl | rfl | rfl
  · exact single_tree_ok (by rw [List.length_map]) (by
      rw [List.length_map, hpp]; show (S.layout.map _).length = _; rw [List.length_map, hlay])
  · exact single_tree_ok (by rw [List.length_map]) (by
      rw [List.length_map, htr]; show ((CircuitVerify.traceColumnLogSizes S.logSizes).map _).length = _
      rw [List.length_map]
      unfold CircuitVerify.traceColumnLogSizes
      rw [List.length_flatMap]
      simp only [List.length_replicate]
      rw [show ((CircuitAirData.traceShape.toList.zip S.logSizes).map fun p => p.1)
        = (CircuitAirData.traceShape.toList.zip S.logSizes).map Prod.fst from rfl,
        List.map_fst_zip (by rw [hls]; decide)]
      decide)
  · set P' := P.add (PointF.intoQ (canonicStep S.logTrace).conjugate)
    rw [← interT_fst _ P P', ← interT_snd _ P P', ← interT_thd _ P P']
    simp only [List.length_map, true_and]
    rw [zip3_self]
    exact fun c hc => interT_cols_ok c hc
  · exact single_tree_ok (by rw [List.length_map]) (by
      rw [List.length_map, hcmp]; show (List.replicate 8 _).length = 8; rw [List.length_replicate])

/-! ### Response-layout column indices -/

theorem singlesL_fc {pt : PointReg} :
    ∀ {vs : List ℕ} {fc : ℕ} {x : RespReg × ℕ}, x ∈ singlesL pt vs fc → x.2 < fc + vs.length
  | [], _, _, h => absurd h (by simp [singlesL])
  | v :: rest, fc, x, h => by
    rcases List.mem_cons.mp h with rfl | h
    · simp
    · have := singlesL_fc h; simp at this ⊢; omega

theorem doublesL_fc {oods prev period : PointReg} :
    ∀ {dv : List (ℕ × ℕ)} {fc : ℕ} {x : RespReg × ℕ}, x ∈ doublesL oods prev period dv fc →
      x.2 < fc + dv.length
  | [], _, _, h => absurd h (by simp [doublesL])
  | (vp, vo) :: rest, fc, x, h => by
    simp only [doublesL, List.mem_cons] at h
    rcases h with rfl | rfl | rfl | h
    · simp
    · simp
    · simp
    · have := doublesL_fc h; simp at this ⊢; omega

theorem interL_fc {oods prev : PointReg} :
    ∀ {ents : List (PointReg × List ℕ × List (ℕ × ℕ) × ℕ)} {fc : ℕ} {x : RespReg × ℕ},
      x ∈ interL oods prev ents fc →
      x.2 < fc + (ents.map fun c => c.2.1.length + c.2.2.1.length).sum
  | [], _, _, h => absurd h (by simp [interL])
  | (per, sv, dv, L) :: rest, fc, x, h => by
    simp only [interL, List.mem_append] at h
    simp only [List.map_cons, List.sum_cons]
    rcases h with (h | h) | h
    · have := singlesL_fc h; omega
    · have := doublesL_fc h; omega
    · have := interL_fc h; omega

theorem respLayout_fc {oods prev : PointReg} {ppAt traceAt compAt : List ℕ}
    {ents : List (PointReg × List ℕ × List (ℕ × ℕ) × ℕ)} {x : RespReg × ℕ}
    (h : x ∈ respLayout oods prev ppAt traceAt ents compAt) :
    x.2 < ppAt.length + traceAt.length + (ents.map fun c => c.2.1.length + c.2.2.1.length).sum
      + compAt.length := by
  simp only [respLayout, List.mem_append] at h
  rcases h with ((h | h) | h) | h
  · have := singlesL_fc h; omega
  · have := singlesL_fc h; omega
  · have := interL_fc h; omega
  · have := singlesL_fc h; omega

theorem interEntries_sum (pers : List PointReg) (comps : List (List ℕ × List (ℕ × ℕ))) (Ls : List ℕ) :
    ((interEntries pers comps Ls).map fun c => c.2.1.length + c.2.2.1.length).sum
      ≤ (comps.map fun c => c.1.length + c.2.length).sum := by
  induction comps generalizing pers Ls with
  | nil => cases pers <;> cases Ls <;> simp [interEntries]
  | cons c cs ih =>
    cases pers with
    | nil => simp [interEntries]
    | cons p ps =>
      cases Ls with
      | nil => simp [interEntries]
      | cons l ls =>
        have := ih ps ls
        simp only [interEntries, List.zip_cons_cons, List.map_cons, List.sum_cons] at this ⊢
        omega

theorem comps_sum {comps : List (List ℕ × List (ℕ × ℕ))} (hl : comps.length = 11)
    (hs : ∀ j, j < 11 → (comps.getD j ([], [])).1.length = CircuitAirData.interShape.toList.getD j 0 - 4 ∧
      (comps.getD j ([], [])).2.length = 4) :
    (comps.map fun c => c.1.length + c.2.length).sum = CircuitAirData.nInter := by
  have e := congrArg (List.map fun p : ℕ × ℕ => p.1 + p.2) (comps_lens hl hs)
  rw [List.map_map, List.map_map] at e
  rw [show (comps.map fun c => c.1.length + c.2.length)
    = comps.map ((fun p : ℕ × ℕ => p.1 + p.2) ∘ fun c => (c.1.length, c.2.length)) from rfl, e]
  decide

/-! ### The raw queried values -/

/-- Tree → column → raw query values. -/
noncomputable def rdQueriedRaw (ρ : ℕ → QM31) (S : Stmt) (g : ProofRegs) : List (List (List F)) :=
  (List.range 4).map fun t => (List.range (treeCols.getD t 0)).map fun c =>
    (List.range S.nq).map fun q => xv ρ g t c q

theorem isBase_eq {x : QM31} (h : IsBase x) : x = QM31.fromBase (baseOf x) := by
  obtain ⟨hb, hc⟩ := h
  obtain ⟨⟨a, b⟩, c⟩ := x
  simp only at hb hc
  subst hb; subst hc
  rfl

/-- A register column carries a value column. -/
def ColRel (ρ : ℕ → QM31) (nq : ℕ) (regs : List ℕ) (vals : List F) : Prop :=
  regs.length = nq ∧ vals.length = nq ∧ ∀ i, i < nq → ρ (regs.getD i 0) = QM31.fromBase (vals.getD i 0)

theorem forall2_getD {α β : Type} {R : α → β → Prop} {l : List α} {l' : List β} (h : List.Forall₂ R l l')
    (a : α) (b : β) {i : ℕ} (hi : i < l.length) : R (l.getD i a) (l'.getD i b) := by
  have hl := h.length_eq
  have := (List.forall₂_iff_get.mp h).2 i hi (by omega)
  simp only [List.get_eq_getElem] at this
  rw [List.getD_eq_getElem _ _ hi, List.getD_eq_getElem _ _ (by omega)]
  exact this

theorem tree_colRel (ρ : ℕ → QM31) (S : Stmt) (g : ProofRegs)
    (hGF : GuessFacts ρ S.nq (S.logTrace + 1) g) {t : ℕ} (ht : t < 4) :
    List.Forall₂ (ColRel ρ S.nq) (g.cols.getD t [])
      ((List.range (treeCols.getD t 0)).map fun c => (List.range S.nq).map fun q => xv ρ g t c q) := by
  obtain ⟨hl1, hl2⟩ := hGF.colsLen t ht
  refine List.forall₂_iff_get.mpr ⟨by rw [List.length_map, List.length_range, hl1], fun c h1 h2 => ?_⟩
  have hc : c < treeCols.getD t 0 := by rw [← hl1]; exact h1
  simp only [List.get_eq_getElem, List.getElem_map, List.getElem_range]
  have hcl := hl2 c hc
  rw [← List.getD_eq_getElem _ [] h1]
  refine ⟨hcl, by simp, fun i hi => ?_⟩
  rw [show (List.map (fun q => xv ρ g t c q) (List.range S.nq)).getD i 0 = xv ρ g t c i from by
    rw [List.getD_eq_getElem _ _ (by simpa using hi)]; simp]
  exact isBase_eq (hGF.cols t ht c hc i hi)

theorem forall2_append {α β : Type} {R : α → β → Prop} :
    ∀ {a : List α} {b : List β} {c : List α} {d : List β},
      List.Forall₂ R a b → List.Forall₂ R c d → List.Forall₂ R (a ++ c) (b ++ d)
  | [], [], _, _, .nil, h => h
  | _ :: _, _ :: _, _, _, .cons h1 h2, h => .cons h1 (forall2_append h2 h)

theorem allCols_colRel (ρ : ℕ → QM31) (S : Stmt) (g : ProofRegs)
    (hGF : GuessFacts ρ S.nq (S.logTrace + 1) g) :
    List.Forall₂ (ColRel ρ S.nq) (allCols g) (rdQueriedRaw ρ S g).flatten := by
  unfold allCols rdQueriedRaw
  rw [show List.range 4 = [0, 1, 2, 3] from rfl]
  simp only [List.map_cons, List.map_nil, List.flatten_cons, List.flatten_nil, List.append_nil,
    List.append_assoc]
  exact forall2_append (tree_colRel ρ S g hGF (t := 0) (by norm_num))
    (forall2_append (tree_colRel ρ S g hGF (t := 1) (by norm_num))
      (forall2_append (tree_colRel ρ S g hGF (t := 2) (by norm_num))
        (tree_colRel ρ S g hGF (t := 3) (by norm_num))))

theorem queriedRaw_length (ρ : ℕ → QM31) (S : Stmt) (g : ProofRegs) :
    (rdQueriedRaw ρ S g).flatten.length
      = CircuitAirData.nPp + CircuitAirData.nTrace + CircuitAirData.nInter + 8 := by
  unfold rdQueriedRaw
  rw [show List.range 4 = [0, 1, 2, 3] from rfl]
  simp [treeCols]
  omega

end StwoVerifier.Phase5Glue
