/-
**`compute_fri_input`, composed** (`oods.zig`): the grouping walk
(`friGroups`), the finalize loop with its product guard
(`friFinalize`), and the per-query row loop (`deepRows`), wired as the
emitter wires them — each group's query values in its fiber order.

`deepComposite_spec`: given the response list's flat view **is** the
spec's push-order pair list (`horder`, the statement-level response
layout, proven separately), the composed gadget's row registers are
exactly the spec's `friAnswers` at the query positions. The circuit's
wire-keyed groups become `SampleBatch`es (`batchOf`); their flat view
permutes the response list (`zip_partition_perm`), hence the spec
batches' (`buildSampleBatches_flat`); `bound_of_walk` binds every
group, and the spec's nondegeneracy guards come from the product guard
(`im(P.y) ≠ 0`) and `den_nonzero`.
-/
import StwoVerifier.GroupedRows
import StwoVerifier.FriGroups
import StwoVerifier.DenNonzero
import StwoVerifier.SelectQueriesBridge

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

instance instInhabitedPointQ' : Inhabited PointQ := ⟨CPoint.zero⟩

/-- A response's fiber: the indexed responses sharing its key. -/
def fibOf (rs : List RespReg) (k : ℕ × ℕ) : List (RespReg × ℕ) :=
  rs.zipIdx.filter fun p => respKey p.1 = k

/-- Per query `i`: each group's finalized registers with its fiber's
query-value registers. -/
def gvsOf (rs : List RespReg) (fcs : List ℕ) (valReg : ℕ → ℕ → ℕ)
    (groups : List ((ℕ × ℕ) × PG)) (fins : List GroupRegs) (i : ℕ) :
    List (GroupRegs × List ℕ) :=
  (groups.zip fins).map fun x =>
    (x.2, (fibOf rs x.1.1).map fun p => valReg (fcs.getD p.2 0) i)

/-- The composed `compute_fri_input` over given query-point registers. -/
noncomputable def deepCompositeG (imMask zero alpha : ℕ) (rs : List RespReg)
    (fcs : List ℕ) (qpts : List (ℕ × ℕ)) (valReg : ℕ → ℕ → ℕ) (n : ℕ) : Out (List ℕ) :=
  let g := friGroups imMask zero alpha rs n
  let fin := friFinalize g.res.1 g.next
  let rows := deepRows zero (qpts.zipIdx.map fun x =>
    (x.1, gvsOf rs fcs valReg g.res.1 fin.res x.2)) fin.next
  ⟨g.ops ++ fin.ops ++ rows.ops, rows.res, rows.next⟩

/-- A circuit group as a spec batch. -/
noncomputable def batchOf (ρ : ℕ → QM31) (α : QM31) (rs : List RespReg) (fcs : List ℕ)
    (k : ℕ × ℕ) : Quotients.SampleBatch :=
  ⟨⟨ρ k.1, ρ k.2⟩, (fibOf rs k).map fun p => ⟨fcs.getD p.2 0, ρ p.1.value, α ^ p.2⟩⟩

/-- The flat view of the response list. -/
noncomputable def respPairs (ρ : ℕ → QM31) (α : QM31) (rs : List RespReg) (fcs : List ℕ) :
    List (PointQ × Quotients.NumeratorData) :=
  rs.zipIdx.map fun p => (⟨ρ p.1.px, ρ p.1.py⟩, ⟨fcs.getD p.2 0, ρ p.1.value, α ^ p.2⟩)

/-- **The wire-keyed groups' flat view permutes the response list.** -/
theorem groups_flat_perm (ρ : ℕ → QM31) (α : QM31) (rs : List RespReg) (fcs : List ℕ)
    (keys : List (ℕ × ℕ)) (hnd : keys.Nodup) (hcov : ∀ r ∈ rs, respKey r ∈ keys) :
    (Quotients.flattenBatches (keys.map (batchOf ρ α rs fcs))).Perm
      (respPairs ρ α rs fcs) := by
  have hz := Quotients.zip_partition_perm (rs.zipIdx.map fun p => respKey p.1)
    (respPairs ρ α rs fcs) keys hnd
    (fun k hk => by
      obtain ⟨p, hp, rfl⟩ := List.mem_map.mp hk
      exact hcov p.1 (List.fst_mem_of_mem_zipIdx hp))
    (by simp [respPairs])
  refine List.Perm.trans ?_ hz
  unfold Quotients.flattenBatches
  rw [List.flatMap_map]
  refine List.Perm.of_eq (List.flatMap_congr fun k _ => ?_)
  -- One key's batch is its fiber's pairs.
  have hzip : ((rs.zipIdx.map fun p => respKey p.1).zip (respPairs ρ α rs fcs))
      = rs.zipIdx.map fun p => (respKey p.1, (⟨ρ p.1.px, ρ p.1.py⟩ : PointQ),
          (⟨fcs.getD p.2 0, ρ p.1.value, α ^ p.2⟩ : Quotients.NumeratorData)) := by
    unfold respPairs
    rw [List.zip_map']
  rw [hzip, List.filter_map, List.map_map]
  unfold batchOf fibOf
  simp only [List.map_map]
  refine List.map_congr_left fun p hp => ?_
  have hk : respKey p.1 = k := by simpa using (List.mem_filter.mp hp).2
  simp only [Function.comp_apply]
  rw [← hk]
  rfl

/-! ### Spec batches are nonempty -/

namespace NE

open Quotients

def NE (bs : List SampleBatch) : Prop := ∀ b ∈ bs, b.entries ≠ []

theorem pushEntry_ne : ∀ (bs : List SampleBatch) (pt : PointQ) (e : NumeratorData),
    NE bs → NE (pushEntry bs pt e)
  | [], pt, e, _ => by
    intro b hb
    rw [show pushEntry [] pt e = [⟨pt, [e]⟩] from rfl] at hb
    rw [List.mem_singleton.mp hb]; simp
  | b :: rest, pt, e, h => by
    by_cases hp : b.point = pt
    · rw [show pushEntry (b :: rest) pt e = ⟨b.point, b.entries ++ [e]⟩ :: rest from by
        simp only [pushEntry]; rw [if_pos hp]]
      intro b' hb'
      rcases List.mem_cons.mp hb' with rfl | hb'
      · simp
      · exact h b' (List.mem_cons_of_mem _ hb')
    · rw [show pushEntry (b :: rest) pt e = b :: pushEntry rest pt e from by
        simp only [pushEntry]; rw [if_neg hp]]
      intro b' hb'
      rcases List.mem_cons.mp hb' with rfl | hb'
      · exact h b' List.mem_cons_self
      · exact pushEntry_ne rest pt e (fun x hx => h x (List.mem_cons_of_mem _ hx)) b' hb'

theorem foldl_ne (rc : QM31) :
    ∀ (l : List (PointQ × QM31)) (st : BatchState), NE st.batches →
      NE (l.foldl (fun st (point, value) =>
          { st with
            batches := pushEntry st.batches point ⟨st.flatColumn, value, st.randomPow⟩
            randomPow := st.randomPow * rc }) st).batches
  | [], st, h => h
  | (pt, v) :: rest, st, h => foldl_ne rc rest _ (pushEntry_ne _ _ _ h)

theorem pushColumn_ne (step : PointF) (rc : QM31) (st : BatchState)
    (cp : List PointQ) (cv : List QM31) (ls : ℕ) {st' : BatchState}
    (h : pushColumn step rc st cp cv ls = .ok st') (hne : NE st.batches) :
    NE st'.batches := by
  unfold pushColumn at h
  dsimp only at h
  split at h
  · exact absurd (show Except.error VError.shapeMismatch = Except.ok st' from h) (by simp)
  · split at h
    · obtain rfl : _ = st' := Except.ok.inj (show Except.ok _ = Except.ok st' from h)
      exact foldl_ne rc _ _ (pushEntry_ne _ _ _ hne)
    · obtain rfl : _ = st' := Except.ok.inj (show Except.ok _ = Except.ok st' from h)
      exact foldl_ne rc _ _ hne

theorem pushTree_ne (step : PointF) (rc : QM31) :
    ∀ (cols : List (List PointQ × List QM31 × Nat)) (st : BatchState) {st' : BatchState},
      pushTree step rc st cols = .ok st' → NE st.batches → NE st'.batches
  | [], st, st', h, hne => by
    obtain rfl : st = st' := Except.ok.inj h
    exact hne
  | (cp, cv, ls) :: rest, st, st', h, hne => by
    rw [show pushTree step rc st ((cp, cv, ls) :: rest)
      = (pushColumn step rc st cp cv ls) >>= fun st => pushTree step rc st rest from rfl] at h
    cases hc : pushColumn step rc st cp cv ls with
    | error e =>
      rw [hc] at h
      exact absurd (show Except.error e = Except.ok st' from h) (by simp)
    | ok st1 =>
      rw [hc, ok_bind] at h
      exact pushTree_ne step rc rest st1 h (pushColumn_ne step rc st cp cv ls hc hne)

theorem pushTrees_ne (step : PointF) (rc : QM31) :
    ∀ (trees : List (List (List PointQ) × List (List QM31) × List Nat)) (st : BatchState)
      {st' : BatchState}, pushTrees step rc st trees = .ok st' → NE st.batches →
      NE st'.batches
  | [], st, st', h, hne => by
    obtain rfl : st = st' := Except.ok.inj h
    exact hne
  | (tp, tv, ts) :: rest, st, st', h, hne => by
    rw [Quotients.pushTrees] at h
    dsimp only at h
    split at h
    · exact absurd (show Except.error VError.shapeMismatch = Except.ok st' from h) (by simp)
    · cases hc : pushTree step rc st (tp.zip (tv.zip ts)) with
      | error e =>
        rw [hc] at h
        exact absurd (show Except.error e = Except.ok st' from h) (by simp)
      | ok st1 =>
        rw [hc, ok_bind] at h
        exact pushTrees_ne step rc rest st1 h (pushTree_ne step rc _ st hc hne)

theorem build_ne {sp : List (List (List PointQ))} {sv : List (List (List QM31))}
    {cls : List (List Nat)} {L : Nat} {rc : QM31} {batches : List SampleBatch}
    (h : buildSampleBatches sp sv cls L rc = .ok batches) : NE batches := by
  unfold buildSampleBatches at h
  dsimp only at h
  split at h
  · exact absurd (show Except.error VError.shapeMismatch = Except.ok batches from h)
      (by simp)
  · cases hc : pushTrees (canonicStep L) rc ⟨[], QM31.one, 0⟩ (sp.zip (sv.zip cls)) with
    | error e =>
      rw [hc] at h
      exact absurd (show Except.error e = Except.ok batches from h) (by simp)
    | ok st1 =>
      rw [hc, ok_bind] at h
      obtain rfl : st1.batches = batches :=
        Except.ok.inj (show Except.ok st1.batches = Except.ok batches from h)
      exact pushTrees_ne _ rc _ _ hc (fun b hb => absurd hb (by simp))

end NE

/-! ### The composite theorem -/

/-- The proof-side bindings of query `i`. -/
noncomputable def bindingsOf (ρ : ℕ → QM31) (α : QM31) (rs : List RespReg) (fcs : List ℕ)
    (valReg : ℕ → ℕ → ℕ) (groups : List ((ℕ × ℕ) × PG)) (fins : List GroupRegs)
    (apRegs : List ℕ) (i : ℕ) : List GroupBinding :=
  (groups.zip fins).map fun x =>
    ⟨x.2, (fibOf rs x.1.1).map (fun p => valReg (fcs.getD p.2 0) i),
     (fibOf rs x.1.1).map (fun p => (apRegs.getD p.2 0, p.1.value)),
     batchOf ρ α rs fcs x.1.1⟩

theorem bindingsOf_map (ρ : ℕ → QM31) (α : QM31) (rs : List RespReg) (fcs : List ℕ)
    (valReg : ℕ → ℕ → ℕ) (groups : List ((ℕ × ℕ) × PG)) (fins : List GroupRegs)
    (apRegs : List ℕ) (i : ℕ) :
    (bindingsOf ρ α rs fcs valReg groups fins apRegs i).map (fun gb => (gb.g, gb.valRegs))
      = gvsOf rs fcs valReg groups fins i := by
  unfold bindingsOf gvsOf
  rw [List.map_map]
  rfl

/-- A spec flat pair comes from a response. -/
theorem specPair_mem {ρ : ℕ → QM31} {α : QM31} {rs : List RespReg} {fcs : List ℕ}
    {batches : List Quotients.SampleBatch} {sp : List (List (List PointQ))}
    {sv : List (List (List QM31))} {cls : List (List Nat)} {L : Nat}
    (hbuild : Quotients.buildSampleBatches sp sv cls L α = .ok batches)
    (horder : respPairs ρ α rs fcs
      = (Quotients.treesPairs (canonicStep L) α QM31.one 0 (sp.zip (sv.zip cls))).1)
    {pt : PointQ} {e : Quotients.NumeratorData}
    (hm : (pt, e) ∈ Quotients.flattenBatches batches) :
    ∃ p ∈ rs.zipIdx, pt = ⟨ρ p.1.px, ρ p.1.py⟩ ∧ e.columnIndex = fcs.getD p.2 0 := by
  have hm' := (Quotients.buildSampleBatches_flat sp sv cls L α hbuild).mem_iff.mp hm
  rw [← horder] at hm'
  obtain ⟨p, hp, he⟩ := List.mem_map.mp hm'
  injection he with h1 h2
  exact ⟨p, hp, h1.symm, by rw [← h2]⟩

set_option maxHeartbeats 4000000 in
/-- **The composed `compute_fri_input` is the spec's `friAnswers`.** -/
theorem deepComposite_spec {ρ : ℕ → QM31} {imMask zero alpha : ℕ} {rs : List RespReg}
    {fcs : List ℕ} {qpts : List (ℕ × ℕ)} {valReg : ℕ → ℕ → ℕ} {n : ℕ} {α : QM31}
    (cls : List (List Nat)) (sp : List (List (List PointQ)))
    (sv : List (List (List QM31))) (L : Nat) (ps : List Nat)
    (queried : List (List (List F))) (batches : List Quotients.SampleBatch)
    (hmask : ρ imMask = QM31.fromM31s 0 0 1 1) (hzero : ρ zero = 0)
    (halpha : ρ alpha = α)
    (hbuild : Quotients.buildSampleBatches sp sv cls L α = .ok batches)
    (horder : respPairs ρ α rs fcs
      = (Quotients.treesPairs (canonicStep L) α QM31.one 0 (sp.zip (sv.zip cls))).1)
    (honc : ∀ r ∈ rs, OnCircleQ ⟨ρ r.px, ρ r.py⟩)
    (hcols : ∀ col ∈ queried.flatten, col.length = ps.length)
    (hfc : ∀ j, j < rs.length → fcs.getD j 0 < queried.flatten.length)
    (hpos : ∀ pos ∈ ps, pos < (canonicDomain L).size)
    (hqlen : qpts.length = ps.length)
    (hq : ∀ i, i < qpts.length →
      ρ (qpts.getD i default).1 = QM31.fromBase ((canonicDomain L).at'
        (bitReverseIndex (ps.getD i 0) L)).x ∧
      ρ (qpts.getD i default).2 = QM31.fromBase ((canonicDomain L).at'
        (bitReverseIndex (ps.getD i 0) L)).y)
    (hval : ∀ j, j < rs.length → ∀ i, i < ps.length →
      ρ (valReg (fcs.getD j 0) i)
        = QM31.fromBase ((queried.flatten.getD (fcs.getD j 0) []).getD i 0))
    (h : AllHold ρ (deepCompositeG imMask zero alpha rs fcs qpts valReg n).ops) :
    Quotients.friAnswers cls sp sv α ps queried L
      = .ok ((deepCompositeG imMask zero alpha rs fcs qpts valReg n).res.map ρ) ∧
    (∀ b ∈ batches, Deep.imQ b.point.y ≠ 0) ∧
    (∀ b ∈ batches, ∀ e ∈ b.entries, e.columnIndex < queried.flatten.length) ∧
    (∀ b ∈ batches, ∀ pos : ℕ, Quotients.denominator b.point ((canonicDomain L).at'
      (bitReverseIndex pos L)) ≠ 0) := by
  set g := friGroups imMask zero alpha rs n with hgdef
  set fin := friFinalize g.res.1 g.next with hfindef
  rw [show (deepCompositeG imMask zero alpha rs fcs qpts valReg n).ops =
    g.ops ++ fin.ops ++ (deepRows zero (qpts.zipIdx.map fun x =>
      (x.1, gvsOf rs fcs valReg g.res.1 fin.res x.2)) fin.next).ops from rfl,
    allHold_append, allHold_append] at h
  obtain ⟨⟨hg, hfn⟩, hr⟩ := h
  obtain ⟨hinv, happlen, hap⟩ := friGroups_sound hmask hzero halpha hg
  obtain ⟨hfl, hff, hdne⟩ := friFinalize_sound hfn
  set keys := g.res.1.map Prod.fst with hkeys
  set groupsSB := keys.map (batchOf ρ α rs fcs) with hgroupsSB
  set entries := qpts.zipIdx.map fun x =>
    (x.1, bindingsOf ρ α rs fcs valReg g.res.1 fin.res g.res.2.2 x.2) with hentries
  have hrows : (entries.map fun e => (e.1, e.2.map fun gb => (gb.g, gb.valRegs)))
      = qpts.zipIdx.map fun x => (x.1, gvsOf rs fcs valReg g.res.1 fin.res x.2) := by
    rw [hentries, List.map_map]
    refine List.map_congr_left fun x _ => ?_
    simp only [Function.comp_apply, bindingsOf_map]
  -- Every response's group has a nonzero `im(P.y)`.
  have himr : ∀ r ∈ rs, Deep.imQ (ρ r.py) ≠ 0 := by
    intro r hr'
    have hcov := hinv.cover (r, rs.idxOf r) (by
      rw [List.mem_zipIdx_iff_getElem?]
      simp [List.getElem?_idxOf hr'])
    obtain ⟨pr, hpr, hk⟩ := List.mem_map.mp hcov
    have hd := (hinv.facts pr hpr).hd
    rw [hk] at hd
    rw [show r.py = (respKey r).2 from rfl, ← hd]
    exact hdne pr hpr
  -- Spec batch points are response points.
  have hspecPt : ∀ b ∈ batches, ∃ r ∈ rs, b.point = ⟨ρ r.px, ρ r.py⟩ := by
    intro b hb
    obtain ⟨e, he⟩ := List.exists_mem_of_ne_nil _ (NE.build_ne hbuild b hb)
    obtain ⟨p, hp, hpt, -⟩ := specPair_mem hbuild horder
      (mem_flattenBatches.mpr ⟨b, hb, rfl, he⟩)
    exact ⟨p.1, List.fst_mem_of_mem_zipIdx hp, hpt⟩
  have him : ∀ b ∈ batches, Deep.imQ b.point.y ≠ 0 := by
    intro b hb
    obtain ⟨r, hr', hpt⟩ := hspecPt b hb
    rw [hpt]; exact himr r hr'
  have hidx : ∀ b ∈ batches, ∀ e ∈ b.entries, e.columnIndex < queried.flatten.length := by
    intro b hb e he
    obtain ⟨p, hp, -, hci⟩ := specPair_mem hbuild horder
      (mem_flattenBatches.mpr ⟨b, hb, rfl, he⟩)
    rw [hci]
    exact hfc p.2 (by
      obtain ⟨k, hk, rfl⟩ := List.getElem_of_mem hp
      simp at hk ⊢; omega)
  have hdenAll : ∀ b ∈ batches, ∀ pos : ℕ,
      Quotients.denominator b.point ((canonicDomain L).at'
        (bitReverseIndex pos L)) ≠ 0 := by
    intro b hb pos
    obtain ⟨r, hr', hpt⟩ := hspecPt b hb
    have hq' := Bridge.onCircle_toPoint ((canonicDomain L).indexAt (bitReverseIndex pos L))
    have := Deep.den_nonzero b.point ((canonicDomain L).at' (bitReverseIndex pos L))
      (by rw [hpt]; exact honc r hr') hq' (him b hb)
    exact this
  have hdenS : ∀ b ∈ batches, ∀ pos ∈ ps,
      Quotients.denominator b.point ((canonicDomain L).at'
        (bitReverseIndex pos L)) ≠ 0 := fun b hb pos _ => hdenAll b hb pos
  have hentlen : entries.length = qpts.length := by simp [hentries]
  have hentD : ∀ i, i < entries.length → entries.getD i default
      = (qpts.getD i default, bindingsOf ρ α rs fcs valReg g.res.1 fin.res g.res.2.2 i) := by
    intro i hi
    rw [hentlen] at hi
    rw [hentries, getD_map _ _ _ i (by simpa using hi), List.getD_eq_getElem?_getD,
      List.getElem?_zipIdx, List.getElem?_eq_getElem hi, List.getD_eq_getElem?_getD,
      List.getElem?_eq_getElem hi]
    simp
  have hfiblt : ∀ k, ∀ p ∈ fibOf rs k, p.2 < rs.length := by
    intro k p hp
    have hp' := (List.mem_filter.mp hp).1
    obtain ⟨j, hj, rfl⟩ := List.getElem_of_mem hp'
    simp at hj ⊢; omega
  -- Every binding is `Bound`.
  have hB : ∀ i, i < entries.length → ∀ gb ∈ (entries.getD i default).2,
      Bound ρ queried.flatten i gb := by
    intro i hi gb hgb
    rw [hentD i hi] at hgb
    obtain ⟨x, hx, rfl⟩ := List.mem_map.mp hgb
    obtain ⟨idx, hidx', hxe⟩ := List.getElem_of_mem hx
    have hidx1 : idx < g.res.1.length := by simpa using (List.length_zip ▸ hidx' |>.trans_le (Nat.min_le_left _ _))
    have hidx2 : idx < fin.res.length := by rw [hfl]; exact hidx1
    have hx1 : x.1 = g.res.1[idx] := by rw [← hxe, List.getElem_zip]
    have hx2 : x.2 = fin.res[idx] := by rw [← hxe, List.getElem_zip]
    have hmem1 : x.1 ∈ g.res.1 := by rw [hx1]; exact List.getElem_mem _
    have hgf := hinv.facts x.1 hmem1
    have hff' : FinFacts ρ x.1 x.2 := by
      have := hff idx hidx1
      rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hidx1,
        List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hidx2] at this
      rw [hx1, hx2]; exact this
    have hiq : i < ps.length := by rw [← hqlen, ← hentlen]; exact hi
    exact bound_of_walk (fiber := fibOf rs x.1.1) (N := rs.length) hgf hff'
      (fun j hj => hap j hj)
      (hfiblt x.1.1) rfl rfl (by simp [batchOf])
      (fun j hj => by
        unfold batchOf
        rw [getD_map _ _ _ j hj])
      (fun j hj => by
        unfold batchOf
        rw [getD_map _ _ _ j hj])
      (by simp)
      (fun j hj => by
        rw [getD_map _ _ _ j hj]
        unfold batchOf
        rw [getD_map _ _ _ j hj]
        have hmemf : (fibOf rs x.1.1).getD j default ∈ fibOf rs x.1.1 := by
          rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hj]
          exact List.getElem_mem hj
        exact hval _ (hfiblt x.1.1 _ hmemf) i hiq)
  have hgroups : ∀ i, i < entries.length →
      (entries.getD i default).2.map GroupBinding.batch = groupsSB := by
    intro i hi
    rw [hentD i hi]
    unfold bindingsOf
    rw [List.map_map]
    show ((g.res.1.zip fin.res).map fun x => batchOf ρ α rs fcs x.1.1) = _
    rw [show (fun x : ((ℕ × ℕ) × PG) × GroupRegs => batchOf ρ α rs fcs x.1.1)
        = (fun y : (ℕ × ℕ) × PG => batchOf ρ α rs fcs y.1) ∘ Prod.fst from rfl,
      ← List.map_map, List.map_fst_zip (by rw [hfl]), hgroupsSB, hkeys, List.map_map]
    rfl
  have hne : ∀ gsb ∈ groupsSB, gsb.entries ≠ [] := by
    intro gsb hgsb
    obtain ⟨k, hk, rfl⟩ := List.mem_map.mp hgsb
    obtain ⟨pr, hpr, rfl⟩ := List.mem_map.mp hk
    unfold batchOf
    exact fun h0 => hinv.fiber_ne pr hpr (List.map_eq_nil_iff.mp h0)
  have hperm : (Quotients.flattenBatches groupsSB).Perm (Quotients.flattenBatches batches) := by
    refine (groups_flat_perm ρ α rs fcs keys hinv.nodup ?_).trans ?_
    · intro r hr'
      exact hinv.cover (r, rs.idxOf r) (by
        rw [List.mem_zipIdx_iff_getElem?]
        simp [List.getElem?_idxOf hr'])
    · rw [horder]
      exact (Quotients.buildSampleBatches_flat sp sv cls L α hbuild).symm
  have hmain := friAnswers_eq_rows_grouped cls sp sv α ps queried L batches groupsSB
    entries fin.next hbuild hcols him hidx hpos hdenS hzero (by rw [hentlen, hqlen])
    (fun i hi => by rw [hentD i hi]; exact hq i (by rw [← hentlen]; exact hi))
    hB hgroups hne hperm (by rw [hrows]; exact hr)
  refine ⟨?_, him, hidx, hdenAll⟩
  rw [hmain, hrows]
  rfl

end StwoVerifier.Gadgets
