/-
**Phase 4 of the in-circuit `verify`: the eval-domain decommitment**
(`merkle.zig` `decommitEvalDomainSamples`, `sort_queries.zig`).

Per tree and query: the query's column values (sorted into committed
order for the trace and interaction trees), `hash_leaf_m31s`,
`verify_merkle_path` against the tree root with the query's bits.
`queryPathG_sound`: the root is `pathRoot` of the spec leaf of the
row; the plain and sorted tree loops give that for every query, the
sorted rows in the spec's `columnOrder`.
-/
import StwoVerifier.QuerySorter
import StwoVerifier.PhaseTranscript

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates Merkle

/-- One query's leaf and path. -/
noncomputable def queryPathG (vals bits root : List ℕ) (auth : List (List ℕ)) (n : ℕ) :
    Out Unit :=
  (leafG vals n).seq fun leaf n => verifyPathG leaf bits root auth n

theorem queryPathG_sound {ρ : ℕ → QM31} {vals bits root : List ℕ} {auth : List (List ℕ)}
    {n : ℕ} {row : List F} {wr : List Blake2s.Word} {sws : List (List Blake2s.Word)}
    (hlen : vals.length = row.length)
    (hv : ∀ i, i < vals.length → ρ (vals.getD i 0) = QM31.fromBase (row.getD i 0))
    (hroot : RegsWords ρ root wr) (hr8 : wr.length = 8)
    (hsl : auth.length = sws.length)
    (hsibs : ∀ i, i < auth.length → RegsWords ρ (auth.getD i []) (sws.getD i []) ∧
      (sws.getD i []).length = 8)
    (hbits : ∀ b ∈ bits, ρ b = 0 ∨ ρ b = 1)
    (h : AllHold ρ (queryPathG vals bits root auth n).ops) :
    wordsBytes wr = pathRoot (leafHash row) (bits.map fun b => qbit (ρ b))
      (sws.map wordsBytes) := by
  unfold queryPathG at h
  rw [allHold_seq] at h
  obtain ⟨hl, hp⟩ := h
  obtain ⟨hw, hrw, h8, hb⟩ := leafG_sound hlen hv hl
  rw [verifyPathG_sound hrw h8 hroot hr8 hsl hsibs hbits hp, hb]

/-- A query's values in a column-major sample block. -/
def qvals (samples : List ℕ) (ncols nq q : ℕ) : List ℕ :=
  (List.range ncols).map fun c => samples.getD (c * nq + q) 0

/-- An unsorted tree: every query's leaf and path. -/
noncomputable def plainTreeG (samples : List ℕ) (ncols nq : ℕ) (bitsOf : ℕ → List ℕ)
    (root : List ℕ) (authOf : ℕ → List (List ℕ)) : List ℕ → ℕ → Out Unit
  | [], n => ⟨[], (), n⟩
  | q :: qs, n =>
    (queryPathG (qvals samples ncols nq q) (bitsOf q) root (authOf q) n).seq fun _ n =>
      plainTreeG samples ncols nq bitsOf root authOf qs n

theorem plainTreeG_sound {ρ : ℕ → QM31} {samples : List ℕ} {ncols nq : ℕ}
    {bitsOf : ℕ → List ℕ} {root : List ℕ} {authOf : ℕ → List (List ℕ)}
    (x : ℕ → ℕ → F) {wr : List Blake2s.Word} (swsOf : ℕ → List (List Blake2s.Word))
    (hx : ∀ c, c < ncols → ∀ q, q < nq → ρ (samples.getD (c * nq + q) 0) = QM31.fromBase (x c q))
    (hroot : RegsWords ρ root wr) (hr8 : wr.length = 8)
    (hsl : ∀ q, q < nq → (authOf q).length = (swsOf q).length)
    (hsibs : ∀ q, q < nq → ∀ i, i < (authOf q).length →
      RegsWords ρ ((authOf q).getD i []) ((swsOf q).getD i []) ∧ ((swsOf q).getD i []).length = 8)
    (hbits : ∀ q, q < nq → ∀ b ∈ bitsOf q, ρ b = 0 ∨ ρ b = 1) :
    ∀ (qs : List ℕ) (n : ℕ), (∀ q ∈ qs, q < nq) →
      AllHold ρ (plainTreeG samples ncols nq bitsOf root authOf qs n).ops →
      ∀ q ∈ qs, wordsBytes wr = pathRoot (leafHash ((List.range ncols).map fun c => x c q))
        ((bitsOf q).map fun b => qbit (ρ b)) ((swsOf q).map wordsBytes)
  | [], _, _, _ => fun q hq => absurd hq (by simp)
  | q :: qs, n, hqs, h => by
    unfold plainTreeG at h
    rw [allHold_seq] at h
    obtain ⟨h1, h2⟩ := h
    intro q' hq'
    rcases List.mem_cons.mp hq' with rfl | hq'
    · have hq := hqs q' List.mem_cons_self
      refine queryPathG_sound (by simp [qvals]) (fun i hi => ?_) hroot hr8 (hsl q' hq)
        (hsibs q' hq) (hbits q' hq) h1
      have hi' : i < ncols := by simpa [qvals] using hi
      unfold qvals
      rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range hi',
        List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range hi']
      exact hx i hi' q' hq
    · exact plainTreeG_sound x swsOf hx hroot hr8 hsl hsibs hbits qs _
        (fun q'' h'' => hqs q'' (List.mem_cons_of_mem _ h'')) h2 q' hq'

/-- Later queries of a sorted tree: sort with keys pinned to the first
query's, then leaf and path. -/
noncomputable def sortedRestG (one : ℕ) (keys first samples : List ℕ) (ncols nq : ℕ)
    (bitsOf : ℕ → List ℕ) (root : List ℕ) (authOf : ℕ → List (List ℕ)) :
    List ℕ → ℕ → Out Unit
  | [], n => ⟨[], (), n⟩
  | q :: qs, n =>
    (sortCoreG one (qvals samples ncols nq q) keys n).seq fun c n =>
    (⟨keysEqG c.2 first, (), n⟩ : Out Unit).seq fun _ n =>
    (queryPathG c.1 (bitsOf q) root (authOf q) n).seq fun _ n =>
    sortedRestG one keys first samples ncols nq bitsOf root authOf qs n

/-- A sorted tree: the sort keys, the first query (order range check),
the rest (keys pinned). -/
noncomputable def sortedTreeG (zero one u shift uinv : ℕ) (logRegs : List ℕ) (b : ℕ)
    (samples : List ℕ) (ncols nq : ℕ) (bitsOf : ℕ → List ℕ) (root : List ℕ)
    (authOf : ℕ → List (List ℕ)) (n : ℕ) : Out Unit :=
  (keysG u shift logRegs 0 n).seq fun keys n =>
  (sortCoreG one (qvals samples ncols nq 0) keys n).seq fun c0 n =>
  (verifyFirstG zero uinv c0.2 (5 + b) n).seq fun _ n =>
  (queryPathG c0.1 (bitsOf 0) root (authOf 0) n).seq fun _ n =>
  sortedRestG one keys c0.2 samples ncols nq bitsOf root authOf ((List.range nq).drop 1) n

theorem qvals_sound {ρ : ℕ → QM31} {samples : List ℕ} {ncols nq : ℕ} {x : ℕ → ℕ → F}
    (hx : ∀ c, c < ncols → ∀ q, q < nq → ρ (samples.getD (c * nq + q) 0) = QM31.fromBase (x c q))
    {q : ℕ} (hq : q < nq) :
    (qvals samples ncols nq q).length = ncols ∧
    ∀ c, c < ncols → ρ ((qvals samples ncols nq q).getD c 0) = QM31.fromBase (x c q) := by
  refine ⟨by simp [qvals], fun c hc => ?_⟩
  unfold qvals
  rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range hc]
  exact hx c hc q hq

theorem ord_row_getD (logs : List ℕ) (x : ℕ → F) {k : ℕ} (hk : k < logs.length) :
    ((columnOrder logs).map x).getD k 0 = x ((columnOrder logs).getD k 0) := by
  have hco : (columnOrder logs).length = logs.length :=
    (ColumnOrder.columnOrder_perm logs).length_eq.trans List.length_range
  rw [List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_eq_getElem (by rw [hco]; exact hk), List.getD_eq_getElem?_getD,
    List.getElem?_eq_getElem (by rw [hco]; exact hk)]
  rfl

theorem sortedRestG_sound {ρ : ℕ → QM31} {one : ℕ} {keys first samples : List ℕ}
    {ncols nq : ℕ} {bitsOf : ℕ → List ℕ} {root : List ℕ} {authOf : ℕ → List (List ℕ)}
    (logs : List ℕ) (b : ℕ) (x : ℕ → ℕ → F) {wr : List Blake2s.Word}
    (swsOf : ℕ → List (List Blake2s.Word))
    (hone : ρ one = 1) (hb : 5 + b ≤ 30) (hm : logs.length ≤ 2 ^ b)
    (hlogs : ∀ c, c < logs.length → logs.getD c 0 < 2 ^ 5) (hnc : ncols = logs.length)
    (hkl : keys.length = logs.length)
    (hk : ∀ c, c < logs.length →
      ρ (keys.getD c 0) = uQ * QM31.fromBase ((colKey logs b c : ℕ) : F))
    (hfirst : ∀ k, k < logs.length → ρ (first.getD k 0)
      = uQ * QM31.fromBase ((colKey logs b ((columnOrder logs).getD k 0) : ℕ) : F))
    (hx : ∀ c, c < ncols → ∀ q, q < nq → ρ (samples.getD (c * nq + q) 0) = QM31.fromBase (x c q))
    (hroot : RegsWords ρ root wr) (hr8 : wr.length = 8)
    (hsl : ∀ q, q < nq → (authOf q).length = (swsOf q).length)
    (hsibs : ∀ q, q < nq → ∀ i, i < (authOf q).length →
      RegsWords ρ ((authOf q).getD i []) ((swsOf q).getD i []) ∧ ((swsOf q).getD i []).length = 8)
    (hbits : ∀ q, q < nq → ∀ b ∈ bitsOf q, ρ b = 0 ∨ ρ b = 1) :
    ∀ (qs : List ℕ) (n : ℕ), (∀ q ∈ qs, q < nq) →
      AllHold ρ (sortedRestG one keys first samples ncols nq bitsOf root authOf qs n).ops →
      ∀ q ∈ qs, wordsBytes wr = pathRoot
        (leafHash ((columnOrder logs).map fun c => x c q))
        ((bitsOf q).map fun b => qbit (ρ b)) ((swsOf q).map wordsBytes)
  | [], _, _, _ => fun q hq => absurd hq (by simp)
  | q :: qs, n, hqs, h => by
    unfold sortedRestG at h
    set C := sortCoreG one (qvals samples ncols nq q) keys n with hCdef
    rw [allHold_seq] at h
    obtain ⟨hc, h⟩ := h
    beta_reduce at h
    rw [allHold_seq] at h
    obtain ⟨he, h⟩ := h
    beta_reduce at h
    rw [allHold_seq] at h
    obtain ⟨hp, hrest⟩ := h
    intro q' hq'
    rcases List.mem_cons.mp hq' with rfl | hq'
    · have hq := hqs q' List.mem_cons_self
      obtain ⟨hvl, hvv⟩ := qvals_sound hx hq
      have hlow := sortLater_sound logs b (fun c => x c q') hone hb hm hlogs
        (by rw [hvl, hnc]) hkl (fun c hc => hvv c (by omega)) hk hfirst hc he
      obtain ⟨-, hl1, -, -⟩ := sortCore_sound (x := fun c => x c q')
        (K := fun c => ((colKey logs b c : ℕ) : F)) hone (by rw [hvl, hkl, hnc])
        (fun c hc => hvv c (by omega)) (fun c hc => hk c (by omega)) hc
      refine queryPathG_sound (by
          rw [hl1, hvl, List.length_map,
            (ColumnOrder.columnOrder_perm logs).length_eq, List.length_range, hnc])
        (fun i hi => ?_) hroot hr8 (hsl q' hq) (hsibs q' hq) (hbits q' hq) hp
      rw [hl1, hvl, hnc] at hi
      rw [hlow i hi, ord_row_getD logs (fun c => x c q') hi]
    · exact sortedRestG_sound logs b x swsOf hone hb hm hlogs hnc hkl hk hfirst hx hroot hr8
        hsl hsibs hbits qs _ (fun q'' h'' => hqs q'' (List.mem_cons_of_mem _ h'')) hrest q' hq'

theorem range_drop_mem {nq q : ℕ} (hq : q ∈ (List.range nq).drop 1) : q < nq ∧ 0 < q := by
  rw [List.mem_iff_getElem] at hq
  obtain ⟨i, hi, rfl⟩ := hq
  simp at hi ⊢; omega

theorem sortedTreeG_sound {ρ : ℕ → QM31} {zero one u shift uinv : ℕ} {logRegs : List ℕ}
    {b : ℕ} {samples : List ℕ} {ncols nq : ℕ} {bitsOf : ℕ → List ℕ} {root : List ℕ}
    {authOf : ℕ → List (List ℕ)} {n : ℕ}
    (logs : List ℕ) (x : ℕ → ℕ → F) {wr : List Blake2s.Word}
    (swsOf : ℕ → List (List Blake2s.Word))
    (hzero : ρ zero = 0) (hone : ρ one = 1) (hu : ρ u = uQ)
    (hshift : ρ shift = QM31.fromBase ((2 ^ b : ℕ) : F)) (huinv : ρ uinv = uQ⁻¹)
    (hb : 5 + b ≤ 30) (hm : logs.length ≤ 2 ^ b)
    (hlogs : ∀ c, c < logs.length → logs.getD c 0 < 2 ^ 5) (hnc : ncols = logs.length)
    (hlr : logRegs.length = logs.length)
    (hlrv : ∀ c, c < logs.length → ρ (logRegs.getD c 0) = QM31.fromBase ((logs.getD c 0 : ℕ) : F))
    (hnq : 0 < nq)
    (hx : ∀ c, c < ncols → ∀ q, q < nq → ρ (samples.getD (c * nq + q) 0) = QM31.fromBase (x c q))
    (hroot : RegsWords ρ root wr) (hr8 : wr.length = 8)
    (hsl : ∀ q, q < nq → (authOf q).length = (swsOf q).length)
    (hsibs : ∀ q, q < nq → ∀ i, i < (authOf q).length →
      RegsWords ρ ((authOf q).getD i []) ((swsOf q).getD i []) ∧ ((swsOf q).getD i []).length = 8)
    (hbits : ∀ q, q < nq → ∀ b ∈ bitsOf q, ρ b = 0 ∨ ρ b = 1)
    (h : AllHold ρ (sortedTreeG zero one u shift uinv logRegs b samples ncols nq bitsOf root
      authOf n).ops) :
    ∀ q, q < nq → wordsBytes wr = pathRoot (leafHash ((columnOrder logs).map fun c => x c q))
      ((bitsOf q).map fun b => qbit (ρ b)) ((swsOf q).map wordsBytes) := by
  unfold sortedTreeG at h
  set K := keysG u shift logRegs 0 n with hKdef
  rw [allHold_seq] at h
  obtain ⟨hK, h⟩ := h
  beta_reduce at h
  set C0 := sortCoreG one (qvals samples ncols nq 0) K.res K.next with hC0def
  rw [allHold_seq] at h
  obtain ⟨hC0, h⟩ := h
  beta_reduce at h
  rw [allHold_seq] at h
  obtain ⟨hV, h⟩ := h
  beta_reduce at h
  rw [allHold_seq] at h
  obtain ⟨hP0, hrest⟩ := h
  beta_reduce at hrest
  obtain ⟨hkl, hkv⟩ := keysG_sound hu hshift (fun c => logs.getD c 0) logRegs 0 n
    (fun k hk => by rw [Nat.zero_add]; exact hlrv k (by omega)) hK
  have hk : ∀ c, c < logs.length →
      ρ (K.res.getD c 0) = uQ * QM31.fromBase ((colKey logs b c : ℕ) : F) := by
    intro c hc
    rw [hkv c (by omega), Nat.zero_add]; rfl
  obtain ⟨hvl, hvv⟩ := qvals_sound hx hnq
  have hfirst := sortFirst_sound logs b (fun c => x c 0) hzero hone huinv hb hm hlogs
    (by rw [hvl, hnc]) (by rw [hkl, hlr]) (fun c hc => hvv c (by omega)) hk hC0 hV
  obtain ⟨-, hl1, hl2, -⟩ := sortCore_sound (x := fun c => x c 0)
    (K := fun c => ((colKey logs b c : ℕ) : F)) hone (by rw [hvl, hkl, hlr, hnc])
    (fun c hc => hvv c (by omega)) (fun c hc => hk c (by omega)) hC0
  intro q hq
  by_cases hq0 : q = 0
  · subst hq0
    refine queryPathG_sound (by
        rw [hl1, hvl, List.length_map,
          (ColumnOrder.columnOrder_perm logs).length_eq, List.length_range, hnc])
      (fun i hi => ?_) hroot hr8 (hsl 0 hnq) (hsibs 0 hnq) (hbits 0 hnq) hP0
    rw [hl1, hvl, hnc] at hi
    rw [(hfirst i hi).1, ord_row_getD logs (fun c => x c 0) hi]
  · exact sortedRestG_sound logs b x swsOf hone hb hm hlogs hnc (by rw [hkl, hlr])
      hk (fun k hk' => (hfirst k hk').2) hx hroot hr8 hsl hsibs hbits _ _
      (fun q' h' => (range_drop_mem h').1) hrest q
      (by rw [List.mem_iff_getElem]; exact ⟨q - 1, by simp; omega, by simp; omega⟩)

end StwoVerifier.Gadgets
