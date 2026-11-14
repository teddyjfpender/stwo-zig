/-
**Spec-side glue for the scope-B assembly.**

* `friAnswers_select`: the DEEP answers are row-local, so the answers at
  the unique positions (with each column restricted to a representative
  raw query) are the raw answers at the representatives.
* `commitInner_ok` / `friCommit_ok`: the FRI commit transcript, at the
  pinned fold step 1 and last-layer bound 0, is the circuit's `friTr`
  root/alpha loop plus the last-layer mix.
* `pcsCommit_ok`: `Pcs.commit` under its height law.
-/
import StwoVerifier.SpecRow
import StwoVerifier.Pcs
import StwoVerifier.TranscriptGadgets

namespace StwoVerifier.SpecGlue

open StwoVerifier Quotients

/-! ### DEEP answers at the unique positions -/

theorem batchTerm_congr (b : SampleBatch) {F1 F2 : List (List F)} {r1 r2 : ℕ} (p : PointF)
    (h : ∀ ci, (F1.getD ci []).getD r1 0 = (F2.getD ci []).getD r2 0) :
    batchTerm b F1 r1 p = batchTerm b F2 r2 p := by
  unfold batchTerm
  congr 2
  refine List.map_congr_left fun e _ => ?_
  rw [h]

theorem zipIdx_map_getD {α β : Type} (f : α × ℕ → β) (l : List α) (d : β) (dα : α) {k : ℕ}
    (hk : k < l.length) : (l.zipIdx.map f).getD k d = f (l.getD k dα, k) := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_zipIdx,
    List.getElem?_eq_getElem hk, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hk]
  simp

set_option maxHeartbeats 1600000 in
/-- **DEEP answers at the unique positions** are the raw answers at
representative raw queries. -/
theorem friAnswers_select (cls : List (List ℕ)) (sp : List (List (List PointQ)))
    (sv : List (List (List QM31))) (α : QM31) (ps uniq : List ℕ)
    (Q QU : List (List (List F))) (L : ℕ) (batches : List SampleBatch) (rows : List QM31)
    (rep : ℕ → ℕ)
    (hbuild : buildSampleBatches sp sv cls L α = .ok batches)
    (him : ∀ b ∈ batches, Deep.imQ b.point.y ≠ 0)
    (hidx : ∀ b ∈ batches, ∀ e ∈ b.entries, e.columnIndex < Q.flatten.length)
    (hden : ∀ b ∈ batches, ∀ pos : ℕ,
      denominator b.point ((canonicDomain L).at' (bitReverseIndex pos L)) ≠ 0)
    (hcols : ∀ col ∈ Q.flatten, col.length = ps.length)
    (hpos : ∀ pos ∈ ps, pos < (canonicDomain L).size)
    (hraw : friAnswers cls sp sv α ps Q L = .ok rows)
    (hflen : QU.flatten.length = Q.flatten.length)
    (hcolsU : ∀ col ∈ QU.flatten, col.length = uniq.length)
    (hrep : ∀ k, k < uniq.length → rep k < ps.length ∧ ps.getD (rep k) 0 = uniq.getD k 0)
    (hval : ∀ k, k < uniq.length → ∀ ci,
      (QU.flatten.getD ci []).getD k 0 = (Q.flatten.getD ci []).getD (rep k) 0) :
    friAnswers cls sp sv α uniq QU L
      = .ok ((List.range uniq.length).map fun k => rows.getD (rep k) 0) := by
  have hposU : ∀ pos ∈ uniq, pos < (canonicDomain L).size := by
    intro pos hp
    obtain ⟨k, hk, rfl⟩ := List.getElem_of_mem hp
    obtain ⟨hr, he⟩ := hrep k hk
    rw [← List.getD_eq_getElem uniq 0 hk, ← he]
    apply hpos
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hr]
    exact List.getElem_mem _
  rw [friAnswers_ok cls sp sv α uniq QU L batches hbuild hcolsU him
    (fun b hb e he => by rw [hflen]; exact hidx b hb e he) hposU
    (fun b hb pos _ => hden b hb pos)]
  rw [friAnswers_ok cls sp sv α ps Q L batches hbuild hcols him hidx hpos
    (fun b hb pos _ => hden b hb pos)] at hraw
  have hrows := (Except.ok.inj hraw).symm
  congr 1
  refine List.ext_getElem (by simp) fun k h1 h2 => ?_
  have hk : k < uniq.length := by simpa using h1
  obtain ⟨hr, he⟩ := hrep k hk
  have hr' : ((List.range uniq.length).map fun k => rows.getD (rep k) 0).getD k 0
      = rows.getD (rep k) 0 := by
    rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range hk]; rfl
  rw [← List.getD_eq_getElem _ 0 h1, ← List.getD_eq_getElem _ 0 h2, hr',
    zipIdx_map_getD _ uniq 0 0 hk, hrows, zipIdx_map_getD _ ps 0 0 hr]
  have he' : uniq.getD k 0 = ps.getD (rep k) 0 := he.symm
  simp only [List.getD_eq_getElem?_getD] at he' ⊢
  rw [he']
  congr 1
  refine List.map_congr_left fun b _ => ?_
  exact batchTerm_congr b _ (hval k hk)

/-! ### The FRI commit transcript -/

/-- A placeholder layer proof (for `getD`). -/
def dummyLP : Fri.FriLayerProof := ⟨[], [], []⟩

open Gadgets in
theorem commitInner_ok (cfg : Fri.FriConfig) (hf : cfg.foldStep = 1)
    (hl0 : cfg.logLastLayerDegreeBound = 0) :
    ∀ (ps : List Fri.FriLayerProof) (bound : ℕ) (dom : LineDomain) (s : Channel.St),
      ps.length ≤ bound → (friTr s (ps.map (·.commitment))).1.length = ps.length →
      Fri.commitInner true cfg ps bound dom s = .ok
        ((List.range ps.length).map (fun i => (LineDomain.double^[i] dom,
            (friTr s (ps.map (·.commitment))).1.getD i 0, ps.getD i dummyLP)),
         bound - ps.length, LineDomain.double^[ps.length] dom,
         (friTr s (ps.map (·.commitment))).2)
  | [], bound, dom, s, _, _ => by simp [Fri.commitInner, friTr]
  | p :: rest, bound, dom, s, hb, hlen => by
    simp only [List.map_cons, friTr] at hlen ⊢
    cases hd : Channel.drawSecureFelt true (Channel.mixRoot true s p.commitment) with
    | none => rw [hd] at hlen; simp at hlen
    | some r =>
      obtain ⟨a, s2⟩ := r
      rw [hd] at hlen
      rw [Fri.commitInner, hd]
      simp only [List.length_cons, Nat.add_right_cancel_iff] at hlen
      simp only [List.length_cons] at hb
      have ih := commitInner_ok cfg hf hl0 rest (bound - 1) dom.double s2 (by omega) hlen
      simp only [hf, hl0, Nat.sub_zero]
      rw [if_neg (by omega), if_neg (by omega), if_neg (by omega),
        show min 1 bound = 1 by omega]
      simp only [List.range_one, List.foldl_cons, List.foldl_nil]
      rw [ih]
      simp only [List.length_cons, Except.ok.injEq, Prod.mk.injEq]
      refine ⟨?_, by omega, by rw [Function.iterate_succ_apply], trivial⟩
      rw [List.range_succ_eq_map, List.map_cons, List.map_map]
      congr 1

open Gadgets in
/-- **`Fri.commit` on the circuit's FRI transcript.** -/
theorem friCommit_ok (s : Channel.St) (cfg : Fri.FriConfig) (hf : cfg.foldStep = 1)
    (hl0 : cfg.logLastLayerDegreeBound = 0) (hbl : cfg.logBlowupFactor = 1)
    (proof : Fri.FriProof) (B : ℕ) (hB : 1 ≤ B)
    (hlen : proof.innerLayers.length = B - 1)
    (htr : (friTr s ((proof.firstLayer :: proof.innerLayers).map (·.commitment))).1.length
      = proof.innerLayers.length + 1)
    (hpoly : proof.lastLayerPoly.length ≤ 1) :
    Fri.commit true s cfg proof B = .ok
      (⟨cfg, canonicDomain (B + 1),
        (friTr s ((proof.firstLayer :: proof.innerLayers).map (·.commitment))).1.getD 0 0,
        proof.firstLayer,
        (List.range (B - 1)).map (fun i => (LineDomain.double^[i] ⟨Coset.halfOdds B⟩,
          (friTr s ((proof.firstLayer :: proof.innerLayers).map (·.commitment))).1.getD (i + 1) 0,
          proof.innerLayers.getD i dummyLP)),
        LineDomain.double^[B - 1] ⟨Coset.halfOdds B⟩, proof.lastLayerPoly⟩,
       Channel.mixFelts true
         (friTr s ((proof.firstLayer :: proof.innerLayers).map (·.commitment))).2
         proof.lastLayerPoly) := by
  simp only [List.map_cons, friTr] at htr ⊢
  cases hd : Channel.drawSecureFelt true (Channel.mixRoot true s proof.firstLayer.commitment) with
  | none => rw [hd] at htr; simp at htr
  | some r =>
    obtain ⟨a0, s1⟩ := r
    rw [hd] at htr
    simp only [List.length_cons, Nat.add_right_cancel_iff] at htr
    have hci := commitInner_ok cfg hf hl0 proof.innerLayers (B - 1)
      ⟨Coset.halfOdds (B - 1 + 1)⟩ s1 (by omega) htr
    unfold Fri.commit
    rw [if_neg (by omega), hbl, hf]
    simp only [pure, Except.pure, bind, Except.bind]
    rw [hd]
    simp only []
    rw [if_neg (by omega), hci, hlen, show B - 1 - (B - 1) = 0 by omega, hl0]
    simp only [ne_eq, not_true_eq_false, if_false, pow_zero]
    rw [if_neg (by omega), show B - 1 + 1 = B by omega]
    rfl

/-! ### PCS commit -/

theorem pcsCommit_ok (m31 : Bool) (config : Pcs.PcsConfig) (trees : List Pcs.Tree)
    (s : Channel.St) (root : Channel.Bytes) (logSizes : List ℕ) (hne : logSizes ≠ [])
    (hall : ∀ l ∈ logSizes, l + config.logBlowupFactor ≤ config.liftingLogSize trees.length) :
    Pcs.commit m31 config trees s root logSizes = .ok
      (trees ++ [⟨root, logSizes.map (· + config.logBlowupFactor),
        config.liftingLogSize trees.length⟩], Channel.mixRoot m31 s root) := by
  unfold Pcs.commit
  have h1 : ¬ ((logSizes.map (· + config.logBlowupFactor)).isEmpty = true ∧
      config.liftingLogSize trees.length ≠ 0) := by
    rintro ⟨he, -⟩
    exact hne (List.map_eq_nil_iff.mp (List.isEmpty_iff.mp he))
  have h2 : (logSizes.map (· + config.logBlowupFactor)).any
      (· > config.liftingLogSize trees.length) = false := by
    rw [List.any_eq_false]
    intro x hx
    obtain ⟨l, hl, rfl⟩ := List.mem_map.mp hx
    simpa using hall l hl
  simp only [h1, h2, if_false, pure, Except.pure, bind, Except.bind]
  rfl

end StwoVerifier.SpecGlue
