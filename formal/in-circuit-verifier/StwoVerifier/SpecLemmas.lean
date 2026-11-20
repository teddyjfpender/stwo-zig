/-
**Spec-side lemmas for the assembly proofs**, enabled by the functional
refactor of the verifier spec's loops.

At the pinned profile `log_last_layer_degree_bound = 0`, the last-layer
polynomial is a single coefficient, so the spec's last-layer check is
exactly "every remaining evaluation equals that coefficient" — which is
the in-circuit decommit's final battery of `eq` gates.
-/
import StwoVerifier.Fri

namespace StwoVerifier.SpecLemmas

open StwoVerifier

/-- A singleton `LinePoly` is the constant polynomial. -/
theorem linePolyEval_singleton (c x : QM31) : linePolyEval [c] x = c := rfl

/-- At last-layer degree bound 0, the spec's check is pointwise equality
with the constant coefficient (given matching lengths). -/
theorem lastLayerCheck_const (c : Fri.Committed) (c0 : QM31)
    (hpoly : c.lastLayerPoly = [c0])
    (positions : List Nat) (evals : List QM31)
    (hlen : positions.length = evals.length) :
    Fri.lastLayerCheck c positions evals = .ok ()
      ↔ ∀ e ∈ evals, e = c0 := by
  unfold Fri.lastLayerCheck
  rw [if_neg (by omega)]
  constructor
  · intro h e he
    by_contra hne
    rw [if_pos ?_] at h
    · exact absurd h (by simp)
    · rw [List.any_eq_true]
      obtain ⟨i, hi, rfl⟩ := List.getElem_of_mem he
      refine ⟨(positions.getD i 0, evals[i]), ?_, ?_⟩
      · have : (positions.zip evals)[i]? = some (positions.getD i 0, evals[i]) := by
          rw [List.getElem?_zip_eq_some]
          refine ⟨?_, ?_⟩
          · rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by omega)]
            rfl
          · exact List.getElem?_eq_getElem hi
        exact List.mem_of_getElem? this
      · simp only [decide_eq_true_eq]
        rw [hpoly, linePolyEval_singleton]
        exact hne
  · intro h
    rw [if_neg ?_]
    · rfl
    · intro hany
      rw [List.any_eq_true] at hany
      obtain ⟨pe, hmem, hviol⟩ := hany
      simp only [decide_eq_true_eq] at hviol
      apply hviol
      rw [hpoly, linePolyEval_singleton]
      exact h pe.2 (List.of_mem_zip hmem).2

/-- `commitInner` shape: on success, the committed layers pair the proof
layers one-to-one in order, and the degree bound drops by the per-layer
fold step — at the pinned fold step 1, by exactly one per layer. -/
theorem commitInner_shape (m31 : Bool) (config : Fri.FriConfig)
    (hfold : config.foldStep = 1) :
    ∀ (ps : List Fri.FriLayerProof) (bound : Nat) (domain : LineDomain)
      (s : Channel.St)
      {layers : List (LineDomain × QM31 × Fri.FriLayerProof)}
      {bound' : Nat} {domain' : LineDomain} {sOut : Channel.St},
      Fri.commitInner m31 config ps bound domain s
        = .ok (layers, bound', domain', sOut) →
      layers.map (fun l => l.2.2) = ps ∧ bound' + ps.length = bound := by
  intro ps
  induction ps with
  | nil =>
    intro bound domain s layers bound' domain' sOut h
    rw [Fri.commitInner] at h
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨hl, hb, -, -⟩ := h
    exact ⟨by rw [← hl]; rfl, by simpa using hb.symm⟩
  | cons p rest ih =>
    intro bound domain s layers bound' domain' sOut h
    rw [Fri.commitInner] at h
    split at h
    · simp at h
    · split at h
      · simp at h
      · split at h
        · simp at h
        · split at h
          · simp at h
          · split at h
            · simp at h
            · rename_i hrec
              simp only [Except.ok.injEq, Prod.mk.injEq] at h
              obtain ⟨hl, hb, -, -⟩ := h
              obtain ⟨hmap, hbd⟩ := ih _ _ _ hrec
              constructor
              · rw [← hl]
                simp [hmap]
              · simp only [List.length_cons]
                omega

/-- `commitInner` domains: at the pinned fold step 1 and last-layer
degree bound 0, the stored layer domains are the successive doubles of
the initial line domain, in order. -/
theorem commitInner_domains (m31 : Bool) (config : Fri.FriConfig)
    (hfold : config.foldStep = 1) (hlast : config.logLastLayerDegreeBound = 0) :
    ∀ (ps : List Fri.FriLayerProof) (bound : Nat) (domain : LineDomain)
      (s : Channel.St)
      {layers : List (LineDomain × QM31 × Fri.FriLayerProof)}
      {bound' : Nat} {domain' : LineDomain} {sOut : Channel.St},
      Fri.commitInner m31 config ps bound domain s
        = .ok (layers, bound', domain', sOut) →
      layers.map Prod.fst
        = (List.range ps.length).map fun i => LineDomain.double^[i] domain := by
  intro ps
  induction ps with
  | nil =>
    intro bound domain s layers bound' domain' sOut h
    rw [Fri.commitInner] at h
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨hl, -, -, -⟩ := h
    rw [← hl]
    rfl
  | cons p rest ih =>
    intro bound domain s layers bound' domain' sOut h
    rw [Fri.commitInner] at h
    split at h
    · simp at h
    · split at h
      · simp at h
      · split at h
        · simp at h
        · split at h
          · simp at h
          · split at h
            · simp at h
            · rename_i hrec
              rw [hfold, hlast] at hrec
              have hone : min 1 (bound - 0) = 1 := by omega
              rw [hone] at hrec
              rw [show ((List.range 1).foldl
                (fun d _ => LineDomain.double d) domain)
                = domain.double from rfl] at hrec
              simp only [Except.ok.injEq, Prod.mk.injEq] at h
              obtain ⟨hl, -, -, -⟩ := h
              have hmap := ih _ _ _ hrec
              rw [← hl]
              simp only [List.map_cons, List.length_cons,
                List.range_succ_eq_map, List.map_map]
              refine congrArg (domain :: ·) ?_
              rw [hmap]
              refine List.map_congr_left fun i _ => ?_
              show LineDomain.double^[i] domain.double = _
              rw [Function.comp_apply, ← Function.iterate_succ_apply]

end StwoVerifier.SpecLemmas
