/-
**`collect_oods_responses`' layout is the spec's push-order pair list.**

The emitter lists, in order: every preprocessed and trace column at the
OODS point; per component, each plain interaction column at the OODS
point and each cumulative-sum column as `[periodicity, previous row,
OODS]` (the periodicity response carrying the OODS value); then the
composition columns. `respLayout` builds that list of response
registers with their flat column indices; `layout_pairs` proves its
flat view (global power `αʲ` at response `j`) **is** `circuitPairs` —
hence, by `treesPairs_circuit`, the spec's `treesPairs`, the
`horder` hypothesis of `deepComposite_spec`.
-/
import StwoVerifier.DeepComposite

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates Quotients

/-- A response list's flat view from global index `j`. -/
noncomputable def rpairs (ρ : ℕ → QM31) (α : QM31) :
    List (RespReg × ℕ) → ℕ → List (PointQ × NumeratorData)
  | [], _ => []
  | (r, fc) :: rest, j => (⟨ρ r.px, ρ r.py⟩, ⟨fc, ρ r.value, α ^ j⟩) :: rpairs ρ α rest (j + 1)

theorem rpairs_append (ρ : ℕ → QM31) (α : QM31) :
    ∀ (a b : List (RespReg × ℕ)) (j : ℕ),
      rpairs ρ α (a ++ b) j = rpairs ρ α a j ++ rpairs ρ α b (j + a.length)
  | [], b, j => by simp [rpairs]
  | (r, fc) :: rest, b, j => by
    simp only [List.cons_append, rpairs, rpairs_append ρ α rest b (j + 1), List.length_cons,
      List.cons_append]
    rw [show j + 1 + rest.length = j + (rest.length + 1) by omega]

/-- The whole list's flat view is `respPairs`. -/
theorem rpairs_eq_respPairs (ρ : ℕ → QM31) (α : QM31) (l : List (RespReg × ℕ)) :
    rpairs ρ α l 0 = respPairs ρ α (l.map Prod.fst) (l.map Prod.snd) := by
  suffices h : ∀ (l : List (RespReg × ℕ)) (j : ℕ) (pre : List (RespReg × ℕ)),
      pre.length = j →
      rpairs ρ α l j = ((l.map Prod.fst).zipIdx j).map fun p =>
        ((⟨ρ p.1.px, ρ p.1.py⟩ : PointQ),
          (⟨((pre ++ l).map Prod.snd).getD p.2 0, ρ p.1.value, α ^ p.2⟩ : NumeratorData)) by
    have := h l 0 [] rfl
    rw [this]
    unfold respPairs
    simp
  intro l
  induction l with
  | nil => intro j pre _; rfl
  | cons x rest ih =>
    intro j pre hpre
    obtain ⟨r, fc⟩ := x
    rw [rpairs, ih (j + 1) (pre ++ [(r, fc)]) (by simp [hpre])]
    simp only [List.map_cons, List.zipIdx_cons, List.cons.injEq]
    refine ⟨?_, ?_⟩
    · congr
      rw [List.getD_eq_getElem?_getD, List.map_append, List.getElem?_append_right
        (by simp [hpre]), ← hpre]
      simp
    · simp [List.append_assoc]

/-! ### The emitter's segments -/

/-- Single-sample columns at one point: one response each, consecutive
flat columns. -/
def singlesL (pt : PointReg) : List ℕ → ℕ → List (RespReg × ℕ)
  | [], _ => []
  | v :: rest, fc => (⟨pt.x, pt.y, v⟩, fc) :: singlesL pt rest (fc + 1)

/-- Cumulative-sum columns: periodicity (with the OODS value), previous
row, OODS — three responses per column. -/
def doublesL (oods prev period : PointReg) : List (ℕ × ℕ) → ℕ → List (RespReg × ℕ)
  | [], _ => []
  | (vp, vo) :: rest, fc =>
    (⟨period.x, period.y, vo⟩, fc) :: (⟨prev.x, prev.y, vp⟩, fc) :: (⟨oods.x, oods.y, vo⟩, fc)
      :: doublesL oods prev period rest (fc + 1)

/-- The interaction tree: per component, its plain columns then its
cumulative sums. -/
def interL (oods prev : PointReg) :
    List (PointReg × List ℕ × List (ℕ × ℕ) × ℕ) → ℕ → List (RespReg × ℕ)
  | [], _ => []
  | (period, sv, dv, _) :: rest, fc =>
    singlesL oods sv fc ++ doublesL oods prev period dv (fc + sv.length)
      ++ interL oods prev rest (fc + sv.length + dv.length)

/-- `collect_oods_responses`. -/
def respLayout (oods prev : PointReg) (ppAt traceAt : List ℕ)
    (inter : List (PointReg × List ℕ × List (ℕ × ℕ) × ℕ)) (compAt : List ℕ) :
    List (RespReg × ℕ) :=
  singlesL oods ppAt 0 ++ singlesL oods traceAt ppAt.length
    ++ interL oods prev inter (ppAt.length + traceAt.length)
    ++ singlesL oods compAt (ppAt.length + traceAt.length
      + (inter.map fun c => c.2.1.length + c.2.2.1.length).sum)

/-! ### Segment by segment -/

theorem singlesL_pairs (ρ : ℕ → QM31) (α : QM31) (pt : PointReg) (P : PointQ)
    (hp : pt.val ρ = P) :
    ∀ (vs : List ℕ) (fc j : ℕ),
      rpairs ρ α (singlesL pt vs fc) j = (singlesPairs α P (vs.map ρ) (α ^ j) fc).1 ∧
      (singlesPairs α P (vs.map ρ) (α ^ j) fc).2 = (α ^ (j + vs.length), fc + vs.length) ∧
      (singlesL pt vs fc).length = vs.length
  | [], fc, j => by simp [singlesL, rpairs, singlesPairs]
  | v :: rest, fc, j => by
    obtain ⟨ih1, ih2, ih3⟩ := singlesL_pairs ρ α pt P hp rest (fc + 1) (j + 1)
    have hpow : α ^ j * α = α ^ (j + 1) := (pow_succ α j).symm
    refine ⟨?_, ?_, ?_⟩
    · simp only [singlesL, rpairs, List.map_cons, singlesPairs, hpow, ih1]
      rw [← hp]; rfl
    · simp only [List.map_cons, singlesPairs, hpow, ih2, List.length_cons]
      rw [show j + 1 + rest.length = j + (rest.length + 1) by omega,
        show fc + 1 + rest.length = fc + (rest.length + 1) by omega]
    · simp [singlesL, ih3]

theorem doublesL_pairs (ρ : ℕ → QM31) (α : QM31) (step : PointF) (L : ℕ)
    (oods prev period : PointReg) (P Pp : PointQ)
    (ho : oods.val ρ = P) (hpv : prev.val ρ = Pp)
    (hper : period.val ρ = P.add (PointF.intoQ (step.repeatedDouble L))) :
    ∀ (dv : List (ℕ × ℕ)) (fc j : ℕ),
      rpairs ρ α (doublesL oods prev period dv fc) j
        = (doublesPairs step α P Pp (dv.map fun d => (ρ d.1, ρ d.2))
            (List.replicate dv.length L) (α ^ j) fc).1 ∧
      (doublesPairs step α P Pp (dv.map fun d => (ρ d.1, ρ d.2))
          (List.replicate dv.length L) (α ^ j) fc).2
        = (α ^ (j + 3 * dv.length), fc + dv.length) ∧
      (doublesL oods prev period dv fc).length = 3 * dv.length
  | [], fc, j => by simp [doublesL, rpairs, doublesPairs]
  | (vp, vo) :: rest, fc, j => by
    obtain ⟨ih1, ih2, ih3⟩ := doublesL_pairs ρ α step L oods prev period P Pp ho hpv hper
      rest (fc + 1) (j + 3)
    have hp1 : α ^ j * α = α ^ (j + 1) := (pow_succ α j).symm
    have hp2 : α ^ (j + 1) * α = α ^ (j + 1 + 1) := (pow_succ α (j + 1)).symm
    have hp3 : α ^ j * α ^ 3 = α ^ (j + 3) := (pow_add α j 3).symm
    refine ⟨?_, ?_, ?_⟩
    · simp only [doublesL, rpairs, List.map_cons, List.length_cons, List.replicate_succ,
        doublesPairs, hp1, hp2, hp3, ih1]
      rw [← hper, ← ho, ← hpv]
      rfl
    · simp only [List.map_cons, List.length_cons, List.replicate_succ, doublesPairs, hp3, ih2]
      rw [show j + 3 + 3 * rest.length = j + 3 * (rest.length + 1) by ring,
        show fc + 1 + rest.length = fc + (rest.length + 1) by omega]
    · simp [doublesL, ih3]; ring

theorem interL_pairs (ρ : ℕ → QM31) (α : QM31) (step : PointF)
    (oods prev : PointReg) (P Pp : PointQ) (ho : oods.val ρ = P) (hpv : prev.val ρ = Pp) :
    ∀ (cs : List (PointReg × List ℕ × List (ℕ × ℕ) × ℕ)),
      (∀ c ∈ cs, c.1.val ρ = P.add (PointF.intoQ (step.repeatedDouble c.2.2.2))) →
      ∀ (fc j : ℕ),
      rpairs ρ α (interL oods prev cs fc) j
        = (interTreePairs step α P Pp (cs.map fun c => (c.2.1.map ρ,
            c.2.2.1.map fun d => (ρ d.1, ρ d.2), c.2.2.2)) (α ^ j) fc).1 ∧
      (interTreePairs step α P Pp (cs.map fun c => (c.2.1.map ρ,
          c.2.2.1.map fun d => (ρ d.1, ρ d.2), c.2.2.2)) (α ^ j) fc).2
        = (α ^ (j + (interL oods prev cs fc).length),
           fc + (cs.map fun c => c.2.1.length + c.2.2.1.length).sum)
  | [], _, fc, j => by simp [interL, rpairs, interTreePairs]
  | (period, sv, dv, L) :: rest, hper, fc, j => by
    obtain ⟨s1, s2, s3⟩ := singlesL_pairs ρ α oods P ho sv fc j
    obtain ⟨d1, d2, d3⟩ := doublesL_pairs ρ α step L oods prev period P Pp ho hpv
      (hper _ List.mem_cons_self) dv (fc + sv.length) (j + sv.length)
    obtain ⟨i1, i2⟩ := interL_pairs ρ α step oods prev P Pp ho hpv rest
      (fun c hc => hper c (List.mem_cons_of_mem _ hc))
      (fc + sv.length + dv.length) (j + sv.length + 3 * dv.length)
    have hcomp : componentPairs step α P Pp (sv.map ρ) (dv.map fun d => (ρ d.1, ρ d.2)) L
        (α ^ j) fc
        = ((singlesPairs α P (sv.map ρ) (α ^ j) fc).1 ++
            (doublesPairs step α P Pp (dv.map fun d => (ρ d.1, ρ d.2))
              (List.replicate dv.length L) (α ^ (j + sv.length)) (fc + sv.length)).1,
           (α ^ (j + sv.length + 3 * dv.length), fc + sv.length + dv.length)) := by
      unfold componentPairs
      dsimp only
      rw [s2]
      simp only [List.length_map]
      rw [d2]
    refine ⟨?_, ?_⟩
    · simp only [interL, List.map_cons, interTreePairs, hcomp, rpairs_append, s1, d1, s3, d3,
        List.length_append]
      rw [show j + (sv.length + 3 * dv.length) = j + sv.length + 3 * dv.length by ring] at *
      rw [← i1]
      try simp [List.append_assoc]
    · simp only [interL, List.map_cons, interTreePairs, hcomp, i2, List.length_append, s3, d3,
        List.sum_cons]
      rw [show j + sv.length + 3 * dv.length + (interL oods prev rest
          (fc + sv.length + dv.length)).length
          = j + (sv.length + 3 * dv.length + (interL oods prev rest
          (fc + sv.length + dv.length)).length) by ring,
        show fc + sv.length + dv.length + (rest.map fun c => c.2.1.length + c.2.2.1.length).sum
          = fc + (sv.length + dv.length + (rest.map fun c => c.2.1.length + c.2.2.1.length).sum)
          by ring]

/-- **The response layout's flat view is `circuitPairs`.** -/
theorem layout_pairs (ρ : ℕ → QM31) (α : QM31) (step : PointF)
    (oods prev : PointReg) (P Pp : PointQ) (ho : oods.val ρ = P) (hpv : prev.val ρ = Pp)
    (ppAt traceAt compAt : List ℕ) (inter : List (PointReg × List ℕ × List (ℕ × ℕ) × ℕ))
    (hper : ∀ c ∈ inter, c.1.val ρ = P.add (PointF.intoQ (step.repeatedDouble c.2.2.2))) :
    rpairs ρ α (respLayout oods prev ppAt traceAt inter compAt) 0
      = (circuitPairs step α P Pp (ppAt.map ρ) (traceAt.map ρ)
          (inter.map fun c => (c.2.1.map ρ, c.2.2.1.map fun d => (ρ d.1, ρ d.2), c.2.2.2))
          (compAt.map ρ) 1 0).1 := by
  obtain ⟨a1, a2, a3⟩ := singlesL_pairs ρ α oods P ho ppAt 0 0
  obtain ⟨b1, b2, b3⟩ := singlesL_pairs ρ α oods P ho traceAt ppAt.length ppAt.length
  obtain ⟨c1, c2⟩ := interL_pairs ρ α step oods prev P Pp ho hpv inter hper
    (ppAt.length + traceAt.length) (ppAt.length + traceAt.length)
  obtain ⟨d1, -, -⟩ := singlesL_pairs ρ α oods P ho compAt
    (ppAt.length + traceAt.length + (inter.map fun c => c.2.1.length + c.2.2.1.length).sum)
    (ppAt.length + traceAt.length + (interL oods prev inter
      (ppAt.length + traceAt.length)).length)
  rw [pow_zero] at a1 a2
  unfold circuitPairs respLayout
  dsimp only
  rw [a2]
  dsimp only
  simp only [Nat.zero_add] at a2 a3 b1 b2 ⊢
  rw [b2]
  dsimp only
  rw [c2]
  dsimp only
  rw [rpairs_append, rpairs_append, rpairs_append, a1]
  simp only [Nat.zero_add, List.length_append, a3, b3]
  rw [b1, c1, d1]
  simp only [List.append_assoc]

end StwoVerifier.Gadgets
