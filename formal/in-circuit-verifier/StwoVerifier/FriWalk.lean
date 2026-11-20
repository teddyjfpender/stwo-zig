/-
**`fri_decommit`'s layer walk at the pinned fold step 1**
(`src/frontends/circuit/stark_verifier/fri.zig` `friDecommit`,
stwo-zig `4afa09dbf`).

Per layer and query, the circuit checks the incoming layer value sits
at its bit-selected position in the guessed coset
(`validate_query_position_in_coset`, cosets of width 2 at fold step 1),
Merkle-verifies the coset (the Blake2s gadget — outside this file), and
folds the coset into the next layer's value (`fold_coset`, one
`ibutterfly`). `Chain1` is the value-flow relation this enforces;
`friLayers1_sound` derives it from the gates, and `friDecommit1_sound`
appends the last-layer `eq` battery, yielding the spec's
`lastLayerCheck` on the final values.
-/
import StwoVerifier.FriGadgets
import StwoVerifier.SelectByIndex

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-- One query in one fold-step-1 layer: the select check against the
incoming value, then the fold of the witness pair. -/
def layerQuery1 (one w0 w1 bit layerVal twiddle alpha n : ℕ) : Out ℕ :=
  let v := validateQueryInCoset one [w0, w1] [bit] layerVal n
  let f := foldCoset1 w0 w1 twiddle alpha v.next
  ⟨v.ops ++ f.ops, f.res, f.next⟩

/-- The incoming value is the bit-selected coset entry, and the output
register folds the pair (the spec's `foldLinePair`). -/
theorem layerQuery1_sound {ρ : ℕ → QM31}
    {one w0 w1 bit layerVal twiddle alpha n : ℕ} {x : F}
    (hone : ρ one = 1) (hbit : ρ bit = 0 ∨ ρ bit = 1)
    (htw : ρ twiddle * QM31.fromBase x = 1)
    (h : AllHold ρ (layerQuery1 one w0 w1 bit layerVal twiddle alpha n).ops) :
    ρ layerVal = (if ρ bit = 0 then ρ w0 else ρ w1) ∧
    Fri.foldLinePair (ρ w0) (ρ w1) (ρ alpha) x
      = .ok (ρ (layerQuery1 one w0 w1 bit layerVal twiddle alpha n).res) := by
  unfold layerQuery1 at h
  rw [allHold_append] at h
  obtain ⟨hv, hf⟩ := h
  have hsel := validateQueryInCoset_sound hone
    (by rfl : ([w0, w1] : List ℕ).length = 2 ^ ([bit] : List ℕ).length)
    (by intro b hb; rw [List.mem_singleton.mp hb]; exact hbit) hv
  have hfold := foldCoset1_sound htw hf
  refine ⟨?_, hfold⟩
  rw [hsel]
  by_cases hb : ρ bit = 0
  · rw [if_pos hb]
    show ρ ([w0, w1].getD ((if ρ bit = 0 then 0 else 1) + 2 * idxOf ρ []) 0) = _
    rw [if_pos hb]
    rfl
  · rw [if_neg hb]
    show ρ ([w0, w1].getD ((if ρ bit = 0 then 0 else 1) + 2 * idxOf ρ []) 0) = _
    rw [if_neg hb]
    rfl

/-- One layer's query loop: per query `(w0, w1, bit, twiddle)` with its
incoming value register, emit the select check and the fold. -/
def layerFold1 (one alpha : ℕ) :
    List ((ℕ × ℕ × ℕ × ℕ) × ℕ) → ℕ → Out (List ℕ)
  | [], n => ⟨[], [], n⟩
  | ((w0, w1, bit, tw), lv) :: rest, n =>
    let q := layerQuery1 one w0 w1 bit lv tw alpha n
    let t := layerFold1 one alpha rest q.next
    ⟨q.ops ++ t.ops, q.res :: t.res, t.next⟩

/-- Per-query facts for one layer. -/
theorem layerFold1_sound {ρ : ℕ → QM31} {one alpha : ℕ} (hone : ρ one = 1) :
    ∀ (qs : List ((ℕ × ℕ × ℕ × ℕ) × ℕ)) (xs : List F) (n : ℕ),
      (∀ i, i < qs.length →
        (ρ (qs.getD i default).1.2.2.1 = 0 ∨ ρ (qs.getD i default).1.2.2.1 = 1)) →
      (∀ i, i < qs.length →
        ρ (qs.getD i default).1.2.2.2 * QM31.fromBase (xs.getD i 0) = 1) →
      AllHold ρ (layerFold1 one alpha qs n).ops →
      (layerFold1 one alpha qs n).res.length = qs.length ∧
      ∀ i, i < qs.length →
        (ρ (qs.getD i default).2
          = (if ρ (qs.getD i default).1.2.2.1 = 0
             then ρ (qs.getD i default).1.1 else ρ (qs.getD i default).1.2.1)) ∧
        Fri.foldLinePair (ρ (qs.getD i default).1.1)
          (ρ (qs.getD i default).1.2.1) (ρ alpha) (xs.getD i 0)
          = .ok (ρ ((layerFold1 one alpha qs n).res.getD i 0)) := by
  intro qs
  induction qs with
  | nil =>
    intro xs n _ _ _
    exact ⟨rfl, fun i hi => by simp at hi⟩
  | cons qlv rest ih =>
    intro xs n hbits htws h
    obtain ⟨⟨w0, w1, bit, tw⟩, lv⟩ := qlv
    rw [show (layerFold1 one alpha (((w0, w1, bit, tw), lv) :: rest) n).ops =
      (layerQuery1 one w0 w1 bit lv tw alpha n).ops ++
        (layerFold1 one alpha rest
          (layerQuery1 one w0 w1 bit lv tw alpha n).next).ops from rfl,
      allHold_append] at h
    obtain ⟨hq, hrest⟩ := h
    have hhead := layerQuery1_sound hone
      (by simpa using hbits 0 (by simp)) (by simpa using htws 0 (by simp)) hq
    have hbits' : ∀ i, i < rest.length →
        (ρ (rest.getD i default).1.2.2.1 = 0 ∨
          ρ (rest.getD i default).1.2.2.1 = 1) := by
      intro i hi
      have := hbits (i + 1) (by simpa using Nat.succ_lt_succ hi)
      simpa using this
    have htws' : ∀ i, i < rest.length →
        ρ (rest.getD i default).1.2.2.2
          * QM31.fromBase (xs.tail.getD i 0) = 1 := by
      intro i hi
      have := htws (i + 1) (by simpa using Nat.succ_lt_succ hi)
      rw [List.getD_cons_succ] at this
      rwa [show xs.getD (i + 1) 0 = xs.tail.getD i 0 from by
        cases xs <;> simp]
      at this
    obtain ⟨ihlen, ihval⟩ := ih xs.tail
      (layerQuery1 one w0 w1 bit lv tw alpha n).next hbits' htws' hrest
    refine ⟨?_, fun i hi => ?_⟩
    · show (layerFold1 one alpha rest
        (layerQuery1 one w0 w1 bit lv tw alpha n).next).res.length + 1
        = rest.length + 1
      rw [ihlen]
    · cases i with
      | zero =>
        refine ⟨hhead.1, ?_⟩
        show Fri.foldLinePair (ρ w0) (ρ w1) (ρ alpha) (xs.getD 0 0)
          = .ok (ρ (layerQuery1 one w0 w1 bit lv tw alpha n).res)
        exact hhead.2
      | succ i =>
        have hi' : i < rest.length := by simpa using hi
        obtain ⟨hs, hf⟩ := ihval i hi'
        refine ⟨hs, ?_⟩
        show Fri.foldLinePair (ρ (rest.getD i default).1.1)
            (ρ (rest.getD i default).1.2.1) (ρ alpha) (xs.getD (i + 1) 0)
          = .ok (ρ ((layerFold1 one alpha rest
              (layerQuery1 one w0 w1 bit lv tw alpha n).next).res.getD i 0))
        rw [show xs.getD (i + 1) 0 = xs.tail.getD i 0 from by
          cases xs <;> simp]
        exact hf

/-- The per-layer value-flow relation the gates enforce: each layer's
incoming values are bit-selected from the witness cosets, which fold
(at the layer's twiddle points) into the next layer's values. -/
inductive Chain1 (ρ : ℕ → QM31) :
    List (ℕ × List (ℕ × ℕ × ℕ × ℕ)) → List (List F) → List ℕ → List ℕ → Prop
  | nil : ∀ vals, Chain1 ρ [] [] vals vals
  | cons : ∀ alpha qs xs rest xss vals nxt out,
      qs.length = vals.length →
      nxt.length = qs.length →
      (∀ i, i < qs.length →
        ρ (vals.getD i 0)
          = (if ρ ((qs.getD i default).2.2.1) = 0
             then ρ (qs.getD i default).1
             else ρ (qs.getD i default).2.1)) →
      (∀ i, i < qs.length →
        Fri.foldLinePair (ρ (qs.getD i default).1)
          (ρ (qs.getD i default).2.1) (ρ alpha) (xs.getD i 0)
          = .ok (ρ (nxt.getD i 0))) →
      Chain1 ρ rest xss nxt out →
      Chain1 ρ ((alpha, qs) :: rest) (xs :: xss) vals out

/-- The multi-layer walk: fold each layer's cosets, threading the value
registers. -/
def friLayers1 (one : ℕ) :
    List (ℕ × List (ℕ × ℕ × ℕ × ℕ)) → List ℕ → ℕ → Out (List ℕ)
  | [], vals, n => ⟨[], vals, n⟩
  | (alpha, qs) :: rest, vals, n =>
    let l := layerFold1 one alpha (qs.zip vals) n
    let t := friLayers1 one rest l.res l.next
    ⟨l.ops ++ t.ops, t.res, t.next⟩

/-- `getD` through a `zip`, inside both lengths. -/
theorem zip_getD {α β : Type} [Inhabited α] [Inhabited β]
    (l1 : List α) (l2 : List β) (i : ℕ)
    (h1 : i < l1.length) (h2 : i < l2.length) :
    (l1.zip l2).getD i default = (l1.getD i default, l2.getD i default) := by
  rw [List.getD_eq_getElem?_getD,
    show (l1.zip l2)[i]? = some (l1[i], l2[i]) from
      List.getElem?_zip_eq_some.2
        ⟨List.getElem?_eq_getElem h1, List.getElem?_eq_getElem h2⟩,
    List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h1,
    List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h2]
  rfl

set_option maxHeartbeats 800000 in
/-- **The gates enforce the layer chain.** With boolean bit registers
and gate-inverted twiddles at the per-layer fold points, the walk's
`AllHold` yields `Chain1` from the input values to the output
registers, which number `nQ` throughout. -/
theorem friLayers1_sound {ρ : ℕ → QM31} {one nQ : ℕ} (hone : ρ one = 1) :
    ∀ (layers : List (ℕ × List (ℕ × ℕ × ℕ × ℕ))) (xss : List (List F))
      (vals : List ℕ) (n : ℕ),
      layers.length = xss.length →
      vals.length = nQ →
      (∀ l, l < layers.length → (layers.getD l default).2.length = nQ) →
      (∀ l, l < layers.length → ∀ i, i < nQ →
        (ρ ((layers.getD l default).2.getD i default).2.2.1 = 0 ∨
         ρ ((layers.getD l default).2.getD i default).2.2.1 = 1)) →
      (∀ l, l < layers.length → ∀ i, i < nQ →
        ρ ((layers.getD l default).2.getD i default).2.2.2
          * QM31.fromBase ((xss.getD l []).getD i 0) = 1) →
      AllHold ρ (friLayers1 one layers vals n).ops →
      Chain1 ρ layers xss vals (friLayers1 one layers vals n).res ∧
      (friLayers1 one layers vals n).res.length = nQ := by
  intro layers
  induction layers with
  | nil =>
    intro xss vals n hlx hv _ _ _ _
    cases xss with
    | nil => exact ⟨Chain1.nil vals, hv⟩
    | cons xs xss => simp at hlx
  | cons lay rest ih =>
    intro xss vals n hlx hv hql hbits htws h
    obtain ⟨alpha, qs⟩ := lay
    cases xss with
    | nil => simp at hlx
    | cons xs xss =>
      rw [show (friLayers1 one ((alpha, qs) :: rest) vals n).ops =
        (layerFold1 one alpha (qs.zip vals) n).ops ++
          (friLayers1 one rest (layerFold1 one alpha (qs.zip vals) n).res
            (layerFold1 one alpha (qs.zip vals) n).next).ops from rfl,
        allHold_append] at h
      obtain ⟨hl, hrest⟩ := h
      have hq : qs.length = nQ := by
        have := hql 0 (by simp)
        simpa using this
      have hzlen : (qs.zip vals).length = nQ := by
        rw [List.length_zip, hq, hv, Nat.min_self]
      have hzget : ∀ i, i < nQ →
          (qs.zip vals).getD i default
            = (qs.getD i default, vals.getD i default) := by
        intro i hi
        exact zip_getD qs vals i (by rw [hq]; exact hi) (by rw [hv]; exact hi)
      obtain ⟨hflen, hfval⟩ := layerFold1_sound hone (qs.zip vals) xs n
        (by
          intro i hi
          rw [hzlen] at hi
          rw [hzget i hi]
          exact hbits 0 (by simp) i (by simpa using hi))
        (by
          intro i hi
          rw [hzlen] at hi
          rw [hzget i hi]
          exact htws 0 (by simp) i (by simpa using hi))
        hl
      have hnlen : (layerFold1 one alpha (qs.zip vals) n).res.length = nQ := by
        rw [hflen, hzlen]
      obtain ⟨ihchain, ihlen⟩ := ih xss
        (layerFold1 one alpha (qs.zip vals) n).res
        (layerFold1 one alpha (qs.zip vals) n).next
        (by simpa using hlx) hnlen
        (fun l hl' => hql (l + 1) (by simpa using Nat.succ_lt_succ hl'))
        (fun l hl' => hbits (l + 1) (by simpa using Nat.succ_lt_succ hl'))
        (fun l hl' => htws (l + 1) (by simpa using Nat.succ_lt_succ hl'))
        hrest
      refine ⟨?_, ihlen⟩
      refine Chain1.cons alpha qs xs rest xss vals
        (layerFold1 one alpha (qs.zip vals) n).res
        (friLayers1 one rest (layerFold1 one alpha (qs.zip vals) n).res
          (layerFold1 one alpha (qs.zip vals) n).next).res
        (by rw [hq, hv]) (by rw [hnlen, hq]) ?_ ?_ ihchain
      · intro i hi
        rw [hq] at hi
        have := (hfval i (by rw [hzlen]; exact hi)).1
        rw [hzget i hi] at this
        exact this
      · intro i hi
        rw [hq] at hi
        have := (hfval i (by rw [hzlen]; exact hi)).2
        rw [hzget i hi] at this
        exact this

/-- The decommit tail: the layer walk, then the last-layer `eq`
battery. -/
def friDecommit1 (one : ℕ) (layers : List (ℕ × List (ℕ × ℕ × ℕ × ℕ)))
    (vals : List ℕ) (lastCoeff : ℕ) (n : ℕ) : Out Unit :=
  let w := friLayers1 one layers vals n
  let e := lastLayerEqs lastCoeff w.res w.next
  ⟨w.ops ++ e.ops, (), e.next⟩

/-- **The layer walk plus the closing battery**: the gates yield the
value chain and the spec's `lastLayerCheck` on the final values, at
the pinned last-layer degree bound 0. -/
theorem friDecommit1_sound {ρ : ℕ → QM31} {one nQ lastCoeff n : ℕ}
    {layers : List (ℕ × List (ℕ × ℕ × ℕ × ℕ))} {xss : List (List F)}
    {vals : List ℕ}
    (hone : ρ one = 1)
    (c : Fri.Committed) (c0 : QM31) (hpoly : c.lastLayerPoly = [c0])
    (hc : ρ lastCoeff = c0) (positions : List Nat)
    (hplen : positions.length = nQ)
    (hlx : layers.length = xss.length) (hv : vals.length = nQ)
    (hql : ∀ l, l < layers.length → (layers.getD l default).2.length = nQ)
    (hbits : ∀ l, l < layers.length → ∀ i, i < nQ →
      (ρ ((layers.getD l default).2.getD i default).2.2.1 = 0 ∨
       ρ ((layers.getD l default).2.getD i default).2.2.1 = 1))
    (htws : ∀ l, l < layers.length → ∀ i, i < nQ →
      ρ ((layers.getD l default).2.getD i default).2.2.2
        * QM31.fromBase ((xss.getD l []).getD i 0) = 1)
    (h : AllHold ρ (friDecommit1 one layers vals lastCoeff n).ops) :
    Chain1 ρ layers xss vals (friLayers1 one layers vals n).res ∧
    Fri.lastLayerCheck c positions
      ((friLayers1 one layers vals n).res.map ρ) = .ok () := by
  unfold friDecommit1 at h
  rw [allHold_append] at h
  obtain ⟨hw, he⟩ := h
  obtain ⟨hchain, hlen⟩ :=
    friLayers1_sound hone layers xss vals n hlx hv hql hbits htws hw
  refine ⟨hchain, ?_⟩
  exact lastLayerEqs_spec c c0 hpoly hc positions
    (by rw [hplen, hlen]) he

/-- The unpacked scalar twiddle inverts the fold coordinate: `simd.inv`
pins the lane product in `F`, `unpackIdx` lifts the lane to the scalar
register, and the base-field embedding carries the inverse — exactly
the `htws` hypothesis of `friLayers1_sound`. -/
theorem scalar_inverts {ρ : ℕ → QM31} {r : ℕ} {lt lx : F}
    (hr : ρ r = QM31.fromBase lt) (hinv : lt * lx = 1) :
    ρ r * QM31.fromBase lx = 1 := by
  rw [hr,
    show QM31.fromBase lt * QM31.fromBase lx = QM31.fromBase (lt * lx) from
      (map_mul baseHom lt lx).symm,
    hinv]
  exact map_one baseHom

end StwoVerifier.Gadgets
