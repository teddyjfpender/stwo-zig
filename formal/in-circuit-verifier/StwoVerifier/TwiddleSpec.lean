/-
**Every fold-step-1 twiddle inverts the spec's fold coordinate.**

`twiddleChain1_sound` pins each twiddle register against the chain's
own lane points; `base0_eq_evenPoint` and `baseSeq_eq_lineFoldPoints`
identify those points with the spec's per-layer fold points. This file
composes them: with the query-point lane pinned to the spec domain
point (what `selectQueries_domainPoint` provides) and the bit lanes
carrying the query's bits, every per-layer twiddle lane multiplies the
spec fold coordinate (`specFoldCoord`) to one — `friLayers1_sound`'s
`htws` hypotheses at the true coordinates, up to the scalar unpack
(`unpackIdx_sound` + `scalar_inverts`).
-/
import StwoVerifier.FoldBridge
import StwoVerifier.FriWalk

namespace StwoVerifier.Bridge

open StwoVerifier StwoVerifier.Gadgets StwoVerifier.Gates Finset

/-- The spec's per-layer fold coordinate for a query with bits `b`:
the circle layer folds at the even point's `y`, line layer `ℓ` at the
`ℓ`-times-doubled coset point's `x`. -/
noncomputable def specFoldCoord (b : ℕ → ℕ) (L : ℕ) : ℕ → F
  | 0 => ((canonicDomain L).at' (bitReverseIndex
      (∑ i ∈ range L, (if i = 0 then 0 else b i) * 2 ^ i) L)).y
  | ℓ + 1 => ((LineDomain.double^[ℓ] ⟨Coset.halfOdds (L - 1)⟩).coset.indexAt
      (bitReverseIndex
        (∑ t ∈ range (L - 1 - (ℓ + 1)), b (t + (ℓ + 1) + 1) * 2 ^ (t + 1))
        (L - (ℓ + 1)))).toPoint.x

/-- The even position's domain point is the un-conjugated generator
power. -/
theorem evenPoint_eq_smul {b : ℕ → ℕ} (hb : ∀ i, b i ≤ 1) {L : ℕ}
    (hL2 : 2 ≤ L) (hL30 : L ≤ 30) :
    (canonicDomain L).at' (bitReverseIndex
      (∑ i ∈ range L, (if i = 0 then 0 else b i) * 2 ^ i) L)
      = M31_CIRCLE_GEN.smul (queryIndex b L) := by
  have hb' : ∀ i, (if i = 0 then 0 else b i) ≤ 1 := by
    intro i
    by_cases h0 : i = 0 <;> simp [h0, hb i]
  have hqi : queryIndex (fun i => if i = 0 then 0 else b i) L
      = queryIndex b L := by
    unfold queryIndex
    congr 1
  have hmain' := queryIndex_eq_domainPoint hb' hL2 hL30
  simp only [reduceIte] at hmain'
  rw [hqi] at hmain'
  exact hmain'.symm

set_option maxHeartbeats 1600000 in
/-- **The twiddle chain inverts the spec fold coordinates**, lane by
lane and layer by layer. -/
theorem twiddleChain1_spec {ρ : ℕ → QM31} {zero count len : ℕ}
    {bit0 : SimdReg} {points : PointSimd} {bits : List SimdReg} {n : ℕ}
    {L : ℕ} (hL2 : 2 ≤ L) (hL30 : L ≤ 30)
    (hzero : ρ zero = 0)
    (hb0 : BitShape bit0 len count) (hp : points.Shape len count)
    (hshapes : ∀ r ∈ bits, BitShape r len count)
    (hlen : bits.length = L - 1)
    (h : AllHold ρ (twiddleChain1 zero count len bit0 points bits n).ops)
    (q : ℕ) (hq : q < len)
    (b : ℕ → ℕ) (hb : ∀ i, b i ≤ 1)
    (hbit0lane : SimdReg.lane ρ bit0 q = 0 ∨ SimdReg.lane ρ bit0 q = 1)
    (hbitslane : ∀ r ∈ bits, SimdReg.lane ρ r q = 0 ∨ SimdReg.lane ρ r q = 1)
    (hb0def : bitNat ρ bit0 q = b 0)
    (hbtdef : ∀ t, t < bits.length →
      bitNat ρ (bits.getD t dummySimd) q = b (t + 1))
    (hpoint : PointSimd.lane ρ points q
      = (canonicDomain L).at' (bitReverseIndex
          (∑ i ∈ range L, b i * 2 ^ i) L)) :
    ∀ ℓ, ℓ < bits.length + 1 →
      SimdReg.lane ρ ((twiddleChain1 zero count len bit0 points bits n).res.getD
          ℓ dummySimd) q
        * specFoldCoord b L ℓ = 1 := by
  have hcirc : OnCircle (PointSimd.lane ρ points q) := by
    rw [hpoint]
    exact onCircle_toPoint _
  obtain ⟨hlenT, hval⟩ := twiddleChain1_sound hzero hb0 hp hshapes h
  obtain ⟨h0, hinner⟩ := hval q hq hbit0lane hbitslane hcirc
  -- The conjugate-selected point is the even position's point.
  have hsel : (if SimdReg.lane ρ bit0 q = 0 then PointSimd.lane ρ points q
      else (PointSimd.lane ρ points q).conjugate)
      = (canonicDomain L).at' (bitReverseIndex
          (∑ i ∈ range L, (if i = 0 then 0 else b i) * 2 ^ i) L) := by
    rw [hpoint, ← Gadgets.base0_eq_evenPoint hb hL2 hL30]
    rcases hbit0lane with hl0 | hl1
    · have hb00 : b 0 = 0 := by
        rw [← hb0def]
        unfold bitNat
        rw [if_pos hl0]
      rw [if_pos hl0, if_pos hb00]
    · have hb01 : b 0 = 1 := by
        rw [← hb0def]
        unfold bitNat
        rw [if_neg (by rw [hl1]; norm_num)]
      rw [if_neg (by rw [hl1]; norm_num), if_neg (by rw [hb01]; norm_num)]
  -- The lane bit values are `b`'s bits.
  have hlist : (bits.map fun r => bitNat ρ r q)
      = (List.range (L - 1)).map fun t => b (t + 1) := by
    refine List.ext_getElem (by simp [hlen]) ?_
    intro i h1 h2
    rw [List.getElem_map, List.getElem_map, List.getElem_range]
    have hi : i < bits.length := by simpa using h1
    have := hbtdef i hi
    rw [← this, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi]
    rfl
  intro ℓ hℓ
  cases ℓ with
  | zero =>
    have := h0
    rw [hsel] at this
    exact this
  | succ ℓ =>
    have hℓ' : ℓ < bits.length := by omega
    have := hinner ℓ hℓ'
    rw [hsel, evenPoint_eq_smul hb hL2 hL30, hlist,
      baseSeq_eq_lineFoldPoints hb hL2 hL30 ℓ (by omega)] at this
    exact this

set_option maxHeartbeats 800000 in
/-- **`friDecommit1_sound` at the spec fold coordinates**: the layer
walk's `Chain1` and the spec's last-layer check, with every twiddle
hypothesis stated against `specFoldCoord` per query. -/
theorem friDecommit1_atSpec {ρ : ℕ → QM31} {one nQ lastCoeff n : ℕ}
    {layers : List (ℕ × List (ℕ × ℕ × ℕ × ℕ))} {vals : List ℕ}
    {L : ℕ} (bq : ℕ → ℕ → ℕ)
    (hone : ρ one = 1)
    (c : Fri.Committed) (c0 : QM31) (hpoly : c.lastLayerPoly = [c0])
    (hc : ρ lastCoeff = c0) (positions : List Nat)
    (hplen : positions.length = nQ)
    (hv : vals.length = nQ)
    (hql : ∀ l, l < layers.length → (layers.getD l default).2.length = nQ)
    (hbits : ∀ l, l < layers.length → ∀ i, i < nQ →
      (ρ ((layers.getD l default).2.getD i default).2.2.1 = 0 ∨
       ρ ((layers.getD l default).2.getD i default).2.2.1 = 1))
    (htw : ∀ l, l < layers.length → ∀ i, i < nQ →
      ρ ((layers.getD l default).2.getD i default).2.2.2
        * QM31.fromBase (specFoldCoord (bq i) L l) = 1)
    (h : AllHold ρ (friDecommit1 one layers vals lastCoeff n).ops) :
    Chain1 ρ layers
      ((List.range layers.length).map fun l =>
        (List.range nQ).map fun i => specFoldCoord (bq i) L l)
      vals (friLayers1 one layers vals n).res ∧
    Fri.lastLayerCheck c positions
      ((friLayers1 one layers vals n).res.map ρ) = .ok () := by
  refine friDecommit1_sound hone c c0 hpoly hc positions hplen
    (by simp) hv hql hbits ?_ h
  intro l hl i hi
  have hrl : (List.range layers.length).getD l default = l := by
    rw [List.getD_eq_getElem?_getD,
      List.getElem?_eq_getElem (by simpa using hl)]
    simp
  have hri : (List.range nQ).getD i default = i := by
    rw [List.getD_eq_getElem?_getD,
      List.getElem?_eq_getElem (by simpa using hi)]
    simp
  rw [Gadgets.getD_map _ ([] : List F) (List.range layers.length) l
    (by simpa using hl), hrl,
    Gadgets.getD_map _ (0 : F) (List.range nQ) i (by simpa using hi), hri]
  exact htw l hl i hi

end StwoVerifier.Bridge
