/-
**`compute_fri_input`'s outer walk, gadget side**
(`src/frontends/circuit/stark_verifier/oods.zig` `computeFriInput`,
stwo-zig `4afa09dbf`).

The emitter runs each group's `OodsPointAuxiliary` (init, the response
accumulate walk, finalize) **once**, then loops over queries, emitting
per group a `deepQuery` quotient and an `add` into the row accumulator.
`processGroupQuery` glued setup and quotient at adjacent offsets; here
they are split at the emitter's real boundary: `groupSetup` yields the
shared group registers, `groupQuery` is the per-query quotient over
them at an arbitrary later offset, and `deepRow` is one query's sum
over all groups. `AllHold` is membership-based, so the interleaving of
different groups' accumulate steps in response order does not matter.
-/
import StwoVerifier.DeepGadgets
import StwoVerifier.DenNonzero

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-- The registers one group's setup leaves behind for the query loop:
the line coefficients `d`, `e`, `f`, the per-response column
coefficients `cᵢ = d·α'ᵢ`, and the accumulated `a_sum` and `b_sum`. -/
structure GroupRegs where
  d : ℕ
  e : ℕ
  f : ℕ
  coeffs : List ℕ
  aSum : ℕ
  b : ℕ

instance : Inhabited GroupRegs := ⟨⟨0, 0, 0, [], 0, 0⟩⟩

/-- `OodsPointAuxiliary` end to end for one group: init, the accumulate
walk over the group's `(α'ᵢ, Vᵢ)` register pairs, finalize. -/
def groupSetup (imMask zero px py : ℕ) (rsReg : List (ℕ × ℕ)) (n : ℕ) :
    Out GroupRegs :=
  let ini := auxInit imMask px py n
  let walk := auxAccumList imMask ini.res.1 rsReg zero zero ini.next
  let fin := auxFinalize ini.res.1 walk.res.2.2 walk.res.2.1 py walk.next
  ⟨ini.ops ++ walk.ops ++ fin.ops,
   ⟨ini.res.1, ini.res.2.1, ini.res.2.2, walk.res.1, walk.res.2.1, fin.res⟩,
   fin.next⟩

/-- The group registers carry the line coefficients and response sums
of the sample point `P`. -/
theorem groupSetup_sound {ρ : ℕ → QM31} {imMask zero px py n : ℕ}
    {rsReg : List (ℕ × ℕ)} {P : PointQ}
    (hmask : ρ imMask = QM31.fromM31s 0 0 1 1) (hzero : ρ zero = 0)
    (hpx : ρ px = P.x) (hpy : ρ py = P.y)
    (h : AllHold ρ (groupSetup imMask zero px py rsReg n).ops) :
    ρ (groupSetup imMask zero px py rsReg n).res.d = Deep.imQ P.y ∧
    ρ (groupSetup imMask zero px py rsReg n).res.e = Deep.imQ P.x ∧
    ρ (groupSetup imMask zero px py rsReg n).res.f
      = Deep.imQ P.y * P.x - Deep.imQ P.x * P.y ∧
    (groupSetup imMask zero px py rsReg n).res.coeffs.length = rsReg.length ∧
    (∀ i, i < rsReg.length →
      ρ ((groupSetup imMask zero px py rsReg n).res.coeffs.getD i 0)
        = Deep.imQ P.y * ρ (rsReg.getD i (0, 0)).1) ∧
    ρ (groupSetup imMask zero px py rsReg n).res.aSum
      = (rsReg.map fun (a, v) => ρ a * Deep.imQ (ρ v)).sum ∧
    ρ (groupSetup imMask zero px py rsReg n).res.b
      = Deep.imQ P.y * (rsReg.map fun (a, v) => ρ a * ρ v).sum
        - (rsReg.map fun (a, v) => ρ a * Deep.imQ (ρ v)).sum * P.y := by
  unfold groupSetup at h
  rw [allHold_append, allHold_append] at h
  obtain ⟨⟨hini, hwalk⟩, hfin⟩ := h
  obtain ⟨hd, he, hf⟩ := auxInit_sound hmask hini
  obtain ⟨hwlen, hwc, hwa, hwv⟩ := auxAccumList_sound hmask rsReg zero zero _ hwalk
  have hb := auxFinalize_sound hfin
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · show ρ (auxInit imMask px py n).res.1 = _
    rw [hd, hpy]
  · show ρ (auxInit imMask px py n).res.2.1 = _
    rw [he, hpx]
  · show ρ (auxInit imMask px py n).res.2.2 = _
    rw [hf, hpx, hpy]
  · show (auxAccumList imMask (auxInit imMask px py n).res.1 rsReg zero zero
      (auxInit imMask px py n).next).res.1.length = _
    exact hwlen
  · intro i hi
    show ρ ((auxAccumList imMask (auxInit imMask px py n).res.1 rsReg zero zero
      (auxInit imMask px py n).next).res.1.getD i 0) = _
    rw [hwc i hi, hd, hpy]
  · show ρ (auxAccumList imMask (auxInit imMask px py n).res.1 rsReg zero zero
      (auxInit imMask px py n).next).res.2.1 = _
    rw [hwa, hzero, zero_add]
  · show ρ (auxFinalize (auxInit imMask px py n).res.1
      (auxAccumList imMask (auxInit imMask px py n).res.1 rsReg zero zero
        (auxInit imMask px py n).next).res.2.2
      (auxAccumList imMask (auxInit imMask px py n).res.1 rsReg zero zero
        (auxInit imMask px py n).next).res.2.1 py
      (auxAccumList imMask (auxInit imMask px py n).res.1 rsReg zero zero
        (auxInit imMask px py n).next).next).res = _
    rw [hb, hwv, hwa, hzero, zero_add, zero_add, hd, hpy]

/-- One group's per-query quotient: `deepQuery` over the shared group
registers, the query's scalar point registers, and the query's Merkle
value registers — at an arbitrary offset `m`, matching the emitter's
query loop placement. -/
def groupQuery (g : GroupRegs) (valRegs : List ℕ) (qx qy m : ℕ) : Out ℕ :=
  deepQuery g.aSum g.b g.d g.e g.f qx qy (g.coeffs.zip valRegs) m

set_option maxHeartbeats 1600000 in
/-- **The per-group quotient at any offset is the spec's batch term** —
`processGroupQuery_sound` split at the emitter's real setup/query
boundary. The register hypotheses are exactly `groupSetup_sound`'s
conclusions. -/
theorem groupQuery_sound {ρ : ℕ → QM31} {g : GroupRegs}
    {valRegs : List ℕ} {qx qy m : ℕ}
    {rsReg : List (ℕ × ℕ)} {P : PointQ} {xq yq : F}
    {rsAlpha : List QM31} {vals : List F}
    (hd : ρ g.d = Deep.imQ P.y) (he : ρ g.e = Deep.imQ P.x)
    (hf : ρ g.f = Deep.imQ P.y * P.x - Deep.imQ P.x * P.y)
    (hclen : g.coeffs.length = rsReg.length)
    (hcoeff : ∀ i, i < rsReg.length →
      ρ (g.coeffs.getD i 0) = Deep.imQ P.y * ρ (rsReg.getD i (0, 0)).1)
    (haSum : ρ g.aSum = (rsReg.map fun (a, v) => ρ a * Deep.imQ (ρ v)).sum)
    (hb : ρ g.b = Deep.imQ P.y * (rsReg.map fun (a, v) => ρ a * ρ v).sum
        - (rsReg.map fun (a, v) => ρ a * Deep.imQ (ρ v)).sum * P.y)
    (hqx : ρ qx = QM31.fromBase xq) (hqy : ρ qy = QM31.fromBase yq)
    (hlenV : valRegs.length = rsReg.length)
    (halpha : ∀ i, i < rsReg.length →
      ρ (rsReg.getD i (0, 0)).1 = (-2 : QM31) * Deep.uu * rsAlpha.getD i 0)
    (hvals : ∀ i, i < rsReg.length →
      ρ (valRegs.getD i 0) = QM31.fromBase (vals.getD i 0))
    (h : AllHold ρ (groupQuery g valRegs qx qy m).ops)
    (hden : Quotients.denominator P ⟨xq, yq⟩ ≠ 0) :
    ρ (groupQuery g valRegs qx qy m).res
      = ((((List.range rsReg.length).map fun i => (rsAlpha.getD i 0, ρ (rsReg.getD i (0, 0)).2, QM31.fromBase (vals.getD i 0))).map fun r =>
          r.1 * (P.y.complexConjugate - P.y) * r.2.2
            - (r.1 * (r.2.1.complexConjugate - r.2.1) * QM31.fromBase yq
              + (r.1 * (r.2.1 * (P.y.complexConjugate - P.y))
                - r.1 * ((r.2.1.complexConjugate - r.2.1) * P.y)))).sum).mulCM31
          (Quotients.denominator P ⟨xq, yq⟩)⁻¹ := by
  unfold groupQuery at h ⊢
  have hql := deepQuery_sound h
  -- The denominator register value is `−u·embed(den)`.
  have hdenreg : ρ g.d * ρ qx - (ρ g.e * ρ qy + ρ g.f)
      = -Deep.uu * Deep.embed (Quotients.denominator P ⟨xq, yq⟩) := by
    rw [hd, he, hf, hqx, hqy]
    exact Deep.den_identity P xq yq
  -- The three register sums, instantiated to spec data over the triple list.
  have hsumA : (rsReg.map fun (a, v) => ρ a * Deep.imQ (ρ v)).sum
      = (((List.range rsReg.length).map fun i => (rsAlpha.getD i 0, ρ (rsReg.getD i (0, 0)).2, QM31.fromBase (vals.getD i 0))).map fun r => ((-2 : QM31) * Deep.uu * r.1) * Deep.imQ r.2.1).sum := by
    rw [map_sum_eq_range, List.map_map, range_map_sum]
    refine Finset.sum_congr rfl fun i hi => ?_
    have hi' := Finset.mem_range.mp hi
    show ρ (rsReg.getD i (0, 0)).1 * Deep.imQ (ρ (rsReg.getD i (0, 0)).2)
      = ((-2 : QM31) * Deep.uu * rsAlpha.getD i 0) * Deep.imQ (ρ (rsReg.getD i (0, 0)).2)
    rw [halpha i hi']
  have hsumV : (rsReg.map fun (a, v) => ρ a * ρ v).sum
      = (((List.range rsReg.length).map fun i => (rsAlpha.getD i 0, ρ (rsReg.getD i (0, 0)).2, QM31.fromBase (vals.getD i 0))).map fun r => ((-2 : QM31) * Deep.uu * r.1) * r.2.1).sum := by
    rw [map_sum_eq_range, List.map_map, range_map_sum]
    refine Finset.sum_congr rfl fun i hi => ?_
    have hi' := Finset.mem_range.mp hi
    show ρ (rsReg.getD i (0, 0)).1 * ρ (rsReg.getD i (0, 0)).2
      = ((-2 : QM31) * Deep.uu * rsAlpha.getD i 0) * ρ (rsReg.getD i (0, 0)).2
    rw [halpha i hi']
  have hsumC : ((g.coeffs.zip valRegs).map fun (c, v) => ρ c * ρ v).sum
      = (((List.range rsReg.length).map fun i => (rsAlpha.getD i 0, ρ (rsReg.getD i (0, 0)).2, QM31.fromBase (vals.getD i 0))).map fun r => Deep.imQ P.y * ((-2 : QM31) * Deep.uu * r.1) * r.2.2).sum := by
    rw [map_sum_eq_range, List.length_zip, hclen, hlenV, Nat.min_self,
      List.map_map, range_map_sum]
    refine Finset.sum_congr rfl fun i hi => ?_
    have hi' := Finset.mem_range.mp hi
    have hiA : i < g.coeffs.length := by rw [hclen]; exact hi'
    have hiB : i < valRegs.length := by rw [hlenV]; exact hi'
    have hz : (g.coeffs.zip valRegs).getD i default
        = (g.coeffs.getD i 0, valRegs.getD i 0) := by
      rw [List.getD_eq_getElem?_getD,
        show (g.coeffs.zip valRegs)[i]?
            = some (g.coeffs[i], valRegs[i]) from
          List.getElem?_zip_eq_some.2 ⟨List.getElem?_eq_getElem hiA,
            List.getElem?_eq_getElem hiB⟩]
      rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hiA,
        List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hiB]
      rfl
    rw [hz]
    show ρ (g.coeffs.getD i 0) * ρ (valRegs.getD i 0)
      = Deep.imQ P.y * ((-2 : QM31) * Deep.uu * rsAlpha.getD i 0)
          * QM31.fromBase (vals.getD i 0)
    rw [hcoeff i hi', hvals i hi', halpha i hi']
  -- Assemble the numerator: the batched identity.
  have hnum : ρ g.aSum * ρ qy + ρ g.b
      - ((g.coeffs.zip valRegs).map fun (c, v) => ρ c * ρ v).sum
      = -Deep.uu * (((List.range rsReg.length).map fun i => (rsAlpha.getD i 0, ρ (rsReg.getD i (0, 0)).2, QM31.fromBase (vals.getD i 0))).map fun r =>
          r.1 * (P.y.complexConjugate - P.y) * r.2.2
            - (r.1 * (r.2.1.complexConjugate - r.2.1) * QM31.fromBase yq
              + (r.1 * (r.2.1 * (P.y.complexConjugate - P.y))
                - r.1 * ((r.2.1.complexConjugate - r.2.1) * P.y)))).sum := by
    rw [haSum, hb, hqy, hsumA, hsumV, hsumC]
    exact Deep.num_identity_batched P (QM31.fromBase yq) ((List.range rsReg.length).map fun i => (rsAlpha.getD i 0, ρ (rsReg.getD i (0, 0)).2, QM31.fromBase (vals.getD i 0)))
  -- The div gate pins the quotient.
  have hdenne : (-Deep.uu * Deep.embed (Quotients.denominator P ⟨xq, yq⟩)) ≠ 0 :=
    mul_ne_zero (neg_ne_zero.mpr Deep.uu_ne_zero) (Deep.embed_ne_zero hden)
  rw [hdenreg] at hql
  rw [hnum] at hql
  have hfinal : ρ (deepQuery g.aSum g.b g.d g.e g.f qx qy (g.coeffs.zip valRegs) m).res
      = (-Deep.uu * (((List.range rsReg.length).map fun i => (rsAlpha.getD i 0, ρ (rsReg.getD i (0, 0)).2, QM31.fromBase (vals.getD i 0))).map fun r =>
          r.1 * (P.y.complexConjugate - P.y) * r.2.2
            - (r.1 * (r.2.1.complexConjugate - r.2.1) * QM31.fromBase yq
              + (r.1 * (r.2.1 * (P.y.complexConjugate - P.y))
                - r.1 * ((r.2.1.complexConjugate - r.2.1) * P.y)))).sum)
        / (-Deep.uu * Deep.embed (Quotients.denominator P ⟨xq, yq⟩)) :=
    (eq_div_iff hdenne).mpr hql
  rw [hfinal, mul_div_mul_left _ _ (neg_ne_zero.mpr Deep.uu_ne_zero),
    div_eq_mul_inv, ← Deep.embed_inv, ← Deep.mulCM31_eq]

/-- One query's row: starting from the accumulator register (the zero
register for the first group), emit each group's quotient and an `add`
gate — the emitter's `sum.* = try ctx.add(sum.*, quotient)` loop. -/
def deepRow (qx qy : ℕ) : List (GroupRegs × List ℕ) → ℕ → ℕ → Out ℕ
  | [], acc, n => ⟨[], acc, n⟩
  | (g, vs) :: rest, acc, n =>
    let q := groupQuery g vs qx qy n
    let t := deepRow qx qy rest q.next (q.next + 1)
    ⟨q.ops ++ (.add q.next acc q.res :: t.ops), t.res, t.next⟩

/-- The row register accumulates the per-group quotient values: if each
group's quotient gadget is pinned to its term at every offset (what
`groupQuery_sound` provides), the row is the accumulator plus the sum
of the terms. -/
theorem deepRow_sound {ρ : ℕ → QM31} {qx qy : ℕ} :
    ∀ (gs : List (GroupRegs × List ℕ)) (terms : List QM31) (acc n : ℕ),
      gs.length = terms.length →
      (∀ i, i < gs.length → ∀ m,
        AllHold ρ (groupQuery (gs.getD i default).1 (gs.getD i default).2 qx qy m).ops →
        ρ (groupQuery (gs.getD i default).1 (gs.getD i default).2 qx qy m).res
          = terms.getD i 0) →
      AllHold ρ (deepRow qx qy gs acc n).ops →
      ρ (deepRow qx qy gs acc n).res = ρ acc + terms.sum := by
  intro gs
  induction gs with
  | nil =>
    intro terms acc n hlen _ _
    cases terms with
    | nil =>
      show ρ acc = ρ acc + ([] : List QM31).sum
      simp
    | cons t ts => simp at hlen
  | cons gv rest ih =>
    intro terms acc n hlen hquot h
    obtain ⟨g, vs⟩ := gv
    cases terms with
    | nil => simp at hlen
    | cons t ts =>
      rw [show (deepRow qx qy ((g, vs) :: rest) acc n).ops =
        (groupQuery g vs qx qy n).ops ++
          (.add (groupQuery g vs qx qy n).next acc (groupQuery g vs qx qy n).res ::
            (deepRow qx qy rest (groupQuery g vs qx qy n).next
              ((groupQuery g vs qx qy n).next + 1)).ops) from rfl,
        allHold_append, allHold_cons] at h
      obtain ⟨hq, hadd, hrest⟩ := h
      simp only [Holds] at hadd
      have hterm : ρ (groupQuery g vs qx qy n).res = t := by
        have := hquot 0 (by simp) n
        simp only [List.getD_cons_zero] at this
        exact this hq
      have hquot' : ∀ i, i < rest.length → ∀ m,
          AllHold ρ (groupQuery (rest.getD i default).1 (rest.getD i default).2 qx qy m).ops →
          ρ (groupQuery (rest.getD i default).1 (rest.getD i default).2 qx qy m).res
            = ts.getD i 0 := by
        intro i hi m hm
        have := hquot (i + 1) (by simpa using Nat.succ_lt_succ hi) m
        simp only [List.getD_cons_succ] at this
        exact this hm
      have hlen' : rest.length = ts.length := by simpa using hlen
      show ρ (deepRow qx qy rest (groupQuery g vs qx qy n).next
        ((groupQuery g vs qx qy n).next + 1)).res = _
      rw [ih ts (groupQuery g vs qx qy n).next
        ((groupQuery g vs qx qy n).next + 1) hlen' hquot' hrest,
        hadd, hterm]
      simp only [List.sum_cons]
      ring

end StwoVerifier.Gadgets
