/-
**Gadget row = spec row, per group and per query.**

`groupQuery_sound` (gadget side) produces a triple-list batch term;
`friAnswers_ok` (spec side) produces `batchTerm` over a batch's
entries. This file ties them: a `GroupBinding` carries one group's
registers together with its spec batch, `Bound` pins the register
values to the batch data (exactly what `groupSetup_sound` plus the
response-register plumbing provide), and `deepRow_spec` concludes that
the row accumulator register holds the spec row's sum of batch terms.
-/
import StwoVerifier.DeepRow
import StwoVerifier.SpecRow

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

instance : Inhabited Quotients.NumeratorData := ⟨⟨0, QM31.zero, QM31.zero⟩⟩
instance : Inhabited Quotients.SampleBatch := ⟨⟨CPoint.zero, []⟩⟩

/-- `getD` through a `map`, inside the length. -/
theorem getD_map {α β : Type} [Inhabited α] (f : α → β) (dflt : β)
    (l : List α) (i : ℕ) (hi : i < l.length) :
    (l.map f).getD i dflt = f (l.getD i default) := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_eq_getElem hi,
    List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi]
  rfl

/-- One group's registers with its spec batch. -/
structure GroupBinding where
  g : GroupRegs
  valRegs : List ℕ
  rsReg : List (ℕ × ℕ)
  batch : Quotients.SampleBatch

instance : Inhabited GroupBinding := ⟨⟨default, [], [], default⟩⟩

/-- The register values are the batch's data: the `groupSetup_sound`
facts for the batch's point, the response registers carrying
`−2u`-scaled random coefficients and the sampled values, and the
query-value registers carrying the queried column values at `row`. -/
structure Bound (ρ : ℕ → QM31) (flatCols : List (List F)) (row : ℕ)
    (gb : GroupBinding) : Prop where
  hd : ρ gb.g.d = Deep.imQ gb.batch.point.y
  he : ρ gb.g.e = Deep.imQ gb.batch.point.x
  hf : ρ gb.g.f = Deep.imQ gb.batch.point.y * gb.batch.point.x
    - Deep.imQ gb.batch.point.x * gb.batch.point.y
  hclen : gb.g.coeffs.length = gb.rsReg.length
  hcoeff : ∀ i, i < gb.rsReg.length →
    ρ (gb.g.coeffs.getD i 0)
      = Deep.imQ gb.batch.point.y * ρ (gb.rsReg.getD i (0, 0)).1
  haSum : ρ gb.g.aSum = (gb.rsReg.map fun (a, v) => ρ a * Deep.imQ (ρ v)).sum
  hb : ρ gb.g.b
    = Deep.imQ gb.batch.point.y * (gb.rsReg.map fun (a, v) => ρ a * ρ v).sum
      - (gb.rsReg.map fun (a, v) => ρ a * Deep.imQ (ρ v)).sum * gb.batch.point.y
  hlenV : gb.valRegs.length = gb.rsReg.length
  hlenE : gb.rsReg.length = gb.batch.entries.length
  halpha : ∀ i, i < gb.rsReg.length →
    ρ (gb.rsReg.getD i (0, 0)).1
      = (-2 : QM31) * Deep.uu * (gb.batch.entries.getD i default).randomCoeff
  hV : ∀ i, i < gb.rsReg.length →
    ρ (gb.rsReg.getD i (0, 0)).2 = (gb.batch.entries.getD i default).sampleValue
  hvals : ∀ i, i < gb.rsReg.length →
    ρ (gb.valRegs.getD i 0)
      = QM31.fromBase ((flatCols.getD
          (gb.batch.entries.getD i default).columnIndex []).getD row 0)

set_option maxHeartbeats 800000 in
/-- **One group's quotient register holds the spec's `batchTerm`.** -/
theorem groupQuery_spec {ρ : ℕ → QM31} {qx qy m : ℕ}
    {flatCols : List (List F)} {row : ℕ} {xq yq : F}
    (gb : GroupBinding)
    (hB : Bound ρ flatCols row gb)
    (hqx : ρ qx = QM31.fromBase xq) (hqy : ρ qy = QM31.fromBase yq)
    (hden : Quotients.denominator gb.batch.point ⟨xq, yq⟩ ≠ 0)
    (h : AllHold ρ (groupQuery gb.g gb.valRegs qx qy m).ops) :
    ρ (groupQuery gb.g gb.valRegs qx qy m).res
      = Quotients.batchTerm gb.batch flatCols row ⟨xq, yq⟩ := by
  have hmain := groupQuery_sound (P := gb.batch.point) (xq := xq) (yq := yq)
    (rsAlpha := gb.batch.entries.map Quotients.NumeratorData.randomCoeff)
    (vals := gb.batch.entries.map fun e =>
      (flatCols.getD e.columnIndex []).getD row 0)
    hB.hd hB.he hB.hf hB.hclen hB.hcoeff hB.haSum hB.hb hqx hqy hB.hlenV
    (fun i hi => by
      rw [getD_map Quotients.NumeratorData.randomCoeff 0 gb.batch.entries i
        (hB.hlenE ▸ hi)]
      exact hB.halpha i hi)
    (fun i hi => by
      rw [getD_map (fun e => (flatCols.getD e.columnIndex []).getD row 0) 0
        gb.batch.entries i (hB.hlenE ▸ hi)]
      exact hB.hvals i hi)
    h hden
  rw [hmain]
  unfold Quotients.batchTerm
  refine congrArg (fun s => QM31.mulCM31 s _) ?_
  rw [hB.hlenE]
  rw [map_sum_eq_range gb.batch.entries]
  rw [List.map_map]
  refine congrArg List.sum ?_
  refine List.map_congr_left fun i hi' => ?_
  have hiR : i < gb.batch.entries.length := List.mem_range.mp hi'
  have hiL : i < gb.rsReg.length := by rw [hB.hlenE]; exact hiR
  simp only [Function.comp_def]
  rw [getD_map Quotients.NumeratorData.randomCoeff 0 gb.batch.entries i hiR,
    getD_map (fun e => (flatCols.getD e.columnIndex []).getD row 0) 0
      gb.batch.entries i hiR,
    hB.hV i hiL]

/-- **The row register holds the spec row's sum of batch terms** — the
per-query composition of `groupQuery_spec` over all groups, matching
`friAnswers_ok`'s per-row value. -/
theorem deepRow_spec {ρ : ℕ → QM31} {qx qy : ℕ}
    {flatCols : List (List F)} {row : ℕ} {xq yq : F}
    (bindings : List GroupBinding) (acc n : ℕ)
    (hB : ∀ gb ∈ bindings, Bound ρ flatCols row gb)
    (hqx : ρ qx = QM31.fromBase xq) (hqy : ρ qy = QM31.fromBase yq)
    (hden : ∀ gb ∈ bindings,
      Quotients.denominator gb.batch.point ⟨xq, yq⟩ ≠ 0)
    (h : AllHold ρ (deepRow qx qy
      (bindings.map fun gb => (gb.g, gb.valRegs)) acc n).ops) :
    ρ (deepRow qx qy (bindings.map fun gb => (gb.g, gb.valRegs)) acc n).res
      = ρ acc + (bindings.map fun gb =>
          Quotients.batchTerm gb.batch flatCols row ⟨xq, yq⟩).sum := by
  refine deepRow_sound (bindings.map fun gb => (gb.g, gb.valRegs))
    (bindings.map fun gb => Quotients.batchTerm gb.batch flatCols row ⟨xq, yq⟩)
    acc n (by simp) ?_ h
  intro i hi m hm
  rw [List.length_map] at hi
  have h1 : ((bindings.map fun gb => (gb.g, gb.valRegs)).getD i default)
      = ((bindings.getD i default).g, (bindings.getD i default).valRegs) :=
    getD_map _ _ _ i hi
  have h2 : ((bindings.map fun gb =>
        Quotients.batchTerm gb.batch flatCols row ⟨xq, yq⟩).getD i 0)
      = Quotients.batchTerm (bindings.getD i default).batch flatCols row
          ⟨xq, yq⟩ :=
    getD_map _ _ _ i hi
  have hgetD : bindings.getD i default = bindings[i] := by
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi]
    rfl
  have hmem : bindings.getD i default ∈ bindings := by
    rw [hgetD]
    exact List.getElem_mem hi
  rw [h1] at hm
  rw [h1, h2]
  exact groupQuery_spec (bindings.getD i default) (hB _ hmem) hqx hqy
    (hden _ hmem) hm

/-- The full query loop (`fri_queries`): one `deepRow` per query, each
over its own query-point registers and per-query value registers, all
from the shared zero register. -/
def deepRows (zero : ℕ) :
    List ((ℕ × ℕ) × List (GroupRegs × List ℕ)) → ℕ → Out (List ℕ)
  | [], n => ⟨[], [], n⟩
  | (q, gvs) :: rest, n =>
    let r := deepRow q.1 q.2 gvs zero n
    let t := deepRows zero rest r.next
    ⟨r.ops ++ t.ops, r.res :: t.res, t.next⟩

/-- Row registers hold their per-query values, given each query's row
gadget is pinned at every offset. -/
theorem deepRows_sound {ρ : ℕ → QM31} {zero : ℕ} :
    ∀ (qs : List ((ℕ × ℕ) × List (GroupRegs × List ℕ)))
      (rows : List QM31) (n : ℕ),
      qs.length = rows.length →
      (∀ i, i < qs.length → ∀ m,
        AllHold ρ (deepRow (qs.getD i default).1.1 (qs.getD i default).1.2
          (qs.getD i default).2 zero m).ops →
        ρ (deepRow (qs.getD i default).1.1 (qs.getD i default).1.2
          (qs.getD i default).2 zero m).res = rows.getD i 0) →
      AllHold ρ (deepRows zero qs n).ops →
      (deepRows zero qs n).res.length = qs.length ∧
      ∀ i, i < qs.length →
        ρ ((deepRows zero qs n).res.getD i 0) = rows.getD i 0 := by
  intro qs
  induction qs with
  | nil =>
    intro rows n _ _ _
    exact ⟨rfl, fun i hi => by simp at hi⟩
  | cons qgv rest ih =>
    intro rows n hlen hrow h
    obtain ⟨q, gvs⟩ := qgv
    cases rows with
    | nil => simp at hlen
    | cons r rs =>
      rw [show (deepRows zero ((q, gvs) :: rest) n).ops =
        (deepRow q.1 q.2 gvs zero n).ops ++
          (deepRows zero rest (deepRow q.1 q.2 gvs zero n).next).ops from rfl,
        allHold_append] at h
      obtain ⟨hq, hrest⟩ := h
      have hhead : ρ (deepRow q.1 q.2 gvs zero n).res = r := by
        have := hrow 0 (by simp) n
        simp only [List.getD_cons_zero] at this
        exact this hq
      have hrow' : ∀ i, i < rest.length → ∀ m,
          AllHold ρ (deepRow (rest.getD i default).1.1
            (rest.getD i default).1.2 (rest.getD i default).2 zero m).ops →
          ρ (deepRow (rest.getD i default).1.1 (rest.getD i default).1.2
            (rest.getD i default).2 zero m).res = rs.getD i 0 := by
        intro i hi m hm
        have := hrow (i + 1) (by simpa using Nat.succ_lt_succ hi) m
        simp only [List.getD_cons_succ] at this
        exact this hm
      have hlen' : rest.length = rs.length := by simpa using hlen
      obtain ⟨ihlen, ihval⟩ := ih rs (deepRow q.1 q.2 gvs zero n).next
        hlen' hrow' hrest
      refine ⟨?_, ?_⟩
      · show (deepRows zero rest _).res.length + 1 = rest.length + 1
        rw [ihlen]
      · intro i hi
        cases i with
        | zero => exact hhead
        | succ i =>
          show ρ ((deepRows zero rest _).res.getD i 0) = rs.getD i 0
          exact ihval i (by simpa using hi)

set_option maxHeartbeats 800000 in
/-- The query loop's row registers hold the spec row values: at query
`i`, the sum of `batchTerm`s at domain point
`bitrev(queryPositions[i])`, with `row = i`. -/
theorem deepRows_spec {ρ : ℕ → QM31} {zero : ℕ}
    {flatCols : List (List F)} {liftingLogSize : ℕ}
    {queryPositions : List ℕ} {batches : List Quotients.SampleBatch}
    (entries : List ((ℕ × ℕ) × List GroupBinding)) (n : ℕ)
    (hzero : ρ zero = 0)
    (hq : ∀ i, i < entries.length →
      ρ (entries.getD i default).1.1
        = QM31.fromBase ((canonicDomain liftingLogSize).at'
            (bitReverseIndex (queryPositions.getD i 0) liftingLogSize)).x ∧
      ρ (entries.getD i default).1.2
        = QM31.fromBase ((canonicDomain liftingLogSize).at'
            (bitReverseIndex (queryPositions.getD i 0) liftingLogSize)).y)
    (hB : ∀ i, i < entries.length →
      ∀ gb ∈ (entries.getD i default).2, Bound ρ flatCols i gb)
    (hbatch : ∀ i, i < entries.length →
      (entries.getD i default).2.map GroupBinding.batch = batches)
    (hdn : ∀ i, i < entries.length →
      ∀ gb ∈ (entries.getD i default).2,
        Quotients.denominator gb.batch.point
          ((canonicDomain liftingLogSize).at'
            (bitReverseIndex (queryPositions.getD i 0) liftingLogSize)) ≠ 0)
    (h : AllHold ρ (deepRows zero
      (entries.map fun e => (e.1, e.2.map fun gb => (gb.g, gb.valRegs))) n).ops) :
    (deepRows zero (entries.map fun e =>
      (e.1, e.2.map fun gb => (gb.g, gb.valRegs))) n).res.length
      = entries.length ∧
    ∀ i, i < entries.length →
      ρ ((deepRows zero (entries.map fun e =>
        (e.1, e.2.map fun gb => (gb.g, gb.valRegs))) n).res.getD i 0)
        = (batches.map fun b => Quotients.batchTerm b flatCols i
            ((canonicDomain liftingLogSize).at'
              (bitReverseIndex (queryPositions.getD i 0) liftingLogSize))).sum := by
  have hmain := deepRows_sound
    (entries.map fun e => (e.1, e.2.map fun gb => (gb.g, gb.valRegs)))
    ((List.range entries.length).map fun i =>
      (batches.map fun b => Quotients.batchTerm b flatCols i
        ((canonicDomain liftingLogSize).at'
          (bitReverseIndex (queryPositions.getD i 0) liftingLogSize))).sum)
    n (by simp) ?_ h
  · obtain ⟨hlenR, hvalR⟩ := hmain
    refine ⟨by rw [hlenR, List.length_map], fun i hi => ?_⟩
    have := hvalR i (by rw [List.length_map]; exact hi)
    rw [this, getD_map _ 0 (List.range entries.length) i (by simpa using hi)]
    have hri : (List.range entries.length).getD i default = i := by
      rw [List.getD_eq_getElem?_getD,
        List.getElem?_eq_getElem (by simpa using hi)]
      simp
    rw [hri]
  · intro i hi m hm
    rw [List.length_map] at hi
    have h1 : ((entries.map fun e =>
        (e.1, e.2.map fun gb => (gb.g, gb.valRegs))).getD i default)
        = ((entries.getD i default).1,
           (entries.getD i default).2.map fun gb => (gb.g, gb.valRegs)) :=
      getD_map _ _ _ i hi
    rw [h1] at hm
    have hrows : ((List.range entries.length).map fun j =>
        (batches.map fun b => Quotients.batchTerm b flatCols j
          ((canonicDomain liftingLogSize).at'
            (bitReverseIndex (queryPositions.getD j 0) liftingLogSize))).sum).getD i 0
        = (batches.map fun b => Quotients.batchTerm b flatCols i
            ((canonicDomain liftingLogSize).at'
              (bitReverseIndex (queryPositions.getD i 0) liftingLogSize))).sum := by
      rw [getD_map _ 0 (List.range entries.length) i (by simpa using hi)]
      have hri : (List.range entries.length).getD i default = i := by
        rw [List.getD_eq_getElem?_getD,
          List.getElem?_eq_getElem (by simpa using hi)]
        simp
      rw [hri]
    rw [h1, hrows]
    have hrow := deepRow_spec (ρ := ρ)
      (flatCols := flatCols) (row := i)
      (xq := ((canonicDomain liftingLogSize).at'
        (bitReverseIndex (queryPositions.getD i 0) liftingLogSize)).x)
      (yq := ((canonicDomain liftingLogSize).at'
        (bitReverseIndex (queryPositions.getD i 0) liftingLogSize)).y)
      (entries.getD i default).2 zero m
      (hB i hi) (hq i hi).1 (hq i hi).2
      (fun gb hgb => hdn i hi gb hgb) hm
    rw [hrow, hzero, zero_add, ← hbatch i hi, List.map_map]
    rfl

set_option maxHeartbeats 800000 in
/-- **`compute_fri_input` computes `friAnswers`.** Under the circuit's
guards and with the registers bound to the batch data, the spec's
`friAnswers` succeeds and returns exactly the values of the circuit's
row registers — the outer-walk capstone for deliverable 3. -/
theorem friAnswers_eq_rows {ρ : ℕ → QM31} {zero : ℕ}
    (columnLogSizes : List (List Nat)) (sampledPoints : List (List (List PointQ)))
    (sampledValues : List (List (List QM31))) (randomCoeff : QM31)
    (queryPositions : List Nat) (queriedValues : List (List (List F)))
    (liftingLogSize : Nat) (batches : List Quotients.SampleBatch)
    (entries : List ((ℕ × ℕ) × List GroupBinding)) (n : ℕ)
    (hbuild : Quotients.buildSampleBatches sampledPoints sampledValues
      columnLogSizes liftingLogSize randomCoeff = .ok batches)
    (hcols : ∀ col ∈ queriedValues.flatten, col.length = queryPositions.length)
    (him : ∀ b ∈ batches, Deep.imQ b.point.y ≠ 0)
    (hidx : ∀ b ∈ batches, ∀ e ∈ b.entries,
      e.columnIndex < queriedValues.flatten.length)
    (hpos : ∀ pos ∈ queryPositions, pos < (canonicDomain liftingLogSize).size)
    (hdenS : ∀ b ∈ batches, ∀ pos ∈ queryPositions,
      Quotients.denominator b.point ((canonicDomain liftingLogSize).at'
        (bitReverseIndex pos liftingLogSize)) ≠ 0)
    (hzero : ρ zero = 0)
    (hqp : entries.length = queryPositions.length)
    (hq : ∀ i, i < entries.length →
      ρ (entries.getD i default).1.1
        = QM31.fromBase ((canonicDomain liftingLogSize).at'
            (bitReverseIndex (queryPositions.getD i 0) liftingLogSize)).x ∧
      ρ (entries.getD i default).1.2
        = QM31.fromBase ((canonicDomain liftingLogSize).at'
            (bitReverseIndex (queryPositions.getD i 0) liftingLogSize)).y)
    (hB : ∀ i, i < entries.length →
      ∀ gb ∈ (entries.getD i default).2,
        Bound ρ queriedValues.flatten i gb)
    (hbatch : ∀ i, i < entries.length →
      (entries.getD i default).2.map GroupBinding.batch = batches)
    (h : AllHold ρ (deepRows zero
      (entries.map fun e => (e.1, e.2.map fun gb => (gb.g, gb.valRegs))) n).ops) :
    Quotients.friAnswers columnLogSizes sampledPoints sampledValues randomCoeff
        queryPositions queriedValues liftingLogSize
      = .ok ((deepRows zero (entries.map fun e =>
          (e.1, e.2.map fun gb => (gb.g, gb.valRegs))) n).res.map ρ) := by
  have hposD : ∀ i, i < entries.length →
      queryPositions.getD i 0 ∈ queryPositions := by
    intro i hi
    have hi' : i < queryPositions.length := hqp ▸ hi
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi']
    exact List.getElem_mem hi'
  have hdn : ∀ i, i < entries.length →
      ∀ gb ∈ (entries.getD i default).2,
        Quotients.denominator gb.batch.point
          ((canonicDomain liftingLogSize).at'
            (bitReverseIndex (queryPositions.getD i 0) liftingLogSize)) ≠ 0 := by
    intro i hi gb hgb
    have hbm : gb.batch ∈ batches := by
      rw [← hbatch i hi]
      exact List.mem_map_of_mem hgb
    exact hdenS gb.batch hbm _ (hposD i hi)
  obtain ⟨hlenR, hvalR⟩ := deepRows_spec entries n hzero hq hB hbatch hdn h
  rw [Quotients.friAnswers_ok columnLogSizes sampledPoints sampledValues
    randomCoeff queryPositions queriedValues liftingLogSize batches
    hbuild hcols him hidx hpos hdenS]
  refine congrArg Except.ok ?_
  refine List.ext_getElem ?_ ?_
  · rw [List.length_map, List.length_zipIdx, List.length_map, hlenR, hqp]
  · intro i h1 h2
    have hiE : i < entries.length := by
      rw [List.length_map, List.length_zipIdx] at h1
      rw [hqp]
      exact h1
    have hiQ : i < queryPositions.length := hqp ▸ hiE
    rw [List.getElem_map, List.getElem_zipIdx, List.getElem_map]
    have hgd : ρ ((deepRows zero (entries.map fun e =>
        (e.1, e.2.map fun gb => (gb.g, gb.valRegs))) n).res.getD i 0)
        = ρ ((deepRows zero (entries.map fun e =>
          (e.1, e.2.map fun gb => (gb.g, gb.valRegs))) n).res[i]) := by
      rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by
        rw [hlenR]; exact hiE)]
      rfl
    rw [← hgd, hvalR i hiE]
    have hqd : queryPositions.getD i 0 = queryPositions[i] := by
      rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hiQ]
      rfl
    rw [← hqd]
    simp only [Nat.zero_add]

/-- **`Bound` is discharged by the gates.** A group whose registers come
out of `groupSetup` (its `AllHold`), whose response registers carry the
`−2u`-scaled batch random coefficients (what `chain_alphas` provides
from the global alpha chain) and the batch sample values, and whose
query-value registers carry the queried column values, is `Bound`. -/
theorem bound_of_groupSetup {ρ : ℕ → QM31} {imMask zero px py n : ℕ}
    {rsReg : List (ℕ × ℕ)} {valRegs : List ℕ}
    {batch : Quotients.SampleBatch} {flatCols : List (List F)} {row : ℕ}
    (hmask : ρ imMask = QM31.fromM31s 0 0 1 1) (hzero : ρ zero = 0)
    (hpx : ρ px = batch.point.x) (hpy : ρ py = batch.point.y)
    (hsetup : AllHold ρ (groupSetup imMask zero px py rsReg n).ops)
    (hlenV : valRegs.length = rsReg.length)
    (hlenE : rsReg.length = batch.entries.length)
    (halpha : ∀ i, i < rsReg.length →
      ρ (rsReg.getD i (0, 0)).1
        = (-2 : QM31) * Deep.uu * (batch.entries.getD i default).randomCoeff)
    (hV : ∀ i, i < rsReg.length →
      ρ (rsReg.getD i (0, 0)).2 = (batch.entries.getD i default).sampleValue)
    (hvals : ∀ i, i < rsReg.length →
      ρ (valRegs.getD i 0)
        = QM31.fromBase ((flatCols.getD
            (batch.entries.getD i default).columnIndex []).getD row 0)) :
    Bound ρ flatCols row
      ⟨(groupSetup imMask zero px py rsReg n).res, valRegs, rsReg, batch⟩ := by
  obtain ⟨hd, he, hf, hclen, hcoeff, haSum, hb⟩ :=
    groupSetup_sound hmask hzero hpx hpy hsetup
  exact ⟨hd, he, hf, hclen, hcoeff, haSum, hb, hlenV, hlenE, halpha, hV, hvals⟩

end StwoVerifier.Gadgets
