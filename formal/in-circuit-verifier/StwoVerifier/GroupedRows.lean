/-
**The capstone with the circuit's wire batching.** The emitter keys
`OodsPointAuxiliary` groups by the point's `(x, y)` wire ids
(`computeFriInput`'s `AutoArrayHashMap`); the spec batches by point
value (`pushEntry`). Components of equal log size share a periodicity
point value under distinct wires, so the circuit's grouping is strictly
finer on real circuit proofs. `friAnswers_eq_rows_grouped` restates the
deliverable-3 capstone for an arbitrary grouping whose flat view
permutes the spec batches' (`zip_partition_perm` provides exactly that
for a stable wire-keyed partition): the row sums are grouping-agnostic
(`rowSum_perm`).
-/
import StwoVerifier.DeepRowSpec
import StwoVerifier.ResponseOrder

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

theorem mem_flattenBatches {bs : List Quotients.SampleBatch} {p : PointQ}
    {e : Quotients.NumeratorData} :
    (p, e) ∈ Quotients.flattenBatches bs ↔
      ∃ b ∈ bs, b.point = p ∧ e ∈ b.entries := by
  unfold Quotients.flattenBatches
  rw [List.mem_flatMap]
  constructor
  · rintro ⟨b, hb, hm⟩
    obtain ⟨e', he', heq⟩ := List.mem_map.mp hm
    injection heq with h1 h2
    exact ⟨b, hb, h1, h2 ▸ he'⟩
  · rintro ⟨b, hb, rfl, he⟩
    exact ⟨b, hb, List.mem_map.mpr ⟨e, he, rfl⟩⟩

set_option maxHeartbeats 800000 in
/-- **`compute_fri_input` computes `friAnswers`, under any grouping
whose flat view permutes the spec batches'.** The register groups carry
their own (wire-keyed) batches; each group's point value appears among
the spec batches (through the permutation), which transfers the
denominator guards, and the per-row sums agree by `rowSum_perm`. -/
theorem friAnswers_eq_rows_grouped {ρ : ℕ → QM31} {zero : ℕ}
    (columnLogSizes : List (List Nat)) (sampledPoints : List (List (List PointQ)))
    (sampledValues : List (List (List QM31))) (randomCoeff : QM31)
    (queryPositions : List Nat) (queriedValues : List (List (List F)))
    (liftingLogSize : Nat) (batches groups : List Quotients.SampleBatch)
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
    (hgroups : ∀ i, i < entries.length →
      (entries.getD i default).2.map GroupBinding.batch = groups)
    (hne : ∀ g ∈ groups, g.entries ≠ [])
    (hperm : (Quotients.flattenBatches groups).Perm
      (Quotients.flattenBatches batches))
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
    have hgm : gb.batch ∈ groups := by
      rw [← hgroups i hi]
      exact List.mem_map_of_mem hgb
    obtain ⟨e, he⟩ : ∃ e, e ∈ gb.batch.entries := by
      cases hent : gb.batch.entries with
      | nil => exact absurd hent (hne gb.batch hgm)
      | cons a l => exact ⟨a, List.mem_cons_self⟩
    have hmem : (gb.batch.point, e) ∈ Quotients.flattenBatches groups :=
      mem_flattenBatches.mpr ⟨gb.batch, hgm, rfl, he⟩
    obtain ⟨b, hb, hp, -⟩ := mem_flattenBatches.mp (hperm.mem_iff.mp hmem)
    rw [← hp]
    exact hdenS b hb _ (hposD i hi)
  obtain ⟨hlenR, hvalR⟩ := deepRows_spec entries n hzero hq hB hgroups hdn h
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
    rw [← hgd, hvalR i hiE,
      Quotients.rowSum_perm queriedValues.flatten i
        ((canonicDomain liftingLogSize).at'
          (bitReverseIndex (queryPositions.getD i 0) liftingLogSize)) hperm]
    have hqd : queryPositions.getD i 0 = queryPositions[i] := by
      rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hiQ]
      rfl
    rw [← hqd]
    simp only [Nat.zero_add]

end StwoVerifier.Gadgets
