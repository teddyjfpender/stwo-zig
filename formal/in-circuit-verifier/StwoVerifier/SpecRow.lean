/-
**The spec's `friAnswers` row loop in closed form.**

Under the guards the circuit enforces — every batch point has
`im(P.y) ≠ 0` (the single `inv(prod)` gate, via `prodChain_all_ne_zero`)
and the denominators are nonzero at the queried domain points
(`den_nonzero`) — the spec's per-row `mapM`/`foldl` walk evaluates to
the sum over batches of exactly the batch term `groupQuery_sound`
produces on the gadget side. This file proves that closed form.
-/
import StwoVerifier.Quotients
import StwoVerifier.DenNonzero

namespace StwoVerifier

/-- The executable CM31 `inv?` succeeds on nonzero inputs with the
field inverse. -/
theorem CM31.inv?_of_ne_zero {x : CM31} (hx : x ≠ 0) :
    x.inv? = some x⁻¹ := by
  have hn : CM31.norm x ≠ 0 := fun h => hx (CM31.norm2_eq_zero h)
  show (if CM31.norm x = 0 then none
    else some ⟨x.a * (CM31.norm x)⁻¹, -x.b * (CM31.norm x)⁻¹⟩ : Option CM31)
    = some x⁻¹
  rw [if_neg hn]
  refine congrArg some ?_
  show (⟨x.a * (CM31.norm x)⁻¹, -x.b * (CM31.norm x)⁻¹⟩ : CM31)
    = ⟨x.a / CM31.norm2 x, -x.b / CM31.norm2 x⟩
  refine CM31.ext' ?_ ?_ <;> show _ = _ <;> rw [div_eq_mul_inv] <;> rfl

namespace Deep

/-- `im x ≠ 0` rules out the degenerate line: the conjugate differs. -/
theorem conj_ne_of_im {x : QM31} (him : imQ x ≠ 0) :
    x.complexConjugate ≠ x := by
  intro h
  have hc := conj_eq_sub_two_im x
  rw [h] at hc
  have h2 : (2 : QM31) * imQ x = 0 := by linear_combination hc
  rcases mul_eq_zero.mp h2 with h' | h'
  · exact qtwo_ne_zero h'
  · exact him h'

end Deep

/-- `mulM31` is multiplication by the base-field lift. -/
theorem QM31.mulM31_eq (x : QM31) (m : F) :
    x.mulM31 m = x * QM31.fromBase m := by
  refine QM31.ext' ?_ ?_ <;> show _ = _ <;>
    refine CM31.ext' ?_ ?_ <;> show _ = _ <;>
    simp [QM31.mulM31, CM31.mulM31, QM31.fromBase, CM31.fromBase, QM31.R]

namespace Quotients

/-- `mapM` over `Except` with elementwise-successful bodies is `map`. -/
theorem mapM_ok {α β : Type} {f : α → Except VError β} (g : α → β) :
    ∀ l : List α, (∀ x ∈ l, f x = .ok (g x)) → l.mapM f = .ok (l.map g)
  | [], _ => rfl
  | x :: rest, h => by
    rw [List.mapM_cons, h x List.mem_cons_self,
      mapM_ok g rest fun y hy => h y (List.mem_cons_of_mem x hy)]
    rfl

/-- Left-folded addition is the mapped sum. -/
theorem foldl_add_eq {α : Type} (f : α → QM31) :
    ∀ (l : List α) (z : QM31),
      l.foldl (fun acc x => acc + f x) z = z + (l.map f).sum
  | [], z => by simp
  | x :: rest, z => by
    show (rest.foldl (fun acc x => acc + f x) (z + f x)) = _
    rw [foldl_add_eq f rest (z + f x)]
    simp only [List.map_cons, List.sum_cons]
    ring

/-- `lineCoeffs` away from the degenerate line, in closed form. -/
theorem lineCoeffs_eq (point : PointQ) (value alpha : QM31)
    (hne : point.y.complexConjugate ≠ point.y) :
    lineCoeffs point value alpha
      = .ok (alpha * (value.complexConjugate - value),
          alpha * (value * (point.y.complexConjugate - point.y)
            - (value.complexConjugate - value) * point.y),
          alpha * (point.y.complexConjugate - point.y)) := by
  unfold lineCoeffs
  rw [if_neg hne]
  rfl


/-- `Except.ok` bind reduction, for stepwise do-chain rewriting. -/
theorem ok_bind {α β : Type} (a : α) (k : α → Except VError β) :
    (Except.ok a >>= k : Except VError β) = k a := rfl

/-- A `mapM` whose results feed a `pure` continuation. -/
theorem mapM_pure_ok {α β γ : Type} {f : α → Except VError β} (g : α → β)
    (k : List β → γ) (l : List α) (h : ∀ x ∈ l, f x = .ok (g x)) :
    ((l.mapM f) >>= fun terms => pure (k terms)) = .ok (k (l.map g)) := by
  rw [mapM_ok g l h]
  rfl

/-- First components of a `zipIdx` pair are list members. -/
theorem fst_mem_of_mem_zipIdx {α : Type} {x : α × ℕ} {l : List α}
    (h : x ∈ l.zipIdx) : x.1 ∈ l := by
  rw [← List.zipIdx_map_fst 0 l]
  exact List.mem_map_of_mem h

/-- `lineCoeffs`' closed-form value: `(α·a, α·b, α·c)`. -/
def coeffsOf (P : PointQ) (e : NumeratorData) : QM31 × QM31 × QM31 :=
  (e.randomCoeff * (e.sampleValue.complexConjugate - e.sampleValue),
   e.randomCoeff * (e.sampleValue * (P.y.complexConjugate - P.y)
     - (e.sampleValue.complexConjugate - e.sampleValue) * P.y),
   e.randomCoeff * (P.y.complexConjugate - P.y))

/-- The value of `friAnswers`' per-batch precomputation. -/
def withCoeffsOf (batch : SampleBatch) :
    SampleBatch × List (QM31 × QM31 × QM31) × QM31 × QM31 :=
  (batch, batch.entries.map (coeffsOf batch.point),
   (batch.entries.map (coeffsOf batch.point)).foldl
     (fun acc (a, _, _) => acc + a) QM31.zero,
   (batch.entries.map (coeffsOf batch.point)).foldl
     (fun acc (_, b, _) => acc + b) QM31.zero)

/-- The value of `friAnswers`' per-batch per-row term, raw form. -/
noncomputable def rowTerm (flatCols : List (List F)) (row : ℕ) (p : PointF) :
    SampleBatch × List (QM31 × QM31 × QM31) × QM31 × QM31 → QM31 :=
  fun (batch, coeffs, sumA, sumB) =>
    (((batch.entries.zip coeffs).foldl
        (fun acc (e, (_, _, c)) =>
          acc + c.mulM31 ((flatCols.getD e.columnIndex []).getD row 0))
        QM31.zero) - (sumA.mulM31 p.y + sumB)).mulCM31
      (denominator batch.point p)⁻¹

/-- **The spec's batch term in the gadget's shape**: the summand of
`groupQuery_sound`'s right-hand side, over the batch's entries. -/
noncomputable def batchTerm (b : SampleBatch) (flatCols : List (List F)) (row : ℕ)
    (p : PointF) : QM31 :=
  ((b.entries.map fun e =>
      e.randomCoeff * (b.point.y.complexConjugate - b.point.y)
          * QM31.fromBase ((flatCols.getD e.columnIndex []).getD row 0)
        - (e.randomCoeff * (e.sampleValue.complexConjugate - e.sampleValue)
              * QM31.fromBase p.y
          + (e.randomCoeff * (e.sampleValue * (b.point.y.complexConjugate - b.point.y))
            - e.randomCoeff * ((e.sampleValue.complexConjugate - e.sampleValue)
                * b.point.y)))).sum).mulCM31
    (denominator b.point p)⁻¹

/-- Fold of first components (the spec's `sumA`), with its exact lambda. -/
theorem foldl_fst : ∀ (l : List (QM31 × QM31 × QM31)) (z : QM31),
    l.foldl (fun acc (a, _, _) => acc + a) z = z + (l.map fun t => t.1).sum
  | [], z => by simp
  | t :: rest, z => by
    obtain ⟨a, b, c⟩ := t
    show List.foldl (fun acc (a, _, _) => acc + a) (z + a) rest = _
    rw [foldl_fst rest (z + a)]
    simp only [List.map_cons, List.sum_cons]
    ring

/-- Fold of middle components (the spec's `sumB`). -/
theorem foldl_snd : ∀ (l : List (QM31 × QM31 × QM31)) (z : QM31),
    l.foldl (fun acc (_, b, _) => acc + b) z = z + (l.map fun t => t.2.1).sum
  | [], z => by simp
  | t :: rest, z => by
    obtain ⟨a, b, c⟩ := t
    show List.foldl (fun acc (_, b, _) => acc + b) (z + b) rest = _
    rw [foldl_snd rest (z + b)]
    simp only [List.map_cons, List.sum_cons]
    ring

/-- Plain addition fold (the spec's row sum). -/
theorem foldl_sum : ∀ (l : List QM31) (z : QM31),
    l.foldl (· + ·) z = z + l.sum
  | [], z => by simp
  | x :: rest, z => by
    show List.foldl (· + ·) (z + x) rest = _
    rw [foldl_sum rest (z + x)]
    simp only [List.sum_cons]
    ring

/-- The numerator fold over entries zipped with their closed-form
coefficients. -/
theorem foldl_num (P : PointQ) (flatCols : List (List F)) (row : ℕ) :
    ∀ (l : List NumeratorData) (z : QM31),
      ((l.zip (l.map (coeffsOf P))).foldl
        (fun acc (e, (_, _, c)) =>
          acc + c.mulM31 ((flatCols.getD e.columnIndex []).getD row 0)) z)
      = z + (l.map fun e => (coeffsOf P e).2.2
          * QM31.fromBase ((flatCols.getD e.columnIndex []).getD row 0)).sum
  | [], z => by simp
  | e :: rest, z => by
    show ((rest.zip (rest.map (coeffsOf P))).foldl
        (fun acc (e, (_, _, c)) =>
          acc + c.mulM31 ((flatCols.getD e.columnIndex []).getD row 0))
        (z + (coeffsOf P e).2.2.mulM31 ((flatCols.getD e.columnIndex []).getD row 0))) = _
    rw [foldl_num P flatCols row rest _, QM31.mulM31_eq]
    simp only [List.map_cons, List.sum_cons]
    ring

/-- Linearity: the three mapped sums combine into the per-entry term. -/
theorem map_sum_combine {α : Type} (l : List α) (fc fa fb : α → QM31)
    (Y : QM31) :
    (l.map fc).sum - ((l.map fa).sum * Y + (l.map fb).sum)
      = (l.map fun e => fc e - (fa e * Y + fb e)).sum := by
  induction l with
  | nil => simp
  | cons e rest ih =>
    simp only [List.map_cons, List.sum_cons]
    linear_combination ih

set_option maxHeartbeats 1600000 in
/-- **`friAnswers` in closed form.** Under the guards the circuit
enforces — nondegenerate batch points and nonvanishing denominators at
the queried domain points — the spec's row loop succeeds, and each row
is the sum over batches of the gadget-shaped batch term. -/
theorem friAnswers_ok
    (columnLogSizes : List (List Nat)) (sampledPoints : List (List (List PointQ)))
    (sampledValues : List (List (List QM31))) (randomCoeff : QM31)
    (queryPositions : List Nat) (queriedValues : List (List (List F)))
    (liftingLogSize : Nat) (batches : List SampleBatch)
    (hbuild : buildSampleBatches sampledPoints sampledValues columnLogSizes
      liftingLogSize randomCoeff = .ok batches)
    (hcols : ∀ col ∈ queriedValues.flatten, col.length = queryPositions.length)
    (him : ∀ b ∈ batches, Deep.imQ b.point.y ≠ 0)
    (hidx : ∀ b ∈ batches, ∀ e ∈ b.entries,
      e.columnIndex < queriedValues.flatten.length)
    (hpos : ∀ pos ∈ queryPositions, pos < (canonicDomain liftingLogSize).size)
    (hden : ∀ b ∈ batches, ∀ pos ∈ queryPositions,
      denominator b.point ((canonicDomain liftingLogSize).at'
        (bitReverseIndex pos liftingLogSize)) ≠ 0) :
    friAnswers columnLogSizes sampledPoints sampledValues randomCoeff
        queryPositions queriedValues liftingLogSize
      = .ok (queryPositions.zipIdx.map fun (pos, row) =>
          (batches.map fun b => batchTerm b queriedValues.flatten row
            ((canonicDomain liftingLogSize).at'
              (bitReverseIndex pos liftingLogSize))).sum) := by
  have hany : (queriedValues.flatten.any
      fun col => col.length ≠ queryPositions.length) = false := by
    rw [List.any_eq_false]
    intro col hcol
    simp [hcols col hcol]
  have hany2 : (batches.any fun batch => batch.entries.any
      fun e => e.columnIndex ≥ queriedValues.flatten.length) = false := by
    rw [List.any_eq_false]
    intro b hb
    simp only [Bool.not_eq_true, List.any_eq_false, decide_eq_true_eq]
    intro e he
    exact Nat.not_le.mpr (hidx b hb e he)
  have hOuter : (batches.mapM fun batch => do
      let coeffs ← batch.entries.mapM fun e =>
        lineCoeffs batch.point e.sampleValue e.randomCoeff
      let sumA := coeffs.foldl (fun acc (a, _, _) => acc + a) QM31.zero
      let sumB := coeffs.foldl (fun acc (_, b, _) => acc + b) QM31.zero
      pure (batch, coeffs, sumA, sumB))
      = Except.ok (batches.map withCoeffsOf) := by
    refine mapM_ok withCoeffsOf batches fun b hb => ?_
    have hne := Deep.conj_ne_of_im (him b hb)
    have hent : ∀ e ∈ b.entries,
        lineCoeffs b.point e.sampleValue e.randomCoeff
          = Except.ok (coeffsOf b.point e) :=
      fun e _ => lineCoeffs_eq b.point e.sampleValue e.randomCoeff hne
    rw [mapM_ok (coeffsOf b.point) b.entries hent]
    rfl
  unfold friAnswers
  dsimp only
  rw [hany]
  simp only [Bool.false_eq_true, if_false]
  rw [hbuild]
  simp only [ok_bind]
  rw [hOuter]
  simp only [ok_bind]
  rw [hany2]
  simp only [Bool.false_eq_true, if_false]
  refine Eq.trans (mapM_ok (fun (pos, row) =>
      ((batches.map withCoeffsOf).map (rowTerm queriedValues.flatten row
        ((canonicDomain liftingLogSize).at'
          (bitReverseIndex pos liftingLogSize)))).foldl (· + ·) QM31.zero)
      queryPositions.zipIdx ?_) ?_
  · rintro ⟨pos, row⟩ hx
    have hp : pos ∈ queryPositions := fst_mem_of_mem_zipIdx hx
    dsimp only
    rw [if_neg (by have := hpos pos hp; omega)]
    refine mapM_pure_ok (rowTerm queriedValues.flatten row
      ((canonicDomain liftingLogSize).at'
        (bitReverseIndex pos liftingLogSize)))
      (fun terms => terms.foldl (· + ·) QM31.zero) _ ?_
    rintro x hxm
    obtain ⟨b, hb, rfl⟩ := List.mem_map.mp hxm
    dsimp only [withCoeffsOf]
    rw [CM31.inv?_of_ne_zero (hden b hb pos hp)]
    rfl
  · refine congrArg Except.ok ?_
    refine List.map_congr_left ?_
    rintro ⟨pos, row⟩ hx
    dsimp only
    rw [List.map_map, foldl_sum]
    rw [show (QM31.zero : QM31) = 0 from rfl, zero_add]
    refine congrArg List.sum ?_
    refine List.map_congr_left fun b hb => ?_
    show rowTerm queriedValues.flatten row
      ((canonicDomain liftingLogSize).at' (bitReverseIndex pos liftingLogSize))
      (withCoeffsOf b) = _
    dsimp only [rowTerm, withCoeffsOf]
    rw [foldl_num, foldl_fst, foldl_snd, QM31.mulM31_eq]
    rw [show (QM31.zero : QM31) = 0 from rfl, zero_add, zero_add, zero_add]
    simp only [List.map_map, Function.comp_def]
    rw [map_sum_combine]
    refine congrArg (fun s => QM31.mulCM31 s _) ?_
    refine congrArg List.sum ?_
    refine List.map_congr_left fun e he => ?_
    simp only [coeffsOf]
    ring

/-! ### Grouping invariance of the row value

The circuit groups samples by point *wire ids* (first seen), the spec
by point *values* (`pushEntry`). Any two groupings with
permutation-equal flat views give the same row sum, because the batch
term is additive over a batch's entries. -/

theorem mulCM31_add (x y : QM31) (c : CM31) :
    (x + y).mulCM31 c = x.mulCM31 c + y.mulCM31 c := by
  unfold QM31.mulCM31
  refine QM31.ext' ?_ ?_ <;> show _ = _ <;> simp <;> ring

theorem mulCM31_zero (c : CM31) : (0 : QM31).mulCM31 c = 0 := by
  unfold QM31.mulCM31
  refine QM31.ext' ?_ ?_ <;> show _ = _ <;> simp

/-- Scaling distributes over a mapped sum. -/
theorem sum_mulCM31 {α : Type} (l : List α) (f : α → QM31) (c : CM31) :
    ((l.map f).sum).mulCM31 c = (l.map fun e => (f e).mulCM31 c).sum := by
  induction l with
  | nil => simpa using mulCM31_zero c
  | cons e rest ih =>
    simp only [List.map_cons, List.sum_cons]
    rw [mulCM31_add, ih]

/-- The flat per-entry term of a batch row. -/
noncomputable def flatTerm (flatCols : List (List F)) (row : ℕ) (p : PointF)
    (pe : PointQ × NumeratorData) : QM31 :=
  (pe.2.randomCoeff * (pe.1.y.complexConjugate - pe.1.y)
      * QM31.fromBase ((flatCols.getD pe.2.columnIndex []).getD row 0)
    - (pe.2.randomCoeff * (pe.2.sampleValue.complexConjugate - pe.2.sampleValue)
          * QM31.fromBase p.y
      + (pe.2.randomCoeff * (pe.2.sampleValue * (pe.1.y.complexConjugate - pe.1.y))
        - pe.2.randomCoeff * ((pe.2.sampleValue.complexConjugate
            - pe.2.sampleValue) * pe.1.y)))).mulCM31 (denominator pe.1 p)⁻¹

/-- A batch's term is the sum of its flat entries' terms. -/
theorem batchTerm_eq_flat (b : SampleBatch) (flatCols : List (List F))
    (row : ℕ) (p : PointF) :
    batchTerm b flatCols row p
      = ((b.entries.map fun e => (b.point, e)).map
          (flatTerm flatCols row p)).sum := by
  unfold batchTerm
  rw [sum_mulCM31, List.map_map]
  refine congrArg List.sum ?_
  refine List.map_congr_left fun e _ => ?_
  rfl

/-- The row sum over any grouping is the flat sum. -/
theorem rowSum_eq_flat (batches : List SampleBatch) (flatCols : List (List F))
    (row : ℕ) (p : PointF) :
    (batches.map fun b => batchTerm b flatCols row p).sum
      = ((flattenBatches batches).map (flatTerm flatCols row p)).sum := by
  unfold flattenBatches
  rw [List.map_flatMap, List.flatMap_def, List.sum_flatten, List.map_map]
  refine congrArg List.sum ?_
  refine List.map_congr_left fun b _ => ?_
  exact batchTerm_eq_flat b flatCols row p

/-- **Grouping invariance**: permutation-equal flat views give equal
row sums — the bridge between the circuit's wire-id groups and the
spec's value-keyed batches. -/
theorem rowSum_perm {groups batches : List SampleBatch}
    (flatCols : List (List F)) (row : ℕ) (p : PointF)
    (hperm : (flattenBatches groups).Perm (flattenBatches batches)) :
    (groups.map fun b => batchTerm b flatCols row p).sum
      = (batches.map fun b => batchTerm b flatCols row p).sum := by
  rw [rowSum_eq_flat, rowSum_eq_flat]
  exact List.Perm.sum_eq (hperm.map _)

end Quotients
end StwoVerifier
