/-
**`buildSampleBatches`' flat view, in push order.**

The spec groups samples by point value (`pushEntry`); the circuit
groups by point wire id and consumes entries in response order with a
global alpha chain. `rowSum_perm` made the row value grouping-
agnostic; this file supplies the other half: on success, the flat
view of the built batches is a permutation of the exact push-order
pair list (`treesPairs`) — tree by tree, column by column, the
periodicity duplicate first for two-sample columns, with the running
random power advancing once per pushed entry. Matching `treesPairs`
against the emitter's response array is then pure statement-level
data (scope B).
-/
import StwoVerifier.SpecRow

namespace StwoVerifier.Quotients

open StwoVerifier

/-- The pairs one `foldl` push loop emits, with the power running. -/
def pushedPairs (fc : ℕ) (rc : QM31) : QM31 → List (PointQ × QM31) →
    List (PointQ × NumeratorData)
  | _, [] => []
  | pow, (pt, v) :: rest =>
    (pt, ⟨fc, v, pow⟩) :: pushedPairs fc rc (pow * rc) rest

/-- The pairs `pushColumn` pushes, in order. -/
def columnPairs (step : PointF) (rc pow : QM31) (fc : ℕ)
    (colPoints : List PointQ) (colValues : List QM31) (logSize : Nat) :
    List (PointQ × NumeratorData) :=
  if colPoints.length = 2 then
    ((colPoints.getD 1 CPoint.zero).add (PointF.intoQ
        (step.repeatedDouble logSize)),
      ⟨fc, colValues.getD 1 QM31.zero, pow⟩)
      :: pushedPairs fc rc (pow * rc) (colPoints.zip colValues)
  else pushedPairs fc rc pow (colPoints.zip colValues)

/-- The power after `pushColumn`. -/
noncomputable def columnPow (rc pow : QM31) (colPoints : List PointQ)
    (colValues : List QM31) : QM31 :=
  (if colPoints.length = 2 then pow * rc else pow)
    * rc ^ (colPoints.zip colValues).length

/-- The pairs and final state of a whole tree. -/
noncomputable def treePairs (step : PointF) (rc : QM31) :
    QM31 → ℕ → List (List PointQ × List QM31 × Nat) →
    List (PointQ × NumeratorData) × QM31 × ℕ
  | pow, fc, [] => ([], pow, fc)
  | pow, fc, (colPoints, colValues, logSize) :: rest =>
    let head := columnPairs step rc pow fc colPoints colValues logSize
    let r := treePairs step rc (columnPow rc pow colPoints colValues)
      (fc + 1) rest
    (head ++ r.1, r.2)

/-- The pairs and final state across all trees. -/
noncomputable def treesPairs (step : PointF) (rc : QM31) :
    QM31 → ℕ → List (List (List PointQ) × List (List QM31) × List Nat) →
    List (PointQ × NumeratorData) × QM31 × ℕ
  | pow, fc, [] => ([], pow, fc)
  | pow, fc, (treePoints, treeValues, treeSizes) :: rest =>
    let head := treePairs step rc pow fc
      (treePoints.zip (treeValues.zip treeSizes))
    let r := treesPairs step rc head.2.1 head.2.2 rest
    (head.1 ++ r.1, r.2)

/-- The push loop's state walk, flattened. The lambda matches
`pushColumn`'s fold verbatim. -/
theorem foldl_pushEntry_perm (rc : QM31) (fc : ℕ) :
    ∀ (l : List (PointQ × QM31)) (bs : List SampleBatch) (pow : QM31),
      (flattenBatches ((l.foldl (fun st (point, value) =>
          { st with
            batches := pushEntry st.batches point
              ⟨st.flatColumn, value, st.randomPow⟩
            randomPow := st.randomPow * rc })
          (⟨bs, pow, fc⟩ : BatchState)).batches)).Perm
        (pushedPairs fc rc pow l ++ flattenBatches bs) ∧
      (l.foldl (fun st (point, value) =>
          { st with
            batches := pushEntry st.batches point
              ⟨st.flatColumn, value, st.randomPow⟩
            randomPow := st.randomPow * rc })
          (⟨bs, pow, fc⟩ : BatchState)).randomPow = pow * rc ^ l.length ∧
      (l.foldl (fun st (point, value) =>
          { st with
            batches := pushEntry st.batches point
              ⟨st.flatColumn, value, st.randomPow⟩
            randomPow := st.randomPow * rc })
          (⟨bs, pow, fc⟩ : BatchState)).flatColumn = fc := by
  intro l
  induction l with
  | nil =>
    intro bs pow
    refine ⟨by simp [pushedPairs], by simp, rfl⟩
  | cons pv rest ih =>
    intro bs pow
    obtain ⟨pt, v⟩ := pv
    have hstep : ((pt, v) :: rest).foldl (fun st (point, value) =>
        { st with
          batches := pushEntry st.batches point
            ⟨st.flatColumn, value, st.randomPow⟩
          randomPow := st.randomPow * rc })
        (⟨bs, pow, fc⟩ : BatchState)
        = rest.foldl (fun st (point, value) =>
          { st with
            batches := pushEntry st.batches point
              ⟨st.flatColumn, value, st.randomPow⟩
            randomPow := st.randomPow * rc })
          (⟨pushEntry bs pt ⟨fc, v, pow⟩, pow * rc, fc⟩ : BatchState) := rfl
    rw [hstep]
    obtain ⟨hperm, hpow, hfc⟩ := ih (pushEntry bs pt ⟨fc, v, pow⟩) (pow * rc)
    refine ⟨?_, by rw [hpow, List.length_cons, pow_succ]; ring, hfc⟩
    refine hperm.trans ?_
    show (pushedPairs fc rc (pow * rc) rest
      ++ flattenBatches (pushEntry bs pt ⟨fc, v, pow⟩)).Perm
      (((pt, ⟨fc, v, pow⟩) :: pushedPairs fc rc (pow * rc) rest)
        ++ flattenBatches bs)
    refine ((flattenBatches_pushEntry bs pt ⟨fc, v, pow⟩).append_left _).trans ?_
    exact List.perm_middle

set_option maxHeartbeats 800000 in
/-- `pushColumn`, flattened: the column's pairs prepend (as a
permutation), the power advances per entry, the column counter by
one. -/
theorem pushColumn_perm (step : PointF) (rc : QM31)
    (bs : List SampleBatch) (pow : QM31) (fc : ℕ)
    (colPoints : List PointQ) (colValues : List QM31) (logSize : ℕ)
    {st' : BatchState}
    (h : pushColumn step rc ⟨bs, pow, fc⟩ colPoints colValues logSize
      = .ok st') :
    (flattenBatches st'.batches).Perm
      (columnPairs step rc pow fc colPoints colValues logSize
        ++ flattenBatches bs) ∧
    st'.randomPow = columnPow rc pow colPoints colValues ∧
    st'.flatColumn = fc + 1 := by
  unfold pushColumn at h
  dsimp only at h
  split at h
  · exact absurd (show Except.error VError.shapeMismatch
      = Except.ok st' from h) (by simp)
  · split at h
    · rename_i hlen h2
      obtain rfl : _ = st' :=
        Except.ok.inj (show Except.ok _ = Except.ok st' from h)
      obtain ⟨hperm, hpow, hfc⟩ := foldl_pushEntry_perm rc fc
        (colPoints.zip colValues)
        (pushEntry bs ((colPoints.getD 1 CPoint.zero).add
          (PointF.intoQ (step.repeatedDouble logSize)))
          ⟨fc, colValues.getD 1 QM31.zero, pow⟩) (pow * rc)
      refine ⟨?_, ?_, ?_⟩
      · refine hperm.trans ?_
        unfold columnPairs
        rw [if_pos h2]
        refine ((flattenBatches_pushEntry bs _ _).append_left _).trans ?_
        exact List.perm_middle
      · show (_ : BatchState).randomPow = _
        rw [hpow]
        unfold columnPow
        rw [if_pos h2]
      · show (_ : BatchState).flatColumn + 1 = fc + 1
        rw [hfc]
    · rename_i hlen h2
      obtain rfl : _ = st' :=
        Except.ok.inj (show Except.ok _ = Except.ok st' from h)
      obtain ⟨hperm, hpow, hfc⟩ := foldl_pushEntry_perm rc fc
        (colPoints.zip colValues) bs pow
      refine ⟨?_, ?_, ?_⟩
      · refine hperm.trans ?_
        unfold columnPairs
        rw [if_neg h2]
      · show (_ : BatchState).randomPow = _
        rw [hpow]
        unfold columnPow
        rw [if_neg h2]
      · show (_ : BatchState).flatColumn + 1 = fc + 1
        rw [hfc]

/-- `pushTree`, flattened. -/
theorem pushTree_perm (step : PointF) (rc : QM31) :
    ∀ (cols : List (List PointQ × List QM31 × Nat))
      (bs : List SampleBatch) (pow : QM31) (fc : ℕ) {st' : BatchState},
      pushTree step rc ⟨bs, pow, fc⟩ cols = .ok st' →
      (flattenBatches st'.batches).Perm
        ((treePairs step rc pow fc cols).1 ++ flattenBatches bs) ∧
      st'.randomPow = (treePairs step rc pow fc cols).2.1 ∧
      st'.flatColumn = (treePairs step rc pow fc cols).2.2 := by
  intro cols
  induction cols with
  | nil =>
    intro bs pow fc st' h
    obtain rfl : _ = st' := Except.ok.inj h
    exact ⟨by simp [treePairs], rfl, rfl⟩
  | cons col rest ih =>
    intro bs pow fc st' h
    obtain ⟨cp, cv, ls⟩ := col
    rw [show pushTree step rc ⟨bs, pow, fc⟩ ((cp, cv, ls) :: rest)
      = (pushColumn step rc ⟨bs, pow, fc⟩ cp cv ls) >>= fun st =>
          pushTree step rc st rest from rfl] at h
    cases hc : pushColumn step rc ⟨bs, pow, fc⟩ cp cv ls with
    | error e =>
      rw [hc] at h
      exact absurd (show Except.error e = Except.ok st' from h) (by simp)
    | ok st1 =>
      rw [hc, ok_bind] at h
      obtain ⟨bs1, pow1, fc1⟩ := st1
      obtain ⟨hcol, hcpow, hcfc⟩ := pushColumn_perm step rc bs pow fc cp cv ls hc
      have hcpow' : pow1 = columnPow rc pow cp cv := hcpow
      have hcfc' : fc1 = fc + 1 := hcfc
      subst hcpow' hcfc'
      obtain ⟨hrest, hrpow, hrfc⟩ := ih bs1 (columnPow rc pow cp cv) (fc + 1) h
      refine ⟨?_, hrpow, hrfc⟩
      refine hrest.trans ?_
      have hbs1 : (flattenBatches bs1).Perm
          (columnPairs step rc pow fc cp cv ls ++ flattenBatches bs) := hcol
      refine ((hbs1.append_left _).trans ?_)
      show ((treePairs step rc (columnPow rc pow cp cv) (fc + 1) rest).1
        ++ (columnPairs step rc pow fc cp cv ls ++ flattenBatches bs)).Perm
        ((columnPairs step rc pow fc cp cv ls
          ++ (treePairs step rc (columnPow rc pow cp cv) (fc + 1) rest).1)
          ++ flattenBatches bs)
      rw [← List.append_assoc]
      exact List.perm_append_comm.append_right _

/-- `pushTrees`, flattened. -/
theorem pushTrees_perm (step : PointF) (rc : QM31) :
    ∀ (trees : List (List (List PointQ) × List (List QM31) × List Nat))
      (bs : List SampleBatch) (pow : QM31) (fc : ℕ) {st' : BatchState},
      pushTrees step rc ⟨bs, pow, fc⟩ trees = .ok st' →
      (flattenBatches st'.batches).Perm
        ((treesPairs step rc pow fc trees).1 ++ flattenBatches bs) := by
  intro trees
  induction trees with
  | nil =>
    intro bs pow fc st' h
    obtain rfl : _ = st' := Except.ok.inj h
    exact (by simp [treesPairs])
  | cons tree rest ih =>
    intro bs pow fc st' h
    obtain ⟨tp, tv, ts⟩ := tree
    rw [Quotients.pushTrees] at h
    dsimp only at h
    split at h
    · exact absurd (show Except.error VError.shapeMismatch
        = Except.ok st' from h) (by simp)
    · cases hc : pushTree step rc ⟨bs, pow, fc⟩ (tp.zip (tv.zip ts)) with
      | error e =>
        rw [hc] at h
        exact absurd (show Except.error e = Except.ok st' from h) (by simp)
      | ok st1 =>
        rw [hc, ok_bind] at h
        obtain ⟨bs1, pow1, fc1⟩ := st1
        obtain ⟨htree, htpow, htfc⟩ :=
          pushTree_perm step rc (tp.zip (tv.zip ts)) bs pow fc hc
        have htpow' : pow1 = (treePairs step rc pow fc
          (tp.zip (tv.zip ts))).2.1 := htpow
        have htfc' : fc1 = (treePairs step rc pow fc
          (tp.zip (tv.zip ts))).2.2 := htfc
        subst htpow' htfc'
        have hrest := ih bs1 _ _ h
        refine hrest.trans ?_
        refine ((htree.append_left _).trans ?_)
        show ((treesPairs step rc _ _ rest).1
          ++ ((treePairs step rc pow fc (tp.zip (tv.zip ts))).1
            ++ flattenBatches bs)).Perm
          (((treePairs step rc pow fc (tp.zip (tv.zip ts))).1
            ++ (treesPairs step rc _ _ rest).1) ++ flattenBatches bs)
        rw [← List.append_assoc]
        exact List.perm_append_comm.append_right _

/-- **`buildSampleBatches`' flat view is the push-order pair list.** -/
theorem buildSampleBatches_flat
    (sampledPoints : List (List (List PointQ)))
    (sampledValues : List (List (List QM31)))
    (columnLogSizes : List (List Nat)) (liftingLogSize : Nat)
    (randomCoeff : QM31) {batches : List SampleBatch}
    (h : buildSampleBatches sampledPoints sampledValues columnLogSizes
      liftingLogSize randomCoeff = .ok batches) :
    (flattenBatches batches).Perm
      (treesPairs (canonicStep liftingLogSize) randomCoeff QM31.one 0
        (sampledPoints.zip (sampledValues.zip columnLogSizes))).1 := by
  unfold buildSampleBatches at h
  dsimp only at h
  split at h
  · exact absurd (show Except.error VError.shapeMismatch
      = Except.ok batches from h) (by simp)
  · cases hc : pushTrees (canonicStep liftingLogSize) randomCoeff
        ⟨[], QM31.one, 0⟩ (sampledPoints.zip (sampledValues.zip columnLogSizes))
      with
    | error e =>
      rw [hc] at h
      exact absurd (show Except.error e = Except.ok batches from h) (by simp)
    | ok st1 =>
      rw [hc, ok_bind] at h
      obtain ⟨bs1, pow1, fc1⟩ := st1
      obtain rfl : bs1 = batches :=
        Except.ok.inj (show Except.ok bs1 = Except.ok batches from h)
      have := pushTrees_perm (canonicStep liftingLogSize) randomCoeff
        (sampledPoints.zip (sampledValues.zip columnLogSizes)) [] QM31.one 0 hc
      refine this.trans ?_
      simp [flattenBatches]

end StwoVerifier.Quotients
