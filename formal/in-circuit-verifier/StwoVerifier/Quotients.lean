/-
**DEEP quotients at the queried rows**
(`src/core/pcs/quotients/{samples,row_evaluation,fri_answers}.zig`,
`src/core/constraints.zig`, stwo-zig `4afa09dbf`), executable.

`buildSampleBatches` assigns random-coefficient powers in tree/column/sample
order — with the periodicity duplicate first for every two-sample column of
a lifted tree (the sampled point shifted by the period generator carries the
*second* sample's value) — and groups samples by their exact QM31 point in
first-occurrence order.

`friAnswers` evaluates, for each queried row `p` of the lifted canonic
domain (bit-reversed indexing), the sum over batches of
`(Σᵢ cᵢ·colᵢ(p) − (Σᵢ aᵢ)·p.y − Σᵢ bᵢ) / denom(batch.point, p)` with the
complex-conjugate line coefficients `(aᵢ, bᵢ, cᵢ)` scaled by the batch's
random powers, and the CM31 denominator
`(Re(Px) − p.x)·Im(Py) − (Re(Py) − p.y)·Im(Px)`.
-/
import StwoVerifier.Merkle
import StwoVerifier.Circle

namespace StwoVerifier.Quotients

open StwoVerifier

/-- One column's contribution to a point batch. -/
structure NumeratorData where
  columnIndex : Nat
  sampleValue : QM31
  randomCoeff : QM31
  deriving Repr

structure SampleBatch where
  point : PointQ
  entries : List NumeratorData
  deriving Repr

/-- Append an entry to the batch of `point`, creating it at the end on first
occurrence (the Zig `PointBatchMap` + ordered list). -/
def pushEntry (batches : List SampleBatch) (point : PointQ) (e : NumeratorData) :
    List SampleBatch :=
  match batches with
  | [] => [⟨point, [e]⟩]
  | b :: rest =>
    if b.point = point then ⟨b.point, b.entries ++ [e]⟩ :: rest
    else b :: pushEntry rest point e

/-- The flat view of grouped batches: every `(point, entry)` pair. -/
def flattenBatches (batches : List SampleBatch) : List (PointQ × NumeratorData) :=
  batches.flatMap fun batch => batch.entries.map fun e => (batch.point, e)

/-- `pushEntry` only moves the new pair to its bucket: the flat view is a
permutation of consing it. Any sum over the samples is therefore
independent of the grouping — the bridge between the spec's value-grouped
batches and the circuit's register-grouped ones. -/
theorem flattenBatches_pushEntry (batches : List SampleBatch)
    (point : PointQ) (e : NumeratorData) :
    (flattenBatches (pushEntry batches point e)).Perm
      ((point, e) :: flattenBatches batches) := by
  induction batches with
  | nil => simp [flattenBatches, pushEntry]
  | cons b rest ih =>
    by_cases hp : b.point = point
    · rw [show pushEntry (b :: rest) point e
        = ⟨b.point, b.entries ++ [e]⟩ :: rest from by
          simp only [pushEntry]; rw [if_pos hp]]
      unfold flattenBatches
      simp only [List.flatMap_cons, List.map_append, List.map_cons,
        List.map_nil, hp]
      have h1 : (List.map (fun x => (point, x)) b.entries ++ [(point, e)]).Perm
          ((point, e) :: List.map (fun x => (point, x)) b.entries) :=
        List.perm_append_comm
      exact h1.append_right _
    · rw [show pushEntry (b :: rest) point e
        = b :: pushEntry rest point e from by
          simp only [pushEntry]; rw [if_neg hp]]
      unfold flattenBatches at ih ⊢
      simp only [List.flatMap_cons]
      refine ((ih.append_left _).trans ?_)
      exact List.perm_middle

/-- The grouping state: batches so far, the next random power, and the
flat column counter. -/
structure BatchState where
  batches : List SampleBatch
  randomPow : QM31
  flatColumn : Nat

/-- Push one column's samples (periodicity duplicate first). -/
def pushColumn (step : PointF) (randomCoeff : QM31) (st : BatchState)
    (colPoints : List PointQ) (colValues : List QM31) (logSize : Nat) :
    Except VError BatchState := do
  if colPoints.length ≠ colValues.length then throw .shapeMismatch
  let st ←
    if colPoints.length = 2 then
      -- Periodicity duplicate: second sample's point shifted by the
      -- period generator `step^(2^logSize)`, second sample's value.
      let periodic := (colPoints.getD 1 CPoint.zero).add
        (PointF.intoQ (step.repeatedDouble logSize))
      pure { st with
        batches := pushEntry st.batches periodic
          ⟨st.flatColumn, colValues.getD 1 QM31.zero, st.randomPow⟩
        randomPow := st.randomPow * randomCoeff }
    else pure st
  let st := (colPoints.zip colValues).foldl (fun st (point, value) =>
    { st with
      batches := pushEntry st.batches point ⟨st.flatColumn, value, st.randomPow⟩
      randomPow := st.randomPow * randomCoeff }) st
  return { st with flatColumn := st.flatColumn + 1 }

def pushTree (step : PointF) (randomCoeff : QM31) :
    BatchState → List (List PointQ × List QM31 × Nat) → Except VError BatchState
  | st, [] => .ok st
  | st, (colPoints, colValues, logSize) :: rest => do
    let st ← pushColumn step randomCoeff st colPoints colValues logSize
    pushTree step randomCoeff st rest

def pushTrees (step : PointF) (randomCoeff : QM31) :
    BatchState → List (List (List PointQ) × List (List QM31) × List Nat) →
    Except VError BatchState
  | st, [] => .ok st
  | st, (treePoints, treeValues, treeSizes) :: rest => do
    if treePoints.length ≠ treeSizes.length ∨ treePoints.length ≠ treeValues.length then
      throw .shapeMismatch
    let st ← pushTree step randomCoeff st
      (treePoints.zip (treeValues.zip treeSizes))
    pushTrees step randomCoeff st rest

def buildSampleBatches (sampledPoints : List (List (List PointQ)))
    (sampledValues : List (List (List QM31)))
    (columnLogSizes : List (List Nat)) (liftingLogSize : Nat)
    (randomCoeff : QM31) : Except VError (List SampleBatch) := do
  if sampledPoints.length ≠ columnLogSizes.length ∨
     sampledPoints.length ≠ sampledValues.length then throw .shapeMismatch
  let st ← pushTrees (canonicStep liftingLogSize) randomCoeff
    ⟨[], QM31.one, 0⟩ (sampledPoints.zip (sampledValues.zip columnLogSizes))
  return st.batches

/-- `complexConjugateLineCoeffs`: `(α·a, α·b, α·c)` with
`a = conj(v) − v`, `c = conj(P).y − P.y`, `b = v·c − a·P.y`.
Degenerate when `P.y` is its own conjugate. -/
def lineCoeffs (point : PointQ) (value alpha : QM31) :
    Except VError (QM31 × QM31 × QM31) := do
  if point.y.complexConjugate = point.y then throw .degenerateLine
  let a := value.complexConjugate - value
  let c := point.y.complexConjugate - point.y
  let b := value * c - a * point.y
  return (alpha * a, alpha * b, alpha * c)

/-- The CM31 denominator of a batch at domain point `p`:
`(Re(Px) − p.x)·Im(Py) − (Re(Py) − p.y)·Im(Px)`. -/
def denominator (point : PointQ) (p : PointF) : CM31 :=
  let prx := point.x.c0; let pix := point.x.c1
  let pry := point.y.c0; let piy := point.y.c1
  ((prx - CM31.fromBase p.x) * piy) - ((pry - CM31.fromBase p.y) * pix)

/-- `friAnswers`. `queriedValues` is tree → column → per-query M31 values. -/
def friAnswers (columnLogSizes : List (List Nat))
    (sampledPoints : List (List (List PointQ)))
    (sampledValues : List (List (List QM31)))
    (randomCoeff : QM31) (queryPositions : List Nat)
    (queriedValues : List (List (List F))) (liftingLogSize : Nat) :
    Except VError (List QM31) := do
  let flatCols := queriedValues.flatten
  if flatCols.any (fun col => col.length ≠ queryPositions.length) then
    throw .shapeMismatch
  let batches ← buildSampleBatches sampledPoints sampledValues columnLogSizes
    liftingLogSize randomCoeff
  -- Precompute per-batch line coefficients and their sums.
  let withCoeffs ← batches.mapM fun batch => do
    let coeffs ← batch.entries.mapM fun e =>
      lineCoeffs batch.point e.sampleValue e.randomCoeff
    let sumA := coeffs.foldl (fun acc (a, _, _) => acc + a) QM31.zero
    let sumB := coeffs.foldl (fun acc (_, b, _) => acc + b) QM31.zero
    pure (batch, coeffs, sumA, sumB)
  if batches.any (fun batch => batch.entries.any
      (fun e => e.columnIndex ≥ flatCols.length)) then
    throw .columnIndexOutOfBounds
  let domain := canonicDomain liftingLogSize
  queryPositions.zipIdx.mapM fun (pos, row) => do
    if pos ≥ domain.size then throw .queryPositionOutOfRange
    let p := domain.at' (bitReverseIndex pos liftingLogSize)
    let terms ← withCoeffs.mapM fun (batch, coeffs, sumA, sumB) => do
      let d := denominator batch.point p
      let di ← match d.inv? with
        | some di => pure di | none => throw VError.divisionByZero
      let numerator := (batch.entries.zip coeffs).foldl
        (fun acc (e, (_, _, c)) =>
          acc + c.mulM31 ((flatCols.getD e.columnIndex []).getD row 0))
        QM31.zero
      pure ((numerator - (sumA.mulM31 p.y + sumB)).mulCM31 di)
    pure (terms.foldl (· + ·) QM31.zero)

end StwoVerifier.Quotients
