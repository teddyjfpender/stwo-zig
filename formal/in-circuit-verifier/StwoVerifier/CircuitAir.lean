/-
**The circuit AIR as a `Verifier.Air` instance** (scope B).

`circuitAir` packages the circuit AIR for `NativeAccepts`:

- `maskPoints`: every preprocessed column samples `[oods]` (the circuit
  prover commits with `include_all_preprocessed_columns`), every base
  trace column `[oods]`, and every interaction column `[oods]` except
  the last four per component — the cumulative sums — which sample
  `[oods − step, oods]` with `step` the canonic coset step of the mask
  domain. The shape is checked against the captured native programs by
  `harness/maskcheck.zig` (offsets `[0]` / `[-1, 0]`, all 11
  components), and the two-sample order matches the native proof
  decoder (`verifier_proof.zig`: `samples[0] = at_prev`,
  `samples[1] = at_oods`).

- `evalComposition`: flattens the sampled values into the composition
  DAG's input layout (`CircuitAirData`) together with the statement
  data — the interaction elements `z`, `alpha`, the claimed sums and
  the component log sizes — and evaluates `CircuitAir.composition`.
  The claimed/derived component sizes enter as `2^log` scalars and
  one-hot bit atoms, exactly the values the in-circuit verifier's
  bit-decomposition gadgets pin (`extractBits31_sound`).

Every component's captured evaluation domain is one above its trace
domain (`harness/maskcheck.zig` prints `eval_delta 1` for all 11), so
`compositionLogDegreeBound = max log size + 1`.
-/
import StwoVerifier.CircuitAirEval
import StwoVerifier.Verifier

namespace StwoVerifier.CircuitAir

open CircuitAirData

/-- A base-field circle point embedded into the secure field. -/
def embedPoint (p : PointF) : PointQ := ⟨QM31.fromBase p.x, QM31.fromBase p.y⟩

/-- The previous-row sample point: `oods − step` of the mask domain's
canonic coset. -/
def prevPoint (pt : PointQ) (maxLogDegreeBound : Nat) : PointQ :=
  pt.add (embedPoint (canonicStep maxLogDegreeBound)).neg

/-- The circuit AIR's mask points (trace trees only; `NativeAccepts`
appends the composition tree itself). -/
def maskPoints (pt : PointQ) (maxLogDegreeBound : Nat) :
    List (List (List PointQ)) :=
  [ List.replicate nPp [pt],
    List.replicate nTrace [pt],
    interShape.toList.flatMap fun n =>
      List.replicate (n - 4) [pt]
        ++ List.replicate 4 [prevPoint pt maxLogDegreeBound, pt] ]

/-- One sample from a column's sample list, or a shape error. -/
def single (column : List QM31) : Except VError QM31 :=
  match column with
  | [v] => .ok v
  | _ => throw .shapeMismatch

/-- The position in `layout` of each canonical preprocessed column
(`ppIds` order); the sampled tree 0 is in layout (size-sorted) order. -/
def ppPositions (layout : List (String × Nat)) : List Nat :=
  ppIds.toList.map fun id => (layout.findIdx? (·.1 = id)).getD layout.length

/-- Per interaction column (`ComponentList` order): whether it is a
cumulative sum (the last four columns of its component). -/
def cumulativeKinds : List Bool :=
  interShape.toList.flatMap fun n => (List.range n).map fun i => decide (i + 4 ≥ n)

/-- One interaction column's samples: `[at_oods]`, or `[at_prev, at_oods]`
for a cumulative sum. -/
def interSample : List QM31 × Bool → Except VError (QM31 × Option QM31)
  | ([v], false) => .ok (v, none)
  | ([p, v], true) => .ok (v, some p)
  | _ => .error .shapeMismatch

/-- The flat DAG input vector from the proof's sampled values and the
statement data. Sampled-value shape: tree 0 the 45 preprocessed
columns in layout order, tree 1 the 114 trace columns and tree 2 the
152 interaction columns in `ComponentList` order, the cumulative sums
carrying `[at_prev, at_oods]`. -/
def flatInputs (pt : PointQ) (sampledValues : List (List (List QM31)))
    (randomness : QM31) (z alpha : QM31) (claimedSums : List QM31)
    (logSizes : List Nat) (ppPos : List Nat) : Except VError (Array QM31) := do
  let ppCols := sampledValues.getD 0 []
  if ppCols.length ≠ nPp ∨ ppPos.length ≠ nPp then throw .shapeMismatch
  let pp ← ppPos.mapM fun j => single (ppCols.getD j [])
  let trace ← (sampledValues.getD 1 []).mapM single
  if trace.length ≠ nTrace then throw .shapeMismatch
  -- Interaction: at_oods per column in order, at_prev per cumulative sum.
  let interCols := sampledValues.getD 2 []
  if interCols.length ≠ nInter then throw .shapeMismatch
  let interPairs ← (interCols.zip cumulativeKinds).mapM interSample
  let inter := interPairs.map (·.1)
  let prev := interPairs.filterMap (·.2)
  if claimedSums.length ≠ interShape.size ∨ logSizes.length ≠ interShape.size then
    throw .shapeMismatch
  let sizes := logSizes.map fun l => QM31.fromBase ((2 ^ l : Nat) : F)
  let nbits := nbitAtoms.toList.map fun cb =>
    if logSizes.getD cb.1 0 = cb.2 then QM31.one else QM31.zero
  return (#[pt.x] ++ pp.toArray ++ trace.toArray ++ inter.toArray ++ prev.toArray
    ++ #[randomness, z, alpha] ++ claimedSums.toArray ++ sizes.toArray
    ++ nbits.toArray)

/-- **The circuit AIR** for `NativeAccepts`, bound to one statement's
interaction elements, claimed sums and component log sizes. The
returned evaluation also demands the recorded `eq` side conditions
(the generated components' fixed-size checks): the in-circuit verify
enforces them as `eq` gates, so a native run that violates them has no
satisfying circuit. -/
def circuitAir (layout : List (String × Nat)) (z alpha : QM31)
    (claimedSums : List QM31) (logSizes : List Nat) : Air where
  compositionLogDegreeBound := (logSizes.foldl max 0) + 1
  compositionLogSplit := 1
  maskPoints := maskPoints
  evalComposition := fun pt sampledValues randomness maxLogDegreeBound => do
    let inputs ← flatInputs pt sampledValues randomness z alpha
      claimedSums logSizes (ppPositions layout)
    if ¬ eqConditionsHold inputs then throw .shapeMismatch
    return composition inputs maxLogDegreeBound

end StwoVerifier.CircuitAir
