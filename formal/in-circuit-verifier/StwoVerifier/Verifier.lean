/-
**`NativeAccepts`: the statement-level native STARK verifier**
(`src/core/verifier.zig` `verify`/`verifyImpl`, stwo-zig `4afa09dbf`),
executable, under the `proving_5a7c5ed` revision, parameterized by the AIR.

An `Air` packages what `air_components.Components` provides the verifier:
the composition degree bound and split, the OODS mask points per committed
column, and the composition polynomial evaluated at the OODS point from the
sampled mask values. For scope A (the per-gadget theorems) the AIR stays
abstract; scope B instantiates it with the circuit AIR.

The flow, given a channel already carrying the statement and the trace
commitments (the caller replays `commit` for each tree exactly as the Zig
caller does):

1. draw the composition randomness;
2. commit the composition tree (last proof commitment, `2^split · 4`
   columns of the lifted size);
3. draw the OODS seed, map it to the OODS point;
4. sample points = AIR mask points + one point per composition column;
5. the proof's composition OODS evaluation (chunk reconstruction) must
   equal the AIR's composition evaluation at the point;
6. PCS `verifyValues` on everything.
-/
import StwoVerifier.Pcs

namespace StwoVerifier


/-- `COMPOSITION_LOG_SPLIT`-generalized composition column count:
`2^split · SECURE_EXTENSION_DEGREE`, `none` outside `1 ≤ split ≤ 8`. -/
def compositionColumnCount (split : Nat) : Option Nat :=
  if split = 0 ∨ split > 8 then none else some (2^split * 4)

/-- The AIR interface the native verifier consumes. -/
structure Air where
  /-- `Components.compositionLogDegreeBound`. -/
  compositionLogDegreeBound : Nat
  /-- `Components.compositionLogSplit` (`COMPOSITION_LOG_SPLIT = 1` for
  every current AIR). -/
  compositionLogSplit : Nat
  /-- `Components.maskPoints oodsPoint maxLogDegreeBound`: sample points per
  committed tree and column (trace trees only; the composition tree's points
  are appended by the verifier). -/
  maskPoints : PointQ → Nat → List (List (List PointQ))
  /-- `Components.evalCompositionPolynomialAtPoint oodsPoint sampledValues
  randomness maxLogDegreeBound`. -/
  evalComposition : PointQ → List (List (List QM31)) → QM31 → Nat →
    Except VError QM31

/-- `QM31.fromPartialEvals`: recombine four partial evaluations on the
extension basis `1, i, u, iu`. -/
def fromPartialEvals (e : List QM31) : QM31 :=
  (e.getD 0 QM31.zero)
    + (e.getD 1 QM31.zero) * QM31.fromM31s 0 1 0 0
    + (e.getD 2 QM31.zero) * QM31.fromM31s 0 0 1 0
    + (e.getD 3 QM31.zero) * QM31.fromM31s 0 0 0 1

/-- `reconstructCompositionChunkEvals`: pairwise recombination of the chunk
evaluations with the doubled-point x factors. -/
def reconstructChunks (chunks : List QM31) (point : PointQ)
    (compositionLogSize split : Nat) : Option QM31 :=
  if compositionLogSize ≤ split ∨ chunks.length ≠ 2^split then none
  else go chunks (compositionLogSize - split + 1) (2^split)
where
  go (evals : List QM31) (parentLog : Nat) : Nat → Option QM31
    | 0 => none
    | fuel + 1 =>
      match evals with
      | [e] => some e
      | _ =>
        let factor := (CPoint.repeatedDouble point (parentLog - 2)).x
        go (pair evals factor) (parentLog + 1) fuel
  pair : List QM31 → QM31 → List QM31
    | e0 :: e1 :: rest, f => (e0 + f * e1) :: pair rest f
    | _, _ => []

/-- `extractCompositionOodsEvalWithSplit`: the composition value the proof
claims at the OODS point, from the last tree's sampled columns
(`2^split` chunks of four partial evaluations, one sample each). -/
def extractCompositionOodsEval (sampledValues : List (List (List QM31)))
    (oodsPoint : PointQ) (compositionLogSize split : Nat) : Option QM31 := do
  if split = 0 ∨ split > 8 ∨ compositionLogSize ≤ split then none else
  let masks ← sampledValues.getLast?
  let expectedCols ← compositionColumnCount split
  if masks.length ≠ expectedCols then none else
  let chunks ← (List.range (2^split)).mapM fun chunk => do
    let coords ← (List.range 4).mapM fun c => do
      let column := masks.getD (chunk * 4 + c) []
      match column with
      | [v] => some v
      | _ => none
    pure (fromPartialEvals coords)
  reconstructChunks chunks oodsPoint compositionLogSize split

/-- **`NativeAccepts`** (`verifier.zig` `verify`, `proving_5a7c5ed`).

`trees` and `s` are the commitment-scheme state and channel after the
caller's `Pcs.commit` calls for the preprocessed/trace/interaction trees —
exactly the state the Zig caller hands `verify`. `commitments` is the
proof's commitment list (the composition root is its last entry). -/
def NativeAccepts (m31 : Bool) (config : Pcs.PcsConfig) (air : Air)
    (trees : List Pcs.Tree) (s : Channel.St) (commitments : List Channel.Bytes)
    (proof : Pcs.Proof) : Except VError Unit := do
  if trees.length ≤ 0 then throw .invalidPreprocessedTree
  let split := air.compositionLogSplit
  let compositionLogSize := air.compositionLogDegreeBound
  let nCompositionCols ← match compositionColumnCount split with
    | some n => pure n | none => throw .invalidStructure
  if compositionLogSize ≤ split then throw .invalidStructure
  let componentMaskLog := compositionLogSize - split
  -- Lifted revision: the mask domain is at least the lifted trace domain.
  if config.traceLiftingLogSize < config.logBlowupFactor then throw .invalidStructure
  let liftedMaskLog := config.traceLiftingLogSize - config.logBlowupFactor
  let maxLogDegreeBound := max componentMaskLog liftedMaskLog
  let (compositionRandomness, s) ← match Channel.drawSecureFelt m31 s with
    | some r => pure r | none => throw .drawFuelExhausted
  let compositionCommitment ← match commitments.getLast? with
    | some c => pure c | none => throw .invalidStructure
  -- Commit the composition tree: `2^split · 4` columns of the lifted size.
  let (trees, s) ← Pcs.commit m31 config trees s compositionCommitment
    (List.replicate nCompositionCols maxLogDegreeBound)
  let (oodsSeed, s) ← match Channel.drawSecureFelt m31 s with
    | some r => pure r | none => throw .drawFuelExhausted
  let oodsPoint ← match securePointFromSeed oodsSeed with
    | some p => pure p | none => throw .divisionByZero
  let samplePoints := air.maskPoints oodsPoint maxLogDegreeBound
    ++ [List.replicate nCompositionCols [oodsPoint]]
  let claimed ← match extractCompositionOodsEval proof.sampledValues oodsPoint
      (maxLogDegreeBound + split) split with
    | some v => pure v | none => throw .invalidStructure
  let evaluated ← air.evalComposition oodsPoint proof.sampledValues
    compositionRandomness maxLogDegreeBound
  if ¬ (claimed = evaluated) then throw .oodsNotMatching
  Pcs.verifyValues m31 config trees samplePoints proof s

end StwoVerifier
