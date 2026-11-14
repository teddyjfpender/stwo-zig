/-
**The FRI verifier** (`src/core/fri.zig`, `src/core/fri/{config,folding,
merkle_queries}.zig`, stwo-zig `4afa09dbf`), executable, specialized to the
pinned profile's schedule: `fold_step = 1`, so leaves are never packed
(`pack_leaves` needs `fold_step > 1`) and every subset has width 2.

`commit` replays the transcript (mix each layer root, draw its folding
alpha, mix the last-layer coefficients) and checks the layer count and
last-layer degree. `decommit` rebuilds each layer's opened subsets from the
query evaluations and the proof's witness values, Merkle-verifies them
against the layer root, folds them one step, and finally compares every
remaining evaluation with the last-layer polynomial.
-/
import StwoVerifier.Merkle
import StwoVerifier.Circle

namespace StwoVerifier.Fri

open StwoVerifier

structure FriConfig where
  logBlowupFactor : Nat
  logLastLayerDegreeBound : Nat
  nQueries : Nat
  foldStep : Nat
  deriving Repr

structure FriLayerProof where
  friWitness : List QM31
  hashWitness : List Channel.Bytes
  commitment : Channel.Bytes
  deriving Repr

structure FriProof where
  firstLayer : FriLayerProof
  innerLayers : List FriLayerProof
  /-- FFT-order coefficients (`LinePoly`), a power-of-two count. -/
  lastLayerPoly : List QM31
  deriving Repr

/-- Verifier state after `commit`. -/
structure Committed where
  config : FriConfig
  columnCommitmentDomain : CircleDomain
  firstAlpha : QM31
  firstProof : FriLayerProof
  /-- One `(domain, alpha, proof)` per inner layer, in order. -/
  innerLayers : List (LineDomain × QM31 × FriLayerProof)
  lastLayerDomain : LineDomain
  lastLayerPoly : List QM31
  deriving Repr

/-- The inner-layer commit walk: mix each root, draw its alpha, step the
degree bound and domain. Returns the layers in order, the final bound and
domain, and the channel. -/
def commitInner (m31 : Bool) (config : FriConfig) :
    List FriLayerProof → Nat → LineDomain → Channel.St →
    Except VError (List (LineDomain × QM31 × FriLayerProof) × Nat × LineDomain × Channel.St)
  | [], bound, domain, s => .ok ([], bound, domain, s)
  | p :: rest, bound, domain, s =>
    match Channel.drawSecureFelt m31 (Channel.mixRoot m31 s p.commitment) with
    | none => .error .drawFuelExhausted
    | some (alpha, s'') =>
      -- foldStepAt: min(fold_step, remaining); profile: always 1 until bound.
      if bound < config.logLastLayerDegreeBound then .error .invalidNumFriLayers
      else if min config.foldStep (bound - config.logLastLayerDegreeBound) = 0 then
        .error .invalidNumFriLayers
      else if bound < min config.foldStep (bound - config.logLastLayerDegreeBound) then
        .error .invalidNumFriLayers
      else
        match commitInner m31 config rest
            (bound - min config.foldStep (bound - config.logLastLayerDegreeBound))
            ((List.range (min config.foldStep
              (bound - config.logLastLayerDegreeBound))).foldl
              (fun d _ => d.double) domain) s'' with
        | .error e => .error e
        | .ok (layers, bound', domain', sOut) =>
          .ok ((domain, alpha, p) :: layers, bound', domain', sOut)

/-- `FriVerifier.commit`. Returns the committed state and the channel after
the FRI transcript. `m31` selects the channel variant. -/
def commit (m31 : Bool) (s : Channel.St) (config : FriConfig) (proof : FriProof)
    (columnLogBound : Nat) : Except VError (Committed × Channel.St) := do
  if config.foldStep ≠ 1 then throw .invalidStructure  -- profile-pinned spec
  let s := Channel.mixRoot m31 s proof.firstLayer.commitment
  let columnCommitmentDomain := canonicDomain (columnLogBound + config.logBlowupFactor)
  let (firstAlpha, s) ← match Channel.drawSecureFelt m31 s with
    | some r => pure r | none => throw .drawFuelExhausted
  -- First circle-to-line fold consumes `fold_step` levels.
  if columnLogBound < config.foldStep then throw .invalidNumFriLayers
  let (inner, layerBound, layerDomain, ch) ← commitInner m31 config
    proof.innerLayers (columnLogBound - config.foldStep)
    ⟨Coset.halfOdds (columnLogBound - config.foldStep + config.logBlowupFactor)⟩ s
  if layerBound ≠ config.logLastLayerDegreeBound then throw .invalidNumFriLayers
  if proof.lastLayerPoly.length > 2^config.logLastLayerDegreeBound then
    throw .lastLayerDegreeInvalid
  let chOut := Channel.mixFelts m31 ch proof.lastLayerPoly
  return (⟨config, columnCommitmentDomain, firstAlpha, proof.firstLayer,
    inner, layerDomain, proof.lastLayerPoly⟩, chOut)

/-- Fold sorted unique query positions one level (`Queries.fold`, step 1). -/
def foldPositions (ps : List Nat) : List Nat :=
  dedup (ps.map (· / 2))
where
  dedup : List Nat → List Nat
    | [] => []
    | [x] => [x]
    | x :: y :: rest => if x = y then dedup (y :: rest) else x :: dedup (y :: rest)

/-- One rebuilt subset: its start position and its two evaluations. -/
structure Subset where
  start : Nat
  evals : List QM31
  deriving Repr

/-- `computeDecommitmentPositionsAndRebuildEvals` at fold step 1: group the
sorted unique positions by pair, fill the present slots from `queryEvals`
and the rest from the witness, and require the witness to be consumed
exactly. Returns the subsets in position order. -/
def rebuildSubsets (positions : List Nat) (queryEvals : List QM31)
    (witness : List QM31) : Except VError (List Subset) := do
  if positions.length ≠ queryEvals.length then throw .shapeMismatch
  let (subsets, leftover) ← go (positions.zip queryEvals) witness
  if !leftover.isEmpty then throw .shapeMismatch
  return subsets
where
  go : List (Nat × QM31) → List QM31 → Except VError (List Subset × List QM31)
    | [], w => .ok ([], w)
    | (p, v) :: rest, w =>
      let start := p / 2 * 2
      if p % 2 = 0 then
        match rest with
        | (p', v') :: rest' =>
          if p' = p + 1 then do
            let (subs, w') ← go rest' w
            .ok (⟨start, [v, v']⟩ :: subs, w')
          else do
            match w with
            | [] => .error .insufficientWitness
            | wv :: w' => do
              let (subs, w'') ← go rest w'
              .ok (⟨start, [v, wv]⟩ :: subs, w'')
        | [] =>
          match w with
          | [] => .error .insufficientWitness
          | wv :: w' => .ok ([⟨start, [v, wv]⟩], w')
      else
        match w with
        | [] => .error .insufficientWitness
        | wv :: w' => do
          let (subs, w'') ← go rest w'
          .ok (⟨start, [wv, v]⟩ :: subs, w'')

/-- Merkle-verify one FRI layer's rebuilt subsets against its commitment:
positions are the opened leaf positions, and the four QM31 coordinates are
four columns of height `logSize` (`merkle_queries.build` at leaf log 0). -/
def verifyLayerMerkle (subsets : List Subset) (logSize : Nat)
    (commitment : Channel.Bytes) (hashWitness : List Channel.Bytes) : Except VError Unit := do
  let values := (subsets.map fun sub => sub.evals).flatten
  let positions := (subsets.map fun sub => [sub.start, sub.start + 1]).flatten
  let columns := (List.range 4).map fun c => values.map fun v => v.coords.getD c 0
  (Merkle.verify commitment (List.replicate 4 logSize) logSize positions
    columns hashWitness).mapError fun _ => VError.firstLayerCommitmentInvalid

/-- `ibutterfly`-based line fold of one width-2 subset:
`f₀' + α·f₁'` with `f₀' = f₀ + f₁`, `f₁' = (f₀ − f₁)/x`. -/
def foldLinePair (f0 f1 : QM31) (alpha : QM31) (x : F) : Except VError QM31 :=
  if x = 0 then throw .divisionByZero
  else return (f0 + f1) + alpha * (f0 - f1).mulM31 x⁻¹

/-- First-layer circle fold of one subset at domain index
`bitReverse(start)`: the fold point is `domain.indexAt(bitrev(start))`, and
the folded value is `f₀' + α·f₁'` with `f₁' = (f₀ − f₁)/pʸ`. -/
def foldCircleSubset (domain : CircleDomain) (alpha : QM31) (sub : Subset) :
    Except VError QM31 := do
  let idx := bitReverseIndex sub.start domain.logSize
  let p := domain.at' idx
  match sub.evals with
  | [f0, f1] => foldLinePair f0 f1 alpha p.y
  | _ => throw .shapeMismatch

/-- Inner-layer line fold of one subset: fold point x-coordinate of
`coset.indexAt(bitrev(start))`. -/
def foldLineSubset (domain : LineDomain) (alpha : QM31) (sub : Subset) :
    Except VError QM31 := do
  let idx := bitReverseIndex sub.start domain.logSize
  let x := (domain.coset.indexAt idx).toPoint.x
  match sub.evals with
  | [f0, f1] => foldLinePair f0 f1 alpha x
  | _ => throw .shapeMismatch

/-- The inner-layer decommit walk: rebuild, Merkle-verify, line-fold. -/
def decommitInner :
    List (LineDomain × QM31 × FriLayerProof) → List Nat → List QM31 →
    Except VError (List Nat × List QM31)
  | [], positions, evals => .ok (positions, evals)
  | (domain, alpha, proof) :: rest, positions, evals => do
    let subs ← (rebuildSubsets positions evals proof.friWitness).mapError
      fun e => match e with
        | .insufficientWitness | .shapeMismatch => .innerLayerEvaluationsInvalid
        | e => e
    (verifyLayerMerkle subs domain.logSize proof.commitment proof.hashWitness).mapError
      fun _ => VError.innerLayerCommitmentInvalid
    let evals' ← subs.mapM (foldLineSubset domain alpha)
    decommitInner rest (foldPositions positions) evals'

/-- `decommitLastLayer`: every remaining evaluation equals the last-layer
polynomial at the bit-reversed domain point. -/
def lastLayerCheck (c : Committed) (positions : List Nat) (evals : List QM31) :
    Except VError Unit := do
  if positions.length ≠ evals.length then throw .lastLayerEvaluationsInvalid
  if (positions.zip evals).any (fun (q, e) =>
      ¬ (e = linePolyEval c.lastLayerPoly (QM31.fromBase
        (c.lastLayerDomain.at' (bitReverseIndex q c.lastLayerDomain.logSize)))))
  then throw .lastLayerEvaluationsInvalid

/-- `FriVerifier.decommit`: `queries` are the sorted unique first-layer
positions and `queryEvals` the DEEP answers at them. -/
def decommit (c : Committed) (queries : List Nat) (queryEvals : List QM31) :
    Except VError Unit := do
  -- First layer: rebuild, Merkle-verify, circle-fold.
  let subsets ← (rebuildSubsets queries queryEvals c.firstProof.friWitness).mapError
    fun e => match e with
      | .insufficientWitness | .shapeMismatch => .firstLayerEvaluationsInvalid
      | e => e
  (verifyLayerMerkle subsets c.columnCommitmentDomain.logSize
      c.firstProof.commitment c.firstProof.hashWitness).mapError
    fun _ => VError.firstLayerCommitmentInvalid
  let evals ← subsets.mapM (foldCircleSubset c.columnCommitmentDomain c.firstAlpha)
  let positions := foldPositions queries
  let (positions, evals) ← decommitInner c.innerLayers positions evals
  lastLayerCheck c positions evals

end StwoVerifier.Fri
