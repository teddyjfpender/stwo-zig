/-
**The PCS opening verifier** (`src/core/pcs/verifier.zig`
`CommitmentSchemeVerifier.verifyValues`, stwo-zig `4afa09dbf`), executable,
under the `proving_5a7c5ed` revision: explicit per-tree lifting heights,
the FRI/proof domain is the *last* committed tree's height, and the proof
of work is checked at the FRI config's `pow_bits`.

A committed tree is the verifier state `commit` leaves behind: the root,
the blowup-extended column log sizes, and the explicit height. `commit`
itself is also specified here (root mix + height law `PcsConfigV2.treeHeight`).
-/
import StwoVerifier.Fri
import StwoVerifier.Quotients

namespace StwoVerifier.Pcs

open StwoVerifier

/-- `FriConfigV2` + the two lifting heights (`PcsConfigV2`). -/
structure PcsConfig where
  powBits : Nat
  logBlowupFactor : Nat
  logLastLayerDegreeBound : Nat
  nQueries : Nat
  foldStep : Nat
  traceLiftingLogSize : Nat
  preprocessedLiftingLogSize : Nat
  deriving Repr

def PcsConfig.friConfig (c : PcsConfig) : Fri.FriConfig :=
  ⟨c.logBlowupFactor, c.logLastLayerDegreeBound, c.nQueries, c.foldStep⟩

/-- `PcsConfigV2.liftingLogSize`: tree 0 is the preprocessed tree. -/
def PcsConfig.liftingLogSize (c : PcsConfig) (treeIndex : Nat) : Nat :=
  if treeIndex = 0 then c.preprocessedLiftingLogSize else c.traceLiftingLogSize

/-- One committed tree on the verifier side. -/
structure Tree where
  root : Channel.Bytes
  /-- Blowup-extended column log sizes. -/
  columnLogSizes : List Nat
  height : Nat
  deriving Repr

/-- `CommitmentSchemeVerifier.commit`: mix the root, extend the column logs
by the blowup, pin the configured height (`treeHeight`: it must dominate
every column, and be 0 exactly for an empty tree). -/
def commit (m31 : Bool) (config : PcsConfig) (trees : List Tree) (s : Channel.St)
    (root : Channel.Bytes) (logSizes : List Nat) : Except VError (List Tree × Channel.St) := do
  let s' := Channel.mixRoot m31 s root
  let extended := logSizes.map (· + config.logBlowupFactor)
  let height := config.liftingLogSize trees.length
  if extended.isEmpty ∧ height ≠ 0 then throw .invalidTreeHeight
  if extended.any (· > height) then throw .invalidTreeHeight
  return (trees ++ [⟨root, extended, height⟩], s')

/-- The PCS slice of a `StarkProof`. -/
structure Proof where
  /-- tree → column → sampled values (parallel to the sample points). -/
  sampledValues : List (List (List QM31))
  /-- tree → hash witness. -/
  decommitments : List (List Channel.Bytes)
  /-- tree → column → value at each unique query position. -/
  queriedValues : List (List (List F))
  proofOfWork : Nat
  friProof : Fri.FriProof
  deriving Repr

/-- `prepareTreeQueryPositions`: map proof-domain positions to one tree. -/
def prepareTreePositions (positions : List Nat) (maxLog : Nat)
    (treeLog : Option Nat) : List Nat :=
  match treeLog with
  | none => []
  | some 0 => positions.map fun _ => 0
  | some t =>
    if maxLog < t then
      positions.map fun p => p / 2 * 2^(t - maxLog + 1) + p % 2
    else
      positions.map fun p => p / 2^(maxLog - t + 1) * 2 + p % 2

/-- `computeLiftingLogSize`, shape checks only (`explicit_heights` path):
tree/column counts must match; `EmptySampledSet` is swallowed. -/
def shapeCheck (trees : List Tree) (sampledPoints : List (List (List PointQ)))
    : Except VError Unit := do
  if trees.length ≠ sampledPoints.length then throw .shapeMismatch
  if (trees.zip sampledPoints).any (fun (tree, points) =>
      tree.columnLogSizes.length ≠ points.length) then
    throw .shapeMismatch

/-- `verifyValues`: the complete opening verification. Consumes the channel
state right after the composition OODS check. -/
def verifyValues (m31 : Bool) (config : PcsConfig) (trees : List Tree)
    (sampledPoints : List (List (List PointQ))) (proof : Proof) (s : Channel.St) :
    Except VError Unit := do
  if trees.isEmpty then throw .emptyTrees
  if proof.decommitments.length ≠ trees.length then throw .shapeMismatch
  if proof.queriedValues.length ≠ trees.length then throw .shapeMismatch
  -- Mix every sampled value, draw the DEEP randomness.
  let s := Channel.mixFelts m31 s ((proof.sampledValues.map (·.flatten)).flatten)
  let (deepRandomness, s) ← match Channel.drawSecureFelt m31 s with
    | some r => pure r | none => throw .drawFuelExhausted
  shapeCheck trees sampledPoints
  let liftingLogSize := (trees.getLast?.map (·.height)).getD 0
  if liftingLogSize < config.logBlowupFactor then throw .shapeMismatch
  let bound := liftingLogSize - config.logBlowupFactor
  -- FRI commit transcript.
  let (fri, s) ← Fri.commit m31 s config.friConfig proof.friProof bound
  -- Proof of work, then mix the nonce.
  if ¬ Channel.verifyPowNonce m31 s config.powBits proof.proofOfWork then
    throw .proofOfWork
  let s := Channel.mixU64 m31 s proof.proofOfWork
  -- Query draw on the first-layer domain.
  let (raw, _) := Channel.drawQueries m31
    fri.columnCommitmentDomain.logSize config.nQueries s
  let unique := Merkle.sortedUnique raw
  -- Merkle verification per tree.
  let _ ← ((trees.zip proof.decommitments).zip proof.queriedValues).mapM
    fun ((tree, decommitment), queried) =>
      let treeLog : Option Nat := if tree.height = 0 then none else some tree.height
      let positions := prepareTreePositions unique liftingLogSize treeLog
      Merkle.verify tree.root tree.columnLogSizes tree.height positions
        queried decommitment
  -- DEEP quotient answers at the unique positions, then FRI decommit.
  let answers ← Quotients.friAnswers (trees.map (·.columnLogSizes))
    sampledPoints proof.sampledValues deepRandomness unique
    proof.queriedValues liftingLogSize
  Fri.decommit fri unique answers

end StwoVerifier.Pcs
