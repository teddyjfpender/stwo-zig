/-
**The lifted Merkle multiproof verifier**
(`src/core/vcs_lifted/verifier.zig` `MerkleVerifierLifted.verify`, stwo-zig
`4afa09dbf`), executable, for the pinned profile's *plain* Blake2s hasher
(`Blake2sPlainMerkleHasher`: leaf = Blake2s of the row's LE words, node =
Blake2s(left ‖ right); commitments never use the M31-reduced hasher).

The verifier receives per-column query values in the caller's query order
(duplicates included), deduplicates them along the sorted unique positions
(duplicate answers must agree), hashes one leaf per unique position from the
columns sorted by log size, and walks `height` layers pairing sibling nodes
or consuming one witness hash. Success is exact witness consumption and the
root matching.
-/
import StwoVerifier.Channel

namespace StwoVerifier

/-- All verifier failure modes of the native pipeline (union of
`verifier_types.VerificationError`, `FriVerificationError` and
`MerkleVerificationError`; one enum keeps `Except` simple). -/
inductive VError
  | invalidStructure
  | oodsNotMatching
  | proofOfWork
  | shapeMismatch
  | emptySampledSet
  | emptyTrees
  | invalidPreprocessedTree
  | queryPositionOutOfRange
  | columnIndexOutOfBounds
  | divisionByZero
  | degenerateLine
  | invalidNumFriLayers
  | firstLayerEvaluationsInvalid
  | firstLayerCommitmentInvalid
  | innerLayerCommitmentInvalid
  | innerLayerEvaluationsInvalid
  | lastLayerDegreeInvalid
  | lastLayerEvaluationsInvalid
  | witnessTooShort
  | witnessTooLong
  | rootMismatch
  | invalidQueryShape
  | duplicateQueryMismatch
  | invalidTreeHeight
  | insufficientWitness
  | drawFuelExhausted
  deriving DecidableEq, Repr

namespace Merkle

open Channel (Bytes u32Le)

/-- Plain-protocol leaf hash: Blake2s of the row's canonical LE words. -/
def leafHash (row : List F) : Bytes :=
  Blake2s.blake2s ((row.map (fun v => u32Le v.val)).flatten)

/-- Plain-protocol node hash: Blake2s(left ‖ right). -/
def nodeHash (left right : Bytes) : Bytes := Blake2s.blake2s (left ++ right)

/-- Ascending sorted, deduplicated positions (`sortedUniquePositions`). -/
def sortedUnique (ps : List Nat) : List Nat :=
  dedup (ps.mergeSort (· ≤ ·))
where
  dedup : List Nat → List Nat
    | [] => []
    | [x] => [x]
    | x :: y :: rest => if x = y then dedup (y :: rest) else x :: dedup (y :: rest)

/-- The query order: indices `0..n` stably sorted by position. -/
def queryOrder (ps : List Nat) : List Nat :=
  ((List.range ps.length).mergeSort fun i j => ps.getD i 0 ≤ ps.getD j 0)

/-- Column order: indices stably sorted by column log size. -/
def columnOrder (logSizes : List Nat) : List Nat :=
  ((List.range logSizes.length).mergeSort fun i j => logSizes.getD i 0 ≤ logSizes.getD j 0)

/-- Deduplicate one column along the sorted query order: keep the value at
each first occurrence of a position, and require duplicates to agree. -/
def dedupColumn (ps : List Nat) (order : List Nat) (col : List F) :
    Except VError (List F) :=
  go order none [] |>.map List.reverse
where
  go : List Nat → Option Nat → List F → Except VError (List F)
    | [], _, acc => .ok acc
    | oi :: rest, prev, acc =>
      let pos := ps.getD oi 0
      let v := col.getD oi 0
      if prev = some pos then
        match acc with
        | top :: _ => if top = v then go rest (some pos) acc else .error .duplicateQueryMismatch
        | [] => .error .shapeMismatch
      else go rest (some pos) (v :: acc)

/-- One layer of the pairing walk: combine adjacent `(idx, hash)` nodes,
pulling a witness hash when a sibling is absent. Returns the parent layer
and the remaining witness. -/
def layerStep : List (Nat × Bytes) → List Bytes → Except VError (List (Nat × Bytes) × List Bytes)
  | [], w => .ok ([], w)
  | [(i, h)], w =>
    match w with
    | [] => .error .witnessTooShort
    | hw :: w' =>
      let parent := if i % 2 = 0 then nodeHash h hw else nodeHash hw h
      .ok ([(i / 2, parent)], w')
  | (i, h) :: (j, h') :: rest, w =>
    if i ^^^ 1 = j then do
      let (parents, w') ← layerStep rest w
      .ok ((i / 2, nodeHash h h') :: parents, w')
    else
      match w with
      | [] => .error .witnessTooShort
      | hw :: w' => do
        let parent := if i % 2 = 0 then nodeHash h hw else nodeHash hw h
        let (parents, w'') ← layerStep ((j, h') :: rest) w'
        .ok ((i / 2, parent) :: parents, w'')

def walk (height : Nat) (layer : List (Nat × Bytes)) (w : List Bytes) :
    Except VError (List (Nat × Bytes) × List Bytes) :=
  match height with
  | 0 => .ok (layer, w)
  | h + 1 => do
    let (next, w') ← layerStep layer w
    walk h next w'

/-- `MerkleVerifierLifted.verify`. `queriedValues` is column-major in the
caller's query order. -/
def verify (root : Bytes) (columnLogSizes : List Nat) (height : Nat)
    (queryPositions : List Nat) (queriedValues : List (List F))
    (witness : List Bytes) : Except VError Unit := do
  if queriedValues.length ≠ columnLogSizes.length then throw .invalidQueryShape
  if columnLogSizes.isEmpty then return ()
  if queriedValues.any (fun col => col.length ≠ queryPositions.length) then
    throw .invalidQueryShape
  let order := queryOrder queryPositions
  let uniq := sortedUnique queryPositions
  -- Columns sorted by log size, then deduplicated along the query order.
  let cols ← (columnOrder columnLogSizes).mapM fun ci =>
    dedupColumn queryPositions order (queriedValues.getD ci [])
  -- One leaf per unique position: the row of all deduplicated columns.
  let leaves := uniq.zipIdx.map fun (pos, k) =>
    (pos, leafHash (cols.map fun col => col.getD k 0))
  let (top, leftover) ← walk height leaves witness
  if !leftover.isEmpty then throw .witnessTooLong
  match top with
  | [(_, h)] => if h = root then return () else throw .rootMismatch
  | _ => throw .rootMismatch

end Merkle
end StwoVerifier
