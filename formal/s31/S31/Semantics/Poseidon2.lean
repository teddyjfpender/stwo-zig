import S31.Semantics.Graph
import S31.Semantics.Constants
import RiscvRefinement.Recursion.CompactPoseidon

namespace S31.Poseidon2
open Graph

def add (a b : Nat) : FieldBuild Nat := binary .add a b
def mul (a b : Nat) : FieldBuild Nat := binary .mul a b
def constant (x : Nat) : FieldBuild Nat := literal (RiscvRefinement.M31.reduce x)

def fifth (x : Nat) : FieldBuild Nat := do
  let square ← mul x x
  let fourth ← mul square square
  mul x fourth

def m4 (v : List Nat) : FieldBuild (List Nat) := do
  let two ← constant 2
  let four ← constant 4
  let t0 ← add (v.getD 0 0) (v.getD 1 0)
  let t1 ← add (v.getD 2 0) (v.getD 3 0)
  let t2 ← add (← mul two (v.getD 1 0)) t1
  let t3 ← add (← mul two (v.getD 3 0)) t0
  let t4 ← add (← mul four t1) t3
  let t5 ← add (← mul four t0) t2
  return [← add t3 t5, t5, ← add t2 t4, t4]

def sum (xs : List Nat) : FieldBuild Nat := do
  let zero ← constant 0
  xs.foldlM add zero

def externalLayer (state : List Nat) : FieldBuild (List Nat) := do
  let blocks ← (List.range 4).mapM (fun i => m4 ((state.drop (4 * i)).take 4))
  let sums ← (List.range 4).mapM (fun lane => sum (blocks.map (·.getD lane 0)))
  (List.range 16).mapM (fun i => add ((blocks.getD (i / 4) []).getD (i % 4) 0)
    (sums.getD (i % 4) 0))

def externalRound (state constants : List Nat) : FieldBuild (List Nat) := do
  let state ← (state.zip constants).mapM (fun (x, c) => do
    fifth (← add x (← constant c)))
  externalLayer state

def internalRound (state : List Nat) (c : Nat) : FieldBuild (List Nat) := do
  let first ← fifth (← add (state.getD 0 0) (← constant c))
  let state := first :: state.drop 1
  let total ← sum state
  (state.zip Constants.poseidonDiagonal).mapM (fun (x, d) => do
    add (← mul x (← constant d)) total)

def permute (initial : List Nat) : FieldBuild (List Nat) := do
  let state ← externalLayer initial
  let state ← (Constants.poseidonExternal.take 4).foldlM externalRound state
  let state ← Constants.poseidonInternal.foldlM internalRound state
  (Constants.poseidonExternal.drop 4).foldlM externalRound state

/-- Absorb an already padded block of at most eight words. -/
def absorb (state block : List Nat) : FieldBuild (List Nat) := do
  let rate ← (List.range 8).mapM (fun i =>
    if i < block.length then add (state.getD i 0) (block.getD i 0)
    else pure (state.getD i 0))
  permute (rate ++ state.drop 8)

@[irreducible] def leafCode (length : Nat) : Code M31 FieldOp := build length do
  let zero ← constant 0
  let one ← constant 1
  let initial := List.replicate 15 zero ++ [one]
  let message := List.range length ++ [one]
  -- Admitted lengths 4, 8, 12, 16 require one, two, or three blocks.
  let state ← absorb initial (message.take 8)
  let state ← if message.length > 8 then absorb state ((message.drop 8).take 8)
    else pure state
  let state ← if message.length > 16 then absorb state (message.drop 16)
    else pure state
  return state.take 8

@[irreducible] def pairCode : Code M31 FieldOp := build 16 do
  return (← permute (List.range 16)).take 8

def leaf (words : List M31) : List M31 := (leafCode words.length).eval fieldEval words
def pair (left right : List M31) : List M31 := pairCode.eval fieldEval (left ++ right)

end S31.Poseidon2
