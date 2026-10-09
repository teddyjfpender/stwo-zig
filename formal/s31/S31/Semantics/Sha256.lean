import S31.Semantics.Graph
import S31.Semantics.Constants

namespace S31.Sha256
open Graph

def add (a b : Nat) : WordBuild Nat := binary .add a b
def xor (a b : Nat) : WordBuild Nat := binary .xor a b
def and (a b : Nat) : WordBuild Nat := binary .and a b
def not (a : Nat) : WordBuild Nat := unary .not a
def rot (a n : Nat) : WordBuild Nat := unary (.rotr n) a
def shr (a n : Nat) : WordBuild Nat := unary (.shr n) a
def constant (n : Nat) : WordBuild Nat := literal (Words.word n)

def sigma (x a b c : Nat) (logical : Bool) : WordBuild Nat := do
  xor (← xor (← rot x a) (← rot x b))
    (← if logical then shr x c else rot x c)

def schedule (block : List Nat) : WordBuild (List Nat) :=
  (List.range 48).foldlM (fun w offset => do
    let i := offset + 16
    let x ← sigma (w.getD (i - 2) 0) 17 19 10 true
    let y ← sigma (w.getD (i - 15) 0) 7 18 3 true
    return w ++ [← add (← add (← add x (w.getD (i - 7) 0)) y) (w.getD (i - 16) 0)]) block

def round (state : List Nat) (message constantValue : Nat) : WordBuild (List Nat) := do
  let a := state.getD 0 0; let b := state.getD 1 0
  let c := state.getD 2 0; let d := state.getD 3 0
  let e := state.getD 4 0; let f := state.getD 5 0
  let g := state.getD 6 0; let h := state.getD 7 0
  let choice ← xor (← and e f) (← and (← not e) g)
  let majority ← xor (← xor (← and a b) (← and a c)) (← and b c)
  let s1 ← sigma e 6 11 25 false
  let s0 ← sigma a 2 13 22 false
  let t1 ← add (← add (← add (← add h s1) choice) (← constant constantValue)) message
  let t2 ← add s0 majority
  return [← add t1 t2, a, b, c, ← add d t1, e, f, g]

def compression (state block : List Nat) : WordBuild (List Nat) := do
  let words ← schedule block
  let output ← (words.zip Constants.shaRound).foldlM
    (fun s (w, k) => round s w k) state
  (state.zip output).mapM (fun (a, b) => add a b)

@[irreducible] def compressionCode : Code Words.Word WordOp := build 24 do
  compression (List.range 8) ((List.range 16).map (· + 8))

def compress (state block : List Words.Word) : List Words.Word :=
  compressionCode.eval wordEval (state ++ block)

def blockWords (bytes : List Nat) : List Words.Word :=
  (List.range 16).map (fun i => Words.word (Words.readBE bytes (4 * i) 4))

/-- Standard Merkle–Damgård padding; the S31 caller fixes lengths to 80 then 32. -/
def padding (message : List Nat) : List Nat :=
  message ++ [128] ++ List.replicate ((55 + 64 - message.length % 64) % 64) 0 ++
    Words.bytesBE 8 (8 * message.length)

def blocks (message : List Nat) : List (List Words.Word) :=
  let padded := padding message
  (List.range (padded.length / 64)).map (fun i =>
    blockWords ((padded.drop (64 * i)).take 64))

def hash (message : List Nat) : List Nat :=
  let initial := Constants.hashIV.map Words.word
  let state := (blocks message).foldl compress initial
  state.flatMap (fun w => Words.bytesBE 4 w.toNat)

def digestPairs (digest : List Nat) : List (Nat × Nat) :=
  (List.range 16).map (fun i => (digest.getD (2 * i) 0, digest.getD (2 * i + 1) 0))

def digestLimbs (digest : List Nat) : List M31 := (digestPairs digest).map (fun (low, high) =>
  RiscvRefinement.M31.reduce (low + 256 * high))

def header (limbs : List M31) : List M31 :=
  let digest := hash (hash (Words.wordsBytes 2 (limbs.map (·.val))))
  digestLimbs digest

end S31.Sha256
