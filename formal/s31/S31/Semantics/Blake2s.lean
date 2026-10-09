import S31.Semantics.Graph
import S31.Semantics.Constants

namespace S31.Blake2s
open Graph

def add (a b : Nat) : WordBuild Nat := binary .add a b
def xor (a b : Nat) : WordBuild Nat := binary .xor a b
def rot (a n : Nat) : WordBuild Nat := unary (.rotr n) a
def constant (n : Nat) : WordBuild Nat := literal (Words.word n)

def g (v : List Nat) (a b c d x y : Nat) : WordBuild (List Nat) := do
  let va ← add (← add (v.getD a 0) (v.getD b 0)) x
  let vd ← rot (← xor (v.getD d 0) va) 16
  let vc ← add (v.getD c 0) vd
  let vb ← rot (← xor (v.getD b 0) vc) 12
  let va ← add (← add va vb) y
  let vd ← rot (← xor vd va) 8
  let vc ← add vc vd
  let vb ← rot (← xor vb vc) 7
  return ((v.set a va).set b vb).set c vc |>.set d vd

def round (m v sigma : List Nat) : WordBuild (List Nat) := do
  let schedule := [(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
    (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)]
  (schedule.zip (List.range 8)).foldlM (fun state (indices, i) =>
    let (a, b, c, d) := indices
    g state a b c d (m.getD (sigma.getD (2 * i) 0) 0)
      (m.getD (sigma.getD (2 * i + 1) 0) 0)) v

/-- S31's inputs occupy one final block, including the exact 64-byte case. -/
@[irreducible] def code (wordCount : Nat) (personalization : List Nat) : Code Words.Word WordOp :=
  build wordCount do
    let zero ← constant 0
    let iv ← Constants.hashIV.mapM constant
    let h0 ← xor (iv.getD 0 0) (← constant 0x01010020)
    let h6 ← xor (iv.getD 6 0) (← constant (Words.readLE personalization 0 4))
    let h7 ← xor (iv.getD 7 0) (← constant (Words.readLE personalization 4 4))
    let h := ((iv.set 0 h0).set 6 h6).set 7 h7
    let v := h ++ iv
    let v12 ← xor (v.getD 12 0) (← constant (4 * wordCount))
    let v14 ← xor (v.getD 14 0) (← constant 0xffffffff)
    let v := (v.set 12 v12).set 14 v14
    let message := List.range wordCount ++ List.replicate (16 - wordCount) zero
    let v ← Constants.blakeSigma.foldlM (round message) v
    (List.range 8).mapM (fun i => do
      xor (← xor (h.getD i 0) (v.getD i 0)) (v.getD (i + 8) 0))

def leafPersonalization : List Nat := [83, 51, 49, 76, 69, 65, 70, 49]
def pairPersonalization : List Nat := [83, 51, 49, 80, 65, 73, 82, 49]

def hash (xs : List M31) (personalization : List Nat := []) : List M31 :=
  ((code xs.length personalization).eval wordEval (xs.map (Words.word ∘ (·.val)))).map
    (RiscvRefinement.M31.reduce ∘ BitVec.toNat)

end S31.Blake2s
