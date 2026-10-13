/-
**BLAKE2s (RFC 7693)**: the compression function `F` and the unkeyed 256-bit
hash, as executable functions with `#guard` test vectors.

Copied from starked-bitcoin's `StarkedAir/Spec/Blake2s.lean` (same author
chain), renamespaced for this project. It is the hash under every channel
operation and Merkle node of the pinned stwo-zig profile.
-/
import Mathlib

namespace StwoVerifier.Blake2s

abbrev Word := BitVec 32

def IVn : List ℕ :=
  [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]

def IV (i : ℕ) : Word := BitVec.ofNat 32 (IVn.getD i 0)

/-- Message schedule permutations (RFC 7693 §2.7; BLAKE2s uses the first 10). -/
def SIGMA : List (List ℕ) :=
  [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
   [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
   [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
   [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
   [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
   [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
   [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
   [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
   [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
   [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]]

def sigma (r i : ℕ) : ℕ := (SIGMA.getD r []).getD i 0

/-- The four state indices `(a, b, c, d)` of G number `g` in a round: columns, then diagonals. -/
def gIdx : ℕ → ℕ × ℕ × ℕ × ℕ
  | 0 => (0, 4, 8, 12) | 1 => (1, 5, 9, 13) | 2 => (2, 6, 10, 14) | 3 => (3, 7, 11, 15)
  | 4 => (0, 5, 10, 15) | 5 => (1, 6, 11, 12) | 6 => (2, 7, 8, 13) | _ => (3, 4, 9, 14)

/-- The mixing function's outputs `(a, b, c, d)` (RFC 7693 §3.1). -/
def mix (a b c d x y : Word) : Word × Word × Word × Word :=
  let a := a + b + x
  let d := (d ^^^ a).rotateRight 16
  let c := c + d
  let b := (b ^^^ c).rotateRight 12
  let a := a + b + y
  let d := (d ^^^ a).rotateRight 8
  let c := c + d
  let b := (b ^^^ c).rotateRight 7
  (a, b, c, d)

/-- Apply G number `g` of round `r` to the 16-word state `v`. -/
def gStep (m : ℕ → Word) (v : List Word) (r g : ℕ) : List Word :=
  let (ia, ib, ic, id) := gIdx g
  let (a, b, c, d) := mix (v.getD ia 0) (v.getD ib 0) (v.getD ic 0) (v.getD id 0)
    (m (sigma r (2 * g))) (m (sigma r (2 * g + 1)))
  ((((v.set ia a).set ib b).set ic c).set id d)

/-- The state after the first `k` G steps (8 per round, 80 in all). -/
def steps (m : ℕ → Word) (v0 : List Word) : ℕ → List Word
  | 0 => v0
  | k + 1 => gStep m (steps m v0 k) (k / 8) (k % 8)

/-- The initial working vector for chaining value `h`, byte counter `t` and final flag `f`. -/
def initV (h : ℕ → Word) (t : ℕ) (f : Bool) : List Word :=
  (List.range 16).map fun i =>
    if i < 8 then h i
    else if i = 12 then IV 4 ^^^ BitVec.ofNat 32 t
    else if i = 13 then IV 5 ^^^ BitVec.ofNat 32 (t / 2 ^ 32)
    else if i = 14 then IV 6 ^^^ (if f then BitVec.allOnes 32 else 0)
    else IV (i - 8)

/-- **The compression function `F(h, m, t, f)`** (RFC 7693 §3.2): eight output words. -/
def compress (h m : ℕ → Word) (t : ℕ) (f : Bool) (i : ℕ) : Word :=
  let v := steps m (initV h t f) 80
  h i ^^^ v.getD i 0 ^^^ v.getD (i + 8) 0

/-! ### The unkeyed 256-bit hash (for tests and the block commitment) -/

def leWord (b : List UInt8) (k : ℕ) : Word :=
  BitVec.ofNat 32 ((b.getD (4 * k) 0).toNat + 256 * (b.getD (4 * k + 1) 0).toNat +
    65536 * (b.getD (4 * k + 2) 0).toNat + 16777216 * (b.getD (4 * k + 3) 0).toNat)

/-- Initial chaining value: IV with the parameter block (digest 32, no key, fanout and depth 1). -/
def h0 (i : ℕ) : Word := if i = 0 then IV 0 ^^^ 0x01010020#32 else IV i

def hashBlocks (h : ℕ → Word) (t : ℕ) : List UInt8 → (ℕ → Word)
  | [] => compress h (fun _ => 0) t true
  | b =>
    if b.length ≤ 64 then compress h (leWord (b ++ List.replicate (64 - b.length) 0)) (t + b.length) true
    else
      let h' := (List.range 8).map (compress h (leWord (b.take 64)) (t + 64) false)
      hashBlocks (fun i => h'.getD i 0) (t + 64) (b.drop 64)
termination_by b => b.length
decreasing_by simp_wf; omega

def digest (h : ℕ → Word) : List UInt8 :=
  (List.range 8).flatMap fun i => (List.range 4).map fun j => UInt8.ofNat ((h i).toNat / 2 ^ (8 * j))

def blake2s (msg : List UInt8) : List UInt8 := digest (hashBlocks h0 0 msg)

def hex (b : List UInt8) : String :=
  String.join (b.map fun x => let s := String.ofList (Nat.toDigits 16 x.toNat); if s.length = 1 then "0" ++ s else s)

#guard hex (blake2s []) = "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
#guard hex (blake2s "abc".toUTF8.toList) = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
#guard hex (blake2s ((List.range 64).map UInt8.ofNat)) = "56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e"
#guard hex (blake2s ((List.range 65).map UInt8.ofNat)) = "1b53ee94aaf34e4b159d48de352c7f0661d0a40edff95a0b1639b4090e974472"

end StwoVerifier.Blake2s
