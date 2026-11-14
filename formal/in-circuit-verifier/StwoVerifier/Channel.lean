/-
**The native Blake2s Fiat–Shamir channel** (`src/core/channel/blake2s.zig`,
stwo-zig `4afa09dbf`), executable.

`Blake2sChannelGeneric(is_m31_output)`: a 32-byte digest and a draw counter.
Every operation is one Blake2s of `digest ‖ data`; the M31 variant
(`Blake2sM31Channel`, the pinned profile's Fiat–Shamir channel) reduces each
of the eight little-endian digest words mod `P` after every hash
(`vcs/blake2_hash.zig`'s `reduceToM31`).

Draws: `drawU32s` hashes `digest ‖ LE(n_draws) ‖ 0` over 37 bytes and bumps
the counter; `drawBaseFelts` rejects a draw unless all eight words are
`< 2P` (never rejects on the M31 variant, whose words are `< P`); a secure
felt takes the first four base felts.

Proof of work: `H(H(0x12345678 ‖ 0¹² ‖ digest ‖ LE(bits)) ‖ LE64(nonce))`
must end the check with ≥ `bits` trailing zero bits in its first 16 bytes.
-/
import StwoVerifier.Fields
import StwoVerifier.Blake2s

namespace StwoVerifier.Channel

open StwoVerifier (F P QM31)

abbrev Bytes := List UInt8

/-- Little-endian bytes of a `u32` value. -/
def u32Le (x : Nat) : Bytes :=
  [UInt8.ofNat x, UInt8.ofNat (x / 2^8), UInt8.ofNat (x / 2^16), UInt8.ofNat (x / 2^24)]

/-- Little-endian bytes of a `u64` value. -/
def u64Le (x : Nat) : Bytes := u32Le x ++ u32Le (x / 2^32)

/-- The `k`-th little-endian `u32` word of a byte string. -/
def wordAt (b : Bytes) (k : Nat) : Nat :=
  (b.getD (4 * k) 0).toNat + 2^8 * (b.getD (4 * k + 1) 0).toNat +
    2^16 * (b.getD (4 * k + 2) 0).toNat + 2^24 * (b.getD (4 * k + 3) 0).toNat

/-- All eight words of a 32-byte digest. -/
def digestWords (b : Bytes) : List Nat := (List.range 8).map (wordAt b)

/-- `reduceToM31` of one word: `(w &&& P) + (w >>> 31)`, minus `P` once if needed.
Equals `w % P` for every `w < 2³²` except that `P` itself maps to `P`?  No —
`w = P` gives `P + 0 = P ≥ P → 0 = P % P`. It is exactly `w % P` as a value
`< P`, stored back as a `u32`. -/
def reduceWord (w : Nat) : Nat :=
  let folded := (w % 2^31) + (w / 2^31)
  if folded ≥ P then folded - P else folded

/-- `reduceToM31`: each digest word reduced, re-serialized little-endian. -/
def reduceDigest (b : Bytes) : Bytes :=
  (List.range 8).flatMap fun k => u32Le (reduceWord (wordAt b k))

/-- The channel-variant hash: plain Blake2s, or Blake2s with the M31 word
reduction (`Blake2sHasherGeneric(is_m31_output)`). -/
def chHash (m31 : Bool) (data : Bytes) : Bytes :=
  let h := Blake2s.blake2s data
  if m31 then reduceDigest h else h

/-- Bytes of one M31 coordinate: its canonical value, little-endian. -/
def feltBytes (x : F) : Bytes := u32Le x.val

/-- Bytes of a QM31: its four coordinates in stwo order. -/
def qm31Bytes (x : QM31) : Bytes := (x.coords.map feltBytes).flatten

/-- The channel state. -/
structure St where
  digest : Bytes
  nDraws : Nat
  deriving Repr

def init : St := ⟨List.replicate 32 0, 0⟩

/-- `mix_felts`. -/
def mixFelts (m31 : Bool) (s : St) (xs : List QM31) : St :=
  ⟨chHash m31 (s.digest ++ (xs.map qm31Bytes).flatten), 0⟩

/-- `mix_u32s`. -/
def mixU32s (m31 : Bool) (s : St) (ws : List Nat) : St :=
  ⟨chHash m31 (s.digest ++ (ws.map u32Le).flatten), 0⟩

/-- `mix_u64`: low word first. -/
def mixU64 (m31 : Bool) (s : St) (v : Nat) : St :=
  mixU32s m31 s [v % 2^32, v / 2^32]

/-- `mix_root` (`Blake2sMerkleChannelGeneric.mixRoot`): absorb a 32-byte
Merkle root: `digest ← H(digest ‖ root)`, counter reset. -/
def mixRoot (m31 : Bool) (s : St) (root : Bytes) : St :=
  ⟨chHash m31 (s.digest ++ root), 0⟩

/-- `draw_u32s`: the eight words of `H(digest ‖ LE(n_draws) ‖ 0)`, and the
state with the counter bumped. The digest itself does not change. -/
def drawU32s (m31 : Bool) (s : St) : List Nat × St :=
  let h := chHash m31 (s.digest ++ u32Le s.nDraws ++ [0])
  (digestWords h, ⟨s.digest, s.nDraws + 1⟩)

/-- `draw_base_felts` with fuel for the `< 2P` rejection loop. On the M31
variant every word is already `< P`, so one draw always succeeds. -/
def drawBaseFelts (m31 : Bool) : Nat → St → Option (List F × St)
  | 0, _ => none
  | fuel + 1, s =>
    let (ws, s') := drawU32s m31 s
    if ws.all (· < 2 * P) then some (ws.map (fun w => (w : F)), s')
    else drawBaseFelts m31 fuel s'

/-- Draw fuel: `2⁻³¹`-ish rejection chance per word makes 64 tries
astronomically safe; the Zig loop is unbounded. -/
def drawFuel : Nat := 64

/-- `draw_secure_felt`: the first four base felts as a QM31. -/
def drawSecureFelt (m31 : Bool) (s : St) : Option (QM31 × St) := do
  let (fs, s') ← drawBaseFelts m31 drawFuel s
  match fs with
  | a :: b :: c :: d :: _ => pure (QM31.fromM31s a b c d, s')
  | _ => none

/-- `draw_secure_felts n`: each draw of eight base felts yields two QM31. -/
def drawSecureFelts (m31 : Bool) (n : Nat) (s : St) : Option (List QM31 × St) :=
  go n s []
where
  go : Nat → St → List QM31 → Option (List QM31 × St)
    | 0, s, acc => some (acc.reverse, s)
    | n + 1, s, acc => do
      let (fs, s') ← drawBaseFelts m31 drawFuel s
      match fs with
      | a :: b :: c :: d :: e :: f :: g :: h :: _ =>
        if n = 0 then pure ((QM31.fromM31s a b c d :: acc).reverse, s')
        else go (n - 1) s' (QM31.fromM31s e f g h :: QM31.fromM31s a b c d :: acc)
      | _ => none

/-- Trailing zero bits of one natural, up to `fuel` bits. -/
def tzNat : Nat → Nat → Nat
  | 0, _ => 0
  | fuel + 1, n => if n % 2 = 1 ∨ n = 0 then 0 else 1 + tzNat fuel (n / 2)

/-- Trailing zero bits of the first 16 bytes, little-endian byte order
(`trailingZeroBits`): 8 per leading zero byte, then the first byte's count. -/
def trailingZeroBits (b : Bytes) : Nat :=
  go (b.take 16)
where
  go : Bytes → Nat
    | [] => 0
    | x :: rest => if x = 0 then 8 + go rest else tzNat 8 x.toNat

def POW_PREFIX : Nat := 0x12345678

/-- `compute_pow_prefix`: `H(LE(0x12345678) ‖ 0¹² ‖ digest ‖ LE(bits))`. -/
def powPrefix (m31 : Bool) (s : St) (bits : Nat) : Bytes :=
  chHash m31 (u32Le POW_PREFIX ++ List.replicate 12 0 ++ s.digest ++ u32Le bits)

/-- `verify_pow_nonce`. -/
def verifyPowNonce (m31 : Bool) (s : St) (bits : Nat) (nonce : Nat) : Bool :=
  trailingZeroBits (chHash m31 (powPrefix m31 s bits ++ u64Le nonce)) ≥ bits

/-- `⌈n/8⌉` successive `draw_u32s` batches, concatenated. -/
def drawWordBatches (m31 : Bool) : Nat → St → List Nat × St
  | 0, s => ([], s)
  | batches + 1, s =>
    let (ws, s') := drawU32s m31 s
    let (rest, s'') := drawWordBatches m31 batches s'
    (ws ++ rest, s'')

/-- `drawQueries` (`src/core/queries.zig`): `n` values masked to
`log_domain_size` bits. The Zig loop draws eight words at a time and stops
mid-batch at `n`; that is `take n` of `⌈n/8⌉` full batches. -/
def drawQueries (m31 : Bool) (logSize : Nat) (n : Nat) (s : St) : List Nat × St :=
  let (ws, s') := drawWordBatches m31 ((n + 7) / 8) s
  ((ws.take n).map (· % 2^logSize), s')

end StwoVerifier.Channel
