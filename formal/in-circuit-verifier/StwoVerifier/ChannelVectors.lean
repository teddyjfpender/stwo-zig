/-
**Channel known-answer vectors**, copied from stwo-zig's own test suites
(`src/core/channel/blake2s.zig`, `src/core/pcs/config_v2.zig`,
`src/core/vcs_lifted/channel_profile.zig`), which are themselves pinned to
Rust Stwo / proving@5a7c5ed oracles. If the Lean channel spec reproduces
these bytes, it reproduces the upstream transcript law for these operations.

Checked with `#eval` + `decide`-style guards at compile time.
-/
import StwoVerifier.Channel

namespace StwoVerifier.ChannelVectors

open StwoVerifier.Channel StwoVerifier

def hexDigit (n : Nat) : Char := "0123456789abcdef".toList.getD n '?'

def hex (b : Bytes) : String :=
  String.mk (b.flatMap fun x => [hexDigit (x.toNat / 16), hexDigit (x.toNat % 16)])

/- `mix_u64(0x1111_2222_3333_4444)` on the plain channel
(test "mix_u64 matches mix_u32s and upstream digest bytes"). -/
#guard hex (mixU64 false init 0x1111222233334444).digest =
  "bc9e3fc1d24e8897956d3359327397249d6bcacd224d927404e7ba4a77dc6ece"

/- `mix_u32s(&[1..9])` on the plain channel. -/
#guard hex (mixU32s false init [1, 2, 3, 4, 5, 6, 7, 8, 9]).digest =
  "70917683" ++ "57bb1bb3" ++ "346fdab6" ++ "b357d7fa" ++
  "46b8fbe3" ++ "2c2e4324" ++ "a0ffc294" ++ "cbf9a1c7"

/- The production circuit FRI config mix: `FriConfigV2(26, 0, 1, 70, 4)`
mixes `[(26,1,70,0), (4,0,0,0)]` as two felts (`config_v2.zig` oracle test)
— plain channel. -/
#guard hex (mixFelts false init
    [QM31.fromM31s 26 1 70 0, QM31.fromM31s 4 0 0 0]).digest =
  "54eb2c5200f192007d8034e03112037a8dc2438073d5fe0c16ca7422a8cfb3d6"

/- Same mix on the M31 channel. -/
#guard hex (mixFelts true init
    [QM31.fromM31s 26 1 70 0, QM31.fromM31s 4 0 0 0]).digest =
  "54eb2c5200f192007e8034603112037a8ec2430073d5fe0c16ca7422a9cfb356"

/- `mixRoot` oracle (`channel_profile.zig`): `mix_u64(1)` then
`mix_hash(hash_u32s(WORDS))` on the M31 Merkle channel. The root is the
*plain* Blake2s of the words — commitments always use the unreduced hasher. -/
def hasherTestWords : List Nat := [0, 1, 2, 3, 0x12345678, 0xffffffff, 7, 8, 9]

#guard hex (mixRoot true (mixU64 true init 1)
    (Blake2s.blake2s ((hasherTestWords.map u32Le).flatten))).digest =
  "45181730c0e0720f5e2ac400a8308300e579947dd429b721a55b8d103d43f066"

#guard hex (mixRoot false (mixU64 false init 1)
    (Blake2s.blake2s ((hasherTestWords.map u32Le).flatten))).digest =
  "b9511af5d89a9f57095bf95edb9cb1725516152d2628266824c2e4766b620f78"

/- Metal AOT transcript vector (`channel/blake2s.zig`): plain channel,
`mix_felts` of three QM31s, then three secure draws, then thirteen
24-bit query words. -/
def aotSource : List QM31 :=
  [QM31.fromM31s 1 2 3 4, QM31.fromM31s 5 6 7 8, QM31.fromM31s 9 10 11 12]

def aotSecureExpected : List (List Nat) :=
  [[0x2de33d85, 0x186760f3, 0x016dfb8f, 0x5526159e],
   [0x033dfdd3, 0x57435736, 0x76aedb39, 0x79a6e4ab],
   [0x5f39484b, 0x73505dbc, 0x310d05c0, 0x4581f67d]]

#guard
  (match drawSecureFelts false 3 (mixFelts false init aotSource) with
   | some (felts, _) => felts.map (fun q => q.coords.map F.toU32)
   | none => []) = aotSecureExpected

/- The query draw after those felts: 13 words masked to 24 bits. The draws
counter continued from the secure draws (2 batches for 3 felts). -/
def aotQueriesExpected : List Nat :=
  [0x48606d, 0x3b1f59, 0xec55d9, 0xa6ea6c, 0x9bceba,
   0x7fc92c, 0xdb979b, 0x92cb97, 0x8192ec, 0xe06454,
   0x7faf73, 0x006ed0, 0x4577cb]

#guard
  (match drawSecureFelts false 3 (mixFelts false init aotSource) with
   | some (_, s) => (drawQueries false 24 13 s).1
   | none => []) = aotQueriesExpected

/- PoW known answers (`grind matches Rust Stwo SimdBackend known answers`):
`verify_pow_nonce` accepts the grinder's nonce on both channel variants. -/
#guard verifyPowNonce false (mixU64 false init 1) 20 12885063745
#guard verifyPowNonce true (mixU64 true init 1) 20 12885632339
#guard verifyPowNonce true (mixU64 true init 1) 24 4295766292
/- …and rejects a wrong nonce. -/
#guard !(verifyPowNonce false (mixU64 false init 1) 20 12885063744)

/- proving@5a7c5ed grind answers after `mix_u64(0x1111222233334344)`. -/
#guard verifyPowNonce false (mixU64 false init 0x1111222233334344) 10 0x413
#guard verifyPowNonce true (mixU64 true init 0x1111222233334344) 10 0x415
#guard verifyPowNonce true (mixU64 true init 0x1111222233334344) 20 0x1_0005_a700

end StwoVerifier.ChannelVectors
