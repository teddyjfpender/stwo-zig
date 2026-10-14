# Candidate Gate hash profile and migration boundary

`gate_hash_profile_v2.zig` collects the hash choices for the reserved
`S31NAT9F` Gate proof. It is an unselected candidate. The current Gate proof
format and verifier dispatch are unchanged.

## The byte issue in the current raw profile

The production profile in `channel_profile.zig` uses the default BLAKE2s
parameter block throughout. Its raw channel absorbs a root as
`H(digest[32] || root[32])`; it absorbs two QM31 values as the same 64-byte
shape, `H(digest[32] || eight little-endian M31 words)`. If the eight words
equal the root bytes, the two roles invoke BLAKE2s on *identical input*.
Likewise, the plain Merkle profile hashes a 16-word source leaf and a parent
of two 32-byte child digests as untagged 64-byte messages. The focused test
constructs both equal-input cases without relying on a cryptographic
collision. This is a role ambiguity in the hash interface; it does not by
itself construct an accepted false Gate proof.

## Frozen candidate byte roster

| Role | Candidate byte rule |
| --- | --- |
| Transcript statement/root/field/nonce/PoW | `BLAKE2s-256("S31BCS2" || role:u8 || payload_len:u64-le || event:u64-le || payload)`, default personalization |
| Verifier-drawn field/query words | Role 4 frame under a checked block counter; field limbs reject raw words outside `[0,2p)` before reduction |
| Source leaf | `BLAKE2s-256(person="S31S2LEF", canonical M31 row words:u32-le)` |
| Source parent | `BLAKE2s-256(person="S31S2PAR", left[32] || right[32])` |
| FRI line leaf | `BLAKE2s-256(person="S31P2LEF", canonical M31 row words:u32-le)` |
| FRI line parent | `BLAKE2s-256(person="S31P2PAR", left[32] || right[32])` |

The four Merkle personalization strings are fixed eight-byte role names,
pairwise distinct, and nonzero. The transcript frame's role byte, payload
length, and event number distinguish its message inputs. An effective hash
call is the pair **(BLAKE2s parameter block, message bytes)**: the source
and line Merkle roles therefore cannot be silently exchanged for plain
hashes or for each other. The one-block, 64-byte parent message preserves
the efficient parent-hash path; the full tree descriptor is bound in the
statement and named root event, rather than shortened into an eight-byte
personalization value. See `line_descriptor_v2.zig` and
`owned_paired_gate_v2.zig` for candidate descriptor and root custody.

The integrated test builds four small source roots and two line roots,
authenticates openings under their corresponding profiles, and replays the
same typed event schedule on independent producer and verifier channel
instances. It pins sample roots against Python `hashlib.blake2s` parameter
vectors. A wrong interaction root changes later challenges. This establishes
local byte agreement for that synthetic schedule, not a proof producer or
accepted PCS instance. In particular, the test statement uses zero digests;
a selected verifier must derive all eight statement digests from its sealed
key and checked geometry.

## Required steps before selection

1. Freeze a new proof selector, versioned wire decoder, key-owned statement
   and four source-tree descriptors. Keep old proof bytes and dispatch
   separate; a plain source root must never be interpreted as a personalized
   source root.
2. Make the native prover commit every source and FRI line tree under this
   exact profile and drive one typed transcript. Make the native verifier
   derive the same descriptors and event sequence, including both PoW
   barriers, challenge rejection counters, and query projection. Compare
   complete proof bytes and negative mutations, not only this small replay.
   The integration points are `src/prover/prove.zig` and
   `src/prover/pcs/mod.zig` for transcript/PCS construction,
   `src/prover/vcs_lifted/prover.zig` for committed tree hashing,
   `src/core/verifier.zig` and `src/core/pcs/verifier.zig` for verifier event
   order, and `src/core/vcs_lifted/verifier.zig` for path hashing. The current
   `src/core/vcs_lifted/channel_profile.zig` still names the plain profile;
   do not replace that legacy choice in place.
3. Finish the accepted Gate 73-claim paired source/own-quotient ensemble and
   its degree test. The current H3 weighting receipt is diagnostic: 61 source
   columns, 73 explicit OOD claims and 85 raw legacy quotient contributions
   do not automatically instantiate the paper's per-function batch schedule.
4. Prove or explicitly assume a multi-context BLAKE2s Fiat–Shamir/BCS
   reduction covering the framed transcript and four personalized Merkle
   roles, adaptive two-stage grinding, statement custody and the exact FRI
   query law. A distinct parameter block is a byte separation rule, **not**
   by itself an independent-random-oracle theorem. Check the selected
   `T = 2^64` paper work-factor target `epsilon(T)/T <= 2^-96` with actual
   proof parameters. Native proven security bits stay unset until then.

Parent hashing is structurally one BLAKE2s compression for a 64-byte input.
The framed transcript has different costs; only a full prover profile can
establish whole-prover speed. No release gate or native soundness claim is
changed by this module.
