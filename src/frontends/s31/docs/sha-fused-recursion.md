# SHA-fused Bitcoin chain recursion: integration boundary

## What works today

`sha-fused` proves one private 80-byte header, its byte-exact SHA256d,
mainnet proof of work, and an eight-word Poseidon2 commitment to its digest.
Its native verifier authenticates a sealed, source-derived v4 key. The proof
has 14 AIR components, ten claimed sums, three SHA compression calls, a
private SHA digest, and a production FRI schedule of 26 proof-of-work bits,
70 queries, blowup log 1, and fold step 1. The public eight words are
canonical M31 values. This is a **header proof**, not a header-chain proof.

The [Bitcoin chain fold](../bitcoin_chain_fold.zig) instead verifies a prior
**11-component generic circuit** proof inside its circuit, checks the next
80-byte header there, and publishes a BLAKE2s chain-state digest. Its trusted
[native verifier](../bitcoin_chain_verifier.zig) derives the anchor and fold
roots from the checkpoint and a value-free topology. The fold proof uses its
own FRI schedule with fold step 4. A single accepted fold proof can therefore
attest to the earlier chain steps. The SHA256d work for the new header is still
performed by generic circuit gates.

The [sparse-wide wrapper](../recursion_sparse_wide.zig) verifies a third
profile: four sparse-wide circuit components with its own statement and
identity hash. Its fixed-key fold is separate from the Bitcoin chain fold.
Changing a package's lowering flag cannot turn either in-circuit verifier
into a `sha-fused` verifier. The [package CLI](../s31.py) currently refuses
recursive commands for `sha-fused`; that is the correct admission rule.

## Why direct leaf replacement is unsound

The generic child verifier is built from
[`CircuitStatement`](../../circuit/statements/circuit_statement.zig), which
expects exactly eleven circuit AIR evaluators and their transcript. A fused
proof needs fourteen evaluators, its v4 `S31FCJ04` envelope, the fused
source/semantic/air digests, canonical fixed root, Gate and SHA caller
metadata, circuit-to-SHA and word-lookup claim closure, and its own FRI
configuration. Parsing a fused proof as a generic child, or verifying it on
the host and passing only a Boolean into the fold witness, would leave the
fold proof unable to authenticate the fused proof.

The public claims also differ. `sha-fused` exposes only a commitment to one
header's digest. The fold needs the authenticated prior block hash and eleven
timestamps, then checks the new header's previous-hash field, target, time,
and proof of work. Its public output is a BLAKE2s digest of that state, with
unrestricted `u32` words. A Poseidon2 digest root in eight canonical M31 words
cannot be substituted for that chain-state digest.

## One-step joined profile and the recursion blocker

The first useful milestone is a **new joined one-step proof profile**. Its
circuit verifies the existing generic genesis-anchor proof. Split the
new-header step so that the circuit enforces the link, target, time, counter,
and next-state rules, while its private header and SHA256d digest wires are
joined to three SHA compression calls through the fused caller and Gate
lookup. Remove the generic SHA gates for that header. The circuit and SHA
AIRs share one STARK transcript and one fixed root. A native verifier can
accept one proof, one trusted key, and one public chain-state statement for
this **first step**. The AIR roster and column geometry must be measured from
the actual joined topology; the single-header package's 14-component count
does not specify them.

That first-step proof cannot be used as the child of the same circuit on the
next step. The circuit still contains a generic 11-component child verifier,
while its own output has a new joined profile. A stable recursive fold needs
an in-circuit verifier for the joined profile, including its full statement,
transcript, lookup closure, Merkle/FRI checks, and authenticated public
output. It also needs a sound base-versus-recursive branch: a generic anchor
at the base and a joined fold proof thereafter. How to gate or otherwise
support those two different child proof profiles under one fixed fold
topology, while binding the fold's own derived root, is **unsolved here**.
No same-key block-two proof or recursive light-client claim follows from the
one-step milestone.

Keep the current public state ABI for the first version:

```text
statement = (key_sha256, step, current_block_hash[32], last_timestamps[11],
             public_words[8])
public_words = BLAKE2s_S31BFD2!(fold_root || LE32(step) || checkpoint_hash
                                 || current_block_hash || last_timestamps)
```

The eight public words are raw little-endian `u32` BLAKE2s words. The verifier
recomputes them from the named public fields. In the first-step circuit, the
generic anchor proof authenticates the checkpoint; the prior hash and
timestamps are private openings constrained to the genesis state. A later
stable fold must instead authenticate those openings against its verified
prior joined-fold output. The new header's
40 private `u16` limbs and 16 private digest limbs are constrained through the
caller equations and SHA chip. The circuit compares that digest against the
header's target and checks the previous-hash field against the opened prior
hash. No private SHA digest becomes a new public input. This is the smallest
state ABI change: the public statement format can stay stable, but the proof
profile, key, and fixed root must change.
The `fold_root` in the digest formula belongs to that proof's profile; a
bootstrap profile and a later stable profile have distinct roots and keys.

The new key must pin a new profile/schema and derive its fixed root from a
value-free build of the entire joined topology, including the exact circuit
projection, actual AIR roster, SHA call namespace, Gate addresses, caller
equations, all column logs, the SHA semantic digest, checkpoint and epoch
rules, and production FRI parameters. The first-step key must also pin the
generic anchor key/root and its FRI parameters. A later stable-fold key must
pin the accepted child profile or profiles and derive its own root. If the
circuit guesses its self-root to avoid a circular topology constant, the
native statement must bind that guess to the independently derived root,
as the current generic fold does. The native verifier must independently
rebuild and compare each key, reject external-key changes, and bind the same
public words into the proof transcript. The current `sha-fused` package's
single-header key cannot be reused as either key.

## Implementation sequence and acceptance gates

1. Extract a header-step circuit kernel that consumes authenticated SHA256d
   digest wires. Confirm that it has the same link, PoW, target, time, and
   next-state behavior as the current direct-SHA kernel on genesis and
   adversarial headers. Keep both paths testable until the equivalence checks
   pass.
2. Join that kernel's header and digest wires to the three-call fused SHA
   caller AIR. Build a value-free topology and one native proof for block one
   with the existing anchor proof as its child. Publish a distinct sealed
   first-step key and native verifier; do not admit the existing v4 header
   key or old chain key. Compare its rows, proof size, and proving time with
   the generic chain fold for block one.
3. Design and implement the joined-profile verifier inside the fold circuit,
   including a sound anchor/recursive child selection and fixed-root binding.
   Derive a stable key from that complete value-free topology. Only then try
   a block-two proof with the block-one proof as child, and a block-three
   proof with block two as child. If the bootstrap proof has a distinct key,
   the stable circuit must verify that exact bootstrap profile at its base;
   a generic-only child verifier cannot do so. Confirm that the top native
   verifier accepts only its key, statement, and newest proof.
4. Reject changes to every binding boundary: external key or source identity,
   child key/root/proof/public digest, current hash, prior-state opening,
   one header byte, SHA caller input/output/ID/word coordinate, lookup sum,
   timestamp or target, public state words, fixed/main/interaction opening,
   FRI witness, and proof envelope. Also reject cross-profile proof replay
   and incorrect FRI geometry. The latest-header digest must remain private
   in both the statement and proof ABI.

This is not a package-dispatch edit. The current `sha-fused` package compiles
exactly one private `Bytes80` input and one eight-M31 public output, while the
fold circuit has a recursive verifier, BLAKE2s state digest, and additional
private state. The joined fold needs a new profile and measured geometry
before it is safe to expose as a recursive package.
