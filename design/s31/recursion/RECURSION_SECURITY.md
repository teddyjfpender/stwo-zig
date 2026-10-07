# S31 recursion: soundness boundary and audit ledger

This is the security claim supported by the current code and fixtures, not a
claim of a measured security level. It covers three distinct constructions:
the fixed-claim fold repeats verification of **one unchanged leaf claim**;
the gate-profile state fold also constrains a four-lane M31 transition
extracted from S31 source; and the Bitcoin hash-chain fold checks a new
80-byte header at each step. The earlier sparse-wide Bitcoin fixture verifies
two linked headers **inside one leaf proof**.

## What an accepted top proof needs

For a fixed-claim fold with public counter `n`, the native verifier checks the
sealed `KF` key, its AIR root and circuit hash, and the public digest
`F(RF,n,D)`. `F` is BLAKE2s-256 over the actual 32-byte root, little-endian
`u32` step, and eight raw `u32` base-digest words in separate fixed-width
slots. Inside the circuit a single child STARK verifier checks a proof under
the base wrapper key at `n=0`, or a prior fold proof under `KF` at `n>0`.
The base and recursive branches use the same child verifier AIR layout.
The private root used by the fold circuit is bound to the sealed actual root
through the top public digest, subject to BLAKE2s collision resistance.

The counter gadget is shared with the state fold. Both current and previous
counter values have two independently constrained `u16` limbs. The branch
selector and borrow are Boolean. The limb sum used for the zero test is at
most 131,070, below the M31 modulus, so it is zero in M31 exactly at integer
zero. The predecessor equations force an integer decrement on every
recursive branch, including `65536 → 65535`, and cannot wrap at zero or
above `2³²−1`. The [fixed-fold design](FIXED_KEY_FOLD.md) gives the case
argument. The [gate acceptance](../../../src/frontends/s31/tests/acceptance/acceptance_fixed_fold.py)
and [wide regression](../measurements/recursion/sparse-wide-fold-u32-overflow-regression-2026-10-07.json)
check rehashed false high-step statements and output-free overflow rejection.
The isolated circuit digest test compares the host and circuit at `0`,
`65536`, `2³¹`, and `2³²−1`.
`inspect-fold` and `inspect-state-fold` also accept `--step N` and rebuild the
witness-free AIR at that counter. The
[topology invariance record](../measurements/recursion/fold-counter-topology-invariance-2026-10-07.json)
compares all reported fields except the requested step at `0`, `1`,
`65535`, `65536`, `2³¹`, and `2³²−1` for gate fixed, gate state and
sparse-wide fixed folds. Each case reproduces its sealed AIR root, circuit
hash and exact geometry. These boundary samples guard against a
counter-dependent circuit shape; they do not enumerate all `u32` values.

The proof-system argument then proceeds by induction on `n`: a valid top
proof implies a valid child proof for the selected root and output, and the
counter reaches the base case. This depends on the native and in-circuit
STARK verifiers agreeing on serialization, public values, transcript,
commitments, Merkle openings, LogUp, OODS, FRI, and proof-of-work checks.
The prover authenticates the child natively before converting its openings
to circuit witness values. The circuit still verifies those witness values;
native preverification is an input-integrity check, not a substitute for
constraints. The value-bearing gate graph must match the witness-free graph
before and after padding, and the generated proof is natively checked before
being returned.

The child transcript uses the M31-output BLAKE2s channel. Its proof-of-work
predicate checks low bits **after reducing each 32-bit digest word modulo
M31**. The [channel regression](../../../src/frontends/circuit/stark_verifier/channel_test.zig)
uses two nonces whose raw first digest word exceeds the modulus: one passes
only after reduction and the other passes only before it. The in-circuit
predicate and native verifier agree on both. A raw-digest PoW check would
silently change the protocol.

The state fold adds a separately constrained source-defined transition
between predecessor and current state. Its initial/current state is also
included in the public fold digest. Extracting the shared counter left the
mix4 state-fold AIR root and every raw/padded component row count unchanged;
the [current acceptance record](../measurements/recursion/mix4-state-fold-shared-counter-2026-10-07.json)
checks three steps, 27 base and 28 recursive mutations, a repaired false
state, and independent replay of the final state from source semantics.
The transition gates also pass 48 deterministic mixed-body differential
cases against the host source evaluator, covering bodies of one through
sixteen operations and values near the M31 modulus. Extracting this gate
builder for the test preserved the sealed arith4 state-fold AIR root and
raw/padded geometry.

The Bitcoin fold has a different base case. Its current key profile pins the
Bitcoin mainnet genesis hash and accepts final steps at most 2014, so step
2014 proves block height 2015 and the first retarget at height 2016 is out
of scope. A key-pinned checkpoint anchor proof publishes the Poseidon2 root
of that 32-byte genesis hash. At step
zero, the fold verifies that anchor under its fixed AIR root, forces the
private prior-hash root to equal the checkpoint root, and checks a fresh
header's exact previous-hash bytes, `nBits = 0x1d00ffff`, SHA256d and proof
of work. At positive
step `n`, it verifies a fold proof with public digest for step `n-1`, the
witnessed prior-hash root, and an eleven-timestamp window, then checks the
next header and the same exact `nBits`. The genesis and height limits are
native key-policy checks; the header `nBits` equality is proof-bound. The
current header-hash root and shifted timestamp window enter `S31BFD2!`, a
personalized BLAKE2s digest of the actual fold AIR root, full `u32` step,
checkpoint root, current root, and eleven newest-first `u32` timestamps.
The outer native verifier reconstructs that digest from the key, statement,
displayed current block hash, and timestamp window. The fold AIR cannot contain its own root
as a constant without a hash fixed-point problem; its guessed self-root is
bound by the outer public digest, subject to BLAKE2s collision resistance.
The prior and current hash roots also depend on Poseidon2 collision
resistance. The base branch fixes the genesis time and ten missing-ancestor
markers. Each recursive branch opens the window through the verified child
digest, constrains the new header time to exceed the median of the available
one-to-eleven ancestors, and shifts the time into the next state. The
[MTP walkthrough](../bitcoin/BITCOIN_MTP_FOLD.md) gives the integer comparator and
Bitcoin Core source. This is an induction argument for a
**checkpoint-relative header chain** over the first difficulty epoch, not
full Bitcoin consensus or proof of the most-work chain. The first retarget,
contextual future-time policy, cumulative chainwork and best-chain selection
remain absent. See the
[Bitcoin design](../bitcoin/BITCOIN_LIGHT_CLIENT.md) and
[standalone acceptance](../../../src/frontends/s31/tests/acceptance/acceptance_bitcoin_chain_cli.py).
An [exact first-retarget circuit gadget](../bitcoin/BITCOIN_RETARGET.md) exists for a
future height-2016 profile, but the current fold does not call it and its
key continues to reject that height.

## Sealed parameters and what they mean

`showcasePcsConfig` and `recursivePcsConfig` in
[`mvp_runtime.zig`](../../../src/frontends/s31/runtime/mvp_runtime.zig) use 26 grinding
bits, blowup factor two, 70 FRI queries, and last-layer degree bound one.
The child FRI fold step is one or four; the sparse-wide wrappers and fold use
four. The child key records these parameters, and package/key checks reject
a mismatched child profile. The wide wrapper and fold keys bind their
fourfold schedule and exact parent key bytes. The
[source-key replay record](../measurements/recursion/sparse-wide-fold-u32-key-binding-2026-10-07.json)
and [FRI-key replay record](../measurements/recursion/sparse-wide-fold-u32-fri-key-binding-2026-10-07.json)
show that repairing the public digest under a different valid key does not
make a top proof verify there.

The [Stwo-Cairo README](https://github.com/starkware-libs/stwo-cairo#readme)
describes this parameter tuple as targeting **96 bits of conjectured
soundness for its own system**. The
[Stwo README](https://github.com/starkware-libs/stwo#security) says soundness
depends on blowup, query count, and grinding bits and that consumers must
choose parameters for their target. The underlying
[Circle STARKs paper](https://eprint.iacr.org/2024/278.pdf) analyzes circle
FRI. The matching tuple does **not** transfer a 96-bit claim to S31: this
Zig implementation, its AIR bundle, transcript adaptation, and recursively
embedded verifier need a concrete end-to-end analysis and independent review.
The `u32` counter is an encoding capacity, not an analyzed secure or practical
proof depth. Repeated verification can accumulate soundness error; this
repository does not yet publish an acceptable maximum depth for a chosen
security target.

For a top counter `n`, the gate construction contains `n+1` fold proofs,
one first-wrapper proof, and one leaf proof: `n+3` STARK proofs in the
inductive chain. The sparse-wide construction has two wrappers and a leaf,
so its count is `n+4`. If a separate analysis established a uniform
per-proof error bound `ε` against adaptively selected false statements under
all these keys, a conservative union-bound term would be at most
`(n+3)ε` or `(n+4)ε`, respectively. Hash binding failures and any protocol
composition loss must be added separately. This equation is a budgeting
template, **not** a soundness theorem for the current implementation. For
the Bitcoin fold, there are `n+1` fold proofs and one anchor proof, or
`n+2` proofs; the analogous conditional term is `(n+2)ε`, plus BLAKE2s,
Poseidon2, and proof-system composition losses. For
scale only, inserting a hypothetical `ε = 2⁻⁹⁶` and allowing around `2³²`
proofs leaves a term around `2⁻⁶⁴`; the 96-bit premise has not been
established for S31. Neither the `securityBits()` helper nor a matching
Stwo-Cairo parameter tuple supplies it.

The native `fold-verify` and `state-fold-verify` commands and their `s31.py`
wrappers accept `--max-step N`. The verifier validates the sealed key and
statement, then rejects `step > N` before reading proof bytes. The limit is
supplied by the relying party and is never taken from the prover's statement.
It is an application policy bound; it does not by itself establish a
soundness level. Step zero already contains one fold proof. The acceptance
suites prove a step-three top proof with
limit three and reject the same proof with limit two. Omitting the option
preserves the protocol's full `u32` counter range. The
[policy acceptance record](../measurements/recursion/fold-depth-policy-2026-10-07.json)
covers gate fixed, gate state and sparse-wide fixed folds.

The standalone Bitcoin verifier instead requires the caller to pin the
SHA-256 digest of the exact key file. It re-derives the checkpoint-bound
anchor and fold roots, checks the fixed AIR layout and FRI schedule, and
enforces the key's `max_step` before verifying the proof. Its current
two-header key permits steps zero and one. The acceptance script regenerates
the key and statements byte for byte, accepts both saved fold proofs, and
rejects a different checkpoint, key digest, current hash, timestamp window, step replay,
public words, proof bytes, and a step beyond the cap. The cap is a host
policy choice; no per-proof `ε` has been established for this Bitcoin fold.

The optional `audit-fold-chain` and `audit-state-fold-chain` commands inspect
saved checkpoints starting at step zero. They run the sealed native verifier
on every proof, require contiguous counters and unchanged public leaf/base
claims and key identity, and, for the state fold, independently replay each
sealed four-lane source transition over M31. They reject a missing base
checkpoint or a caller-supplied depth cap below the top step. This is an
artifact and implementation audit; it does not improve the top proof's
cryptographic soundness bound. The [checkpoint audit record](../measurements/recursion/fold-checkpoint-audit-2026-10-07.json)
covers gate fixed, gate state and sparse-wide fixed chains.
The coupled `mix4` state-fold acceptance also exercises the scalar replay
against a transition in which every output lane depends on all four previous
lanes.

## Evidence and limits

| Boundary | Evidence in this repository | Remaining obligation |
| --- | --- | --- |
| Counter and digest | Full-range circuit unit tests, host/circuit digest equality, repaired high-step statements | Formal constraint proof or independent gate audit |
| Key identity | Exact embedded-key checks, source/FRI cross-key replay rejection, versioned gate v3 and wide v4 fold schemas | Independent build-chain audit |
| Child verifier | Direct commitment, transcript, OODS, Merkle, FRI and nonce mutations; native capture parity | Independent verifier equivalence review |
| Fixed-key closure | Witness-free/value topology equality, reproducible key, isolated top verification and induction argument | End-to-end recursive soundness theorem and depth bound |
| Stateful relation | Source-bound step body, false-state rejection, independent replay | Typed state and transition support beyond four M31 lanes |
| Bitcoin | Byte-exact SHA256d/target two-header leaf; two successive new-header fold proofs under one AIR root; checkpoint-bound key, rolling eleven-timestamp MTP state and standalone native verification | Retarget, future-time context, chainwork, best-chain selection, independent soundness review and concrete depth bound |

An additional graph audit checked the child-proof witness before
`Context.finalize(false)` adds the gates that yield guessed values. In the
gate-profile fold, all 799,388 variables created while guessing the child
proof had at least one use, and all 219,188 representative proof-field wires
were used. In the sparse-wide fold the counts were 340,096 and 106,360,
respectively, again with zero unused wires. The latter check includes every
root word, claim, OODS value, sample, Merkle path word, nonce, FRI commitment,
FRI path word, FRI witness value, and final-layer coefficient. Both audited
circuits reproduced their sealed AIR roots and raw row counts. This is a
structural dead-field check, not a proof that every field reaches an asserted
equality or that the verifier implements the intended protocol. The mutation
tests and independent verifier review address those stronger questions.

`inspect-fold` and `inspect-state-fold` now also report
`proof_witness_connectivity` for the exact child-proof guess range. The
inspector builds an undirected graph from the pre-finalization gates, excludes
all interned constant wires as bridges, and counts proof variables in a
component containing a public output or a nontrivial equality. Inspection
fails if any proof variable lacks a path to a public output; the equality
count is an additional diagnostic. In the [connectivity record](../measurements/recursion/fold-proof-witness-connectivity-2026-10-07.json),
all 799,388 default gate fold proof variables and all 340,096 fourfold gate,
state-fold, and sparse-wide proof variables reach **both** kinds of anchor.
The unit test includes a disconnected witness that shares a constant with a
connected witness and confirms it remains disconnected. This is stronger
than a use-count check but remains a structural audit: paths through other
shared variables or algebraic cancellation could still make a field
semantically irrelevant. The native/circuit mutation tests remain necessary.

The current fourfold sparse-wide fold has about 5.59 million raw circuit
variables. In the measured verifier stages, Merkle plus FRI decommitment
dominates raw variable count; the [stage record](../measurements/recursion/sparse-wide-fold-u32-v1-2026-10-07.json)
is the starting point for an authenticated multiproof or dedicated verifier
chip. Any sharing of authentication paths must preserve tree root, leaf,
query index, transcript challenge, and proof identity in constraints.
Removing duplicate-looking witness paths without those equalities would
weaken soundness. The `u32` counter itself adds only 13 raw variables over
the earlier `u16` fold and leaves padded row sizes unchanged. The
[three-trial batch record](../measurements/recursion/sparse-wide-fold-u32-batch-memory-2026-10-07.json)
measures 5.753 s median for a cached three-step batch versus 6.596 s for
separate commands, with byte-identical outputs and about 74 MiB more peak
resident memory. These timings are local performance evidence, not security
evidence.

Before a production light-client claim, calculate concrete per-proof and
recursive soundness bounds for the exact AIR/PCS/transcript parameters,
review the in-circuit verifier against the native verifier, constrain a
full Bitcoin header-chain transition, and test adversarial chains including
target changes, work overflow, reorg choice, and malformed compact targets.
