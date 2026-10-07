# S31 Bitcoin header light client: executable base and recursive target

Status: wide integers, byte-exact SHA256d, mainnet compact target decoding,
proof of work, and a genesis-anchored two-header same-difficulty link are executable and have
generated native verifiers. A dedicated SHA AIR witness planner feeds the
existing packed SHA provider, but S31 proofs still use the generic SHA
circuit. Sparse-wide proof wrappers and a homogeneous claim fold now verify
the two-header leaf recursively. A **changing-header** recursive state
transition and full header-chain policy remain open. The
[recursion security brief](RECURSION_SECURITY.md) gives the current proof
boundary, soundness limits, and verifier depth policy. The
[Bitcoin header chapter](../../src/frontends/s31/docs/bitcoin-sha256d.md)
shows the concrete program and handwritten constraints.
This document specifies a **header-chain light client**. It does not claim
transaction, UTXO, or script validity from headers alone.

## The library boundary

The present `std@1` exposes nominal `Bytes32` and `UInt256` values over sixteen
little-endian `u16` limbs. `std::bytes::to_u256_le` is an explicit, zero-row
reinterpretation. `std::math::add_u256` proves the modulo-$2^{256}$ sum with
sixteen range-checked output digits and Boolean carries;
`add_u256_checked` also constrains the final carry to zero. `le_u256` proves a
Boolean unsigned comparison with sixteen borrows. `limbs_m31` allows the
range-checked bytes to feed a field-native auxiliary commitment. The native
verifier accepts the [wide-order example](../../src/frontends/s31/examples/wide_order.s31)
and rejects a changed public root. Its [full-profile baseline](measurements/bitcoin-wide-v1-2026-10-06.json)
and [sparse-wide trial](measurements/bitcoin-wide-sparse-v5-2026-10-06.json)
are cost records for this exact program, not Bitcoin block proofs. The source
uses modular `add_u256`; a separately measured variant uses
`add_u256_checked` to reject overflow.

`Bytes80` adds the serialized header shape. `std::hash::sha256d_header` fully
constrains the two header compression blocks and one second-hash block.
`std::bitcoin::target_mainnet` decodes bytes 72–75 with a constrained compact
exponent and nonnegative mantissa, enforces a nonzero result within mainnet
`powLimit`, and returns `UInt256`. The
[`bitcoin_header_pow.s31`](../../src/frontends/s31/examples/bitcoin_header_pow.s31)
program compares the digest interpreted as a little-endian integer to that
target and asserts success. Its generated native verifier accepted the
genesis-header proof and rejected a changed public commitment. This is a
single-header proof, not a chain validity proof.
The [matched single-header measurement](measurements/bitcoin-header-sha256d-v1-2026-10-06.json)
records hash-only and PoW versions of the same genesis witness. The latter
adds 614 raw QM31 rows and uses the same padded trace size; it proves byte
exactness and the target inequality inside one Stwo proof.

[`bitcoin_header_pair.s31`](../../src/frontends/s31/examples/bitcoin_header_pair.s31)
pins its parent SHA256d digest to the mainnet genesis checkpoint, then proves
the child's exact previous-hash bytes, equal `nBits` for this non-retarget
step, a strictly later timestamp for the first-step median-time-past rule,
and PoW checks for both headers. Its generated native verifier accepted
the real genesis-to-block-one witness and rejected a changed public pair root. The
[current single-trial record](measurements/bitcoin-header-pair-time-v1-2026-10-06.json)
contains geometry, proof bytes and timings with the timestamp check; the
[earlier record](measurements/bitcoin-header-pair-v1-2026-10-06.json)
predates it. This is a two-header
segment proof, not a general chain-policy or recursive proof.

[`bitcoin_header_link.s31`](../../src/frontends/s31/examples/bitcoin_header_link.s31)
is a reusable transition leaf. It takes a claimed `BlockHash` state opening,
constrains the new header's exact previous-hash field to that opening, proves
the new header's SHA256d and mainnet PoW, and publishes an ordered Poseidon2
commitment to the old and new hashes. The checked genesis-to-block-one
assignment has the same public pair root as the two-header fixture, while
performing only one SHA256d. Its [native acceptance
gate](../../src/frontends/s31/acceptance_header_link.py) checks the independent
SHA/Poseidon oracle, a valid proof, a forged predecessor, and a changed root.
It also wraps the leaf in one sparse-wide recursive verifier proof and rejects
a changed authenticated child statement.
The opening is still private and unauthenticated by this leaf alone; the
changing-header fold must bind it to the prior verified state.
The leaf's local fourfold-FRI run used 365,487 raw QM31 rows and a
236,523-byte proof, versus 714,614 rows and 266,285 bytes for the typed
two-header fixture under the same profile. This halves the raw arithmetic
trace without claiming a measured wall-clock speedup. The scalar
`poseidon2.linkRootCircuit` helper can recompute this ordered commitment
from range-checked hash openings inside a future fold; its value and
witness-free topologies are tested against the pinned host hash.

## Dedicated SHA chip: proof-bound integration contract

The existing RISC-V packed SHA provider already expresses one compression
call as fixed source, schedule, round and feed-forward AIRs. A focused test
now proves six compression calls in one STARK and rejects a substituted
output boundary. It checks the exact `recursion_wire` multiset before proving.
Each call closes 24 input and eight output word wires against trusted public
boundary rows. S31's header witness is private, so those boundary
rows **cannot** be trusted or copied from the prover. The
[`sha_chip_plan.zig`](../../src/frontends/s31/sha_chip_plan.zig) adapter
constructs the three exact compression calls for one `Bytes80` header and
passes them to the packed row provider. It checks byte order, padding,
lengths, state chaining, call order and digest bytes; independent randomized
SHA256d checks and corrupted-boundary tests pass. It is witness preparation,
not proof integration.

The first integrated SHA profile must use one STARK transcript and one
PCS/FRI proof for the generic circuit and the SHA AIR components. For each
compression call, the circuit emits the 24 input and consumes the eight
output `recursion_wire` word tuples `(call_id, wire_id, byte0, byte1,
byte2, byte3)`, with opposite signs to the packed SHA components. The
`call_id` namespace is verifier-assigned (1–3 for one header, 1–6 for this
two-header program); the wire IDs and multiplicities come from the fixed
SHA graph. The circuit constrains the tuple bytes to its `Bytes80` limbs,
intermediate SHA states, fixed pads and final digest limbs. The shared LogUp
sum must close only when every private circuit word matches the chip word.
The verifier reconstructs a versioned component roster, all active lookup
tables, fixed topology, call count, row geometry and semantic digests from
the sealed key. It mixes those and the public ABI into Fiat–Shamir before
the base commitment. It rejects any missing call, duplicate ID, noncanonical
byte, changed padding, changed digest, altered table or unmatched lookup.
The previously used `S31NAT5W` profile stays unchanged; a new envelope and
key version are required.

For one header, the packed provider has 264 live source rows, 144 schedule
rows, 192 round rows and 24 feed-forward rows before padding. The boundary
adds 32 word rows per call. The six-call test has 528 source, 288 schedule,
384 round, 48 feed-forward and 192 boundary live rows. In one local run its
prove phase took about 1.12 s and verify phase about 0.26 s; setup and a
negative verifier check raised total test time to about 2.89 s. The public
boundary test uses a different statement from private-header S31, so these
numbers are *not* a proving-time or
proof-size improvement claim: the SHA components are wide, use several
lookup tables, and the full circuit/chip proof geometry and PoW must be
measured. Promotion requires a same-statement, same-parameter comparison
against the generic circuit, including cold and cached setup, witness,
non-PoW proving, total proving, native verification, bytes and peak memory.
This is the major remaining efficiency gate.

| Six-call pair component | Live rows | Padded rows |
| --- | ---: | ---: |
| SHA source | 528 | 1,024 |
| Message schedule | 288 | 512 |
| Compression rounds | 384 | 512 |
| Feed-forward | 48 | 64 |
| Input/output word boundary | 192 | 256 |

The first four padded sizes are exercised by the six-call provider test. The
boundary size follows its 24 input and eight output words per call. The
generic two-header circuit currently has 714,595 raw QM31 rows, padded to
1,048,576; these row counts cannot be converted into a speedup ratio without
counting all column widths, lookup tables, interactions and verifier work.

The source frontend now distinguishes `BlockHash` from `Bytes32`.
`std::bitcoin::block_hash(header)` produces one from the existing constrained
SHA256d relation; `parent_hash(header)` and `genesis_block_hash_mainnet()`
produce matching typed views and a pinned constant. `hash_bytes` explicitly
views its sixteen limbs as raw digest-order `Bytes32`. The typed two-header
example lowers to the same relation as the prior source, so this type layer
adds no AIR rows. A `BlockHash` parameter remains an externally claimed value;
source typing alone does not prove its origin.

The next type layer should distinguish `Target`, `Work`, and `ChainWork` from
generic integers. Each conversion must name byte order and prove its
preconditions. A
`Target` can originate from the current mainnet compact decoder, but its type
should prevent accidental use with another network or policy. A `ChainWork`
update should use checked addition or another
reviewed overflow contract; modular `add_u256` would hide overflow if the
statement intends mathematical accumulated work.

## The first Bitcoin statement

For a versioned network parameter set and trusted checkpoint, a header-step
relation should take the previous header hash, height, difficulty context,
and accumulated work as public state. Its private witness is an 80-byte
header. It should constrain:

1. byte-exact field positions, including `prev_block`, timestamp, `nBits`,
   and nonce;
2. `SHA256(SHA256(header))` over those exact 80 bytes and the exact
   Bitcoin byte order, with an independent host oracle;
3. previous-hash linkage and `hash <= target(nBits)` as unsigned 256-bit
   values;
4. target validity and permitted difficulty transition for the selected
   network, including adjustment-boundary context;
5. work increment, height increment, and a public commitment to the next
   state.

Bitcoin's [block-header reference](https://developer.bitcoin.org/reference/block_chain.html#block-headers)
defines the 80-byte layout and hash ordering. Bitcoin Core's
[`DeriveTarget` and `CheckProofOfWork` contract](https://github.com/bitcoin/bitcoin/blob/master/src/pow.h)
and [chainwork calculation](https://github.com/bitcoin/bitcoin/blob/master/src/chain.cpp)
are differential-test references. The relation must be tested against
mainnet and testnet boundary cases, invalid compact encodings, and historical
headers. A header-only proof says the chain of headers obeys these rules; it
does not establish the transactions beneath their Merkle roots.

The current public ABI has eight direct words. That is too narrow to expose a
raw 32-byte block hash plus height, work, network, and checkpoint in one
statement. A versioned wider ABI, or a reviewed collision-resistant state
commitment with precise opening rules, is required before that statement is
usable by a light client. The current Poseidon2 commitment is a development
fixture pending cryptographic review for this bridge use.

## General recursive wrapper

The wrapper should be **proof-format generic** rather than Bitcoin-specific.
Define a fixed `VerifiedProof` input carrying a canonical child proof, its
trusted verifier identity, public statement, and profile. A circuit verifier
must reconstruct the child verification key identity, transcript, public
binding, AIR composition, FRI queries, and all rejection conditions. A
successful in-circuit verifier yields the child's authenticated public state.
The wrapper's transition callback then checks `old_state -> new_state`, and
the outer proof exposes a compact commitment to `new_state`, checkpoint,
height, chainwork, network, and wrapper version. The wrapper must reject an
untrusted verifier key, profile downgrade, malformed child proof, or a child
statement that differs from the state used by the transition.

An ordinary program can call the same wrapper for a Merkle accumulator,
rollup, or Bitcoin header step once its inner relation is available. The
base case anchors a trusted checkpoint and must be domain-separated from a
recursive step. To make proof size and verifier cost independent of chain
length, the *outer* verifier must itself be accepted as the next child in a
compatible proof system. Host-side verification of two proofs and a JSON
linkage check is useful integration tooling, but it does not provide that
recursive property.

This repository has a separate
[Cairo-oriented recursion product](../../src/products/circuit_recursion_cpu/README.md).
Its `leaf-wrap` consumes a Cairo proof through a pinned registry. S31's
`S31NAT*` envelopes and generated keys are different. A [one-level S31 gate
wrapper](../../src/frontends/s31/docs/recursion.md) now verifies and converts a
saved `circuit-v1` S31 proof into the eleven-component in-circuit verifier, proves
the satisfied verifier circuit, and independently verifies its outer proof
under an embedded child key and a build-time sealed outer key. The native
verifier uses the sealed layout and root instead of rebuilding its large
topology for each outer proof. The adversarial corpus also regenerates that
key and compares it field-for-field. The v2 wrapper fixes the child AIR root
in-circuit and binds the exact child key digest in its public claim. A
same-AIR, different-key fixture confirms that child proof portability does
not allow outer proof replay. The [two-level chain](../../src/frontends/s31/docs/recursion-chain.md)
wraps the first recursive proof again, including a private-witness leaf.
The [sparse-wide wrapper](../../src/frontends/s31/docs/recursion-sparse-wide.md)
admits the two-header Bitcoin leaf, and the
[homogeneous fold](../../src/frontends/s31/docs/recursion-wide-fold.md)
keeps one sealed verifier key across subsequent steps. The fold repeats that
same leaf claim; it does not consume or validate a new header per step.
The current native verifier can enforce a caller-chosen `--max-step` cap,
but a concrete accumulated soundness bound is still required.

### Changing-header fold contract

The preferred next fold verifies **one prior fold proof** under its sealed key
and checks the new header directly in the same circuit. The
[`bitcoin_fold_step.zig`](../../src/frontends/s31/bitcoin_fold_step.zig)
kernel already range-checks the old hash and new 80-byte header, equates the
header's previous-hash field to the old hash, constrains byte-exact SHA256d,
decodes the mainnet target, proves PoW, equates the old Poseidon2 root to an
authenticated prior-state root, and returns the new root. Its
[witness-free inspector](../../src/frontends/s31/inspect_bitcoin_fold_step.zig)
reports 366,721 variables and 363,049 QM31 arithmetic rows for this kernel.
The recorded Bitcoin sparse-wide claim fold has 259,481 spare QM31 rows before its
next padding boundary. The complete witness-free
[`bitcoin_chain_fold.zig`](../../src/frontends/s31/bitcoin_chain_fold.zig)
candidate now measures 1,151,865 raw QM31 rows, padded to 2,097,152. Eq
rows also rise to 65,536 padded. With those two child sizes enlarged, all
five AIR components reproduce the same padded child geometry; the
preprocessed root is identical at counters `0`, `1`, `65536`, and
`0xffffffff`. Changing the checkpoint or base-proof root changes that root.
This is a fixed-point **topology**, not a generated chain-fold proof. A
matched end-to-end proving benchmark is required before claiming a time win. The
[inspection record](measurements/bitcoin-direct-fold-step-v1-2026-10-07.json)
pins the kernel counts; the [composed topology record](measurements/bitcoin-chain-fold-topology-v1-2026-10-07.json)
pins the fixed-point geometry and key-parameter checks.

For a first **hash-chain-only** fold, the eight-word ABI can hold one
authenticated state root. The fold must open the previous output digest in
its circuit, equate its authenticated root to the kernel's old-hash root,
then publish a domain-separated digest binding the new root, `u32` counter,
checkpoint, and sealed fold identity. At step zero, the base proof must bind
the trusted checkpoint; the recursive branch must verify exactly step `n-1`.
A host-side equality check cannot replace either circuit constraint.
The candidate circuit now makes those equalities: at step zero a Boolean
base selector forces the witnessed prior root to equal the key-pinned
checkpoint, selects a base proof with that public output, and checks the
first new header. At step `n>0`, it verifies a prior fold proof whose public
output equals the digest of the witnessed prior root at step `n-1`, then
checks one new header. The child root switches between a key-pinned base
root and the fold's own root. The small branch test checks selection at
`0`, `1`, and `65536` and rejects a changed prior root. A base proof with the
candidate geometry, a sealed key, value-bearing STARK proof, native verifier,
and adversarial proof replay tests remain to be built.
[`bitcoin_fold_digest.zig`](../../src/frontends/s31/bitcoin_fold_digest.zig)
now pins the proposed 100-byte `S31BFD1!` digest preimage: 32 bytes of fold
AIR root, four bytes of little-endian counter, 32 bytes of canonical M31
checkpoint root, and 32 bytes of canonical M31 current root. Host and circuit
implementations agree at boundary counters including `0xffffffff`; the host
rejects noncanonical root words. The candidate circuit uses this digest in
its child and output statements; no Bitcoin chain-fold proof or sealed key
yet authenticates it.

The separately proved [`bitcoin_header_link.s31`](../../src/frontends/s31/examples/bitcoin_header_link.s31)
leaf remains useful for independent proofs and for a future dedicated SHA
chip. If a proof-bound chip makes verifying that leaf cheaper than direct
header gates, a two-child fold can authenticate the prior fold and the new
leaf instead. The `poseidon2.constrainLinkedState` kernel checks the two
state-root equalities for that route. The
[`recursive_public_words.zig`](../../src/frontends/s31/recursive_public_words.zig)
bridge proves that each verified packed `u32` leaf word equals a canonical
M31 word before Poseidon2 consumes it; it rejects `p` and is tested with the
link kernel. No fold invokes either route yet.

This hash-only stage would establish linked, PoW-valid headers against a
trusted checkpoint. Full mainnet policy additionally needs a versioned state
commitment binding difficulty context, timestamps, height, and checked
chainwork, plus a leaf or direct circuit relation updating that state. The
new fold needs a versioned proof envelope, fixed statement encoding, and
adversarial tests for changed old/new state, wrong prior key or checkpoint,
omitted header work, wrong network parameters, and counter wraparound. The
current four-lane `state_fold` proves only a fixed field recurrence and
verifies one child proof; it cannot be relabeled as this Bitcoin transition.

## Engineering sequence and exit gates

| Stage | Deliverable | Required evidence |
| --- | --- | --- |
| 1. Wide arithmetic | Typed byte/int values, carry/borrow relations, independent oracle | Current example and native proof; add boundary and randomized adversarial vectors. |
| 2. Byte-exact header hash | **Generic circuit complete:** `Bytes80`, SHA256d relation, nominal `BlockHash`, one native proof. **SHA AIR witness planner complete:** three call records and packed provider rows. Remaining: authenticated circuit-to-chip lookup, new proof roster and verifier, broader Bitcoin Core differential vectors, and measured cost crossover. | Genesis and randomized byte checks; native proof and changed-root rejection currently pass. Chip substitution must fail until one-proof lookup closure is implemented. |
| 3. Header policy | **Genesis-anchored two-header first step complete:** compact target, powLimit, unsigned comparison, exact previous-hash link, equal `nBits`, and strict first-step timestamp order. A one-new-header transition leaf now proves link and PoW against a claimed prior hash. Remaining: prior-state authentication, retarget transitions, general eleven-block MTP and contextual future-time policy, work increment and versioned public state ABI. | Real genesis-to-block-one proof accepted; changed public claim rejected by native verifier; changed checkpoint, link, bits and equal time rejected by independent oracle; transition leaf rejects a forged predecessor and changed root. |
| 4. In-circuit S31 verifier | **Gate and sparse-wide wrappers implemented:** native capture of saved proofs, in-circuit child verifier, sealed recursive keys and native outer verifier. Fourfold FRI is supported for the sparse-wide leaf and wrappers. Remaining: independent end-to-end soundness review and proof-bound SHA chip integration. | Valid arithmetic/private-witness and Bitcoin two-header leaves, two wrapper levels, exact-key/FRI replay rejection and hostile proof-field mutations. |
| 5. Recursive fold | **Fixed-key gate and sparse-wide claim folds implemented:** `u32` counter, one sealed fold key across steps, cached batch proving and top-only native verification. Gate-profile four-lane state transitions also fold under one key. Remaining: a typed Bitcoin state and new-header-per-step transition, plus an analyzed depth/security bound. | Base and recursive branch mutation suites; byte-identical batch and separate proofs; high-counter adversarial statements; source-state replay; caller-supplied native `--max-step` cap. |

Optimization should now focus on a dedicated SHA chip and the header-chain
policy.
The current wide example takes 16,422 raw QM31 rows, 69 Eq rows, and 88
M31-to-u32 rows. `sparse-wide-gate` retains only the four AIR components it
needs, cutting fixed cells from 4,507,264 to 328,320 and the one-sample
proof from 427,557 to 238,047 bytes. Its proving sample was 0.433 s versus
1.688 s for `gate`; proof-of-work made those single timings stochastic. The
cost includes two Poseidon2 leaf hashes and a parent, not just wide arithmetic.
A dedicated hash chip should be promoted only after a same-statement trial
shows end-to-end proof, time, memory, and verifier improvements without
weakening constraints.
