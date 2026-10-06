# S31 Bitcoin header light client: executable base and recursive target

Status: wide integers, byte-exact SHA256d of one 80-byte header, mainnet compact
target decoding, and the proof-of-work inequality are executable and have
generated native verifiers. Header-chain policy and recursive proof verification
remain design work. The [Bitcoin header chapter](../../src/frontends/s31/docs/bitcoin-sha256d.md)
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

The next type layer should distinguish `BlockHash`, `Target`, `Work`, and
`ChainWork` from generic bytes and integers. Each conversion must name byte
order and prove its preconditions. A `BlockHash` should originate from a
constrained SHA256d call, or be visibly an externally asserted value. A
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

The current public ABI has eight M31 words. That is too narrow to expose a
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
`S31NAT*` envelopes and generated keys are different, so that product is not
yet an S31 proof verifier. An S31 recursion implementation must first choose
the supported inner profile and build a circuit verifier for its exact proof
format. The native verifier is the differential oracle for valid and
malformed inputs. Then the wrapper can prove one step, two linked steps, and
a fold while keeping the outer verifier and proof size bounded.

## Engineering sequence and exit gates

| Stage | Deliverable | Required evidence |
| --- | --- | --- |
| 1. Wide arithmetic | Typed byte/int values, carry/borrow relations, independent oracle | Current example and native proof; add boundary and randomized adversarial vectors. |
| 2. Byte-exact header hash | **Generic circuit complete:** `Bytes80`, SHA256d relation, one native proof. Remaining: nominal `BlockHash`, broader Bitcoin Core differential vectors, and a dedicated chip cost crossover. | Genesis and randomized byte checks; native proof and changed-root rejection currently pass. |
| 3. Header policy | **Single-header mainnet PoW complete:** compact target, powLimit, unsigned comparison. Remaining: difficulty transitions, header linkage, work increment, and versioned public state ABI. | Historical and edge-case header corpus; invalid transitions rejected by native verifier. |
| 4. In-circuit S31 verifier | One pinned `S31NAT*` profile and verification-key policy | Valid native/circuit parity; malformed proof, key, profile, transcript, FRI and statement mutations all reject. |
| 5. Recursive fold | Base and step wrappers; proof of a proof of a step | Two- and many-step folds; fixed-size outer statement/proof; checkpoint and fork-policy tests. |

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
