# Byte-exact Bitcoin header hashing and proof of work

This chapter follows one 80-byte header through S31 source, circuit wires,
generic AIR rows, and the native verifier. The checked-in assignment is the
Bitcoin genesis header. Its four important byte ranges are:

| Serialized byte offsets | Value in the assignment | Meaning |
| --- | --- | --- |
| 0–3 | `01 00 00 00` | Version 1, encoded little endian. |
| 4–35 | 32 zero bytes | Previous block hash. |
| 36–67 | `3b a3 ed fd … 4b 1e 5e 4a` | Merkle root bytes in the serialized header. |
| 68–71 | `29 ab 5f 49` | Timestamp bytes. |
| 72–75 | `ff ff 00 1d` | Compact target `0x1d00ffff`. |
| 76–79 | `1d ac 2b 7c` | Nonce bytes. |

`Bytes80` is forty little-endian `u16` limbs. For example, the first two
header bytes `01 00` become limb zero `1`; the `nBits` bytes become limbs
36 and 37, `65535` and `7424`. Each limb is range checked. The exact source is
[`bitcoin_header_pow.s31`](../examples/bitcoin_header_pow.s31):

```s31
use std@1;

circuit bitcoin_header_pow(private header: Bytes80) -> public Digest<Poseidon2> {
    let hash_bytes = std::hash::sha256d_header(header);
    let hash_number = std::bytes::to_u256_le(hash_bytes);
    let target = std::bitcoin::target_mainnet(header);
    let within_target = std::math::le_u256(hash_number, target);
    assert_eq(within_target, splat<1>(1_m31));

    let hash_limbs = std::bytes::limbs_m31(hash_bytes);
    let root = std::hash::poseidon2_leaf(hash_limbs);
    root
}
```

For assignment tooling, `s31_stdlib.decode_header80(raw_bytes)` produces the
forty limbs from an 80-byte buffer; `encode_header80(limbs)` reverses that
conversion and rejects noncanonical limbs.

The `sha256d_header` and `target_mainnet` calls each become one relation node.
The `to_u256_le` call changes the nominal type and adds no gate. The comparison
becomes `u256_le`, and `assert_eq` forces its result to one. The Poseidon2 call
commits the digest to the eight-word public ABI. It is an auxiliary S31
commitment, not a Bitcoin block hash.

## The three SHA-256 compression blocks

SHA256d means `SHA256(SHA256(header))`. An 80-byte first message spans two
64-byte compression blocks; its 32-byte digest spans one more block:

| Compression | First message bytes | Fixed padding and length | Output |
| --- | --- | --- | --- |
| 1 | Header bytes 0–63 | None in this block. | Intermediate eight-word state. |
| 2 | Header bytes 64–79 | `80`, zeroes, then 64-bit big-endian `640`. | First SHA-256 digest. |
| 3 | The 32 digest bytes | `80`, zeroes, then 64-bit big-endian `256`. | Double-SHA digest. |

SHA-256 reads each four-byte message word in **big-endian** order. The first
four serialized bytes `01 00 00 00` become SHA word `0x01000000`. S31 swaps
the constrained input bits into that order. The final eight SHA state words
are written back as big-endian bytes, then repacked as little-endian `u16`
limbs. For this header, the raw digest bytes begin `6f e2 8c 0a`; the familiar
displayed block hash reverses all 32 bytes and is
`000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`.

No witness chooses a block count, padding byte, or length. They are fixed by
the `Bytes80` operation. Each of the 192 compression rounds is constrained.

## A few circuit equations by hand

Every dynamic SHA word has two `u16` limbs and, when a bit operation needs it,
32 Boolean bits. If the low limb is `L`, its decomposition proves

$$
b_i(b_i-1)=0\quad(0\le i<16),\qquad
L=\sum_{i=0}^{15}2^i b_i.
$$

For two 32-bit words `a` and `b`, modular addition uses two checked carry
equations. With base $B=65536$:

$$
a_{lo}+b_{lo}=r_{lo}+Bc_{lo},\qquad
a_{hi}+b_{hi}+c_{lo}=r_{hi}+Bc_{hi},
$$

where each result limb is `u16` and each carry is Boolean. The last carry is
discarded, giving addition modulo $2^{32}$. The word-level SHA operations
are assembled from bits: a rotate rewires bit positions;
`XOR(x,y)=x+y-2xy`; `Ch(e,f,g)=g+e(f-g)`; and
`Maj(a,b,c)=ab+c(a\operatorname{XOR}b)`. These identities agree with the
Boolean truth tables when the inputs are bits. Message schedule words, round
state words, and the final digest are connected by these same gates.

The generic circuit AIR proves each gate result and address lookup across a
fixed row trace. The SHA operation is currently **unrolled into that circuit**;
there is no separate SHA AIR chip. The proof commits the relevant trace
columns, and the native verifier checks the pinned AIR, public values, lookup
closure, and FRI queries. The `equations` command shows semantic formulas and
gate counts; it does not print every physical AIR polynomial.

## Compact target and the inequality

The header has `nBits = 0x1d00ffff`. Its top byte is exponent 29 and its
lower 23 bits are mantissa `0x00ffff`, so the mainnet target is
$65535\cdot 2^{208}$. In the circuit, header limbs 36 and 37 are decomposed
into bytes. Thirty-two Boolean selectors encode legal exponents 1 through 32:

$$
\sum_{e=1}^{32}s_e=1,\qquad
\sum_{e=1}^{32}e s_e=\mathrm{exponent}.
$$

Each target byte is a selected, shifted mantissa byte. Exponents below three
drop low-order mantissa bytes, as Bitcoin's compact decoding does. The sign
bit must be zero, the resulting target must be nonzero, and target bytes
28–31 must vanish. For this compact encoding, that last rule enforces the
mainnet `powLimit`: at exponent 29, bytes 26–27 can only reach `ff ff` with
all lower bytes zero; exponent 28 has top byte at most `7f`, and exponent 30
can only put one byte at offset 27. A sixteen-limb borrow
chain then proves the double-SHA digest, interpreted as a little-endian
integer, is at most that target. The final assertion requires the comparison
bit to equal one. Bitcoin Core's [compact decoder](https://github.com/bitcoin/bitcoin/blob/master/src/arith_uint256.cpp#L164-L181)
and [proof-of-work check](https://github.com/bitcoin/bitcoin/blob/master/src/pow.cpp#L131-L154)
are the reference semantics for this operation.

## Run and interpret the proof

```sh
python3 src/frontends/s31/s31.py trial \
  src/frontends/s31/examples/bitcoin_header_pow.s31 \
  src/frontends/s31/examples/bitcoin_header_hash.valid.json \
  --lowering sparse-wide-gate \
  --out zig-out/s31/bitcoin-header-pow-trial
```

The independent Python oracle uses `hashlib.sha256` on the 80 raw bytes,
decodes `nBits` with Python integers, and checks the claim before proving.
For the genesis assignment, the public Poseidon2 root is
`[93892305,397617766,1762064199,2128125525,211345822,958247097,595994426,1074837273]`.
The generated native verifier accepted the proof and rejected a changed root.

In one local `sparse-wide-gate` run, the complete program used 356,882 raw
QM31 arithmetic rows, 4,757 equality rows, and 3,664 conversion rows. The
proof was 338,687 bytes; proving took 0.335 seconds and verification 0.421
seconds. These are single measurements, including stochastic proof of work.
The [hash-only program](../examples/bitcoin_header_hash.s31) used 356,268
arithmetic rows in a separate run, so compact-target decoding and comparison
added 614 arithmetic rows. The [measurement record](../../../../design/s31/measurements/bitcoin-header-sha256d-v1-2026-10-06.json)
contains both verified trials. A dedicated SHA chip is the next major cost target.

## Two actual headers in one proof

[`bitcoin_header_pair_typed.s31`](../examples/bitcoin_header_pair_typed.s31) proves a
non-retarget step from Bitcoin mainnet genesis to block one. Its assignment
contains both real serialized headers. The child's serialized bytes 4–35 are
`6f e2 8c 0a … 00 00 00 00` in *raw digest order*: they equal the
32 output bytes of `SHA256d(parent)`. The displayed parent block ID reverses
those bytes. Both headers contain `ff ff 00 1d` at byte offsets 72–75.

```s31
use std@1;

circuit bitcoin_header_pair(private parent: Bytes80, private child: Bytes80)
    -> public Digest<Poseidon2> {
    let parent_hash = std::bitcoin::block_hash(parent);
    let child_hash = std::bitcoin::block_hash(child);
    assert_eq(parent_hash, std::bitcoin::genesis_block_hash_mainnet());
    assert_eq(std::bitcoin::parent_hash(child), parent_hash);
    assert_eq(std::bitcoin::header_bits(child), std::bitcoin::header_bits(parent));
    let later_time = std::math::lt_u32(std::bitcoin::header_time(parent), std::bitcoin::header_time(child));
    assert_eq(later_time, splat<1>(1_m31));
    let parent_target = std::bitcoin::target_mainnet(parent);
    let child_target = std::bitcoin::target_mainnet(child);
    let parent_pow = std::math::le_u256(std::bytes::to_u256_le(std::bitcoin::hash_bytes(parent_hash)), parent_target);
    let child_pow = std::math::le_u256(std::bytes::to_u256_le(std::bitcoin::hash_bytes(child_hash)), child_target);
    assert_eq(parent_pow, splat<1>(1_m31));
    assert_eq(child_pow, splat<1>(1_m31));
    let parent_root = std::hash::poseidon2_leaf(std::bytes::limbs_m31(std::bitcoin::hash_bytes(parent_hash)));
    let child_root = std::hash::poseidon2_leaf(std::bytes::limbs_m31(std::bitcoin::hash_bytes(child_hash)));
    let segment_root = std::hash::poseidon2_pair(parent_root, child_root);
    segment_root
}
```

`BlockHash` is a source type for the sixteen raw SHA256d byte-pair limbs.
`block_hash(parent)` emits the same byte-exact SHA circuit as
`sha256d_header(parent)`; `hash_bytes` only changes the source view so the
existing byte and unsigned-integer operations can consume it. Neither view
adds gates. A standalone `BlockHash` input is a claim until a relation links it
to a computed header digest or trusted checkpoint. This typed source and the
[earlier untyped source](../examples/bitcoin_header_pair.s31) lower to
byte-identical normalized relations and have the same AIR and verifier key.

The fixed `genesis_block_hash_mainnet()` value is the raw byte order of mainnet's
genesis digest, with its displayed value pinned in
[Bitcoin Core's mainnet parameters](https://github.com/bitcoin/bitcoin/blob/master/src/kernel/chainparams.cpp#L145-L149).
The first assertion pins the private parent's computed digest
to that network checkpoint. It adds no witness-controlled input. For this
source, `prev_hash(child)` is a view of the already constrained
`child` limbs 2–17. `header_bits(child)` is a view of limbs 36–37, and
`header_time` views limbs 34–35. For the genesis-to-block-one transition,
the previous median-time-past is the genesis timestamp, so the strict
`lt_u32` assertion proves the child's timestamp is later. Its two borrow
digits and two Boolean borrows are constrained in M31; the initial borrow
is one, making equal timestamps fail. For the actual headers, the parent time
is `1231006505 = (43817, 18783)` and the child time is
`1231469665 = (48225, 18790)` in little-endian `u16` limbs. The circuit
uses `child[i] + 65536·borrow[i+1] = parent[i] + borrow[i] + digit[i]`:

| Limb `i` | Parent | Child | Incoming borrow | Digit | Outgoing borrow |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 43817 | 48225 | 1 | 4407 | 0 |
| 1 | 18783 | 18790 | 0 | 7 | 0 |

The result is `1 - borrow[2] = 1`. If the timestamps were equal, the
initial borrow would propagate through both limbs, and the result would be
zero. The
assertions compare these same circuit wires with the SHA output wires and
the parent's bits wires; the views introduce no new witness values. In the
actual profile, each equality is packed into Eq component rows. Two SHA256d
calls contribute six fixed compression blocks, and two target checks each
prove a 256-bit inequality. The public value is a Poseidon2 commitment to
the two hashes in their specified order. A relying party must still check the
expected public root to identify a particular child header or chain segment.

```sh
python3 src/frontends/s31/s31.py trial \
  src/frontends/s31/examples/bitcoin_header_pair_typed.s31 \
  src/frontends/s31/examples/bitcoin_header_pair.valid.json \
  --lowering sparse-wide-gate \
  --out zig-out/s31/bitcoin-header-pair-trial
```

The current source passed an end-to-end proof and native verification trial,
including rejection of a changed public root. It used 714,614 raw QM31 rows,
9,528 Eq rows, and 7,322 conversion rows; the QM31 trace still pads to
1,048,576 rows. Its proof was 372,904 bytes. In this one run, prove took
0.517 s and verify 0.486 s, with 0.097 s of prover FRI proof of work.
The [current trial record](../../../../design/s31/measurements/bitcoin-header-pair-time-v1-2026-10-06.json)
pins source, proof and profile hashes. The
[earlier record](../../../../design/s31/measurements/bitcoin-header-pair-v1-2026-10-06.json)
without the timestamp check used 714,595 raw QM31 rows; timings and proof
bytes from the two runs should not be read as a speed comparison.

This program fixes the bits of adjacent headers equal, so it applies only
inside a difficulty interval, matching Bitcoin Core's
[ordinary mainnet step rule](https://github.com/bitcoin/bitcoin/blob/master/src/pow.cpp#L12-L43).
It enforces the strict timestamp rule only for this first transition, where
Bitcoin Core's [median-time-past rule](https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp#L4088-L4102)
compares the child against the sole previous timestamp. It does not enforce
retargeting, general eleven-block median time past, the contextual future-time
limit, version policy, height, accumulated chainwork, best-chain selection,
or recursive header-chain state transitions. The
[sparse-wide recursion wrapper](recursion-sparse-wide.md) can verify this
proof profile inside an outer circuit, but it does not supply the missing
consensus state transition. The genesis hash is an explicit checkpoint. The
[light-client brief](../../../../design/s31/BITCOIN_LIGHT_CLIENT.md) tracks
those separate relations.

## One fresh header per transition proof

The [header-link program](../examples/bitcoin_header_link.s31) is the smaller
leaf needed by a changing-header fold. It takes the previous block hash as a
private, nominal `BlockHash` opening and hashes only the **new** 80-byte
header. Here is the complete source:

```s31
use std@1;

circuit bitcoin_header_link(
    private prior_hash: BlockHash,
    private child: Bytes80
) -> public Digest<Poseidon2> {
    let child_hash = std::bitcoin::block_hash(child);
    assert_eq(std::bitcoin::parent_hash(child), prior_hash);

    let target = std::bitcoin::target_mainnet(child);
    let pow_ok = std::math::le_u256(
        std::bytes::to_u256_le(std::bitcoin::hash_bytes(child_hash)), target
    );
    assert_eq(pow_ok, splat<1>(1_m31));

    let old_root = std::hash::poseidon2_leaf(std::bytes::limbs_m31(std::bitcoin::hash_bytes(prior_hash)));
    let new_root = std::hash::poseidon2_leaf(std::bytes::limbs_m31(std::bitcoin::hash_bytes(child_hash)));
    let link_root = std::hash::poseidon2_pair(old_root, new_root);
    link_root
}
```

The `parent_hash(child)` view reads the child's byte pairs 2–17. Sixteen
equalities enforce `child[i+2] - prior_hash[i] = 0` for `i=0..15`; both sides
are canonical `u16` values. The SHA256d node constrains the three compression
blocks of the child header. Target decoding and the 256-bit comparison then
constrain `SHA256d(child) <= target(child.nBits)`. The output is
`Poseidon2_pair(Poseidon2_leaf(prior_hash limbs), Poseidon2_leaf(child_hash limbs))`,
so it commits to the *ordered* old/new hash pair. In the checked
genesis-to-block-one fixture, the `prior_hash` limbs begin
`[57967, 2700, 61878, 29363]`, and the public pair root begins
`[928491885, 399009276, 910063533, 515587455]`. It equals the root of the
two-header program above, but this program performs only one SHA256d.

This leaf proves linkage and the child's PoW under its encoded mainnet target.
It does **not** prove the private `prior_hash` belongs to an accepted parent.
A recursive fold must authenticate its prior-state opening and check that it
equals the old hash committed by this leaf **inside the fold circuit**. The
leaf also omits retargeting, general median-time-past, height, accumulated
work, and best-chain selection. Its pair root cannot be interpreted as an
accepted chain tip until those checks and the state binding are added.

```sh
python3 src/frontends/s31/acceptance_header_link.py
```

This acceptance command derives the two hashes with independent `hashlib`
SHA256d, checks the pair with the independent Poseidon2 oracle, proves the
link, verifies it with the generated native verifier, and rejects a forged
predecessor and a changed public root. It then proves verification of that
leaf inside the sparse-wide recursive circuit, natively verifies the outer
proof, and rejects a changed authenticated child statement. That wrapper
authenticates one transition leaf; it does not yet join it to a previous fold.

With `sparse-wide-gate` and FRI fold step 4, this leaf used 365,487 raw QM31
arithmetic rows, padded to 524,288, and emitted a 236,523-byte proof in one
local run. The typed two-header fixture has the same relation as the earlier
714,614-row program and emitted a 266,285-byte proof under those settings.
Removing the redundant parent SHA therefore cut raw arithmetic rows by
48.9% and proof bytes by 11.2% in these matched configurations. The one-level
recursive proof was 354,417 bytes. These counts do not establish a
proving-time speedup; that needs repeated timed trials.

The recursive verifier carries each public claim word as a packed `u32`:
`(low_u16, high_u16, 0, 0)` in QM31. Poseidon2 uses one canonical M31 value
per word. The two encodings are distinct circuit wires. For the first link
root word, `928491885 = 43373 + 65536·14167`. The
[`bindCanonicalM31Output`](../recursive_public_words.zig) gadget witnesses
the M31 value, constrains it as a base-field element, decomposes it back to
the packed `u32`, and equates that result to the word authenticated by the
child proof. The circuit test also rejects the packed word
`p = 2147483647`: it is a valid `u32` but has no equal canonical M31
representation. The same test composes this boundary with the
[`constrainLinkedState`](../poseidon2.zig) circuit equalities and rejects a
changed prior-state root. These gates are available for a two-proof fold;
the current one-level wrapper does not yet invoke them.

The faster fold candidate computes the new header inside the fold circuit
after verifying only the prior recursive proof. The
[`constrainMainnetPowLinkStep`](../bitcoin_fold_step.zig) kernel consumes a
trusted old hash root and private old-hash/header limbs. For the same fixture,
it checks `child[2] = prior_hash[0] = 57967` (and the next fifteen limb
equalities), recomputes SHA256d and the target comparison, and yields the new
hash root `[1230097977, 338045265, 582454319, 1194138423, …]`.
The trusted old root begins `[93892305, 397617766, …]`; changing it makes
the circuit unsatisfied. A value-bearing and witness-free circuit produce
identical gate lists in the Zig test.

```sh
zig build --build-file src/frontends/s31/build.zig inspect-bitcoin-fold-step -Doptimize=ReleaseSafe -j2
```

That inspector reports 366,721 raw variables and 363,049 QM31 arithmetic
rows for the header-step kernel alone. The recorded Bitcoin claim fold has 259,481
spare QM31 rows, so adding the kernel is expected to cross one padding
boundary. This is a circuit cost estimate, not a completed recursive header
proof or a timed proving comparison. The
[measurement record](../../../../design/s31/measurements/bitcoin-direct-fold-step-v1-2026-10-07.json)
pins the inspector command, source hashes, exact gate counts, and additive
padding estimate.

The proposed fold output uses a fixed 100-byte BLAKE2s preimage with the
`S31BFD1!` domain: `fold_AIR_root[32] || LE32(step) ||
LE32(checkpoint_root[0..8]) || LE32(current_root[0..8])`.
[`bitcoin_fold_digest.zig`](../bitcoin_fold_digest.zig) computes it both on the
host and with circuit gates. Each root word must be canonical M31 before
four-byte encoding; raw digest bytes cannot be reduced into the field. The
test checks that changing the checkpoint, current root, AIR root, or tested
high-counter values changes the output.

The [candidate chain-fold circuit](../bitcoin_chain_fold.zig) connects the
pieces. Let `G = Poseidon2_leaf(genesis_hash)` be the trusted checkpoint,
`H1` the hash of block 1, and `R1 = Poseidon2_leaf(H1)`:

```text
step 0: base proof publicly says G
        witnessed old hash = genesis_hash; new header = block 1
        circuit checks Poseidon2_leaf(old hash) = G
        circuit checks header.prev_hash = old hash, SHA256d, target and PoW
        public output D0 = BLAKE2s_S31BFD1!(fold_root || 0 || G || R1)

step 1: verified child fold proof publicly says D0
        witnessed previous root = R1; new header = block 2
        circuit checks child output = BLAKE2s_S31BFD1!(fold_root || 0 || G || R1)
        circuit checks block 2 extends the witnessed H1 and satisfies PoW
        public output D1 = BLAKE2s_S31BFD1!(fold_root || 1 || G || R2)
```

The base selector and `u32` predecessor relation are circuit constraints.
The branch test checks steps `0`, `1`, and `65536`; changing the witnessed
previous root makes the selected claim unsatisfied. The full candidate
topology is inspectable with:

```sh
zig build --build-file src/frontends/s31/build.zig inspect-bitcoin-chain-fold -Doptimize=ReleaseSafe -j2
python3 src/frontends/s31/record_bitcoin_chain_fold.py
```

The [record](../../../../design/s31/measurements/bitcoin-chain-fold-topology-v1-2026-10-07.json)
shows 5,956,015 raw variables, 1,151,865 raw QM31 rows, and 2,097,152
padded QM31 rows for a representative nonzero base root. Eq needs 33,131
raw rows and pads to 65,536. The candidate child layout reproduces all five
padded component sizes, with one preprocessed root at steps `0`, `1`,
`65536`, and `0xffffffff`; changing the checkpoint or base root changes the
preprocessed root. This establishes a reusable AIR layout. A base proof,
sealed verifier key, Bitcoin chain-fold proof, and timed proving comparison
remain pending.

## Dedicated SHA AIR boundary under construction

[`sha_chip_plan.zig`](../sha_chip_plan.zig) now constructs the exact three
`(state, 64-byte block, output state)` calls for one header and checks every
byte of the proposed chip boundary. It checks the fixed `0x80` padding,
big-endian bit lengths `640` and `256`, the first-pass chaining state, the
second-pass initial state, and the final raw digest bytes. Randomized tests
compare the result with Zig's independent SHA256 implementation and corrupt
each boundary. This is witness preparation and a native boundary check; the
current proof still uses the generic circuit AIR.

To replace the generic SHA circuit soundly, the SHA source, schedule, round,
feed-forward and boundary components must join the S31 component roster in
one STARK proof. For each call, the S31 circuit must emit an authenticated
lookup for its exact input state, 64 input bytes and output state. The chip
must consume the opposite lookup, including a call ID and operation domain.
The verifier must require lookup-sum closure, reconstruct the fixed six-call
geometry for this pair, and bind that manifest and public statement before
the first commitment. The chip's three internal calls per header must obey
the exact boundary equations above. The existing standalone SHA compression
proof uses trusted public boundary data; it cannot directly authenticate a
private S31 header. No `--lowering` option selects this chip yet.

Verifier acceptance establishes that **some** private 80-byte header has a
byte-exact double-SHA digest that meets the mainnet target encoded in that
header and commits to the public root. A relying party must bind that root to
the header or hash it cares about. This program does not prove that the header
belongs to the best chain, that the previous hash links to an accepted parent,
that a block's transactions match the Merkle root, or that difficulty and
timestamp rules hold across headers. Recursive verification and a full light
client require those separate relations.
