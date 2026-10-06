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

[`bitcoin_header_pair.s31`](../examples/bitcoin_header_pair.s31) proves a
non-retarget step from Bitcoin mainnet genesis to block one. Its assignment
contains both real serialized headers. The child's serialized bytes 4–35 are
`6f e2 8c 0a … 00 00 00 00` in *raw digest order*: they equal the
32 output bytes of `SHA256d(parent)`. The displayed parent block ID reverses
those bytes. Both headers contain `ff ff 00 1d` at byte offsets 72–75.

```s31
use std@1;

circuit bitcoin_header_pair(private parent: Bytes80, private child: Bytes80)
    -> public Digest<Poseidon2> {
    let parent_hash = std::hash::sha256d_header(parent);
    let child_hash = std::hash::sha256d_header(child);
    assert_eq(parent_hash, std::bitcoin::genesis_hash_mainnet());
    assert_eq(std::bitcoin::prev_hash(child), parent_hash);
    assert_eq(std::bitcoin::header_bits(child), std::bitcoin::header_bits(parent));
    let parent_target = std::bitcoin::target_mainnet(parent);
    let child_target = std::bitcoin::target_mainnet(child);
    let parent_pow = std::math::le_u256(std::bytes::to_u256_le(parent_hash), parent_target);
    let child_pow = std::math::le_u256(std::bytes::to_u256_le(child_hash), child_target);
    assert_eq(parent_pow, splat<1>(1_m31));
    assert_eq(child_pow, splat<1>(1_m31));
    let parent_root = std::hash::poseidon2_leaf(std::bytes::limbs_m31(parent_hash));
    let child_root = std::hash::poseidon2_leaf(std::bytes::limbs_m31(child_hash));
    let segment_root = std::hash::poseidon2_pair(parent_root, child_root);
    segment_root
}
```

The fixed `genesis_hash_mainnet()` value is the raw byte order of mainnet's
genesis digest, with its displayed value pinned in
[Bitcoin Core's mainnet parameters](https://github.com/bitcoin/bitcoin/blob/master/src/kernel/chainparams.cpp#L145-L149).
The first assertion pins the private parent's computed digest
to that network checkpoint. It adds no witness-controlled input. For this
source, `prev_hash(child)` is a view of the already constrained
`child` limbs 2–17. `header_bits(child)` is a view of limbs 36–37. The
assertions compare these same circuit wires with the SHA output wires and
the parent's bits wires; the views introduce no new witness values. In the
actual profile, each equality is packed into Eq component rows. Two SHA256d
calls contribute six fixed compression blocks, and two target checks each
prove a 256-bit inequality. The public value is a Poseidon2 commitment to
the two hashes in their specified order. A relying party must still check the
expected public root to identify a particular child header or chain segment.

```sh
python3 src/frontends/s31/s31.py trial \
  src/frontends/s31/examples/bitcoin_header_pair.s31 \
  src/frontends/s31/examples/bitcoin_header_pair.valid.json \
  --lowering sparse-wide-gate \
  --out zig-out/s31/bitcoin-header-pair-trial
```

One local trial accepted the real pair and rejected a changed public root.
It used 714,595 raw QM31 rows, 9,523 Eq rows, and 7,320 conversion rows;
the proof was 379,136 bytes. Proving took 0.702 s and native verification
0.474 s in that run; 0.280 s of proving was a variable FRI nonce search.
The raw SHA arithmetic is nearly twice the single-header
cost; the QM31 trace pads to 1,048,576 rows. These are single stochastic-PoW
observations. The [trial record](../../../../design/s31/measurements/bitcoin-header-pair-v1-2026-10-06.json)
pins the source and proof digests.

This program fixes the bits of adjacent headers equal, so it applies only
inside a difficulty interval, matching Bitcoin Core's
[ordinary mainnet step rule](https://github.com/bitcoin/bitcoin/blob/master/src/pow.cpp#L12-L43).
It does not enforce retargeting, timestamps,
median time past, version policy, height, accumulated chainwork, a trusted
checkpoint, best-chain selection, or recursive verification. The
[light-client brief](../../../../design/s31/BITCOIN_LIGHT_CLIENT.md) tracks
those separate relations.

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
