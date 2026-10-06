# Thirty-two bytes and 256-bit arithmetic

Bitcoin makes byte order, 256-bit integers, and exact hash bytes unavoidable.
S31 has three distinct byte and integer source types:

| Source type | Meaning | Erased relation shape |
| --- | --- | --- |
| `Bytes32` | Exactly 32 uninterpreted bytes | `u16[16]` |
| `UInt256` | Unsigned integer in $0\ldots 2^{256}-1$ | `u16[16]` |
| `Bytes80` | Exactly 80 serialized Bitcoin header bytes | `u16[40]` |

For raw bytes $b_0,\ldots,b_{31}$, limb $L_i=b_{2i}+2^8b_{2i+1}$, and the
integer interpretation is $\sum_{i=0}^{15}L_i2^{16i}$. The conversion
`std::bytes::to_u256_le` changes the source type without introducing an AIR
row. It explicitly chooses little-endian interpretation; a display-order
Bitcoin hash should be reversed **before** being supplied as `Bytes32`.
Bitcoin's [block-header reference](https://developer.bitcoin.org/reference/block_chain.html#block-headers)
distinguishes internal hash byte order from human display order.

Each limb is checked by S31's existing `u16` range component. Therefore
the 16-limb encoding is injective over exactly 32 bytes. `std::bytes::limbs_m31`
is an explicit typed cast for using those already constrained limbs as M31
values in a field-native commitment; it does not hash them or change their
byte order. `UInt256` and `Bytes32` are nominal types: a `Bytes32` value cannot
accidentally enter integer addition or comparison.

## A carry and a comparison by hand

This program starts with $H=2^{255}+65535$ and adds one. The first two
little-endian limbs carry from `(65535,0)` to `(0,1)`; limb 15 stays `32768`.
Thus $T=H+1=2^{255}+65536$, and $H\le T$.

| Limb index | $H_i$ | Increment | Incoming carry | $T_i$ | Outgoing carry |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 65535 | 1 | 0 | 0 | 1 |
| 1 | 0 | 0 | 1 | 1 | 0 |
| 2–14 | 0 | 0 | 0 | 0 | 0 |
| 15 | 32768 | 0 | 0 | 32768 | 0 |

For each addition limb, the circuit proves

$$
H_i+I_i+c_i=T_i+65536c_{i+1},\qquad
0\le T_i<65536,\quad c_i\in\{0,1\},\quad c_0=0.
$$

The final carry is discarded, so `add_u256` is addition modulo $2^{256}$.
`std::math::add_u256_checked` uses the same sixteen equations and also proves
$c_{16}=0$; a witness with an overflow cannot satisfy that circuit. For an
accumulator, write the operation explicitly:

```s31
fn advance_work(work: UInt256, delta: UInt256) -> UInt256 {
    std::math::add_u256_checked(work, delta)
}
```

For `le_u256(H,T)`, the compiler separately subtracts each limb with a
Boolean borrow:

$$
T_i+65536q_{i+1}=H_i+q_i+d_i,\qquad
0\le d_i<65536,\quad q_i\in\{0,1\},\quad q_0=0.
$$

The result bit is $1-q_{16}$. For these values, limb 0 borrows once,
limb 1 repays the borrow, and $q_{16}=0$, so the result is one. Every
integer equation fits well inside the M31 modulus $2^{31}-1$; equality
in the field therefore cannot hide a different integer carry. The generic
circuit AIR proves the gates, the `u16` range lookups, Boolean carry gates,
and wire reuse. The displayed equations are the **semantic projection** of
that AIR, not a complete dump of its fixed opcode and LogUp columns.

## A complete S31 program

```s31
use std@1;

// The 32 bytes and unsigned integer share sixteen little-endian u16 limbs.
// The public root is an auxiliary S31 commitment, not a Bitcoin block hash.
circuit wide_order(
    private digest_bytes: Bytes32,
    private increment: UInt256,
    private target: UInt256
) -> public Digest<Poseidon2> {
    let digest_number = std::bytes::to_u256_le(digest_bytes);
    let computed_target = std::math::add_u256(digest_number, increment);
    assert_eq(computed_target, target);

    let within_target = std::math::le_u256(digest_number, target);
    assert_eq(within_target, splat<1>(1_m31));

    let digest_limbs = std::bytes::limbs_m31(digest_bytes);
    let increment_limbs = std::bytes::limbs_m31(increment);
    let digest_commitment = std::hash::poseidon2_leaf(digest_limbs);
    let increment_commitment = std::hash::poseidon2_leaf(increment_limbs);
    let root = std::hash::poseidon2_pair(digest_commitment, increment_commitment);
    root
}
```

The checked assignment has `digest_bytes=[65535,0,…,0,32768]`,
`increment=[1,0,…,0]`, and `target=[0,1,0,…,0,32768]`. Its eight-word public
root is
`[1516562408,720678098,331586352,1266462312,857462184,360942592,889867968,271788129]`.
The [full assignment](../examples/wide_order.valid.json) and [exact normalized
relation](../examples/wide_order.s31.json) are checked against this page.

For a trusted program/key and this public root, verifier acceptance means
that **some** private digest bytes and increment commit to that root through
the pinned S31 Poseidon2 construction, and their 256-bit sum modulo $2^{256}$
equals `target`. The shown assignment does not wrap. Use
`std::math::add_u256_checked` when the circuit must reject overflow. The sum
and comparison are both constrained. The root is
an auxiliary commitment. A verifier that knows the intended 32-byte digest
and increment can calculate the same root outside the proof. This prototype
has not established the security of Poseidon2 as a production Bitcoin bridge
commitment.

```sh
python3 src/frontends/s31/s31.py oracle src/frontends/s31/examples/wide_order.s31 src/frontends/s31/examples/wide_order.valid.json
python3 src/frontends/s31/s31.py trial src/frontends/s31/examples/wide_order.s31 src/frontends/s31/examples/wide_order.valid.json --lowering sparse-wide-gate --out zig-out/s31/wide-order-trial
```

`sparse-wide-gate` keeps the equality, QM31 arithmetic, M31-to-`u32`, and
`u16` range AIRs needed by this program. Its 14 fixed columns contain 328,320
cells for this example, versus 4,507,264 cells in `gate`. In a single local
run, the native proof was 238,047 bytes and proving took 0.433 s, versus
427,557 bytes and 1.688 s for `gate`. Both native verifiers accepted the
correct statement and rejected a changed public root. These timing samples
include proof of work and are not a throughput estimate; the evidence is in
[`design/s31/measurements/bitcoin-wide-sparse-v5-2026-10-06.json`](../../../../design/s31/measurements/bitcoin-wide-sparse-v5-2026-10-06.json).

## Boundary for a Bitcoin proof

This **wide arithmetic** example takes digest bytes as an independent private
input, so it does not itself prove Bitcoin proof of work. The newer
[Bitcoin header walkthrough](bitcoin-sha256d.md) starts from `Bytes80`,
constrains both SHA-256 passes, decodes the header's compact target, and checks
the resulting hash inequality. The current public ABI has eight M31 words,
fewer than the sixteen `u16` slots needed to reveal the 32-byte hash directly;
that example publishes an auxiliary Poseidon2 commitment. A dedicated SHA chip,
header-chain rules, and an S31 verifier inside a circuit remain future work for
an efficient recursive Bitcoin light client. A two-level verifier wrapper
for this proof profile is now available; see
[sparse-wide recursion](recursion-sparse-wide.md). A repeatable
header-chain fold and proof-bound SHA chip remain to be built.
