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

## Subtraction and underflow by hand

`sub_u256(A,B)` computes $(A-B)\bmod 2^{256}$; `sub_u256_checked(A,B)`
also proves $A\ge B$. Both use sixteen little-endian, range-checked output
limbs $D_i$ and Boolean borrow bits $b_i$:

$$
A_i+65536b_{i+1}=B_i+b_i+D_i,\qquad
0\le D_i<65536,\quad b_i\in\{0,1\},\quad b_0=0.
$$

The checked variant requires $b_{16}=0$. The wrapping variant discards that
final bit. Here $A=2^{128}+7$ and $B=2^{128}-1$, so $D=8$. The borrow passes
through eight limbs before limb 8 repays it:

| Limb | $A_i$ | $B_i$ | Incoming $b_i$ | Difference $D_i$ | Outgoing $b_{i+1}$ |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 7 | 65535 | 0 | 8 | 1 |
| 1–7 | 0 | 65535 | 1 | 0 | 1 |
| 8 | 1 | 0 | 1 | 0 | 0 |
| 9–15 | 0 | 0 | 0 | 0 | 0 |

Each equation stays below the M31 modulus, so a field equality cannot
conceal an integer borrow. The [source](../examples/wide/u256_sub_checked.s31)
and [assignment](../examples/wide/u256_sub_checked.valid.json) commit the
resulting sixteen limbs with a Poseidon2 leaf and expose its eight-word root:

```s31
use std@1;

circuit u256_sub_checked(
    private total: UInt256,
    private previous: UInt256
) -> public Digest<Poseidon2> {
    let delta = std::math::sub_u256_checked(total, previous);
    let limbs = std::bytes::limbs_m31(delta);
    let root = std::hash::poseidon2_leaf(limbs);
    root
}
```

The independent oracle computes root
`[552785778,528026874,1337939194,1238002988,529560134,669980742,1274389821,1249346016]`.
The verifier proves a valid checked subtraction and this exact root; it
does not reveal either private operand. A false final borrow makes the
checked circuit unsatisfiable, including when the wrapping difference
would otherwise be a valid `UInt256`.

The companion [wrapping source](../examples/wide/u256_sub_wrap.s31) proves
$0-1=2^{256}-1$; its [assignment](../examples/wide/u256_sub_wrap.valid.json)
has sixteen `65535` difference limbs. Reproduce both native proofs and the
negative checks with:

```sh
python3 src/frontends/s31/python/s31.py trial src/frontends/s31/examples/wide/u256_sub_checked.s31 src/frontends/s31/examples/wide/u256_sub_checked.valid.json --lowering sparse-wide-gate --out zig-out/s31/u256-sub-checked-trial
python3 src/frontends/s31/python/s31.py trial src/frontends/s31/examples/wide/u256_sub_wrap.s31 src/frontends/s31/examples/wide/u256_sub_wrap.valid.json --lowering sparse-wide-gate --out zig-out/s31/u256-sub-wrap-trial
python3 src/frontends/s31/tests/acceptance/acceptance_u256_sub.py
```

The [one-run record](../../../../design/s31/measurements/language/u256-subtraction-v1-2026-10-07.json)
reports 231,674 bytes for the checked proof and 238,493 for wrapping. They
use 7,744 and 7,743 raw QM31 rows, respectively, including the Poseidon2
leaf. Both pad to 32 Eq rows: checked subtraction constrains its final
borrow with an arithmetic zero assertion, so it does not double the Eq
component's padded length. The acceptance run
rejects checked underflow and cross-key proof replay even when both proofs
carry the same valid public root; it also rejects changed public roots and
damaged proof bytes. These are local proof samples; the different final
borrow constraint changes the AIR key, and stochastic proof of work prevents
inferring a stable timing difference from these runs.

## Order and choose a 256-bit value by hand

The [ordering program](../examples/wide/u256_order_select.s31) compares two private
integers, selects their minimum and maximum, and commits to the checked
difference. Its [assignment](../examples/wide/u256_order_select.valid.json) uses
$A=2^{128}-1$ and $B=2^{128}+7$. The table shows why their order is clear
even though limb zero of $B$ is smaller:

| Little-endian limb | $A_i$ | $B_i$ | Meaning |
| ---: | ---: | ---: | --- |
| 0 | 65535 | 7 | The low limb alone does not decide the order. |
| 1–7 | 65535 | 0 | Borrow propagates across these limbs. |
| 8 | 0 | 1 | This higher limb determines $A<B$. |
| 9–15 | 0 | 0 | Equal high limbs. |

`le_u256(A,B)` proves sixteen borrow equations as above and returns a typed
`bit` equal to one. `lt_u256(A,B)` lowers to `not(le_u256(B,A))`, also one.
`eq_u256` combines both non-strict comparisons with Boolean `and`; `ne_u256`
negates that bit. There is no distinct comparison hint.

The minimum uses `select(s,B,A)` with $s=\operatorname{le}(A,B)=1$; the
maximum uses `select(s,A,B)`. For every limb, selection enforces

$$
s(s-1)=0,\qquad R_i=(1-s)L_i+sU_i.
$$

Because $s$ is Boolean and both inputs are already checked as `u16`, $R_i$
equals an existing range-checked limb. No extra range witness is needed.
The checked subtraction then proves $B-A=8$ with a final borrow of zero.
The published Poseidon2 leaf of the sixteen difference limbs is
`[552785778,528026874,1337939194,1238002988,529560134,669980742,1274389821,1249346016]`.
Swapping $A$ and $B$ exercises the other selection branch and produces the
same difference; equality produces a zero difference. The
[`test_text_frontend.py` cases](../tests/python/test_text_frontend.py) check all three
assignments against an independent value oracle.

The source operations expand into the existing `u256_le`, `bool_not`,
`bool_and`, `select`, and checked subtraction relation nodes. The canonical
relation shares repeated comparisons with identical operands. Inspect the
lowered relation and the selected backend's gate cost with:

```sh
python3 src/frontends/s31/python/s31.py lower src/frontends/s31/examples/wide/u256_order_select.s31
python3 src/frontends/s31/python/s31.py trial src/frontends/s31/examples/wide/u256_order_select.s31 src/frontends/s31/examples/wide/u256_order_select.valid.json --lowering sparse-wide-gate --out zig-out/s31/u256-order-select-trial
python3 src/frontends/s31/python/s31.py equations zig-out/s31/u256-order-select-trial/package
python3 src/frontends/s31/tests/acceptance/acceptance_u256_select.py
```

The source comparison and select helpers add no new AIR opcode: the ordinary
gate AIR checks their arithmetic equations and the lookup machinery ties
every reused wire to its producer. The verifier receives only the eight-word
commitment; the two operands remain private. One `sparse-wide-gate`
`ReleaseFast` run used 8,162 raw QM31 rows (8,192 padded) and a 236,386-byte
proof. Repeated source comparisons shared canonical IDs in the cost report.
The acceptance script proved the $A<B$, $A>B$, and equality assignments with
the same sealed key. For every case the native verifier accepted the correct
statement and rejected both a changed public root and damaged proof bytes;
the prover rejected a private-input change with the old root. These are
functional proof checks and a one-run cost observation, not a speed claim.

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
The [full assignment](../examples/wide/wide_order.valid.json) and [exact normalized
relation](../examples/wide/wide_order.s31.json) are checked against this page.

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
python3 src/frontends/s31/python/s31.py oracle src/frontends/s31/examples/wide/wide_order.s31 src/frontends/s31/examples/wide/wide_order.valid.json
python3 src/frontends/s31/python/s31.py trial src/frontends/s31/examples/wide/wide_order.s31 src/frontends/s31/examples/wide/wide_order.valid.json --lowering sparse-wide-gate --out zig-out/s31/wide-order-trial
```

`sparse-wide-gate` keeps the equality, QM31 arithmetic, M31-to-`u32`, and
`u16` range AIRs needed by this program. Its 14 fixed columns contain 328,320
cells for this example, versus 4,507,264 cells in `gate`. In a single local
run, the native proof was 238,047 bytes and proving took 0.433 s, versus
427,557 bytes and 1.688 s for `gate`. Both native verifiers accepted the
correct statement and rejected a changed public root. These timing samples
include proof of work and are not a throughput estimate; the evidence is in
[`design/s31/measurements/bitcoin/bitcoin-wide-sparse-v5-2026-10-06.json`](../../../../design/s31/measurements/bitcoin/bitcoin-wide-sparse-v5-2026-10-06.json).

## Boundary for a Bitcoin proof

This **wide arithmetic** example takes digest bytes as an independent private
input, so it does not itself prove Bitcoin proof of work. The newer
[Bitcoin header walkthrough](bitcoin-sha256d.md) starts from `Bytes80`,
constrains both SHA-256 passes, decodes the header's compact target, and checks
the resulting hash inequality. The current public ABI has eight M31 words,
fewer than the sixteen `u16` slots needed to reveal the 32-byte hash directly;
that example publishes an auxiliary Poseidon2 commitment. A dedicated SHA chip,
complete header-chain rules, and a proof-bound SHA chip remain future work for
an efficient recursive Bitcoin light client. A two-level verifier wrapper
for this proof profile is available in
[sparse-wide recursion](recursion-sparse-wide.md), and a
[fixed-key claim fold](recursion-wide-fold.md) repeats verification of its
leaf claim. A state-transition header-chain fold remains to be built.
