# Checked 256-bit division and block work circuit

`src/frontends/s31/bitcoin/consensus/bitcoin_work.zig` is a reusable circuit primitive. S31
source exposes `std::bitcoin::block_work(target: Target) -> Work`, which
lowers to that primitive. A general source `std::math::div_rem_u256` is not
yet available because the source language has no pair return type; the Zig
API has `divRemU256`. Its input
and output integers are sixteen little-endian `u16` words. The caller can
pass input wires without trusting their range: the primitive splits each
word into two constrained bytes and equates the result to the supplied wire.

## The relation by hand

For numerator $n$, denominator $d$, quotient $q$, and remainder $r$,
the circuit proves both

\[
q d + r = n \quad\text{as a nonnegative integer}, \qquad 0 \leq r < d.
\]

The second equation also excludes $d=0$. The quotient and remainder are
not accepted merely because a host division routine returned them: they are
witnesses whose digits enter circuit constraints.

For a small example, $17 / 5$ has $q=3,r=2$. The low byte column says

\[
3\cdot5+2=17+256\cdot0.
\]

All 63 remaining byte columns, including the high product half, are zero.
The strict comparison subtracts $r+1$ from $d$: $5-2-1=2$, with no
final borrow. An alternative $q=2,r=7$ satisfies $2\cdot5+7=17$ but
fails the comparison because $7\not<5$.

For each byte column $k=0,\ldots,63$, the implementation imposes

\[
c_k + \sum_{i+j=k} q_i d_j + [k<32]r_k
  = [k<32]n_k + 256c_{k+1},
\quad c_0=c_{64}=0.
\]

All $q_i,d_j,r_i,n_i$ are eight-bit values. The carries are range-checked
`u16` values. The left side is at most

\[
32\cdot255^2 + 255 + 65535 = 2{,}146{,}590 < 2^{31}-1.
\]

The right side is at most $255+256\cdot65535=16{,}777{,}215$, also below
the M31 modulus. Equality in the circuit field therefore implies equality
of these ordinary integers; there is no field wrap. The high 32 columns and
terminal zero carry rule out dropping the upper half of $q d$.

The remainder check performs sixteen base-65536 subtraction columns for
$d-r-1$. A Boolean borrow and a range-checked difference word are
constrained at each step, and the final borrow is zero. Each equation is
below $2^{18}$, so the comparison is also an integer statement.

## Bitcoin work

For a target $t$, `blockWork` constrains checked additions and division:

\[
d=t+1,\quad n=(2^{256}-1)-t,\quad(q,r)=\operatorname{divrem}(n,d),
\quad w=q+1.
\]

This equals Bitcoin's $\lfloor 2^{256}/(t+1)\rfloor$. The first checked
addition rejects $t=2^{256}-1$; the last rejects $t=0$. A mainnet target
decoder already confines useful targets to $1\leq t\leq 2^{224}-1$.

The [source example](../../../src/frontends/s31/examples/bitcoin/bitcoin_block_work.s31)
uses the genesis target $0xffff\ll208$ and commits to the computed work
$0x100010001$ with Poseidon2. Its [handwritten relation](../../../src/frontends/s31/examples/bitcoin/bitcoin_block_work.s31.json)
has one `bitcoin_block_work` node, a value-preserving `cast_m31`, and one hash
node. The independent Python oracle and Zig relation evaluator use the
integer formula, while the circuit compiler calls the constrained primitive.

## Verification and scope

`zig build test-bitcoin-work -Doptimize=ReleaseFast`
checks boundary values against a `u512` reference and tests wrong quotient,
wrong remainder, a remainder at least as large as the divisor, zero divisor,
and truncated high product. The circuit validity check exercises its actual
gate equations. Text compilation, the independent oracle, and package
inspection pass for the source example. A [production-parameter local
trial](../measurements/bitcoin/bitcoin-block-work-gate-2026-10-07.json) also built the
source package, proved the genesis target case, verified it with the generated
native verifier, and rejected a changed public output. The proof was
435,880 bytes; end-to-end proving took 1.51 seconds and verification took
0.48 seconds in that run. These are single local observations. A broader
proof-level negative corpus remains open.

The current multiplication uses 32-by-32 byte products, hence up to 1,024
product gates plus byte range and carry checks. In a local `ReleaseFast`
builder run using 32 range-checked input words, one reserved public output,
and the mainnet genesis target for the work case, the raw circuit counts
were:

| Circuit | QM31 operation rows | Equality rows | M31-to-u32 rows |
| --- | ---: | ---: | ---: |
| `divRemU256` | 7,544 | 1,154 | 112 |
| `blockWork` | 7,754 | 1,220 | 128 |

The focused tests keep upper bounds of 7,600/1,200 and 7,800/1,250 for the
first two counts. These are circuit builder counts, not padded trace rows,
proving time, proof size, or an end-to-end chainwork profile. The primitive
is a sound general baseline; a sparse quotient profile or dedicated work
chip is needed to make it fast for common Bitcoin targets.

The compiled source example, including the Poseidon2 output commitment,
public binding, and finalization, has 15,113 raw QM31 operation rows,
1,220 equality rows, and 136 M31-to-u32 rows in `s31.py inspect` with the
`gate` profile. The compiler's source map assigns 6,439 raw QM31 rows to
the `bitcoin_block_work` node before the hash. These are source profile
geometry, not proving speed measurements.
