# Fixed-width integers, from source to AIR

An M31 field element and an integer answer different questions. In M31,
$p-1+1=0$ because arithmetic is modulo $p=2^{31}-1$. In `u8`, the same bit
patterns use modulus $2^8=256$ for **wrapping** addition, while **checked**
addition rejects an overflow. S31 keeps those meanings separate in source,
in its normalized relation, and in the proof.

## A complete one-byte program

This is the checked-in [source](../examples/math/int_u8_checked.s31) and its
[assignment](../examples/math/int_u8_checked.valid.json):

```s31
use std@1;

// Both inputs are one-byte integers. A proof exists only if their exact sum
// fits in u8; 250 + 5 = 255 is the largest accepted result.
circuit int_u8_checked(private a: u8, private b: u8) -> public u8 {
    let sum = std::int::add_checked(a, b);
    sum
}
```

```json
{
  "public_inputs": {},
  "private_inputs": {"a": [250], "b": [5]},
  "public_outputs": {"sum": [255]}
}
```

The brackets in the assignment carry one little-endian limb; the source
value is a scalar `u8`. The verifier learns the claimed result 255 and that
some private bytes sum to it. It does not learn that the inputs specifically
were 250 and 5; the prover could use any pair satisfying the same circuit.
Run `s31.py lower` to inspect the relation. It contains two `int_view` nodes
tagged with width 8 and one `int_add_checked` node. The tags bind the intended
width to the compiled relation and verifier key. For example, replacing
`u8` with `i8` changes the tag and the arithmetic interpretation even though
both occupy one `u16` limb in the low-level relation.

## Representation and operations

| Source type | Range as an integer | Proof representation |
| --- | ---: | --- |
| `u8`, `i8` | `0..255`, `-128..127` | One range-checked `u16` limb, additionally proved below 256. |
| `u16`, `i16` | `0..65535`, `-32768..32767` | One `u16` limb. |
| `u32`, `i32` | Unsigned `0..2^32-1`, signed `-2^31..2^31-1` | Two little-endian `u16` limbs. |
| `u64`, `i64` | Unsigned `0..2^64-1`, signed `-2^63..2^63-1` | Four little-endian `u16` limbs. |
| `u128`, `i128` | Unsigned `0..2^128-1`, signed `-2^127..2^127-1` | Eight little-endian `u16` limbs. |

For `iW`, the stored pattern $x$ represents $x$ if its high bit is zero, and
$x-2^W$ otherwise. Thus an `i8` value of $-1$ appears as `[255]` in a
proof assignment; `[−1]` is not a canonical limb. Every operation requires
two operands of the same nominal type. Neither field arithmetic nor
`UInt256` arithmetic is chosen implicitly.

| `std::int` call | Meaning |
| --- | --- |
| `add_checked(a,b)`, `sub_checked(a,b)` | Exact integer result in the type's signed or unsigned range; overflow or underflow has no valid witness. |
| `add_wrapping(a,b)`, `sub_wrapping(a,b)` | Low $W$ bits of the result, interpreted according to the result type. |
| `le(a,b)`, `lt(a,b)`, `ge(a,b)`, `gt(a,b)` | Signed ordering for `iW`, unsigned ordering for `uW`; constrained `bit` result. |
| `eq(a,b)`, `ne(a,b)` | Bit-pattern equality or inequality; constrained `bit` result. |
| `from_limbs_u8(raw)` through `from_limbs_i128(raw)` | Turn an exactly sized `[u16; L]` into the named scalar; the `u8` and `i8` forms prove the extra byte bound. |
| `limbs(x)` | Explicitly view a scalar as its `[u16; L]` bit pattern; no arithmetic node. |
| `reinterpret_u8(x)` through `reinterpret_i128(x)` | Reinterpret the same bits at the **same width** with the named signedness; no numeric conversion. |

There is no integer `+` or `-` operator yet: call `std::int` to choose checked
or wrapping semantics. `std::math::sub` and source `-` remain M31 operations.
There are no fixed-width multiplication, division, shifts, bitwise operations,
or cross-width numeric casts yet. Reinterpreting `i8` to `u8` maps $-1$ to
255; it does not reject or change the bits.

## The one-byte circuit by hand

For the program above, let $a,b,r$ be byte wires and $c$ the carry bit.
The compiler builds range and arithmetic gates enforcing:

$$
0\le a,b,r<256,\qquad c(c-1)=0,\qquad a+b=r+256c,\qquad c=0.
$$

The assignment $(a,b,r,c)=(250,5,255,0)$ satisfies every equation. If
`b=10`, the only byte result is $r=4$ with $c=1$, because
$250+10=4+256$. `add_wrapping` accepts that result; `add_checked` rejects
it by requiring $c=0$. A claimed public result other than the computed byte
also fails its public-output binding. The prover cannot choose an unbounded
`r` to make a false addition appear true: the byte range is proved.

The underlying `u16` range check is a lookup into the existing range table.
For a byte $x$, the circuit additionally guesses a range-checked `u16` wire
$q$ and enforces $256x=q$. As $0\le q<65536$ and the product stays below the
M31 modulus, this proves $0\le x<256$ as an ordinary integer inequality.
The carry is separately constrained by $c^2-c=0$. These witness wires are
verified circuit wires, not trusted host calculations.

For widths above 8, with base $B=65536$ and little-endian digits indexed by
$j$, each addition step proves

$$a_j+b_j+c_j=r_j+B c_{j+1},\qquad c_0=0,\qquad c_j\in\{0,1\}.$$

Subtraction proves $a_j+B d_{j+1}=b_j+d_j+r_j$ with Boolean borrows.
Unsigned checked arithmetic constrains the final carry or borrow to zero.
This scales with one, two, four, or eight digits, instead of padding every
operation to the sixteen digits of `UInt256`.

## Signed values and comparisons

The top digit is split into a lower part $\ell$ and sign bit $s$:

$$t=\ell+2^{k-1}s,\qquad s(s-1)=0,$$

where $k=8$ for `i8` and $k=16$ for the other signed types. The lower part
is bounded with a separate range-checked scaled wire: $512\ell<65536$ for
`i8`, or $2\ell<65536$ for a 16-bit top digit. Thus the bit really is the
high bit; it cannot be assigned independently of the input pattern.

Signed wrapping addition uses the same bit-pattern carry equations. Checked
addition also rejects equal-sign operands whose result has the opposite
sign. For example, `i8(120) + i8(10)` wraps to bit pattern 130, which means
$-126$; checked addition rejects it. Checked subtraction rejects a changed
result sign when the operand signs differ. These are Boolean gate equations
over constrained sign bits.

For `le(a,b)`, the circuit subtracts $a$ from $b$ limb by limb. If the final
borrow is $d$, unsigned $a\le b$ is $1-d$. For signed values with different
sign bits, the answer is the sign of $a$; with equal signs, use the unsigned
answer. So `i8(-1) <= i8(1)` is true even though their raw bytes are 255 and
1. The remaining comparisons compose `le` with constrained Boolean `not`
and `and` gates; they do not use a host-only comparison.

## Where the AIR and proof enter

The source compiler emits width-tagged `int_view`, arithmetic, or comparison
nodes. The circuit compiler expands each node into range checks, carry or
borrow gates, sign gates where needed, and output wires. The generic circuit
AIR then places these gates in trace rows. Gate constraints check the local
equations; address lookups connect an output wire to every later use of that
wire, and public binding fixes the result to the statement. Stwo commits to
the trace and proves the AIR constraints through its polynomial protocol.
The generated native verifier checks that proof against this program's
compiled key and public statement.

For example, the byte addition gate has a zero polynomial
$P_{\mathrm{add}}(a,b,r,c)=a+b-r-256c$. A Boolean carry gate has
$P_{\mathrm{bit}}(c)=c(c-1)$. The prover's trace polynomials must satisfy
these at the active gate rows; the quotient construction and low-degree test
check that claim over the committed trace. The equations above describe the
integer gadget. The [circuit AIR chapter](air.md) describes the actual packed
gate rows, selectors, wire lookups, and quotient used around it.

To inspect this exact program locally:

```sh
python3 src/frontends/s31/python/s31.py lower src/frontends/s31/examples/math/int_u8_checked.s31
python3 src/frontends/s31/python/s31.py oracle src/frontends/s31/examples/math/int_u8_checked.s31 src/frontends/s31/examples/math/int_u8_checked.valid.json
python3 src/frontends/s31/python/s31.py trial src/frontends/s31/examples/math/int_u8_checked.s31 src/frontends/s31/examples/math/int_u8_checked.valid.json --lowering sparse-wide-gate --out zig-out/s31/int-u8-checked
```

`lower` shows width-bearing relation nodes. `oracle` evaluates the relation
independently of proof generation. `trial` builds the native verifier, proves
the fixture, and verifies it. For a focused negative case, change `b` to 10
and `sum` to 4: the oracle or proof rejects `add_checked`; changing the call
to `add_wrapping` makes that bit-pattern result valid.
