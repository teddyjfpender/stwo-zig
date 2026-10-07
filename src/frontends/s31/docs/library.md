# 2. Standard library and math library

S31 currently has one compiler-owned standard package, **std version 1**.
New programs can pin it with `use std@1;` before any `fn` declaration.
Existing sources without that line continue to use the same version
implicitly. `use std@2;` and third-party packages are rejected.
This is a versioned compiler builtin package, not a general module loader.

Most `std::math` helpers below lower to normalized `add`, `mul`,
`add_const`, or `mul_const` nodes. `sum_lanes` and the two `u256` operations
have their own normalized relation nodes. The circuit compiler lowers
`sum_lanes` to
constrained packed-wire additions, a fixed QM31 multiplier, and a base mask.
The wide operations use range-checked limbs and Boolean carries or borrows.
The native verifier proves all these operations through the ordinary circuit
AIR. No helper is a host-only calculation or a new specialized AIR chip.

## The current API

| Call | Meaning | Static restriction |
| --- | --- | --- |
| `std::math::neg(x)` | `-x mod p` | `x: [m31; N]`. |
| `std::math::sub(x,y)` | `x-y mod p` | Equal `[m31; N]` shapes. |
| `std::math::square(x)` | `x·x mod p` | `x: [m31; N]`; also recognized inside `iterate`. |
| `std::math::mix4(x)` | `x[j] + Σₖx[k] mod p` in each lane | `[m31; 4]`, inside an `iterate` step only. |
| `std::math::inv(x)` | Lane-wise field inverse | Every active lane must be nonzero. |
| `std::math::div(x,y)` | `x·y⁻¹ mod p` | Equal `[m31; N]` shapes; every denominator lane must be nonzero. |
| `std::math::pow<K>(x)` | `x^K mod p` | Literal `0 <= K < p`; `x^0=1`, including zero. |
| `std::math::sum([a,b,...])` | `a+b+... mod p` | 1..64 same-shaped arrays grouped in source. |
| `std::math::dot([a,b,...],[u,v,...])` | `a·u+b·v+... mod p` | Equal groups of 1..64 same-shaped arrays. |
| `std::math::sum_lanes(x)` | `Σⱼ x[j] mod p`, returned as `[m31; 1]` | One `[m31; N]`, `1 <= N <= 4096`. |
| `std::math::dot_lanes(x,w)` | `Σⱼ x[j]·w[j] mod p`, returned as `[m31; 1]` | Two equally shaped `[m31; N]` arrays, `1 <= N <= 4096`. |
| `std::math::poly_eval(x,[c0,c1,...,cd])` | `c0+c1·x+...+cd·x^d mod p` | 1..64 coefficients, each the same shape as `x`; **low degree first**. |
| `std::math::add_u256(a,b)` | `(a+b) mod 2^256` | Two `UInt256` values; sixteen little-endian limbs. |
| `std::math::add_u256_checked(a,b)` | `a+b` with final carry zero | Two `UInt256` values; overflow makes the relation unsatisfiable. |
| `std::math::sub_u256(a,b)` | `(a-b) mod 2^256` | Two `UInt256` values; sixteen little-endian limbs. |
| `std::math::sub_u256_checked(a,b)` | `a-b` with final borrow zero | Two `UInt256` values; underflow makes the relation unsatisfiable. |
| `std::math::le_u256(a,b)` | `1` if `a <= b`, else `0` | Two `UInt256` values; result `[m31; 1]`. |

The group in brackets is a compile-time list of existing circuit values,
not a witness array that can be indexed. Each item may be an input,
an earlier result, or a `splat<N>(constant_m31)`. For example, if each
item has type `[m31; 4]`, `dot` returns four independent inner products:
output lane `j` uses lane `j` from every term. It does **not** sum the four
coordinates of one `[m31; 4]` value. Use `sum_lanes` or `dot_lanes` to reduce
those coordinates to one word.

`sum` uses a balanced addition tree. `dot` multiplies corresponding
terms, then uses that tree; before constant folding, `n` terms need
`n` products and `n-1` additions. `poly_eval` uses Horner's rule,
so `d+1` coefficients need at most `d` multiplications and `d`
additions. Compile-time constant folding and canonical graph sharing can
remove or merge nodes. These are transparent lowering bounds, not claims
of globally optimal addition chains.

## Checked field division

The [field division example](../examples/field_div4.s31) uses both operations:

~~~s31
use std@1;

// Four independent field divisions. Zero in any denominator lane is invalid.
circuit field_div4(public numerator: [m31; 4], private denominator: [m31; 4])
    -> public [m31; 4] {
    let inverse = std::math::inv(denominator);
    let quotient = std::math::div(numerator, denominator);
    let result = quotient + inverse;
    result
}
~~~

`div` reuses `inverse`; its normalized relation has only `inv`, `mul`, and
`add` nodes. For each lane, the inverse witness `r` must satisfy
`denominator·r − 1 = 0`, then `quotient = numerator·r`. A zero denominator
cannot satisfy the first equation. `pow<p−2>(denominator)` would return zero
at zero and therefore would not prove nonzero.

| Array position | Numerator | Private denominator | Constrained inverse | Quotient | Public result |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 10 | 2 | 1073741824 | 5 | 1073741829 |
| 1 | 21 | 3 | 1431655765 | 7 | 1431655772 |
| 2 | 0 | 5 | 858993459 | 0 | 858993459 |
| 3 | 14 | 7 | 1840700269 | 2 | 1840700271 |

The compiler packs four M31 lanes per QM31 wire. Inversion adds one
pointwise product, one difference, and one zero-assertion self-loop per
packed wire; division adds one more pointwise product for the quotient.
The self-loop `anchor + difference = anchor` forces the difference to zero
while giving the anchor exactly one producing gate. This is required by the
direct AIR's address lookup. The compiler checks every variable's producer
count both before and after padding and fails if any count differs from one.
An independent oracle agrees with the table, and a
five-lane circuit test checks that the final partial group rejects a zero.
The `direct-gate` profile accepts this relation without an Eq AIR component.
A `ReleaseFast` sample built 327 raw QM31-operation rows (512 padded), eight
preprocessed columns, and a 55,800-byte proof. The generated native verifier
accepted it. These are single-run costs
for this four-lane example, not general throughput measurements.

## A computed bit

This [checked-in program](../examples/computed_choice.s31) chooses the right
value when `x` is zero and the left value otherwise:

~~~s31
use std@1;

// A computed condition: choose right when x is zero, left otherwise.
circuit computed_choice(public x: [m31; 1], public left: [m31; 1],
                        public right: [m31; 1]) -> public [m31; 1] {
    let zero = std::field::is_zero(x);
    let result = std::field::select(zero, left, right);
    result
}
~~~

The compiler introduces a private inverse hint `r` and computed bit `z`.
It constrains `x·r = 1-z` and `x·z = 0`. For `x=0`, the first equation forces
`z=1`; for any nonzero `x`, the second forces `z=0` and the first fixes
`r=x⁻¹`. Thus `z` is Boolean as a consequence of the two equations, without
an extra bit gate. The select output is `(1-z)·left + z·right`.

| `x` | `left` | `right` | `z=is_zero(x)` | Public result |
| ---: | ---: | ---: | ---: | ---: |
| 0 | 17 | 23 | 1 | 23 |
| 1 | 17 | 23 | 0 | 17 |
| $p-1$ | 17 | 23 | 0 | 17 |

The direct profile uses arithmetic self-loops for both zero equations. The
[acceptance corpus](../acceptance_computed_bit_v1.py) proves all three rows
and rejects four mismatched claims. It has 288 raw QM31 rows (512 padded)
and no Eq AIR component in this example.

## Reduce one array to one value

This [checked-in program](../examples/lane_stats4.s31) has private data and
one public result:

~~~s31
use std@1;

circuit lane_stats4(private x: [m31; 4], private weights: [m31; 4])
    -> public [m31; 1] {
    let total = std::math::sum_lanes(x);
    let weighted = std::math::dot_lanes(x, weights);
    let result = total + weighted;
    result
}
~~~

For the [sample assignment](../examples/lane_stats4.valid.json), fill the
per-lane values by hand:

| Lane, one array position | Private `x[j]` | Private `weights[j]` | Product `x[j]·weights[j]` |
| ---: | ---: | ---: | ---: |
| 0 | 2 | 11 | 22 |
| 1 | 3 | 13 | 39 |
| 2 | 5 | 17 | 85 |
| 3 | 7 | 19 | 133 |
| **Sum across lanes** | **17** | — | **279** |

Thus `total=[17]`, `weighted=[279]`, and `result=[296]`. Each bracketed
result is an array of **one** M31 word. The public statement contains only
`result=[296]`; `x` and `weights` are private witnesses. Verification says
there exist private arrays satisfying the compiled equations for that
public result. The public statement does not list the arrays or uniquely
determine them; this is not a general zero-knowledge promise about the proof.
[The full worked proof](worked-proofs.md#example-a-a-private-cross-lane-computation)
follows this exact function through relation JSON, circuit wires, schematic
AIR gate rows, polynomials, and the native verifier's claim.

The text frontend lowers this source to `sum_lanes(x)`, a pointwise
`mul(x,weights)`, `sum_lanes(product)`, and a final `add`. Each `sum_lanes`
adds packed QM31 wires in a balanced tree, masks any unused positions in a
partial final wire, then uses a fixed QM31 multiplier and a base-coordinate
mask to obtain the M31 sum. These are constrained circuit gates. For four
positions, reduction takes **two builder gates** instead of extracting all
four positions. `dot_lanes` adds the pointwise products first. One source
call can still require multiple circuit gates and AIR rows; the row count
is not one per library call. The exact field identity and every hand-filled
wire appear in [the worked proof](worked-proofs.md#example-a-a-private-cross-lane-computation).

For this four-lane source under `direct-gate`, the two `sum_lanes` nodes,
one pointwise product, and one final add make six source arithmetic builder
gates. The **whole** circuit now has 304 raw QM31-operation rows, padded to
512, and 4,096 fixed cells. Input handling, wire lookup, public binding,
and finalization contribute to that total; builder gate spans are not
physical AIR row ownership. The earlier 323-row measurement used the same
packed reduction but guessed private M31 positions one at a time. The checked-in
[handwritten relation](../examples/lane_stats4.s31.json) was separately
compared with the text source under `direct-gate`: they have the same
canonical graph and row geometry, and both native verifiers accepted proofs.

The rest of `std` provides `std::field::from_u16` and
`std::field::select`, Poseidon2 and BLAKE2s reduced leaf/pair calls
under `std::hash`, and fixed-depth path calls under `std::merkle`.
`std::bytes::to_u256_le`, `from_u256_le`, and `limbs_m31` give explicit
conversions for the nominal `Bytes32` and `UInt256` types. The
[wide-value chapter](wide-values.md) shows exact limb equations and a complete
source example. `std::hash::sha256d_header(Bytes80)` now computes and proves
byte-exact Bitcoin header hashing; `std::bitcoin::target_mainnet(Bytes80)`
constrains the mainnet compact target. The [Bitcoin header chapter](bitcoin-sha256d.md)
works through both operations and the proof-of-work comparison.
Their field, bit, digest, and hash rules are in [source semantics](source.md)
and [hash semantics](hashes.md).

## One complete program

This [checked-in program](../examples/mathlib4.s31) evaluates
`P(x)=2x³+3x²+5x+7`, then `2x+3P(x)+11`, independently in four lanes:

~~~s31
use std@1;

fn polynomial(x: [m31; 4]) -> [m31; 4] {
    std::math::poly_eval(x, [
        splat<4>(7_m31), splat<4>(5_m31),
        splat<4>(3_m31), splat<4>(2_m31)
    ])
}

circuit mathlib4(public x: [m31; 4]) -> public [m31; 4] {
    let poly = polynomial(x);
    let weighted = std::math::dot(
        [x, poly], [splat<4>(2_m31), splat<4>(3_m31)]);
    let result = std::math::sum([weighted, splat<4>(11_m31)]);
    result
}
~~~

Horner starts at the **last** coefficient, 2, and moves backwards:

$$
P(x)=((2x+3)x+5)x+7.
$$

For lane 2, `x[2]=2`: `P(2)=((2·2+3)·2+5)·2+7=45`.
The dot call then gives `2·2+3·45=139`; the final sum gives `150`.
All four positions can be checked without a prover:

| Source step | Lane 0, `x[0]=0` | Lane 1, `x[1]=1` | Lane 2, `x[2]=2` | Lane 3, `x[3]=7` |
| --- | ---: | ---: | ---: | ---: |
| `P(x)` | 7 | 17 | 45 | 875 |
| `2x+3P(x)` | 21 | 53 | 139 | 2639 |
| `2x+3P(x)+11` | 32 | 64 | 150 | 2650 |

The [assignment](../examples/mathlib4.valid.json) claims that last row.
The [handwritten normalized relation](../examples/mathlib4.s31.json) names
the Horner and dot gates explicitly. The text frontend emits ten relation
nodes, but canonicalization shares the repeated `2x` term, leaving nine
unique arithmetic nodes. In the direct arithmetic profile, the full circuit
has 334 raw rows, 512 padded rows, and 4,096 fixed cells, including public
binding and wiring. Text and handwritten JSON have the same canonical IR
digest, preprocessed root, and row geometry. Source-dependent names and
the package identities can differ.

## What a package pins

A text build writes `stdlib-lock.json` with package/version, whether the
import was explicit, and SHA-256 hashes of `s31_stdlib.py` and
`s31_mathlib.py`. Its own digest is in the package manifest and the
verification key. The generated native verifier is compiled with that digest
and rejects a key bearing another one. The normalized relation and source
text are separately hashed in the package; the proof still establishes the
relation's AIR constraints, not the truth of Python code at verification time.

Run from the repository root:

~~~sh
python3 src/frontends/s31/s31.py lower src/frontends/s31/examples/mathlib4.s31
python3 src/frontends/s31/s31.py build src/frontends/s31/examples/mathlib4.s31 --lowering direct-gate --out zig-out/s31/mathlib4-text
python3 src/frontends/s31/s31.py explain zig-out/s31/mathlib4-text
python3 src/frontends/s31/s31.py prove zig-out/s31/mathlib4-text src/frontends/s31/examples/mathlib4.valid.json zig-out/s31/mathlib4-text.proof
python3 src/frontends/s31/s31.py verify zig-out/s31/mathlib4-text zig-out/s31/mathlib4-text.proof
~~~

The remaining math gaps are dynamic indexing of one `[m31; N]`, checked
inversion/division, computed bits, wider integer operations beyond addition
and unsigned comparison, general module loading, and dedicated math chips.
`sum_lanes` and `dot_lanes` work on
statically sized arrays; they do not expose an arbitrary lane as a source
value.

Next: [circuit lowering](circuits.md).
