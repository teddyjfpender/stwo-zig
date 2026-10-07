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
| `std::math::matvec(rows, vector)` | Matrix–vector product; each output row is a static reference | 1..16 rectangular rows and 1..16 columns of equally shaped `[m31; N]` values. |
| `std::math::matmul(a,b)` | Matrix product `(a·b)[i,j] = Σₖ a[i,k]·b[k,j] mod p` in every lane | Both matrices have 1..16 rows and columns; matching inner dimension and equally shaped `[m31; N]` cells. Returns nested static rows. |
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

`std::array::get<K>(group)` selects one entry of a static reference group,
and `std::array::concat(left,right)` joins two such groups, at most 64 entries
total. These forms emit **zero relation nodes**: they reorder references to
values that already exist. The same functions accept runtime `[m31; N]` and
`[u16; N]` values. Then `get<K>` produces a one-element array and `concat`
produces an array whose length is the sum of the input lengths, at most 4096.
Those forms emit explicit `array_get` and `array_concat` relation nodes. They
are views of already constrained lanes, not hints chosen by the prover; a
verifier constrains any use of a selected output to the source position.
The index is a literal checked against the source length at compile time.
The relation compiler aliases existing source wires for raw inputs and aligned
packed words. When concatenation crosses a four-lane QM31 boundary, it
unpacks the source positions and repacks them with circuit gates. Selecting a
nonaligned position from a packed result also uses a constrained unpack.
The public-output copy gate binds the selected wire to the claimed word;
`u16` inputs and outputs retain their range checks.

`take<K>` and `drop<K>` also accept runtime `[m31; N]` and `[u16; N]`
values. They emit an `array_slice` relation carrying a checked starting
offset and a nonzero result length. Taking all `N` values or dropping zero
aliases the input and emits no relation node. For a proper slice, the
coordinate rule is `slice[j] = source[offset+j]` for every
`0 <= j < length`. A four-coordinate aligned slice borrows whole QM31
wires; a shifted slice unpacks source coordinates and constrains their new
packing. The source bytes, offset, and length are part of the canonical
program bound by the generated verification key.

`reshape<R>(flat)` divides a flat static group or runtime array into `R`
consecutive rows. Static groups limit both dimensions to 1..16 and emit no
relation nodes. Runtime arrays require 1..16 rows and exact divisibility;
each row is an `array_slice` of `[m31; N/R]` or `[u16; N/R]`. A runtime
`flatten(rows)` joins equal-shaped rows with `array_concat`; static
rectangular groups still flatten by reference alone. Reshape followed by
flatten is functionally the identity, but the current compiler may still
lower intermediate row slices and joins. The cost report shows those gates
when they occur.

For example, the [shifted runtime slice](../examples/array_slice_shifted.s31)
starts from private `x=[2,3,5,7,11,13,17]`:

~~~s31
let tail = std::array::drop<1>(x); // [3,5,7,11,13,17]
std::array::take<4>(tail)          // [3,5,7,11]
~~~

The [handwritten relation](../examples/array_slice_shifted.s31.json) records
two slice nodes: `tail[j]=x[1+j]` for six positions, followed by
`result[j]=tail[j]` for four. In the circuit, the first slice packs the
coordinates `(3,5,7,11)` into a QM31 wire. Because the source window starts
at coordinate 1, that word combines coordinates from two original packed
wires. The unpack and pack gates constrain this combination. The second
slice borrows that packed word. The native verifier checks the output copy
against `[3,5,7,11]`; changing the public claim fails. The [aligned
example](../examples/array_slice_aligned.s31) takes positions 4..7 from an
eight-lane private array and borrows its second packed word without adding
slice gates. The [runtime matrix example](../examples/array_matrix_runtime.s31)
reshapes eight private lanes into two four-lane rows, rejoins them, and
selects position 6, which is 17 in the sample assignment. The
[u16 example](../examples/array_slice_u16.s31) preserves the source's
range constraints while exposing the two-lane slice `[65535,7]`.

## A fixed matrix by hand

The [checked-in matrix program](../examples/static_matvec.s31) illustrates
the distinction between static reference arrays and witness arrays:

~~~s31
use std@1;

// A two-by-two matrix of fixed coefficients acts on two private scalars.
// Static arrays group references; every arithmetic result is still proved.
circuit static_matvec(private a: [m31; 1], private b: [m31; 1])
    -> public [m31; 1] {
    let vector = [a, b];
    let rows = [[splat<1>(2_m31), splat<1>(3_m31)],
                [splat<1>(5_m31), splat<1>(7_m31)]];
    let products = std::math::matvec(rows, vector);
    let first = std::array::get<0>(products);
    let second = std::array::get<1>(products);
    let total = std::math::sum(std::array::concat([first], [second]));
    total
}
~~~

For private `a=2`, `b=3`, the first row is `2·2+3·3=13`, the second is
`5·2+7·3=31`, and the claimed public result is `13+31=44` in M31. The
[handwritten normalized relation](../examples/static_matvec.s31.json) has
four `mul_const` nodes and three `add` nodes. The `vector`, `rows`, `products`,
`get`, and static `concat` expressions add no separate gates. In particular,
`matvec` expands each row into a dot product; the proof checks both products
and their sum. The independent value oracle checks the [sample
assignment](../examples/static_matvec.valid.json), while the native verifier
checks a proof of the compiled relation. For a scalar element `a`, a runtime
array `[m31; N]` is a different thing: its coordinates are witness values,
and selecting one is represented explicitly by `array_get`.

## A fixed matrix product by hand

The [matrix multiplication program](../examples/static_matmul.s31) takes
private scalar cells `a,b,c,d` and multiplies
`[[a,b],[c,d]]` by `[[2,3],[5,7]]`. `reshape<2>` builds the right-hand
matrix from a flat group. `matmul` returns nested rows; `flatten` exposes
the four output cells in row-major order. `take<3>` selects the first three,
and `drop<3>` selects the fourth. The final public word is
`C[0,0] + 2·C[0,1] + 3·C[1,0] + 4·C[1,1]`.

For the [sample assignment](../examples/static_matmul.valid.json),
`(a,b,c,d)=(2,3,5,7)`, so the four cells are `(19,27,45,64)` and the
public word is `19 + 2·27 + 3·45 + 4·64 = 464`. The
[handwritten relation](../examples/static_matmul.s31.json) explicitly lists
all nineteen arithmetic nodes: twelve `mul_const` and seven `add`. The
static views add none. The text and handwritten packages have matching
canonical IR and direct-gate row geometry. Each package produces a proof
accepted by its generated native verifier; changing the claimed public word
is rejected. The independent oracle checks the arithmetic assignment, while
the native proof establishes the emitted relation. In one `ReleaseFast`
direct-gate run, the circuit used 299 raw QM31 rows (512 padded). The text
proof was 56,675 bytes; the handwritten relation proof was 54,811 bytes.
Proof bytes vary with proof randomness. The verifier rejected a changed
public result, and the prover rejected an assignment claiming `465`.

The [runtime array example](../examples/array_views.s31) joins two public
arrays, selects position four from the joined value and position three from
the first value, and adds them:

~~~s31
use std@1;

// Public arrays make both selected coordinates part of the verifier's claim.
// Index 4 crosses from `a` into the first position of `b`.
circuit array_views(public a: [m31; 4], public b: [m31; 3])
    -> public [m31; 1] {
    let joined = std::array::concat(a, b);
    let boundary = std::array::get<4>(joined);
    let prior = std::array::get<3>(a);
    let result = boundary + prior;
    result
}
~~~

For `a=[2,3,5,7]` and `b=[11,13,17]`, `joined=[2,3,5,7,11,13,17]`,
so `boundary=[11]`, `prior=[7]`, and `result=[18]`. The
[normalized relation](../examples/array_views.s31.json) records concat and
both positions explicitly. Its only arithmetic node is the final addition.
The independent oracle checks the same positions, and the compiler must
preserve those references when mapping them to circuit wires. All eight
public words (seven inputs and one output) are bound in the proof statement.

The [private M31 example](../examples/array_views_private.s31) exercises the
packed boundary and a computed array. It joins three lanes of `a` and four of
`b`, doubles the joined array, then returns positions 3 and 4 of the joined
array plus position 5 of the doubled array. For
`a=[2,3,5]`, `b=[7,11,p-2,17]`, those positions are `7`, `11`, and
`2(p-2) mod p = p-4`; the public result is `14`. The
[handwritten relation](../examples/array_views_private.s31.json) records the
concat, three selections, and three arithmetic nodes. The
[u16 example](../examples/array_views_u16.s31) joins a three-word array with
a two-word array and selects the first word of the second array, `65535`,
across that same boundary. Its [handwritten relation](../examples/array_views_u16.s31.json)
has only `array_concat` and `array_get` nodes.

Run `python3 acceptance_array_views.py` from the S31 frontend directory to
compile the text and handwritten JSON versions, compare their canonical IR
and circuit cost, check the assignments with the independent oracle, and
prove both versions. Each generated native verifier accepts the correct
public statement and rejects a changed one. The oracle and prover also
reject a changed output assignment. In one `ReleaseFast` run, the public
M31 example used 291 raw QM31-operation rows, the private shifted M31
example used 336, and the private u16 example used 284 plus five
M31-to-u32 rows. Each had 512 padded QM31-operation rows. The M31 examples
used `direct-gate`; the u16 example used `gate`, whose range-check components
also had 16 padded rows each. These are costs of three different programs,
not a comparison of view overhead in isolation. The native proofs, including
negative-claim checks, establish the compiled relation beyond the oracle's
host-side evaluation.

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

### Compute with bits

The [Boolean example](../examples/bool_computed_choice.s31) computes two bits
from `is_zero`, applies every `std::bool` operation, then uses the final bit
to select a field value. Its [normalized relation](../examples/bool_computed_choice.s31.json)
has explicit `bool_not`, `bool_and`, `bool_or`, `bool_xor`, and `bool_select`
nodes. For field elements `a,b,s` known to be bits, their constraints are:

| Operation | Constraint for result `r` | Values when `a,b` are bits |
| --- | --- | --- |
| `not(a)` | `r = 1-a` | `1,0` for `a=0,1` |
| `and(a,b)` | `r = ab` | One only when both are one |
| `or(a,b)` | `r = a+b-ab` | Zero only when both are zero |
| `xor(a,b)` | `r = a+b-2ab` | One when they differ |
| `select(s,a,b)` | `r = (1-s)a+sb` | `a` at zero, `b` at one |

Every input bit also obeys `b(b-1)=0`. The compiler adds that condition to
any scalar relation operand whose producer has not already proved it. An
`is_zero` output already satisfies the condition because of its two equations
above; a Boolean result satisfies it by the table. The output is an ordinary
arithmetic wire, with no unconstrained output hint. A direct input bit uses a
self-product `b²=b` as its producing gate, and an arbitrary relation scalar
used as a bit gets an arithmetic zero assertion. A value of `2` cannot act as
a selector: its bit equation evaluates to `2`, so the proof constraints fail.

For the example, let `left=17` and `right=23`. Hand evaluation is:

| `x` | `y` | `zx` | `zy` | `n` | `a` | `o` | `q` | `chosen` | Result |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 0 | 1 | 1 | 0 | 0 | 1 | 0 | 1 | 23 |
| 0 | 5 | 1 | 0 | 0 | 0 | 1 | 1 | 0 | 17 |
| 9 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 0 | 17 |
| 9 | 5 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 17 |

Each table row is one possible assignment to the same fixed circuit, not a
different branch of code generated at proof time. The verifier checks the
claimed public inputs and result against the circuit's committed witness and
AIR. The Boolean formulas are ordinary arithmetic gates inside that circuit;
they do not introduce a separate Boolean AIR chip.

The checked-in geometry test reports 310 raw QM31 arithmetic rows (512 after
power-of-two padding) and zero Eq rows for this complete example. The simpler
one-zero-test `computed_choice` above has 288 raw rows. The 22-row difference
includes a second zero test as well as all Boolean operations, so it is not a
per-operation price. The generated package's cost report remains the source of
truth for a particular compiler version and lowering profile.
The [native proof acceptance](../acceptance_boolean_v1.py) verifies five
proofs across the truth table and a typed private bit input. It rejects five
altered public claims and the private bit value `2`. In a ReleaseFast local
run, the computed example's proofs were 54,030–56,098 bytes; the bit-input
example used 275 raw QM31 rows and a 54,529-byte proof. Those are proof-level
correctness samples, not throughput benchmarks.

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
