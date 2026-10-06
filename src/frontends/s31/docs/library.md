# 2. Standard library and math library

S31 currently has one compiler-owned standard package, **std version 1**.
New programs can pin it with `use std@1;` before any `fn` declaration.
Existing sources without that line continue to use the same version
implicitly. `use std@2;` and third-party packages are rejected.
This is a versioned compiler builtin package, not a general module loader.

Every `std::math` helper below lowers to the existing normalized
`add`, `mul`, `add_const`, or `mul_const` nodes. The native verifier proves
those nodes through the ordinary circuit AIR. No helper is a host-only
calculation and none adds a new AIR opcode.

## The current API

| Call | Meaning per M31 lane | Static restriction |
| --- | --- | --- |
| `std::math::neg(x)` | `-x mod p` | `x: [m31; N]`. |
| `std::math::sub(x,y)` | `x-y mod p` | Equal `[m31; N]` shapes. |
| `std::math::square(x)` | `x·x mod p` | `x: [m31; N]`; also recognized inside `iterate`. |
| `std::math::pow<K>(x)` | `x^K mod p` | Literal `0 <= K < p`; `x^0=1`, including zero. |
| `std::math::sum([a,b,...])` | `a+b+... mod p` | 1..64 same-shaped arrays grouped in source. |
| `std::math::dot([a,b,...],[u,v,...])` | `a·u+b·v+... mod p` | Equal groups of 1..64 same-shaped arrays. |
| `std::math::poly_eval(x,[c0,c1,...,cd])` | `c0+c1·x+...+cd·x^d mod p` | 1..64 coefficients, each the same shape as `x`; **low degree first**. |

The group in brackets is a compile-time list of existing circuit values,
not a witness array that can be indexed. Each item may be an input,
an earlier result, or a `splat<N>(constant_m31)`. For example, if each
item has type `[m31; 4]`, `dot` returns four independent inner products:
output lane `j` uses lane `j` from every term. It does **not** sum the four
coordinates of one `[m31; 4]` value.

`sum` uses a balanced addition tree. `dot` multiplies corresponding
terms, then uses that tree; before constant folding, `n` terms need
`n` products and `n-1` additions. `poly_eval` uses Horner's rule,
so `d+1` coefficients need at most `d` multiplications and `d`
additions. Compile-time constant folding and canonical graph sharing can
remove or merge nodes. These are transparent lowering bounds, not claims
of globally optimal addition chains.

The rest of `std` provides `std::field::from_u16` and
`std::field::select`, Poseidon2 and BLAKE2s reduced leaf/pair calls
under `std::hash`, and fixed-depth path calls under `std::merkle`.
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

The remaining math gap is real: there is no projection or dynamic indexing
of one `[m31; N]`, so `sum` and `dot` cannot reduce its lanes. Checked
inversion/division, computed bits, integer comparisons, general module
loading, and dedicated math chips are also absent.

Next: [circuit lowering](circuits.md).
