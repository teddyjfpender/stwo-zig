# 1. Source language and relation

## Values and field arithmetic

S31's base field is `F_p`, `p = 2^31 - 1 = 2147483647`. An `m31` value is a
canonical integer from `0` through `p-1`. Addition and multiplication reduce
modulo `p`; `p` itself is **not** a canonical encoding of zero. A `u16` value
is an integer from `0` through `65535`. `m31_from_u16` preserves its numeric
value and changes its type. There are no implicit integer/field conversions.

Text types are fixed-size `[m31; N]` and `[u16; N]`, a single `bit`, and
`Digest<Poseidon2>` or `Digest<Blake2sReduced>`. `bit` erases to `m31[1]` in
relation JSON and must be a directly declared input used by `select`. The
circuit constrains `b²=b`, so it has only values zero and one. A digest erases
to `m31[8]`, but retains a nominal family in text so a Poseidon2 digest cannot
be paired with a BLAKE2s reduced digest. Declaring a digest input makes a
claim about eight words; it does not prove those words came from a hash.

Array lengths are `1..4096`. Public input words plus named public output words
must total `1..8`. The proof ABI has eight word slots; unused slots are zero.
In a `direct-*` profile each public word is canonical M31. In the older
`gate`/`chip` and `sparse-*` profiles the public slots are `u32` words, with
explicit conversion/range machinery where needed.

## Text syntax

One file has zero or more pure `fn` declarations, then one `circuit`.
Functions are specialized and inlined at calls; recursion is rejected.
Circuit parameters say `public` or `private`, and the result is public.
Bodies have immutable `let` statements, optional `assert_eq(a,b);` statements
in the circuit, and one final expression.

```s31
fn step(v: [m31; 4]) -> [m31; 4] {
    v .* v + splat<4>(7_m31)
}

circuit arith4_m31(public x: [m31; 4]) -> public [m31; 4] {
    let result = iterate<256>(step, x);
    result
}
```

`+` and `.*` are lane-wise M31 operations on equal shapes. A numeric field
literal has the `_m31` suffix and must be canonical. `splat<N>(7_m31)` makes a
compile-time uniform array; it is materialized only when a gate needs it.
Bare integers are accepted only as compile-time arguments such as `N` in
`splat<N>`, `iterate<N>`, or `std::math::pow<N>`. Parentheses, calls, `//`
comments, and static array literals such as `[sibling_0, sibling_1]` work.
These literal arrays group existing values for Merkle helpers; they are not
general witness arrays that can be indexed or returned.

`iterate<R>(step, initial)` accepts a pure step of type `[m31; N] -> [m31; N]`
made from a sequence of `state .* state`, addition of a uniform constant, and
multiplication by a uniform constant. The relation has `1..32768` rounds and
`1..16` static body steps. The special AIR chip recognizes only four lanes,
public endpoints, `square` then `add_const`, and power-of-two `R` from 16 to
32768. Selecting an incompatible chip profile is an error.

The current library is compiler-owned. It has no module loader or imports:

| Text operation | Meaning |
| --- | --- |
| `std::math::neg(x)` | `-x mod p`, lane-wise. |
| `std::math::sub(x,y)` | `x-y mod p`, equal M31 shapes. |
| `std::math::square(x)` | `x.*x`. |
| `std::math::pow<K>(x)` | Static binary exponentiation, `0 <= K < p`; `x^0=1`, including `0^0`. |
| `std::field::from_u16(x)` | Value-preserving cast from `[u16; N]`. |
| `std::field::select(bit,a,b)` | `a` if zero, `b` if one; same type/shape. |
| `std::hash::poseidon2_leaf/pair`, `std::hash::blake2s_leaf/pair` | The [typed hash operations](hashes.md). |
| `std::merkle::path_poseidon2`, `std::merkle::path_blake2s` | Fixed-depth path built from hashes and selects. |

The older unqualified spellings (`select`, `poseidon2_leaf`, etc.) still work
and lower identically. `std::math::sub` with a constant right operand becomes
one `add_const` with `p-c`; `pow<5>` becomes three multiplication nodes. This
is source-level convenience over the same proof gates. `pow<p-2>(x)` is not a
checked inverse: at zero it returns zero, and no nonzero assertion is added.

## A hand-written private-witness function

```s31
circuit preimage4(public target: [m31; 4], private secret: [u16; 4])
    -> public [m31; 4] {
    let secret_field = m31_from_u16(secret);
    let square = secret_field .* secret_field;
    let offset = square + splat<4>(7_m31);
    assert_eq(offset, target);
    square
}
```

The output is `square`, while `offset == target` is a separate proof
obligation. For `secret=[1,2,3,42]`, the public target is
`[8,11,16,1771]` and the public output is `[1,4,9,1764]`. The private
`secret` values are absent from the public statement. The verifier checks
the circuit equality constraint, rather than rerunning this source function.

## Normalized relation JSON

`s31 lower FILE.s31` prints the exact JSON consumed by Zig. The function
above lowers to this complete relation (whitespace has no mathematical
meaning, although source bytes are part of package identity):

```json
{
  "version": 1,
  "name": "preimage4",
  "inputs": [
    {"name":"target","kind":"m31","length":4,"visibility":"public"},
    {"name":"secret","kind":"u16","length":4,"visibility":"private"}
  ],
  "nodes": [
    {"name":"secret_field","op":"cast_m31","lhs":"secret"},
    {"name":"square","op":"mul","lhs":"secret_field","rhs":"secret_field"},
    {"name":"offset","op":"add_const","lhs":"square","constant":7}
  ],
  "assertions": [{"lhs":"offset","rhs":"target"}],
  "public_outputs": ["square"]
}
```

Nodes are listed after their dependencies. The validator rejects unknown
names, duplicate names, wrong shapes, noncanonical constants, invalid loop
bodies, and public ABIs wider than eight words. These are the implemented node
semantics:

| Node | Inputs and result |
| --- | --- |
| `constant` | `constant: c`, `length: N` gives `m31[N]` filled with canonical `c`. |
| `cast_m31` | `lhs: u16[N]` gives the same values as `m31[N]`. |
| `add`, `mul` | Two equally shaped `m31[N]` arrays, lane-wise modulo `p`. |
| `add_const`, `mul_const` | `m31[N]` and one canonical constant, lane-wise. |
| `repeat` | `lhs: m31[N]`, `rounds`, and a static `body` of `square`, `add_const`, `mul_const` steps. |
| `select` | Equal `m31[N]` arrays `lhs`, `rhs`; `selector: m31[1]` constrained to a bit. |
| `hash_blake2s`, `hash_blake2s_leaf/pair`, `hash_poseidon2_leaf/pair` | The [exact encodings and framing](hashes.md); each returns `m31[8]`. |

An assertion names two values of equal type and length. It is part of the
relation even if it is not used by the output expression. The JSON parser
does not accept unknown node fields. The text frontend additionally rejects
unused `bit` inputs and cross-family digest operations before the types erase.

## Assignment versus statement

A prover assignment has three named objects: `public_inputs`, optional
`private_inputs`, and `public_outputs`. For the private-witness example:

```json
{
  "public_inputs": {"target": [8, 11, 16, 1771]},
  "private_inputs": {"secret": [1, 2, 3, 42]},
  "public_outputs": {"square": [1, 4, 9, 1764]}
}
```

`prove` writes a separate statement with only `public_inputs` and
`public_outputs`; the native verifier receives that statement, the proof,
and the verification key. Public words are ordered by input declaration,
then by `public_outputs` order, and zero-fill the eight-slot ABI. A changed
public output must fail verification. A private assignment that violates the
constraints cannot make a valid proof for that public statement.

Next: [how the normalized relation becomes a circuit](circuits.md).
