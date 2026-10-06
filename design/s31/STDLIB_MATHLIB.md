# S31 standard and math library: current contract and remaining work

Status: compiler-owned `std@1` package with an explicit source pin, static
math helpers, and constrained lane reductions, 2026-10-06. This document distinguishes
what is executable today from the work needed for a useful library release.
The [text language guide](../../src/frontends/s31/TEXT_LANGUAGE.md) defines the
implemented syntax; the [MVP roadmap](MVP_ROADMAP.md) tracks proof-backend work.

## What works now

The text frontend exposes compiler-owned qualified operations. They lower into
the same normalized relation as the older unqualified primitives. A leading
`use std@1;` explicitly pins the package; old sources use version 1 implicitly.
Text packages include a source-hashed `stdlib-lock.json`, and its digest is
bound in the generated verification key and native verifier. There is no
general module loader or user-published package format yet.

| Namespace | Implemented operations | Backend relation |
| --- | --- | --- |
| `std::math` | `neg`, `sub`, `square`, static `pow<K>`, static-group `sum`, `dot`, `poly_eval`, fixed-array `sum_lanes`, `dot_lanes` | Existing M31 add/mul and constant gates; `sum_lanes` adds constrained unpacking across packed circuit words. |
| `std::field` | `from_u16`, `select` | Explicit conversion; direct input bit selector with `b²-b=0`. |
| `std::hash` | Poseidon2 and BLAKE2s reduced leaf/pair hashes | Existing pinned hash nodes. |
| `std::merkle` | Fixed-depth Poseidon2 and BLAKE2s paths | Hash nodes plus two constrained selects per level. |

All math operations have fixed shapes. Most operate independently on the lanes
of `[m31; N]`; `sum_lanes` and `dot_lanes` reduce them to `[m31; 1]`. The
compiler checks types and canonical field constants before relation emission.
`pow<K>` requires a compile-time exponent `0 <= K < p`, where
`p = 2^31 - 1`, and defines `x^0 = 1` even for `x = 0`. It uses left-to-right
binary exponentiation: for nonconstant `x`, `K > 0` takes at most
`floor(log2 K) + popcount(K) - 1` multiplication nodes. This is a transparent
upper bound, not a proof of an optimal addition chain. Constant inputs fold at
compile time.

For example, [`math_polynomial4.s31`](../../src/frontends/s31/examples/math_polynomial4.s31)
computes `f(x) = x^5 + 3x - 7` in four independent lanes. The source expression
`std::math::pow<5>(x)` lowers to `x²`, `(x²)²`, then `x⁴·x`. Multiplication by
three is one constant gate; subtraction of seven is one add-constant gate with
coefficient `p-7`. The exact [normalized relation](../../src/frontends/s31/examples/math_polynomial4.s31.json)
has six arithmetic nodes. For each multiplication gate the AIR enforces
`out - left·right = 0`; for an add-constant gate it enforces
`out - left - c = 0`, all over M31. Four coordinate values share the existing
QM31 circuit arithmetic row. Public binding and padded trace rows are included
in the package cost report, so six source nodes do not imply six total proof
rows. The handwritten JSON and text forms are checked for identical canonical
IR and cost geometry, then each proof is checked by its generated native
verifier in `acceptance_text_v1.py`.

This is a zero-overhead *source abstraction* relative to writing these same
nodes by hand. It is not a claim that the chosen exponentiation chain or the
current gate profile is globally optimal. `pow<p-2>(x)` computes `0` when
`x=0`; it is not a safe division or an asserted nonzero inverse.

The [new `mathlib4` program](../../src/frontends/s31/examples/mathlib4.s31)
uses Horner polynomial evaluation, static dot, and static sum in four M31
lanes. Its [handwritten relation](../../src/frontends/s31/examples/mathlib4.s31.json)
has the same canonical IR digest, preprocessed root, and row geometry.
Canonicalization shares a repeated `2x` term: ten text relation nodes become
nine unique arithmetic nodes. The complete direct arithmetic circuit uses
334 raw rows, 512 padded rows, and 4,096 fixed cells. Both package forms
produce proofs accepted by their generated native verifiers. The [library
chapter](../../src/frontends/s31/docs/library.md) gives exact types,
coefficient order, a hand calculation, and the lock format.

The static groups are lists of existing arrays in source. `sum` and `dot`
reduce across that list. In contrast, `sum_lanes(x)` sums the positions of
one `[m31; N]` value, and `dot_lanes(x,w)` multiplies matching positions then
sums them. The new normalized `sum_lanes` operation unpacks each packed M31
coordinate through constrained circuit gates, uses a balanced addition tree,
and publishes a one-word result. It does not expose general indexing.

[`lane_stats4.s31`](../../src/frontends/s31/examples/lane_stats4.s31) is a
private-witness example. With `x=[2,3,5,7]` and `weights=[11,13,17,19]`,
the total is 17, the dot product is 279, and the public output is 296. Its
[handwritten relation](../../src/frontends/s31/examples/lane_stats4.s31.json)
has the same canonical IR, preprocessed root, and row geometry as the text
form. Under `direct-gate`, the circuit has 346 raw QM31 rows, 512 padded
rows, and 4,096 fixed cells. A text proof of 55,883 bytes was accepted by its
native verifier; changing the public output to 297 was rejected. These are
one-run measurements, not a performance comparison with Cairo.
Each four-lane reduction currently accounts for ten QM31 builder gates.
A future packed-coordinate projection could reduce that cost if its field
identity and partial-wire behavior are proved; the current unpack-and-add
path is the correctness baseline.

## Definition of a useful v1 library

A useful v1 means programs can import a versioned library and build common
field, vector, boolean/range, hash, and commitment relations while receiving a
program-bound native verifier. Every helper needs a documented type and field
semantics, an inspectable lowering, an independent value oracle, and at least
one positive and negative proof test when it introduces a new constraint shape.
Library source and compiler version must be bound in the package manifest and
verification key; resolution may not depend on an unpinned local file at prove
time. A helper's cost report must expose both its own gates and any table or
chip it activates.

| Work package | Exit gate | Rough effort for one experienced engineer |
| --- | --- | ---: |
| General modules and shape-polymorphic pure functions | Extend the current `use std@1` pin to named modules, deterministic external resolution, lockfiles for imported source, and source maps through those calls. | 2–4 weeks |
| Field/vector core | Add fixed-array indexing, concatenation, and vector/matrix kernels; direct-gate proofs match independent oracles. Static-group and lane reductions, dot products, and Horner evaluation are implemented. | 2–4 weeks |
| Nonzero inverse and checked division | Witness generation plus `x·inv=1`, a nonzero contract, zero rejection, batch inverse cost comparison, and native-verifier mutation tests. | 2–3 weeks |
| Boolean/range/integer core | Computed bits, comparisons, range constraints and explicit integer/field casts; no host-only assertions or unconstrained hint outputs. | 3–6 weeks |
| Library release discipline | API/version policy, corpus of positive and negative proofs, cost regression gates, and audit views from source to AIR polynomial. | 2–3 weeks |

These are overlapping work packages, not additive calendar promises. A focused
field-and-hash library with modules, reductions, and checked inversion is
roughly **6–10 engineer-weeks** from this prototype. A broader v1 with robust
integer/boolean primitives and release gates is roughly **10–16 engineer-weeks**.
Those estimates exclude a dedicated Poseidon2 chip, general private
circuit-to-chip boundaries, recursion, and a formal soundness review. The
existing Merkle and hash operations are useful now, but larger hash workloads
still need the backend efficiency work in the [MVP roadmap](MVP_ROADMAP.md).

## Engineering order

1. Extend the existing `std@1` lock to named modules and imported source.
   The current package key already binds the compiler-owned library source
   digest; a user module needs the same deterministic resolution.
2. Extend array operations past the implemented lane reductions. Fixed-array
   projection, indexing, concatenation, and small linear algebra remain.
   Compare their direct arithmetic cost and retain matched source/JSON
   programs and independent scalar oracles.
3. Add checked inversion with an explicit nonzero contract. A witness-supplied
   inverse is useful only when the AIR enforces `x·y-1=0`; the prover must reject
   zero input before committing. Compare this with static exponentiation on
   actual circuit cost.
4. Add computed booleans and range/integer gadgets as typed values. Review
   lookup closure and boundary constraints before exposing comparisons or
   conditional arithmetic in the standard library.
5. Promote math kernels into chips only where measured end-to-end proving,
   verification, memory, and proof size improve. Keep the direct circuit as a
   correctness oracle and preserve the generated native verifier for each
   selected profile.

The principal blocker is therefore not a collection of function names: the
normalized relation lacks general projections, computed
bits, and constrained witness hints, while the text frontend lacks general
modules. The versioned compiler-owned package and matched math examples
establish a source-to-AIR audit pattern without changing the proof protocol.
