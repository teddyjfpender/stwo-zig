# S31 standard and math library: current contract and remaining work

Status: compiler-owned `std@1` package with an explicit source pin, static
math helpers, constrained lane reductions, and checked field inversion/division,
2026-10-06. This document distinguishes
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
| `std::math` | `neg`, `sub`, `square`, checked `inv`, `div`, static `pow<K>`, static-group `sum`, `dot`, `poly_eval`, fixed-array `sum_lanes`, `dot_lanes`, `add_u256`, `add_u256_checked`, `sub_u256`, `sub_u256_checked`, `le_u256` | M31 arithmetic and constrained packed reduction; inversion uses a pointwise product and arithmetic zero assertion per four active lanes, and division reuses the inverse; wide operations use sixteen range-checked digits and Boolean carries/borrows. |
| `std::field` | `from_u16`, `is_zero`, `select` | Explicit conversion; direct input bits have `b²-b=0`, while computed zero bits use two algebraic constraints. |
| `std::bytes` | `to_u256_le`, `from_u256_le`, `limbs_m31` | Explicit nominal byte/integer reinterpretation and value-preserving cast of sixteen `u16` limbs. |
| `std::hash` | Poseidon2 and BLAKE2s reduced leaf/pair hashes; byte-exact SHA256d of `Bytes80` | Existing pinned hash nodes plus a constrained three-block SHA circuit. |
| `std::bitcoin` | `target_mainnet(Bytes80)` | Constrained compact `nBits` decoder with mainnet powLimit. |
| `std::merkle` | Fixed-depth Poseidon2 and BLAKE2s paths | Hash nodes plus two constrained selects per level. |

All math operations have fixed shapes. Most operate independently on the lanes
of `[m31; N]`; `sum_lanes` and `dot_lanes` reduce them to `[m31; 1]`. The
wide [256-bit example](../../src/frontends/s31/docs/wide-values.md) treats
these values as a separate type: ordinary addition wraps modulo $2^{256}$,
checked addition forbids overflow, and unsigned comparison returns one M31
bit. It is a base for the
[Bitcoin header light-client plan](BITCOIN_LIGHT_CLIENT.md), which also
now has byte-exact SHA256d and compact-target rules for a single mainnet
header. A one-level `gate` verifier exists, but the Bitcoin profile still
requires broader chain policy, a wider public statement, and a sparse-wide
in-circuit verifier.

The compiler checks types and canonical field constants before relation emission.
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
`x=0`; it is not a safe division or an asserted nonzero inverse. The new
`std::math::inv(x)` instead witnesses `r` and constrains `x·r=1` on every
active lane; `std::math::div(a,x)` shares that inverse and multiplies by `a`.
Zero is rejected before proving, and a partial final packed group has a
circuit-validity test. The [field division example](../../src/frontends/s31/examples/field_div4.s31)
has a 55,800-byte `direct-gate` proof with 327 raw rows (512 padded) in one
`ReleaseFast` run; the [acceptance corpus](../../src/frontends/s31/acceptance_field_div_v1.py)
checks nine native proofs (including boundary and seeded random inputs) and
five negative cases. This is a single-program
cost observation, not a batch-inverse performance comparison.

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
sums them. The normalized `sum_lanes` operation adds packed QM31 words in a
balanced tree, masks unused coordinates in a partial final word, and applies
a constrained field-linear projection into the base coordinate. In the basis
`(1, i, u, iu)` with `i² = -1` and `u² = 2 + i`, the base coordinate of
`(a + bi + cu + diu) * (1 - i + u/5 - 3iu/5)` is `a+b+c+d` in M31. A
pointwise base mask isolates that coordinate. The projection uses circuit
multiplication gates, so the sum is checked by the proof. It does not expose
general indexing.

[`lane_stats4.s31`](../../src/frontends/s31/examples/lane_stats4.s31) is a
private-witness example. With `x=[2,3,5,7]` and `weights=[11,13,17,19]`,
the total is 17, the dot product is 279, and the public output is 296. Its
[handwritten relation](../../src/frontends/s31/examples/lane_stats4.s31.json)
has the same canonical IR, preprocessed root, and row geometry as the text
form. Under `direct-gate`, the packed lowering has 323 raw QM31 rows, 512
padded rows, and 4,096 fixed cells. The earlier unpack-and-add lowering had
346 raw rows; each four-lane sum now uses two builder gates instead of ten.
The partial-word and wraparound cases have circuit-validity tests, and the
native verifier accepts the correct output and rejects a changed one. Proof
bytes and proving times vary with proof randomness; the [reproducible 64-lane
benchmark](measurements/packed-reduction-2026-10-06.json) records matched
programs and native-verifier checks. These are local measurements, not a
performance comparison with Cairo.

On that private 64-lane reduction, the same normalized relation uses 639 to
474 raw rows and 1,024 to 512 padded rows. Across ten distinct valid
witnesses, median proof size fell from 73,567.5 to 55,578 bytes (24.5%).
Median prover-reported time after subtracting its logged proof-of-work stages
fell from 1.983 to 1.358 ms (1.46×); whole-process median prove time was
117 to 111 ms. The transcript-dependent proof-of-work time ranged widely,
so this short run does not establish a stable end-to-end proving speedup.

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
| Nonzero inverse and checked division | **Core implemented:** witness generation, `x·inv=1`, zero rejection, direct-gate proof and native-verifier negative cases. Remaining: batch inverse cost comparison and wider random proof corpus. | Remaining effort depends on batching design. |
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
3. Extend the implemented checked inverse with randomized proof vectors and
   compare batched inversion with static exponentiation on actual circuit
   cost. Preserve the direct profile's one-producer lookup invariant and
   the zero-input rejection constraint.
4. Extend the implemented `is_zero` computed bit to range/integer gadgets as typed values. Review
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
