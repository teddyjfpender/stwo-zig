# S31 standard and math library: current contract and remaining work

Status: first qualified library surface, 2026-10-06. This document distinguishes
what is executable today from the work needed for a useful library release.
The [text language guide](../../src/frontends/s31/TEXT_LANGUAGE.md) defines the
implemented syntax; the [MVP roadmap](MVP_ROADMAP.md) tracks proof-backend work.

## What works now

The text frontend exposes compiler-owned qualified operations. They lower into
the same normalized relation as the older unqualified primitives. There is no
module loader or user-published package format yet.

| Namespace | Implemented operations | Backend relation |
| --- | --- | --- |
| `std::math` | `neg`, `sub`, `square`, static `pow<K>` | Existing M31 add/mul and constant gates. |
| `std::field` | `from_u16`, `select` | Explicit conversion; direct input bit selector with `b²-b=0`. |
| `std::hash` | Poseidon2 and BLAKE2s reduced leaf/pair hashes | Existing pinned hash nodes. |
| `std::merkle` | Fixed-depth Poseidon2 and BLAKE2s paths | Hash nodes plus two constrained selects per level. |

All math operations are lane-wise on `[m31; N]` and have fixed shapes. The
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
| Versioned modules and shape-polymorphic pure functions | Explicit `use`/imports, lockfile or embedded version, deterministic specialization, source maps through calls, compiler-bound library identity. | 2–4 weeks |
| Field/vector core | `sum`, `dot`, fixed-array indexing, concatenation, vector/matrix kernels, and constant-folding checks; direct-gate proofs match independent oracles. | 2–4 weeks |
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

1. Freeze library identity and add explicit module imports before many more
   source-level helpers. Otherwise packaged verifiers cannot state which
   library implementation they bind.
2. Add array projections and reductions with a direct arithmetic lowering.
   Use matched source/JSON programs and independent scalar oracles to guard
   semantics and cost. This unlocks `sum`, `dot`, polynomial evaluation, and
   small linear algebra without a new AIR profile.
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
normalized relation lacks projections, reductions, computed bits, and
constrained witness hints, while the text frontend lacks versioned modules.
The qualified surface and the polynomial example establish the library's
semantics and audit pattern without changing the proof protocol.
