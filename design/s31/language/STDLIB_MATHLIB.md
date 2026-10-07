# S31 standard and math library: current contract and remaining work

Status: compiler-owned `std@1` package with an explicit source pin, static
math helpers, constrained lane reductions, checked field inversion/division,
proved fixed-array views, and source-level `Target`, `Work`, and `ChainWork`
types, 2026-10-07. This document distinguishes
what is executable today from the work needed for a useful library release.
The [text language guide](../../../src/frontends/s31/docs/reference/TEXT_LANGUAGE.md) defines the
implemented syntax; the [MVP roadmap](../MVP_ROADMAP.md) tracks proof-backend work.

## What works now

The text frontend exposes compiler-owned qualified operations. They lower into
the same normalized relation as the older unqualified primitives. A leading
`use std@1;` explicitly pins the package; old sources use version 1 implicitly.
Text packages include a source-hashed `stdlib-lock.json`, and its digest is
bound in the generated verification key and native verifier. There is no
general module loader or user-published package format yet.

| Namespace | Implemented operations | Backend relation |
| --- | --- | --- |
| `std::math` | `neg`, `sub`, `square`, checked `inv`, `div`, static `pow<K>`, static-group `sum`, `dot`, `matvec`, `matmul`, `poly_eval`, fixed-array `sum_lanes`, `dot_lanes`, `add_u256`, `add_u256_checked`, `sum_u256`, `sum_u256_checked`, `sub_u256`, `sub_u256_checked`, `le_u256`, `lt_u256`, `gt_u256`, `ge_u256`, `eq_u256`, `ne_u256`, `min_u256`, `max_u256` | M31 arithmetic and constrained packed reduction; `matvec` and `matmul` expand to ordinary dot and add nodes; inversion uses a pointwise product and arithmetic zero assertion per four active lanes, and division reuses the inverse; wide operations use sixteen range-checked digits and Boolean carries/borrows. Fixed wide sums expand to balanced trees of ordinary checked or wrapping additions. Ordering helpers reuse `u256_le`, Boolean logic, and a range-preserving wide select. |
| `std::array` | Static-reference and runtime-array `get<K>`, `concat`, `take<K>`, `drop<K>`, `reshape<R>`, `flatten` | Static forms erase to references. Runtime forms use `array_get`, `array_concat`, and `array_slice` relation nodes. Aligned packed source words alias existing wires; shifted views use constrained unpack/repack gates. |
| `std::field` | `from_u16`, `is_zero`, `select` | Explicit conversion; direct input bits have `b²-b=0`, while computed zero bits use two algebraic constraints. Selection also accepts `UInt256` and keeps each chosen limb equal to a range-checked input limb. |
| `std::bool` | `not`, `and`, `or`, `xor`, `select` | Scalar typed bits; input bitness is constrained, and every result follows from Boolean field identities. |
| `std::bytes` | `to_u256_le`, `from_u256_le`, `limbs_m31` | Explicit nominal byte/integer reinterpretation and value-preserving cast of sixteen `u16` limbs. |
| `std::hash` | Poseidon2 and BLAKE2s reduced leaf/pair hashes; byte-exact SHA256d of `Bytes80` | Existing pinned hash nodes plus a constrained three-block SHA circuit. |
| `std::bitcoin` | `target_mainnet(Bytes80) -> Target`, `pow_valid(Bytes80)`, `block_work(Target) -> Work`, `chainwork_from_work(Work) -> ChainWork`, `accumulate_chainwork(ChainWork, Work) -> ChainWork`, explicit `target_u256`, `work_u256`, `chainwork_u256` views | Constrained compact `nBits` decoder with mainnet powLimit. `pow_valid` expands to byte-exact SHA256d, an explicit little-endian target view, and unsigned comparison. `block_work` lowers to checked 256-bit division with a 512-bit product relation and strict remainder bound; chainwork addition has a constrained final carry. |
| `std::merkle` | Fixed-depth Poseidon2 and BLAKE2s paths | Hash nodes plus two constrained selects per level. |

All math operations have fixed shapes. Most operate independently on the lanes
of `[m31; N]`; `sum_lanes` and `dot_lanes` reduce them to `[m31; 1]`. The
wide [256-bit example](../../../src/frontends/s31/docs/wide-values.md) treats
these values as a separate type: ordinary addition wraps modulo $2^{256}$,
checked addition forbids overflow, and unsigned comparison returns one M31
bit. It is a base for the
[Bitcoin header light-client plan](../bitcoin/BITCOIN_LIGHT_CLIENT.md), which also
now has byte-exact SHA256d and compact-target rules for a single mainnet
header. The generic Bitcoin chain fold verifies its prior circuit proof and
checks another header; the fused SHA package has a separate native verifier.
Joining that fused proof to a stable recursive fold still needs the verifier
and commitment work described in the
[recursion integration brief](../../../src/frontends/s31/docs/sha-fused-recursion.md).

`std::bitcoin::pow_valid(header)` is now the source-level shorthand for
`SHA256d(header) <= target_mainnet(header)`. The
[standard](../../../src/frontends/s31/examples/bitcoin/bitcoin_pow_valid_std.s31) and
[manual](../../../src/frontends/s31/examples/bitcoin/bitcoin_pow_valid_manual.s31)
programs normalize to structurally identical relations and have the same
cost geometry. The [acceptance script](../../../src/frontends/s31/tests/acceptance/acceptance_bitcoin_pow_valid.py)
checks the genesis header with Python's independent SHA256 and compact-target
calculation, generated native proofs, a changed public bit, and invalid nonce
and compact-target witnesses. The helper returns a constrained bit; callers
that require a valid header must assert that it equals one.

### Checked Bitcoin work division

The Zig circuit API now has checked unsigned
`divRemU256(numerator, nonzero_denominator) -> (quotient, remainder)`.
The source language exposes the complete Bitcoin calculation as
`std::bitcoin::block_work(t: Target) -> Work`. For a nonzero target `t`,
it computes Core's `floor(2^256 / (t+1))` through proved constraints:

```text
d = checked_add_u256(t, 1)
(q, r) = div_rem_u256(bitwise_not_256(t), d)
work = checked_add_u256(q, 1)
```

The [division design and measured circuit geometry](../bitcoin/BITCOIN_WORK_DIVISION.md)
show the exact byte-column equations and tests. The circuit proves `q*d+r`
as a 512-bit integer equality, `0 <= r < d`, and `d != 0`; every column is
bounded below the M31 modulus. The Zig API and S31 source now distinguish
`Target`, `Work`, and `ChainWork`. They erase to the same sixteen `u16` limbs
only after source type checking; a direct nominal input is a claim, not proof
of origin. The target is constrained to the header when produced by
`target_mainnet(header)`. `accumulate_chainwork` adds a `Work` to a prior
`ChainWork` through `u256_add_checked`, so a final carry makes the relation
unsatisfiable. A general pair-returning division source operation, broader
adversarial proof corpus, and a specialized faster work chip remain open.

The source math library supports `sum_u256_checked([a,b,...])` for a fixed
group of 1–16 generic `UInt256` values. It emits a balanced tree of
`u256_add_checked` nodes, so the sum costs one proved wide addition per
extra term and rejects overflow. A `Work` value requires an explicit
`work_u256` view before entering this generic helper; use
`chainwork_from_work` and `accumulate_chainwork` to keep nominal ChainWork
semantics. The wrapping `sum_u256` uses `u256_add` nodes at the same positions. The
[checked fixture](../../../src/frontends/s31/examples/wide/u256_sum_checked.s31)
and [manual chain](../../../src/frontends/s31/examples/wide/u256_sum_checked_manual.s31)
have structurally identical normalized relations; the
[wide-value chapter](../../../src/frontends/s31/docs/wide-values.md#adding-several-256-bit-values)
shows the limb carries. This is source-level accumulation, not a nominal
specialized chainwork chip; source-level `accumulate_chainwork` now provides
the checked nominal transition. The
[acceptance record](../measurements/language/u256-static-sum-v1-2026-10-07.json)
pins three native proofs, checked overflow rejection, same-claim cross-key
replay rejection, and equal helper/manual row geometry. Its one-run proof
sizes and times do not establish a speed difference.

The compiler checks types and canonical field constants before relation emission.
`pow<K>` requires a compile-time exponent `0 <= K < p`, where
`p = 2^31 - 1`, and defines `x^0 = 1` even for `x = 0`. It uses left-to-right
binary exponentiation: for nonconstant `x`, `K > 0` takes at most
`floor(log2 K) + popcount(K) - 1` multiplication nodes. This is a transparent
upper bound, not a proof of an optimal addition chain. Constant inputs fold at
compile time.

For example, [`math_polynomial4.s31`](../../../src/frontends/s31/examples/arithmetic/math_polynomial4.s31)
computes `f(x) = x^5 + 3x - 7` in four independent lanes. The source expression
`std::math::pow<5>(x)` lowers to `x²`, `(x²)²`, then `x⁴·x`. Multiplication by
three is one constant gate; subtraction of seven is one add-constant gate with
coefficient `p-7`. The exact [normalized relation](../../../src/frontends/s31/examples/arithmetic/math_polynomial4.s31.json)
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
circuit-validity test. The [field division example](../../../src/frontends/s31/examples/arithmetic/field_div4.s31)
has a 55,800-byte `direct-gate` proof with 327 raw rows (512 padded) in one
`ReleaseFast` run; the [acceptance corpus](../../../src/frontends/s31/tests/acceptance/acceptance_field_div_v1.py)
checks nine native proofs (including boundary and seeded random inputs) and
five negative cases. This is a single-program
cost observation, not a batch-inverse performance comparison.

The [new `mathlib4` program](../../../src/frontends/s31/examples/arithmetic/mathlib4.s31)
uses Horner polynomial evaluation, static dot, and static sum in four M31
lanes. Its [handwritten relation](../../../src/frontends/s31/examples/arithmetic/mathlib4.s31.json)
has the same canonical IR digest, preprocessed root, and row geometry.
Canonicalization shares a repeated `2x` term: ten text relation nodes become
nine unique arithmetic nodes. The complete direct arithmetic circuit uses
334 raw rows, 512 padded rows, and 4,096 fixed cells. Both package forms
produce proofs accepted by their generated native verifiers. The [library
chapter](../../../src/frontends/s31/docs/library.md) gives exact types,
coefficient order, a hand calculation, and the lock format.

The static groups are lists of existing arrays in source. `sum`, `dot`,
`matvec`, and `matmul` operate on those groups; `get<K>`, `concat`,
`take<K>`, `drop<K>`, `reshape<R>`, and `flatten` rearrange references
without adding gates. The [two-by-two matrix example](../../../src/frontends/s31/examples/arrays/static_matvec.s31)
has four multiply-by-constant and three addition nodes. Its handwritten
[relation](../../../src/frontends/s31/examples/arrays/static_matvec.s31.json) and
independent assignment evaluate $(2a+3b)+(5a+7b)=44$ for $(a,b)=(2,3)$.
These operations are a partial step toward general arrays: the group is a
compile-time list of whole values, whereas a runtime `[m31; N]` contains
positions selected by an explicit `array_get` relation node.

Runtime `get<K>` and `concat` are now accepted by the native proof backend for
public M31 arrays, private M31 arrays crossing a QM31 packing boundary, and
private u16 arrays crossing that boundary. The [private M31 example](../../../src/frontends/s31/examples/arrays/array_views_private.s31)
uses `a=[2,3,5]` and `b=[7,11,p-2,17]`: positions 3 and 4 of the joined
array are 7 and 11, while position 5 of the doubled joined array is `p-4`,
so the claimed output is 14 modulo $p$. The [u16 example](../../../src/frontends/s31/examples/arrays/array_views_u16.s31)
selects 65535 from the right input after an unaligned concat. These examples
have handwritten relations, independent oracle checks, matching text/JSON
canonical IR and cost reports, and proofs accepted by generated native
verifiers. A changed public statement fails native verification; changed
output assignments fail the oracle and prover. The backend reuses raw input
wires, and an unaligned packed concat or get uses constrained unpack and
repack gates. A circuit test also corrupts the intermediate selected wire
and observes a failed gate check. In one `ReleaseFast` run, the public,
private M31, and private u16 examples used respectively 291, 336, and 284
raw QM31-operation rows (all padded to 512); the u16 profile also used five
M31-to-u32 rows. The [acceptance script](../../../src/frontends/s31/tests/acceptance/acceptance_array_views.py)
reproduces the positive and negative proofs. These are program-specific
costs, not a general view-cost benchmark.

Runtime `take<K>` and `drop<K>` now lower to a checked `array_slice` with
`out[j] = source[offset+j]`. `reshape<R>` exposes `R` row slices of a
runtime array; `flatten` concatenates equal-shaped rows. The compiler rejects
empty or escaping slices before proving. The [aligned](../../../src/frontends/s31/examples/arrays/array_slice_aligned.s31),
[shifted](../../../src/frontends/s31/examples/arrays/array_slice_shifted.s31),
[matrix](../../../src/frontends/s31/examples/arrays/array_matrix_runtime.s31), and
[u16](../../../src/frontends/s31/examples/arrays/array_slice_u16.s31) programs have
handwritten normalized relations and independent oracle assignments. A
focused Zig test confirms that an aligned packed slice adds zero QM31 rows,
while shifted M31 and u16 slices add constrained packing rows. The
[library chapter](../../../src/frontends/s31/docs/library.md) works through the
hand calculation and the exact relation equations. Native proof acceptance
for these new examples is run by `acceptance_array_views.py`. Its independent
list evaluator and changed private-witness proofs exercise the semantics;
stale claims, damaged proofs, and altered sealed keys must fail. Canonically
equivalent text and handwritten JSON relations can share a proof. The
[cost baseline](../measurements/language/array-view-cost-v1-2026-10-07.json) pins matched
text/JSON circuit rows and geometry, plus a proof-size ceiling, as a release
regression gate. Run `python3 src/frontends/s31/tests/acceptance/acceptance_array_views.py` to
check it; `--record-baseline` deliberately rewrites the record after all
native proof and rejection checks pass.

The [matrix product example](../../../src/frontends/s31/examples/arrays/static_matmul.s31)
multiplies two 2×2 static groups and then takes a weighted sum of all four
output cells. Its `reshape`, `flatten`, `take`, and `drop` calls emit no
relation nodes. The [handwritten relation](../../../src/frontends/s31/examples/arrays/static_matmul.s31.json)
lists the nineteen ordinary arithmetic nodes, and the
[independent assignment](../../../src/frontends/s31/examples/arrays/static_matmul.valid.json)
checks `(19,27,45,64)` and public word `464` for input `(2,3,5,7)`.
The text and handwritten packages have the same canonical IR digest and
299 raw/512 padded QM31 rows under `direct-gate`. Their generated native
verifiers accepted both proofs; the text verifier rejected a changed public
word, and the prover rejected an assignment claiming `465`. The two proof
files were 56,675 and 54,811 bytes in one `ReleaseFast` run; those sizes
depend on proof randomness.

The static groups are lists of existing arrays in source. `sum` and `dot`
reduce across that list. In contrast, `sum_lanes(x)` sums the positions of
one `[m31; N]` value, and `dot_lanes(x,w)` multiplies matching positions then
sums them. The normalized `sum_lanes` operation adds packed QM31 words in a
balanced tree, masks unused coordinates in a partial final word, and applies
a constrained field-linear projection into the base coordinate. In the basis
`(1, i, u, iu)` with `i² = -1` and `u² = 2 + i`, the base coordinate of
`(a + bi + cu + diu) * (1 - i + u/5 - 3iu/5)` is `a+b+c+d` in M31. A
pointwise base mask isolates that coordinate. The projection uses circuit
multiplication gates, so the sum is checked by the proof.

[`lane_stats4.s31`](../../../src/frontends/s31/examples/arithmetic/lane_stats4.s31) is a
private-witness example. With `x=[2,3,5,7]` and `weights=[11,13,17,19]`,
the total is 17, the dot product is 279, and the public output is 296. Its
[handwritten relation](../../../src/frontends/s31/examples/arithmetic/lane_stats4.s31.json)
has the same canonical IR, preprocessed root, and row geometry as the text
form. Under `direct-gate`, the packed lowering has 323 raw QM31 rows, 512
padded rows, and 4,096 fixed cells. The earlier unpack-and-add lowering had
346 raw rows; each four-lane sum now uses two builder gates instead of ten.
The partial-word and wraparound cases have circuit-validity tests, and the
native verifier accepts the correct output and rejects a changed one. Proof
bytes and proving times vary with proof randomness; the [reproducible 64-lane
benchmark](../measurements/language/packed-reduction-2026-10-06.json) records matched
programs and native-verifier checks. These are local measurements, not a
performance comparison with Cairo.

On that private 64-lane reduction, the same normalized relation uses 639 to
474 raw rows and 1,024 to 512 padded rows. Across ten distinct valid
witnesses, median proof size fell from 73,567.5 to 55,578 bytes (24.5%).
Median prover-reported time after subtracting its logged proof-of-work stages
fell from 1.983 to 1.358 ms (1.46×); whole-process median prove time was
117 to 111 ms. The transcript-dependent proof-of-work time ranged widely,
so this short run does not establish a stable end-to-end proving speedup.

## Focused library MVP contract

The supported package is the compiler-owned `std@1` API listed above.
`use std@1;` selects it explicitly; packages pin hashes of its implementation
and the compiler, and native verifiers recheck the sealed key and relation.
Changing the compiler-owned implementation requires rebuilding a package and
rerunning its proofs. This is not yet an external-module compatibility promise.

For this focused MVP, each represented family needs a documented type and
field meaning, inspectable source-to-relation and equation output, an
independent value calculation, a native proof, a changed-statement or
damaged-proof rejection, and a pinned circuit geometry ceiling. A helper that
introduces a new constraint shape also needs a direct adversarial witness
case. The [library MVP gate](../../../src/frontends/s31/tests/acceptance/library_mvp_gate.py)
is the single command for this supported surface. Its default mode includes
the [one-header ChainWork transition](../../../src/frontends/s31/examples/bitcoin/bitcoin_chainwork_step.s31):
SHA256d, mainnet target and proof-of-work check, proved block work, checked
accumulation, and a Poseidon2 commitment to the previous and next work values.
The previous work is a claimed checkpoint; this program does not prove a
whole chain from genesis.

The package supports useful field, static vector, bit, byte, hash, Merkle,
and Bitcoin work programs today. The library MVP is a **supported subset**,
not a general-purpose mathematical package or a production light client.
The next math-library family is the ten
[fixed-width unsigned and signed scalar types](FIXED_WIDTH_INTEGERS.md):
`u8` through `u128` and `i8` through `i128`, with explicit range, cast,
ordering, and overflow contracts. They are designed but not implemented;
the current `[u16; N]` limbs and M31 values do not supply those semantics.
The main additions beyond this bar are:

1. Deterministic named-module imports and a version policy for third-party
   libraries. The current source-hashed `std@1` lock covers only the
   compiler-owned package.
2. Witness-dependent indexing and broader vector kernels, each with measured
   costs and negative proof cases. Current `get<K>` and slices have static
   indices and lengths.
3. The fixed-width integer family above, plus general source-level `UInt256`
   multiplication and quotient/remainder beyond the special proved
   `block_work` calculation. A faster wide-arithmetic chip needs a measured
   crossover and sound private boundary.
4. Larger independent proof corpora and a formal review of the chip, lookup,
   and polynomial degree bounds. Native acceptance tests are evidence of
   implementation behavior, not a complete cryptographic security proof.
5. Automatic cost-based choice between generic circuits and purpose-built
   hash/math AIRs. The SHA-specific proof profiles already exist, while the
   source library's generic lowering remains the correctness baseline.
