# S31 text language and proof-aware core library

This is the **implemented, deliberately narrow** `.s31` frontend. It lowers to
the existing normalized relation v1. The Zig relation validator and compiler
then produce the same prover, AIR and sealed native verifier as a handwritten
`.s31.json` relation. The text compiler is not a second proving backend.

## Build and audit a program

From the repository root:

```sh
python3 src/frontends/s31/s31.py lower src/frontends/s31/examples/arith4_m31.s31
python3 src/frontends/s31/s31.py build src/frontends/s31/examples/arith4_m31.s31 --lowering direct-chip --out zig-out/s31/text-arith4
python3 src/frontends/s31/s31.py explain zig-out/s31/text-arith4
python3 src/frontends/s31/s31.py equations zig-out/s31/text-arith4
python3 src/frontends/s31/s31.py prove zig-out/s31/text-arith4 src/frontends/s31/examples/arith4.valid.json zig-out/s31/text-arith4.proof
python3 src/frontends/s31/s31.py verify zig-out/s31/text-arith4 zig-out/s31/text-arith4.proof
```

`lower` prints the exact normalized JSON relation that the Zig compiler will
consume. A text package contains `source.s31`, `source.s31.json`,
`source-map.json`, and `typed-interface.json`; the manifest hashes all four.
The proof protocol currently
binds the normalized JSON bytes. `source_text_sha256` records the original text
in the package manifest. `explain` joins text source positions to the backend's
node gate-row spans and reports the chosen profile, chip, raw/padded rows, and
preprocessed cells. `source_expressions` groups emitted nodes by source location
and lists the chip's internal row count for `iterate` when selected. A node's
gate-row span is not an additive whole-program total: shared expressions,
padding, and chip boundaries are separately represented. Use the whole
program cost report for totals.
`equations` prints source-level field equations beside their source positions,
canonical IDs, and builder gate counts. It does not expand the pinned generic
AIR's lookup, public-binding, or polynomial terms.

Equivalent handwritten JSON can have different whitespace and therefore a
different source digest, circuit identity and proof bytes. The zero-overhead
gate checks compare canonical IR, selected AIR components, raw/padded rows,
preprocessed geometry and native-verifier acceptance, rather than identical
proof byte strings.

## Syntax and staging

```text
fn step(v: [m31; 4]) -> [m31; 4] {
    v .* v + splat<4>(7_m31)
}

circuit arith4_m31(public x: [m31; 4]) -> public [m31; 4] {
    let result = iterate<256>(step, x);
    result
}
```

A file may begin with `use std@1;`, then has zero or more top-level `fn`
declarations followed by one `circuit`. Without `use`, existing sources use
the same compiler-owned standard library version implicitly. Other packages
and versions are rejected.
Functions and circuit bodies contain immutable `let` statements, optional
`assert_eq(a, b);` statements, and a final expression. Supported expressions
are names, `_m31` field literals, `+`, lane-wise `.*`, calls, parentheses, and
static array literals such as `[sibling_0, sibling_1]`. Comments start with
`//`. A scalar literal enters a circuit through `splat<N>(7_m31)`. Bare
integers are used only as the compile-time `N` in `splat<N>`, `iterate<N>`,
and `std::math::pow<N>`;
circuit arithmetic uses canonical field literals.

Every array shape and iteration count is fixed in source. Pure functions are
specialized at calls and cannot recurse. An `iterate` step is recognized before
normal node emission and must be a composition of `state .* state` (or
`std::math::square(state)`), addition of a uniform field constant, and
multiplication by a uniform field constant. The
existing relation permits 1–16 such steps and 1–32768 rounds. The current chip
is narrower: only the four-lane, public, square-then-add form at power-of-two
round counts 16–32768. Select the chip explicitly with `--lowering direct-chip`
or another chip profile; an unsupported shape fails instead of falling back.

The example above lowers to one `repeat` node with a `square` and `add_const 7`
body. With `--lowering direct-chip`, its chip rows constrain
`out[j] - in[j]^2 - 7 = 0` for each of four lanes. The indexed lookup relation
connects round outputs to round inputs and the public endpoints. See the
[source-to-AIR guide](LANGUAGE_AND_AIR.md#the-repeated-step-chip) for the full
lookup and polynomial explanation. The text form and
[`arith4_m31.s31.json`](examples/arith4_m31.s31.json) have the same normalized
relation and canonical IR digest.

## Types and library operations

| Text type | Relation representation | Constraint meaning |
| --- | --- | --- |
| `[m31; N]` | `m31[N]` | Each word is canonical modulo `2^31-1`. |
| `[u16; N]` | `u16[N]` | Input words are range checked by the selected proof profile. |
| `Bytes32` | `u16[16]` | Thirty-two bytes packed into sixteen little-endian, range-checked limbs. |
| `UInt256` | `u16[16]` | Unsigned integer with the same limbs; arithmetic is explicit. |
| `bit` | `m31[1]` | Must be a direct input used by `select`; the circuit constrains `b²=b`. |
| `Digest<Poseidon2>` | `m31[8]` | Nominal type for the pinned field-native digest. |
| `Digest<Blake2sReduced>` | `m31[8]` | Nominal type for eight reduced BLAKE2s words. |

These digest types prevent text programs from mixing hash families even though
both erase to `m31[8]` in relation v1. They do **not** claim that any arbitrary
eight-word input was produced by hashing; a digest input is a claimed value.
Raw BLAKE2s-256 bytes are distinct from its reduced M31-word digest.

| Function/operator | Lowering | Preconditions |
| --- | --- | --- |
| `a + b`, `a .* b` | Lane-wise `add`/`mul`, or constant variants | Equally shaped `[m31; N]`. |
| `splat<N>(c_m31)` | Compile-time uniform constant | Canonical M31 literal; materialized only if needed. |
| `m31_from_u16(x)` | `cast_m31` | Explicit value-preserving conversion. |
| `select(bit, a, b)` | `select` | Same array/digest type; bit is a direct input and is constrained. |
| `poseidon2_leaf(x)`, `blake2s_leaf(x)` | Corresponding leaf hash node | 4, 8, 12, or 16 M31 words. |
| `poseidon2_pair(a,b)`, `blake2s_pair(a,b)` | Ordered-pair hash node | Two digests of the selected family. |
| `merkle_path_poseidon2(leaf, siblings, directions)` and `merkle_path_blake2s(...)` | Optional leaf hash, then two selects and one ordered pair per level | Raw M31 leaf or same-family digest; static arrays of 1–16 digest and bit inputs. |
| `assert_eq(a,b);` | Relation assertion | Equally typed operands; checked as a proof constraint. |
| `std::bytes::to_u256_le(x)`, `from_u256_le(x)` | No node; change nominal type | Explicit little-endian interpretation of `Bytes32` or `UInt256`. |
| `std::bytes::limbs_m31(x)` | `cast_m31` | `Bytes32` or `UInt256`; preserves all sixteen limb values. |

Qualified standard operations are compiler-owned. An explicit `use std@1;`
pin is recorded in `stdlib-lock.json`; the lock digest is embedded in the
verification key and checked by the generated native verifier. Legacy text
sources get the same version 1 lock implicitly. `std::field::from_u16`,
`std::field::select`,
`std::hash::{poseidon2_leaf,poseidon2_pair,blake2s_leaf,blake2s_pair}` and
`std::merkle::{path_poseidon2,path_blake2s}` are aliases of the corresponding
unqualified operations above. The aliases emit identical normalized relations.
There is no general module loader or third-party package system yet.

| Math operation | Lowering | Preconditions |
| --- | --- | --- |
| `std::math::neg(x)` | `mul_const(x, p-1)` | `[m31; N]`; compile-time constants fold. |
| `std::math::sub(x,y)` | Negate `y`, then add; a constant `y` becomes one `add_const`. | Equally shaped `[m31; N]`. |
| `std::math::square(x)` | `mul(x,x)` | `[m31; N]`. |
| `std::math::pow<K>(x)` | Static square-and-multiply chain | `[m31; N]`, `0 <= K < p`; `x^0 = 1`. |
| `std::math::sum([a,...])` | Balanced addition tree over statically grouped terms | 1–64 equally shaped `[m31; N]` values. |
| `std::math::dot([a,...],[b,...])` | Pairwise products and balanced sum | Equal groups of 1–64 equally shaped `[m31; N]` values. |
| `std::math::sum_lanes(x)` | Constrained extraction and balanced sum of every lane in one array | `[m31; N] -> [m31; 1]`, `1 <= N <= 4096`. |
| `std::math::dot_lanes(a,b)` | One pointwise `mul` followed by `sum_lanes` | Equal `[m31; N]` shapes; returns `[m31; 1]`. |
| `std::math::poly_eval(x,[c0,...,cd])` | Horner evaluation, low-degree coefficient first | 1–64 coefficients, each shaped like `x`. |
| `std::math::add_u256(a,b)` | `u256_add` with sixteen constrained carries | Two `UInt256` values; modular sum. |
| `std::math::add_u256_checked(a,b)` | `u256_add_checked` with final carry constrained to zero | Two `UInt256` values; overflow rejected. |
| `std::math::le_u256(a,b)` | `u256_le` with sixteen constrained borrows | Two `UInt256` values; `[m31; 1]` Boolean result. |

The [wide-value worked example](docs/wide-values.md) gives the exact integer
equations, source, assignment, and current Bitcoin boundary. Its `u16`
operands use the general `gate` proof profile: the current sparse profile
rejects the equality rows used by these constraints.

[`math_polynomial4.s31`](examples/math_polynomial4.s31) is a complete math
example, with an equivalent [normalized relation](examples/math_polynomial4.s31.json)
and a [valid assignment](examples/math_polynomial4.valid.json). The
[library brief](../../../design/s31/STDLIB_MATHLIB.md) shows its six arithmetic
nodes, AIR equations, and the remaining work for a full standard/math library.
The [versioned library example](examples/mathlib4.s31) exercises the three
static group helpers. Its [handwritten relation](examples/mathlib4.s31.json)
has the same canonical IR and AIR row geometry. The [library chapter](docs/library.md)
works through the values, lowering, and package lock.
Unlike static-group `sum` and `dot`, the [lane statistics example](examples/lane_stats4.s31)
reduces positions of one witness array. Its [handwritten relation](examples/lane_stats4.s31.json)
uses a normalized `sum_lanes` node. Each extracted lane and addition is
constrained by circuit gates; `dot_lanes` emits one pointwise multiplication
followed by the same reduction.

The BLAKE2s leaf and pair operations use `S31LEAF1` and `S31PAIR1`
personalization and little-endian canonical M31 words. Their digest words are
individually reduced modulo M31. Poseidon2 uses the pinned Stark-V constants
and the S31 sponge and ordered-parent framing. Exact encodings and existing
security-review limits are in the [hash library brief](../../../design/s31/HASH_LIBRARY.md).
The library's `encode_m31_words_le` and `decode_m31_words_le` pin the host-side
four-byte word format and reject noncanonical values. `Bytes32` is a nominal
32-byte value backed by sixteen `u16` limbs; arbitrary-length byte arrays are
not yet first-class circuit values in this text subset.

`merkle_path_poseidon2` accepts a source expression such as:

```text
let root = merkle_path_poseidon2(
    leaf, [sibling_0, sibling_1], [direction_0, direction_1]);
```

The brackets group existing inputs at compile time. They create no witness
array and must appear directly as Merkle arguments. They cannot be returned as
a circuit value. The compiler emits one leaf node, then for each level two constrained
select nodes and one ordered-pair hash node. The
[`merkle_path2_poseidon.s31`](examples/merkle_path2_poseidon.s31) example is
complete. A depth-one program written with ordinary pure functions and `let`
is [`merkle_path1_poseidon.s31`](examples/merkle_path1_poseidon.s31); it lowers
exactly to the existing JSON example.

[`preimage4.s31`](examples/preimage4.s31) shows an `assert_eq` over a private
`u16` witness and a public M31 target. It lowers exactly to the existing
relation, including the equality assertion.

## Checks and current boundary

```sh
python3 -m unittest discover -s src/frontends/s31 -p 'test_text_frontend.py' -v
python3 src/frontends/s31/acceptance_text_v1.py
zig build --build-file src/frontends/s31/build.zig test -Doptimize=ReleaseSafe
```

The Python tests compare five complete text relations to existing JSON
relations, check independent arithmetic/hash/path values, and reject wrong
digest families, unused unconstrained bits, dynamic loop counts, and recursion.
The acceptance script builds both text and JSON forms for the recurrence and
Poseidon2 Merkle path, checks their canonical IR and cost geometry, and proves
both forms through their generated native verifiers. It also requires rejection
of a changed public output and a non-Boolean private direction. The Zig suite
independently validates and compiles the emitted relation.

This initial text language has no user-defined modules or imports, macros, arbitrary recursion,
witness-dependent control flow, computed bit selectors, general `map`/`fold`,
or private circuit-to-chip boundary. It reports source positions for emitted
nodes and gate spans, but it does not yet render every symbolic AIR polynomial
as source text. Expanding those features belongs after the backend has a
general cost model and reviewed mixed circuit/chip boundary.
