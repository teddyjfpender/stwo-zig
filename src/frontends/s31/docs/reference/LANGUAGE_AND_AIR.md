# S31 source to circuits, AIR, and polynomials

This guide describes the **implemented** normalized S31 relation format and proof profiles. A [limited typed `.s31` text frontend](TEXT_LANGUAGE.md) now lowers into this same relation; the JSON below remains the exact compiler input. A program fixes its array lengths, graph, loop counts, public interface, and lowering when the package is built. An assignment supplies values later; it cannot change that shape. Every package includes a prover and a separate native verifier bound to its program and verification key.

## A complete function

[`examples/arith4.s31.json`](../../examples/arith4.s31.json) expresses four independent recurrences:

```json
{
  "version": 1,
  "name": "arith4",
  "inputs": [{"name": "x", "kind": "u16", "length": 4, "visibility": "public"}],
  "nodes": [
    {"name": "field", "op": "cast_m31", "lhs": "x"},
    {"name": "result", "op": "repeat", "lhs": "field", "rounds": 256,
     "body": [{"op": "square"}, {"op": "add_const", "constant": 7}]}
  ],
  "assertions": [],
  "public_outputs": ["result"]
}
```

Mathematically, with `p = 2^31 - 1`, `s[0,j] = x[j]`, and `j ∈ {0,1,2,3}`:

```text
s[i+1,j] = (s[i,j]^2 + 7) mod p,   0 <= i < 256
y[j] = s[256,j]
```

The public statement contains eight `u32` words: `x[0..4]` followed by `y[0..4]`. The input words must fit `u16`; the output words encode canonical M31 elements. The `cast_m31` changes the type, not the value. For `x = [1,2,3,65535]`, the first state is `[8,11,16,2147352585]`; the final four values are computed by the recurrence. An assignment file supplies the same named public arrays under `public_inputs` and `public_outputs`; see [`examples/arith4.valid.json`](../../examples/arith4.valid.json). The compiler and verifier check the declared types and public word count. The reference evaluator independently recomputes the output during proving.

The node list is topologically ordered. Other implemented nodes are `constant`, lane-wise `add` and `mul`, `add_const`, `mul_const`, `select`, and the BLAKE2s and Poseidon2 hash operations described below. A `repeat` body can contain `square`, `add_const`, `mul_const`, and four-lane `mix4`, with a compile-time round count. `mix4` adds the sum of all four lanes to each lane, modulo M31. The `assertions` array holds pairs such as `{"lhs":"a","rhs":"b"}` and constrains equal arrays. `u16` and `m31` inputs can be public or private; only public inputs and named public outputs enter the eight direct proof words.

## From source to a circuit

The compiler validates types and shapes, then constructs a canonical SSA graph. It folds constants and merges identical expressions before lowering. The package records hashes of the source and canonical IR. The compiled circuit has a fixed graph for every assignment to that source.

Four M31 values are packed into the four coordinates of one QM31-backed SIMD wire. S31 arithmetic here is **coordinate-wise M31 arithmetic**. In particular, `square` means four independent M31 squares, not one QM31 field square. This distinction is enforced by the circuit builder's pointwise multiplication gate.

Under `--lowering gate`, each recurrence round becomes one four-lane pointwise multiplication gate and one four-lane addition gate. The circuit also adds constrained input guesses, public-output bindings, address/permutation rows, and M31-to-`u32` conversion/range checks. That is why the final `qm31_ops` count is larger than `2 × rounds`. For the 256-round example, the report has 829 raw arithmetic rows, padded to 1024. The gate AIR's preprocessed columns fix the operation flags and wire addresses for each row; its witness columns carry values. Lookup arguments force a producer and every consumer of a wire address to agree. The arithmetic gate constrains the declared operation on those values. A host-side evaluation alone would not constrain the proof.

The source map in the cost report traces source nodes, assertions, and public bindings to their circuit row spans. The canonical graph and circuit topology are part of the sealed package, so a later assignment cannot inject gates or choose a different operation.

## The repeated-step chip

`--lowering chip` recognizes this exact four-lane recurrence shape: one public `u16[4]` or `m31[4]` input, an optional `cast_m31`, one `repeat` of `square` then `add_const`, one public output, and a power-of-two round count from 16 to 32768. The chip mode replaces the unrolled repeat region with four constrained output guesses in the circuit. Other circuit work, including public bindings, remains. Unsupported programs are rejected in chip mode.

The chip contributes one row per round, with nine base columns:

| Column | Value in row `i` |
| --- | --- |
| `index` | `i` |
| `in[0..4]` | `s[i,0..4]` |
| `out[0..4]` | `s[i+1,0..4]` |

For each lane `j`, its AIR evaluates the polynomial constraint

```text
C_step,j = out[j] - in[j]^2 - 7 = 0.
```

This local equation alone does not connect one row to the next. The chip therefore emits two indexed lookup tuples per row, with a fixed chip-domain tag `D`:

```text
+ (D, index,   in[0],  in[1],  in[2],  in[3])
- (D, index+1, out[0], out[1], out[2], out[3])
```

Let `H(t) = Σ alpha^k t[k] - z`, where `alpha` and `z` are transcript challenges in QM31. The chip's LogUp trace accumulates `1/H(input_tuple) - 1/H(output_tuple)`. Two secure extension-field values per row occupy eight M31 interaction columns. The AIR checks the first reciprocal and the cumulative-sum update, adding two constraints to the four `C_step` equations. Its claimed sum is closed by public endpoint terms:

```text
claimed_sum - 1/H(D, 0, x[0..4]) + 1/H(D, R, y[0..4]) = 0.
```

The circuit binds those same `x` and `y` values in its own public-output relation. The chip and circuit components share one transcript, one set of commitments, one composition polynomial, and one FRI proof. The native verifier checks both lookup closures and calls the core STARK verifier once with the combined component list. The chip index is committed, so a duplicated or skipped index changes the indexed lookup multiset. Soundness depends on the standard random lookup compression and the fact that `R < p`; the current implementation has tests for wrong endpoints, a middle transition, indices, constant, interaction cells, and claimed sum.

## Sparse arithmetic proof profile

The default `gate` profile uses the pinned eleven-component circuit AIR and 45 preprocessed columns, even for arithmetic-only code. `chip` adds the step component to that same full profile. `sparse-gate` and `sparse-chip` use a separately versioned arithmetic profile. It keeps the `qm31_ops`, `m31_to_u32`, and `range_check_16` circuit components, with 12 preprocessed columns: eight operation/address columns, three conversion columns, and the `seq_16` table. It omits Eq, XOR, Blake-G, and their fixed tables. `sparse-chip` also appends the step component. `sparse-wide-gate` keeps those three components plus Eq and its two address columns, so it can prove carry and borrow constraints over `UInt256`; it omits XOR and Blake-G. Each sparse profile rejects unsupported gate families based on the compiled graph, never on witness values.

The sparse-v3 profile **still uses the M31-to-`u32` converter and `seq_16` range table**. The direct-M31 profile below removes them for all-M31 arithmetic programs. Each profile has its own key schema, proof envelope, circuit identity, transcript tag, tree geometry, component order, and native verifier path. Proofs cannot be replayed between profiles.

### Direct M31 public values

The separately versioned `direct-gate` and `direct-chip` modes implement that direct ABI for arithmetic programs whose inputs are all `m31`. [`examples/arith4_m31.s31.json`](../../examples/arith4_m31.s31.json) expresses the same recurrence as the first example with an `m31[4]` input and no cast. Its eight public words encode canonical M31 values directly. The compiler binds each word as a base-field circuit value; the native verifier rejects any word `>= p`. No M31-to-`u32` conversion is generated, and the circuit has no `u16` range obligation.

The direct profile selects only the QM31 operation AIR component, with eight preprocessed columns. Each guessed M31 scalar is constrained in the circuit by a pointwise multiplication with the base-field unit, which forces its other QM31 coordinates to zero. Public binding gates then connect those scalars to the verifier's canonical M31 words. Its chip variant adds the same repeated-step component and indexed lookup closure described above. It has its own transcript tag, circuit identity, key schema and `S31NAT4G/C` proof envelopes. A direct proof cannot be decoded as a sparse-v3 proof. At 256 rounds, the direct chip has 4,096 preprocessed cells and a 60,616-byte proof for the example assignment. The equivalent sparse-v3 chip with `u32` public binding has 69,680 cells and a 245,493-byte proof for the same source and assignment; these figures are proof artifacts, not timing claims.

For this example, the sparse profile has 69,680 preprocessed cells rather than the full profile's 4,248,656. Those counts measure a real fixed-table reduction. Proving time depends on trace size, hashing, FRI, and proof-of-work as well; use the measured profile record for timing claims.

## Where the polynomials enter

The prover writes each AIR column as field evaluations over a Stwo circle domain, interpolates a low-degree polynomial for that column, and commits its evaluations. On the trace domain, every row equation above must vanish. In schematic notation, for each constraint expression `C(X)` over the trace and its vanishing polynomial `Z_trace(X)`, the prover contributes a quotient `C(X) / Z_trace(X)` to a random linear combination. The implementation evaluates those quotients on a larger domain and at the verifier's sampled out-of-domain point. The gate components use the same composition mechanism for operation equations and lookup recurrences. FRI tests the degree bound of the resulting committed composition; random openings link it to the committed trace columns. The native verifier recomputes the constraint evaluations and challenges from the package key and public statement.

This explains the role of each layer:

```text
S31 JSON → typed SSA → circuit gates and optional chip → AIR trace columns
         → polynomial constraints and lookup closures → PCS/FRI proof
         → generated native verifier + sealed verification key
```

The chip's `C_step,j` is a direct example of a vanishing polynomial constraint. The indexed lookup is a separate global consistency constraint: it links the rows without a next-row column. Neither the prover's computation of `y` nor the reference evaluator substitutes for those AIR checks.

## A second function and the current boundary

A small affine relation is available as [`examples/affine4_v1.s31.json`](../../examples/affine4_v1.s31.json):

```json
{
  "version": 1, "name": "affine4_v1",
  "inputs": [{"name":"x","kind":"u16","length":4,"visibility":"public"}],
  "nodes": [
    {"name":"field","op":"cast_m31","lhs":"x"},
    {"name":"scaled","op":"mul_const","lhs":"field","constant":7},
    {"name":"y","op":"add_const","lhs":"scaled","constant":11}
  ],
  "assertions": [], "public_outputs": ["y"]
}
```

It computes `y[j] = 7*x[j] + 11 mod p`; [`examples/affine4_v1.valid.json`](../../examples/affine4_v1.valid.json) supplies one assignment. The multiplication and addition each become a four-lane arithmetic gate. It can use `gate` or `sparse-gate`; it does not match the specialized repeated-step chip.

[`examples/preimage4.s31.json`](../../examples/preimage4.s31.json) uses a private `u16[4]` called `secret`, computes `square = secret²` and `offset = square + 7`, and asserts `offset == target` for a public `m31[4]` target. The assertion lowers to circuit equality gates and an Eq AIR component; it is a proof condition, not just an evaluator check. [`examples/hash4.s31.json`](../../examples/hash4.s31.json) instead hashes four private M31 words with `hash_blake2s` and exposes eight digest words. The builder lowers that node into its Blake2s/bitwise circuit gates and corresponding AIR components. Both examples require the full `gate` profile because the sparse arithmetic profile excludes Eq, Blake-G and XOR components.

## Hashes, tree nodes, and conditional paths

The hash functions operate on canonical M31 arrays. Each input element is encoded as one little-endian 32-bit word. A BLAKE2s-256 digest is read as eight little-endian `u32` words and each is reduced modulo `p`; the resulting `m31[8]` is S31's **reduced digest**, not the raw 256-bit digest. An application exchanging digests with other systems must use this exact encoding and reduction. The reduction loses up to one bit per word, and this prototype does not claim a new security bound for the reduced construction.

| Operation | Inputs | Domain/framing | Result |
| --- | --- | --- | --- |
| `hash_blake2s` | `lhs`: `m31[4/8/12/16]` | zero, for existing programs | `m31[8]` |
| `hash_blake2s_leaf` | `lhs`: `m31[4/8/12/16]` | ASCII `S31LEAF1` | `m31[8]` |
| `hash_blake2s_pair` | ordered `lhs`, `rhs`: each `m31[8]` | ASCII `S31PAIR1` | `m31[8]` |
| `hash_poseidon2_leaf` | `lhs`: `m31[4/8/12/16]` | capacity word 15 = 1; marker 1 | `m31[8]` |
| `hash_poseidon2_pair` | ordered `lhs`, `rhs`: each `m31[8]` | direct permutation of `lhs || rhs` | `m31[8]` |
| `select` | `lhs`, `rhs`: equal-length M31 arrays; `selector`: `m31[1]` | — | `lhs` for 0, `rhs` for 1 |

The two eight-byte BLAKE2s personalization values enter the [BLAKE2s parameter block](https://www.blake2.net/blake2_20130129.pdf), so a 16-word parent input still uses one compression block. The parent order matters: `pair(left,right)` and `pair(right,left)` are different statements. The circuit's Blake-G, XOR, conversion and range components constrain all BLAKE2s rounds. `select` adds `b²-b=0` for its selector and constrains every output lane to `(1-b)·lhs+b·rhs`. BLAKE2s uses the full `gate` profile. Poseidon2 uses the arithmetic-only `direct-gate` profile when all inputs are M31.

[`examples/merkle2.s31.json`](../../examples/merkle2.s31.json) hashes two private eight-word leaves and then hashes their ordered digests into one public root:

```json
{"name":"left_digest","op":"hash_blake2s_leaf","lhs":"left"}
{"name":"right_digest","op":"hash_blake2s_leaf","lhs":"right"}
{"name":"root","op":"hash_blake2s_pair","lhs":"left_digest","rhs":"right_digest"}
```

[`examples/merkle_path1.s31.json`](../../examples/merkle_path1.s31.json) proves a one-level inclusion path. Its private `direction` chooses where the leaf digest appears, while the circuit proves that the direction is a bit:

```json
{"name":"ordered_left","op":"select","lhs":"digest","rhs":"sibling","selector":"direction"}
{"name":"ordered_right","op":"select","lhs":"sibling","rhs":"digest","selector":"direction"}
{"name":"root","op":"hash_blake2s_pair","lhs":"ordered_left","rhs":"ordered_right"}
```

Repeated parent nodes can express a static-depth path. The verifier binds the final root through the generated native verifier. The [BLAKE2s acceptance script](../../tests/acceptance/acceptance_hash_suite_v5.py) compares both examples to Python's `hashlib.blake2s(person=...)` oracle, verifies real proofs, and rejects changed roots, private leaves, selectors and proof bytes.

### Poseidon2 source to arithmetic AIR

[`examples/merkle2_poseidon.s31.json`](../../examples/merkle2_poseidon.s31.json) uses the same two-leaf tree shape with field-native hashes:

```json
{"name":"left_digest","op":"hash_poseidon2_leaf","lhs":"left"}
{"name":"right_digest","op":"hash_poseidon2_leaf","lhs":"right"}
{"name":"root","op":"hash_poseidon2_pair","lhs":"left_digest","rhs":"right_digest"}
```

All words are canonical elements of `F_p`, `p=2³¹−1`. S31 reuses the [pinned Stark-V permutation](../../../riscv/air/memory_commitment/poseidon2.zig) and [Merkle framing](../../../riscv/recursion/poseidon2_channel.zig). The 16-word state has rate eight. A leaf starts with zeros except `state[15]=1`; each input word is added to the next rate word, permuting after every eight words. It absorbs one further word `1` as an end marker and permutes if that group is partial. The digest is the first eight state words. A parent runs one permutation on `left[0..8] || right[0..8]` and returns its first eight words. An eight-word leaf therefore uses two permutations; a parent uses one. The leaf and parent constructions have different framing.

For each permutation, S31 emits an external linear layer, four full rounds, fourteen partial rounds, and four full rounds. A full round computes `t_i=s_i+c_{r,i}`, `y_i=t_i⁵` for all 16 lanes and then applies the external matrix. A partial round applies `y_0=(s_0+c_r)⁵`, leaves the other 15 lanes unchanged, then computes `s'_i=d_i·y_i+Σ_j y_j` with the pinned diagonal `d_i`. The external matrix uses the pinned four-word M4 followed by cross-block sums. Every `x⁵` is represented as `u=x·x`, `v=u·u`, `y=v·x`: three multiplication gates. Constants and linear layers become addition and multiplication gates. Each arithmetic gate has `out=in0+in1`, `out=in0−in1`, `out=in0·in1`, or coordinate-wise `out=in0.*in1` over QM31 as selected by its fixed opcode column; its operand and output addresses participate in the circuit lookup argument. Inputs and outputs are constrained to the M31 base-field coordinate. The public root is bound to eight canonical M31 proof words and checked by the generated native verifier.

[`examples/merkle_path1_poseidon.s31.json`](../../examples/merkle_path1_poseidon.s31.json) adds a private `direction: m31[1]` and two `select` nodes before the parent hash. In direct mode, the selector must be a directly referenced `m31[1]` input. Its wire's single producing gate is `b·b=b`, forcing `b∈{0,1}` even when private; each chosen digest lane then follows `(1-b)·lhs+b·rhs`. The full `gate` profile uses its Eq component for the same Boolean predicate and can select from a computed M31 value. The [Python arithmetic oracle](../../python/poseidon2_oracle.py) checks the pinned `hashPair(1,2)=1975699496` vector and both example roots. The [Poseidon2 acceptance script](../../tests/acceptance/acceptance_poseidon_v6.py) proves both path directions and checks native-verifier rejection cases. This is arithmetic circuit lowering, not a dedicated Poseidon2 AIR chip.

## Build, inspect, prove, verify

From the repository root:

```sh
python3 src/frontends/s31/python/s31.py check src/frontends/s31/examples/arith4.s31.json
python3 src/frontends/s31/python/s31.py build src/frontends/s31/examples/arith4.s31.json --lowering sparse-chip --out zig-out/s31/arith4-sparse-chip
python3 src/frontends/s31/python/s31.py inspect zig-out/s31/arith4-sparse-chip
python3 src/frontends/s31/python/s31.py prove zig-out/s31/arith4-sparse-chip src/frontends/s31/examples/arith4.valid.json zig-out/s31/arith4-sparse-chip.proof
python3 src/frontends/s31/python/s31.py verify zig-out/s31/arith4-sparse-chip zig-out/s31/arith4-sparse-chip.proof
```

`inspect` reports component sizes, preprocessed cost, chip parameters, and source spans. `prove` writes a public-only statement beside the proof. The packaged native verifier can also be invoked directly with proof, statement, and verification-key paths. See the [S31 README](../../README.md) for the other profiles and test commands.

To exercise the direct-M31 ABI, use the same commands with [`examples/arith4_m31.s31.json`](../../examples/arith4_m31.s31.json), `--lowering direct-chip`, and [`examples/arith4.valid.json`](../../examples/arith4.valid.json). The public values agree with the `u16` example because its selected inputs fit both types.
