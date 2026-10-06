# S31, from source to proof

This is the guide to the **implemented S31 v1 relation and current `.s31` text
subset**. It is meant to be read without knowing Cairo, Stwo internals, or the
repository's design history. Run the commands from the repository root.

S31 has two ways to describe a program: a typed text file (`.s31`) and a
normalized JSON relation (`.s31.json`). Both reach the same Zig compiler. A
build emits a program-specific prover, a native STARK verifier, a verification
key, a public ABI, and a cost report. Values supplied when proving cannot
change the program's types, graph, loop counts, or proof profile.

```text
text .s31 ──parse/typecheck/specialize──▶ normalized relation JSON
                                          │
                                          ▼
                                canonical SSA graph
                                          │
                              ┌───────────┴───────────┐
                              ▼                       ▼
                       circuit gates        optional repeated-step chip
                              └───────────┬───────────┘
                                          ▼
                         AIR columns, constraints, LogUp
                                          ▼
                         one Stwo commitment/FRI proof
                                          ▼
                    program-bound native verifier + key
```

## Read in order

- [One computation, one proof](walkthrough.md): an ELI5 account followed by
   a complete `x²+7` example. Fill circuit wires and schematic AIR rows by
   hand, see why wiring matters, and factor the constraint polynomials.
- [Two proofs worked by hand](worked-proofs.md): a private cross-lane sum
    and dot product from source through gate equations and public binding,
    followed by a 16-round recurrence with actual transition rows.
- [A private choice worked by hand](worked-choice.md): a Boolean selector
   chooses between two public square-plus-seven results. See the filled
   circuit wires, gate equations, two-row polynomial factorization, and the
   exact claim a proof makes.
- [Thirty-two bytes and 256-bit arithmetic](wide-values.md): distinct
   `Bytes32` and `UInt256` types, hand-filled carry and borrow tables,
   and constrained limb equations.
- [Bitcoin header SHA256d and proof of work](bitcoin-sha256d.md): two actual
   linked 80-byte headers, six SHA compression blocks, compact target decoding,
   handwritten gate equations, verified proofs, and the SHA chip boundary.
- [Source language and relation](source.md): syntax, types, field semantics,
   static shapes, normalized JSON, and the public statement.
- [Standard and math library](library.md): the pinned `std@1` package,
   typed operations, static reductions, Horner evaluation, and a proof example.
- [Circuit lowering](circuits.md): a hand-drawn gate graph, packed M31 lanes,
   fixed/witness columns, address lookups, and the six proof profiles.
- [AIR and polynomials](air.md): a hand-filled trace, the **actual six
   repeated-step chip constraints**, lookup closure, quotient, and FRI.
- [Hashes and Merkle paths](hashes.md): complete input/output encodings,
   Poseidon2 permutation and constants, BLAKE2s framing, and a hand-drawn
   one-level path.
- [Packages, verification, and audit](proofs.md): build/prove/verify commands,
   what the key binds, artifact names, cost report fields, and current limits.

The worked examples use checked-in sources under [`../examples`](../examples):

| Program | What it teaches | Recommended profile |
| --- | --- | --- |
| [`math_polynomial4.s31`](../examples/math_polynomial4.s31) | Static power, constants, four M31 lanes, circuit gates | `direct-gate` |
| [`mathlib4.s31`](../examples/mathlib4.s31) | `use std@1`, Horner polynomial, static dot/sum, library lock | `direct-gate` |
| [`lane_stats4.s31`](../examples/lane_stats4.s31) | Private arrays, lane sum and dot, one public result | `direct-gate` |
| [`arith4_m31.s31`](../examples/arith4_m31.s31) | `iterate`, gate unrolling versus one linked AIR chip | `direct-chip` |
| [`merkle_path1_poseidon.s31`](../examples/merkle_path1_poseidon.s31) | Private leaf, constrained bit, ordered hashing, public root | `direct-gate` |
| [`preimage4.s31`](../examples/preimage4.s31) | Private `u16` witness and an equality assertion | `gate` |
| [`wide_order.s31`](../examples/wide_order.s31) | Sixteen-limb addition and comparison with an auxiliary public commitment | `gate` |
| [`bitcoin_header_pow.s31`](../examples/bitcoin_header_pow.s31) | Byte-exact SHA256d and mainnet compact proof of work for one header | `sparse-wide-gate` |
| [`bitcoin_header_pair.s31`](../examples/bitcoin_header_pair.s31) | Genesis-to-block-one hash linkage, same bits, and both PoW checks | `sparse-wide-gate` |

If this is your first STARK, read [the hand-worked walkthrough](walkthrough.md)
before running the tour. It distinguishes the small teaching trace from the
actual packed S31 circuit AIR and states exactly what verifier acceptance
means.

## Five-minute tour

```sh
python3 src/frontends/s31/s31.py lower src/frontends/s31/examples/math_polynomial4.s31
python3 src/frontends/s31/s31.py oracle src/frontends/s31/examples/math_polynomial4.s31 src/frontends/s31/examples/math_polynomial4.valid.json
python3 src/frontends/s31/s31.py build src/frontends/s31/examples/math_polynomial4.s31 --lowering direct-gate --out zig-out/s31/docs-polynomial
python3 src/frontends/s31/s31.py explain zig-out/s31/docs-polynomial
python3 src/frontends/s31/s31.py equations zig-out/s31/docs-polynomial
python3 src/frontends/s31/s31.py prove zig-out/s31/docs-polynomial src/frontends/s31/examples/math_polynomial4.valid.json zig-out/s31/docs-polynomial.proof
python3 src/frontends/s31/s31.py verify zig-out/s31/docs-polynomial zig-out/s31/docs-polynomial.proof
```

`lower` shows the exact relation consumed by Zig. `oracle` checks the
normalized relation against the assignment in Python, without proving. It
now evaluates every current arithmetic and hash node: BLAKE2s uses Python's
`hashlib`, and Poseidon2 uses a separate Python field-arithmetic reference
with the repository's pinned constants. Unknown future operations fail
explicitly. `explain` joins text source
positions to canonical nodes and builder gate spans. `equations` shows each
node's semantic field equation. `prove` writes a public-only
statement beside the proof; `verify` runs the generated native verifier on that
statement, proof, and pinned key. The documented program computes
`x^5 + 3x - 7` over `p = 2^31 - 1`, independently in four lanes.

## Terms used here

| Term | Meaning in this implementation |
| --- | --- |
| Circuit | A fixed graph of wires and arithmetic/hash gates. A gate has named input/output wire addresses. |
| Lane | One position in a fixed-size array. For `x=[0,1,2,7]`, lane 2 holds `x[2]=2`. Four M31 lanes can be packed into one QM31 circuit wire, with pointwise arithmetic acting on each independently. |
| AIR | Polynomial constraints on columns of a trace table, plus boundary and lookup checks. Stwo proves this representation. |
| Chip | A specialized AIR component for one recognized recurrence. It shares the circuit's proof, transcript, and verifier. |
| Trace | Field values assigned to AIR columns for a particular witness. |
| Fixed/preprocessed columns | Program-dependent values such as opcode flags and wire addresses; committed in the verification key's geometry. |
| Interaction columns | LogUp running values used to prove that separately constrained wire uses and outputs match. |
| Public statement | Named public inputs and outputs. Private input values are absent from it. |
| Native verifier | The generated host binary that checks the STARK proof against its embedded program and key. |

The current text frontend has no general imports, user-defined modules, dynamic loops,
computed-bit selectors, arbitrary lane indexing, user-defined folds, or checked inversion. `explain`
does **not** print every instantiated symbolic polynomial from the pinned
circuit AIR bundle. This guide gives the semantic gate equations and the exact
specialized-chip equations; [the audit guide](proofs.md) explains the remaining
symbolic-export gap. The root [frontend README](../README.md) lists benchmark
scripts and older implementation notes.

## Read as a local site

The Markdown is the source of truth. For syntax-colored code, diagrams, and
rendered LaTeX, run the [local preview server](serve.py) from the repository
root after installing its [Python dependencies](requirements.txt):

```sh
python3 -m venv zig-out/s31/docs-venv
zig-out/s31/docs-venv/bin/pip install -r src/frontends/s31/docs/requirements.txt
zig-out/s31/docs-venv/bin/python src/frontends/s31/docs/serve.py
```

Open `http://127.0.0.1:8765/docs/`. The server reads Markdown on each request;
refresh the page after an edit. It listens only on localhost. The preview
downloads one pinned MathJax bundle into a temporary cache on first run, then
serves that bundle locally.
