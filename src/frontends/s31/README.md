# S31 circuit and chip relation compiler

S31 compiles a fixed-size relation into Stwo circuit AIR and, for a supported recurrence, a repeated-step AIR chip. Every `s31 build` package contains a prover, an independently runnable native STARK verifier, a pinned verification key, the typed public ABI, and a cost report. The verifier checks all proof components through `core.verifier`; it does not execute the recursive verifier circuit on the host. The [source-to-AIR guide](LANGUAGE_AND_AIR.md) walks through syntax, circuit gates, chip rows, polynomial constraints, lookup closure, and a complete function.

The compiler accepts normalized JSON and a [limited typed `.s31` text language](TEXT_LANGUAGE.md) that lowers to the same relation. Inputs have `u16` or `m31` type, fixed length, and public or private visibility. Nodes are topologically ordered. Supported normalized operations are `constant`, `cast_m31`, lane-wise `add`/`mul`, `add_const`/`mul_const`, statically bounded `repeat` with `square` and constant steps, `select`, BLAKE2s raw/leaf/ordered-pair hashing, and pinned M31 Poseidon2 leaf/ordered-pair hashing. BLAKE2s hash inputs are canonical M31 words encoded little endian as 32-bit words; its eight digest words are reduced modulo M31. Poseidon2 outputs eight canonical M31 state words directly. Assertions constrain equal arrays. Public inputs and outputs occupy at most eight direct words: `u32` in the original profile, canonical M31 in direct-v4. Witnesses cannot change graph shape.

To use the text frontend and inspect its exact lowering:

```sh
python3 src/frontends/s31/s31.py lower src/frontends/s31/examples/arith4_m31.s31
python3 src/frontends/s31/s31.py build src/frontends/s31/examples/arith4_m31.s31 --lowering direct-chip --out zig-out/s31/text-arith4
python3 src/frontends/s31/s31.py explain zig-out/s31/text-arith4
```

The text package includes the original `.s31`, normalized JSON, and a source map; all are hashed in its manifest. `explain` joins source locations to the existing gate-row cost report. See [the text language guide](TEXT_LANGUAGE.md) for its implemented syntax, typed library functions, constraints, examples, and limits.

From the repository root:

```sh
zig build --build-file src/frontends/s31/build.zig test -Doptimize=ReleaseSafe
python3 src/frontends/s31/s31.py check src/frontends/s31/examples/preimage4.s31.json
python3 src/frontends/s31/s31.py build src/frontends/s31/examples/preimage4.s31.json --out zig-out/s31/preimage4
python3 src/frontends/s31/s31.py inspect zig-out/s31/preimage4
python3 src/frontends/s31/s31.py run zig-out/s31/preimage4 src/frontends/s31/examples/preimage4.valid.json
python3 src/frontends/s31/s31.py prove zig-out/s31/preimage4 src/frontends/s31/examples/preimage4.valid.json zig-out/s31/preimage4.proof
python3 src/frontends/s31/s31.py verify zig-out/s31/preimage4 zig-out/s31/preimage4.proof
```

`prove` writes a public-only statement beside the proof. `verify` uses that statement by default. The generated verifier can also run directly from another directory with `PROOF STATEMENT.json VERIFICATION-KEY.json`. Package manifests hash every artifact. A local cache key includes the program source, compiler inputs, pinned AIR assets, and Zig version. Builds are staged and published atomically.

For the 256-round recurrence, choose a lowering explicitly:

```sh
python3 src/frontends/s31/s31.py build src/frontends/s31/examples/arith4.s31.json --lowering sparse-chip --out zig-out/s31/arith4-sparse-chip
python3 src/frontends/s31/s31.py inspect zig-out/s31/arith4-sparse-chip
python3 src/frontends/s31/s31.py prove zig-out/s31/arith4-sparse-chip src/frontends/s31/examples/arith4.valid.json zig-out/s31/arith4-sparse-chip.proof
python3 src/frontends/s31/s31.py verify zig-out/s31/arith4-sparse-chip zig-out/s31/arith4-sparse-chip.proof
```

The six modes are `gate` (the original eleven-component circuit), `chip` (that circuit plus one linked step AIR), `sparse-gate`/`sparse-chip` (three arithmetic circuit components, optionally with the step AIR), and `direct-gate`/`direct-chip` (one QM31 arithmetic component, optionally with the step AIR). The chip modes accept only the exact four-lane square-then-add recurrence with a public boundary and 16–32768 power-of-two rounds. Sparse arithmetic retains M31-to-`u32` conversion and the 16-bit range table. Direct mode accepts all-M31 arithmetic relations, binds canonical public M31 words directly, and omits that converter and table. The chip and circuit share one STARK proof and one native verifier invocation.

The direct-M31 example is [`examples/arith4_m31.s31.json`](examples/arith4_m31.s31.json). Build it with `--lowering direct-chip` and use [`examples/arith4.valid.json`](examples/arith4.valid.json) as the assignment. The [source-to-AIR guide](LANGUAGE_AND_AIR.md#direct-m31-public-values) explains the different public encoding and constraint profile.

The hash suite includes [`examples/merkle2.s31.json`](examples/merkle2.s31.json), which hashes two private leaves into a public root, and [`examples/merkle_path1.s31.json`](examples/merkle_path1.s31.json), which proves a one-level path with a constrained direction bit. Use `--lowering gate` for both. The [hash section of the language guide](LANGUAGE_AND_AIR.md#hashes-tree-nodes-and-conditional-paths) specifies every byte and field conversion.
The [hash library brief](../../../design/s31/HASH_LIBRARY.md) records the cryptographic encoding, proof cost and next efficiency work.

The field-native suite has matching tree and one-level-path examples: [`examples/merkle2_poseidon.s31.json`](examples/merkle2_poseidon.s31.json) and [`examples/merkle_path1_poseidon.s31.json`](examples/merkle_path1_poseidon.s31.json). Build them with `--lowering direct-gate`. This uses the repository's pinned Stark-V M31 Poseidon2 permutation and eight-column QM31 arithmetic AIR; each build still emits its own native verifier. Direct-mode `select` currently requires a directly referenced `m31[1]` input selector, constrained by `b²=b`. The two hash families produce different roots for the same leaves.

```sh
python3 src/frontends/s31/s31.py build src/frontends/s31/examples/merkle_path1_poseidon.s31.json --lowering direct-gate --out zig-out/s31/merkle-path1-poseidon
python3 src/frontends/s31/s31.py prove zig-out/s31/merkle-path1-poseidon src/frontends/s31/examples/merkle_path1_poseidon.valid.json zig-out/s31/merkle-path1-poseidon.proof
python3 src/frontends/s31/s31.py verify zig-out/s31/merkle-path1-poseidon zig-out/s31/merkle-path1-poseidon.proof
```

```sh
python3 src/frontends/s31/s31.py build src/frontends/s31/examples/merkle_path1.s31.json --lowering gate --out zig-out/s31/merkle-path1
python3 src/frontends/s31/s31.py prove zig-out/s31/merkle-path1 src/frontends/s31/examples/merkle_path1.valid.json zig-out/s31/merkle-path1.proof
python3 src/frontends/s31/s31.py verify zig-out/s31/merkle-path1 zig-out/s31/merkle-path1.proof
```

[`generate_merkle_path.py`](generate_merkle_path.py) expands a fixed-depth path into normalized S31 source plus an independently calculated assignment. For example:

```sh
python3 src/frontends/s31/generate_merkle_path.py --depth 4 --seed 1 --out zig-out/s31/merkle-path4-generated
python3 src/frontends/s31/s31.py check zig-out/s31/merkle-path4-generated/merkle_path4.s31.json
python3 src/frontends/s31/s31.py build zig-out/s31/merkle-path4-generated/merkle_path4.s31.json --lowering gate --out zig-out/s31/merkle-path4
python3 src/frontends/s31/s31.py prove zig-out/s31/merkle-path4 zig-out/s31/merkle-path4-generated/merkle_path4.valid.json zig-out/s31/merkle-path4.proof
python3 src/frontends/s31/s31.py verify zig-out/s31/merkle-path4 zig-out/s31/merkle-path4.proof
```

Pass `--hash poseidon2` to generate a field-native path instead, and build its source with `--lowering direct-gate`. A generated depth-eight path with seed 1 was proved and accepted by its native verifier; the [smoke record](../../../design/s31/measurements/poseidon-depth8-smoke-v6-2026-10-06.json) has 23,055 raw arithmetic rows, 262,144 fixed cells, and a 189,460-byte proof. Its 0.184 s proving time is one run with stochastic proof-of-work.

Run the package acceptance and matched Cairo benchmarks with:

```sh
python3 src/frontends/s31/acceptance_v1.py
python3 src/frontends/s31/acceptance_profiles_v2.py
python3 src/frontends/s31/acceptance_direct_v4.py
python3 src/frontends/s31/acceptance_hash_suite_v5.py
python3 src/frontends/s31/benchmark_hash_suite_v5.py --trials 3
python3 src/frontends/s31/acceptance_poseidon_v6.py
python3 -m unittest discover -s src/frontends/s31 -p 'test_text_frontend.py' -v
python3 src/frontends/s31/acceptance_text_v1.py
python3 src/frontends/s31/benchmark_poseidon_v6.py --trials 5
python3 src/frontends/s31/randomized_proofs_v1.py
python3 src/frontends/s31/benchmark_v1.py --trials 3
python3 src/frontends/s31/benchmark_profiles_v2.py --trials 7
python3 src/frontends/s31/benchmark_direct_v4.py --trials 9
python3 src/frontends/s31/measure_direct_memory_v4.py
python3 src/frontends/s31/compare_direct_cairo_v4.py --rounds 32768 --trials 5
```

The v1 acceptance suite proves arithmetic, Blake2s, mixed, three-lane, and private-witness relations. It rejects bad witnesses, changed public statements, altered keys, malformed proofs, and proofs sent to the wrong program verifier. The profile suites prove shared recurrences across the profile families and reject changed statements, keys, proof bytes, cross-profile replay, and chip-witness mutations. The [BLAKE2s acceptance](../../../design/s31/measurements/hash-suite-acceptance-v5-2026-10-06.json) and [Poseidon2 acceptance](../../../design/s31/measurements/poseidon-acceptance-v6-2026-10-06.json) verify independently calculated tree roots, both valid direction bits, and negative source/witness/proof cases. The [matched hash comparison](../../../design/s31/measurements/poseidon-comparison-v6-2026-10-06.json) records distinct verified inputs and proof costs. The randomized run compiles three generated programs and checks nine proofs against an independent Python M31 oracle. The [engineering brief](../../../design/s31/README.md) explains the architecture and the limits of comparisons with Cairo.

The direct/Cairo comparison also requires the compiled Cairo executable and VM adapter input from `S31_TRIALS=1 src/frontends/s31/scale.sh 32768`, plus a direct profile benchmark including 32,768 rounds. It checks the same public values under both native verifiers; its recorded time ratio applies only to this recurrence and the selected proof implementations.

The default v1 profile still pays for all eleven circuit AIR components and 45 preprocessed columns. The arithmetic-only sparse v3 profile uses three components and 12 preprocessed columns; direct-M31 v4 uses one and eight. Each has a distinct verification key and native verifier. The public ABI is limited to eight words. Poseidon2 is currently lowered into that arithmetic circuit; there is no dedicated batch hash chip. There is no general control flow, automatic chip extraction, private circuit-to-chip boundary, or recursive verifier generation. The older v0 `showcase`, `compare.sh`, and `scale.sh` paths remain available for the large repeated-arithmetic Cairo comparison. The [engineering brief](../../../design/s31/README.md) and [MVP roadmap](../../../design/s31/MVP_ROADMAP.md) describe the remaining work.
