# S31: circuit-native language for Stwo

Status: v0.1 circuit relation compiler plus specialized linked-chip, sparse-arithmetic and direct-M31 proof profiles, personalized BLAKE2s tree functions, pinned field-native Poseidon2 tree functions, and a limited typed text frontend, 2026-10-06. The implementation lives in [`src/frontends/s31`](../../src/frontends/s31). The [text language guide](../../src/frontends/s31/TEXT_LANGUAGE.md) and [language and AIR guide](../../src/frontends/s31/LANGUAGE_AND_AIR.md) explain the current syntax and constraints; the [MVP roadmap](MVP_ROADMAP.md) records the profiles, hash suite, measurements and remaining gates. General chip extraction, a private circuit-to-chip boundary, a dedicated batch hash AIR and recursion remain research milestones. The older slice-0 material below is preserved as its original design and comparison record.

The [standard/math library brief](STDLIB_MATHLIB.md) records the first qualified
field math operations and the work needed for versioned modules, reductions,
checked inversion, and computed boolean/range values.

The concrete post-v0.1 protocol sequence, chip boundary argument, sparse-profile requirements, and exit gates are in the [MVP roadmap](MVP_ROADMAP.md). Its implementation-status section supersedes older forward-looking statements below about the repeated-step chip and sparse arithmetic profile.

The current direct-M31 experiment proves a 256-round four-lane recurrence with one circuit AIR component, 4,096 preprocessed cells and a 60,616-byte native proof. At 32,768 rounds, a [five-input matched Cairo run](measurements/direct-cairo-v4-2026-10-06.json) recorded median `prove` times of 0.161 s for direct-chip and 6.616 s for the equivalent Cairo executable. Both native verifiers accepted the same public outputs. The visible FRI settings align, but the protocols and full security analyses differ; the 41.1× ratio applies to this workload and these executables. The [profile measurement](measurements/profiles-direct-v4-2026-10-06.json) separates cold setup, interaction PoW, PCS/FRI PoW and non-PoW proving work.

The [hash library brief](HASH_LIBRARY.md) specifies both hash families, canonical and reduced digest encodings, conditional Merkle paths, proof evidence, and a native-verified five-trial cost comparison. On two private leaves plus a parent, the pinned Poseidon2 direct circuit used 131,072 fixed cells and a 164,333-byte median proof versus 4,255,616 cells and 464,630 bytes for the current BLAKE2s full-gate circuit. These are distinct hash functions with different roots and security assumptions.

## Delivered v0.1 subset

The v0.1 compiler accepts normalized JSON relations with public/private `u16` and M31 arrays, assertions, public outputs, bounded repeat bodies, and a fixed-size Blake2s node. Graph size is independent of witness values. A reference evaluator, canonical SSA with constant folding and common-subexpression elimination, and the four-lane circuit lowering all use the same typed source but separate evaluation logic. Every proof build checks exact value/topology gate lists before finalization and a satisfied circuit after finalization. Randomized arithmetic relations and hash fixtures exercise the independent evaluator and circuit. A [separate randomized proof run](measurements/mvp-randomized-v1-2026-10-06.json) compiled three generated programs at array lengths 1, 3 and 4, proved three assignments each, matched an independent Python M31 oracle, and rejected changed private witnesses.

`s31 build` stages and installs a prover, a native verifier with its verification key embedded, a typed public ABI, the source, a versioned key, a program and canonical-IR hash, a cost report, and a manifest that hashes all artifacts. The verifier reads only the public statement, proof and pinned key. It reconstructs the Stwo transcript, checks LogUp closure, and invokes `core.verifier` against the bound circuit AIR. The native proof is a versioned S31 envelope around a postcard STARK proof with a fixed 16 MiB input cap and bounded decode allocation. The verifier can run outside the repository. The [acceptance suite](../../src/frontends/s31/acceptance_v1.py) covers five relations and rejects incorrect witnesses, statements, program packages, keys, and proof bytes.

The [release benchmark script](../../src/frontends/s31/benchmark_v1.py) runs equivalent Cairo executables for 256-round M31 arithmetic, Blake2s, and a mixed recurrence plus Blake2s. It records the generated program and proof hashes, aligned visible FRI settings, separate witness/setup/prove/verify measurements, memory and artifact bytes. Results are in [the v0.1 record](measurements/mvp-v1-2026-10-06.json), and the [acceptance record](measurements/mvp-acceptance-v1-2026-10-06.json) pins the five positive cases and mutation checks. The implementation remains constrained by the pinned circuit AIR: at most eight direct public words, eleven components and 45 preprocessed columns, plus 4.25 million fixed preprocessed cells in these cases. The hash node currently accepts only 4, 8, 12 or 16 M31 words so its last packed wire has no unconstrained padding.

Three verified trials per case on this M5 Max gave the following medians. Witness generation is the S31 value-graph build or Cairo VM adapter run; S31 setup builds the preprocessed commitment. The prover column excludes those phases and native verification.

| Case | S31 prove | Cairo prove | Cairo/S31 | S31 native verify process | S31 proof | Cairo JSON / gzip |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 256-round M31 arithmetic | 0.492 s | 0.697 s | 1.42× | 0.017 s | 435 KB | 2.07 MB / 801 KB |
| Blake2s of four M31 words | 0.418 s | 0.742 s | 1.78× | 0.018 s | 471 KB | 2.47 MB / 835 KB |
| Eight M31 rounds then Blake2s | 0.478 s | 0.725 s | 1.52× | 0.017 s | 476 KB | 2.65 MB / 944 KB |

S31 cold setup was about 0.050 s in all three cases; the four-lane witness build was about 0.00013 s. Cairo VM adapter wall time was 0.015–0.031 s. S31 prover peak resident memory was about 1.015 GB; Cairo reported a process physical footprint of 0.769 GB for arithmetic and about 1.086 GB for the two hash cases. Those memory definitions differ. Cairo reported native verification at 0.005–0.006 s inside its proving process, faster than the separately launched S31 verifier. The visible FRI settings match, but the proof protocols, encodings, preprocessing and verifier paths differ. These small cases establish a working circuit-first MVP and measured crossover for the selected programs; they do not support an orders-of-magnitude language-wide speed claim.

## Product objective

S31 is a statically shaped language for programs whose execution will be proved with Stwo. A successful production build must produce a prover, a **native verifier bound to that program**, a public input schema, an authenticated proving key or topology commitment, and a reproducible cost report. Compilation must never succeed with only a witness generator or only an AIR. The source language can be low level; the optimization target is total proving and verification cost for a declared workload, not programmer convenience.

The primary representation is a typed circuit graph. The compiler can lower each region to the existing circuit gate AIR or to a purpose-built AIR chip. A chip is profitable when many instances repeat one transition and its internal wires can be constrained in a compact trace; the surrounding circuit sees only its boundary values. Both paths must join one transcript with a sound, explicit boundary relation. Independent proofs pasted together do not satisfy this requirement.

The repository already provides the circuit builder, an eleven-component circuit AIR, a CPU prover, and an in-circuit STARK verifier. The pinned implementation is documented in the [circuit frontend](../../src/frontends/circuit/README.md) and [circuit CPU integration](../../src/integrations/circuit_cpu/README.md). Upstream development is in [StarkWare's proving repository](https://github.com/starkware-libs/proving). S31 should reuse these implementations and the existing [typed AIR IR](../typed-air/IR.md), not create a second cryptographic stack.

## Language contract

Production S31 should have immutable `let` bindings, compile-time shapes, bounded `for`/`map`/`fold`, typed assertions, pure functions, and explicit `public`, `private`, and `hint` values. The core types are `m31`, `qm31`, `bool`, `u16`, `u32`, fixed arrays, `simd<4,m31>`, typed digests, and `Proof<Program>`. All conversions are explicit. `u16` and `u32` are integer/range types; `m31` arithmetic is modulo (2^{31}-1). A compiler may use four QM31 coordinates as four M31 lanes only where every operation preserves independent lane semantics.

Private values may influence arithmetic and constrained selects, but never graph size, gate order, proof configuration, or public ABI. Dynamic loops require a static maximum and active-row constraints. An `assert` lowers to an AIR constraint, not a host-side check. A hint is an untrusted witness assignment and must have a constraint that establishes every property used downstream. A later `verify<Program>(proof, public_values)` expression invokes an in-circuit verifier for one statically identified program and verification key.

The frontend lowers to a canonical, versioned SSA graph. Every node records type, shape, source location, dependency edges, range facts, and public/private status. The graph is the input to both witness generation and constraint generation. The compiler emits a source map from source node to circuit wire, gate row, AIR column, and proof component. A reference evaluator with independent code provides an oracle for the semantics; using the same lowering twice is insufficient to detect a shared bug.

The original slice-0 format used normalized JSON with one `u16[4]` input and eight public words. The delivered v0.1 format extends that source with private inputs, typed fixed arrays, assertions, bounded repeat bodies and Blake2s while retaining machine-readable JSON. A limited typed text parser now lowers to this JSON; a full production frontend remains future work.

A later surface form could expose exactly the operations the optimizer reasons about:

```text
circuit affine<const N: usize>(public x: [u16; N]) -> public [u32; N] {
    let packed = pack4(map(x, m31));
    let y = packed .* splat4(7) + splat4(11);
    return map(unpack4(y), u32);
}
```

The `.*` operator is coordinate-wise M31 multiplication. A QM31 field multiplication has different semantics and must use a distinct operator. Explicit `pack4` is useful in the low-level form; a higher-level frontend may insert it only after proving lane independence and including conversion costs in its estimate.

## Public statement and program identity

The verifier must bind **both** the program and the public values. A production verification key contains:

1. S31 language and proof-profile version, canonical graph hash, and compiler/build identity.
2. Gate topology, chip definitions, component order, padded log sizes, preprocessed commitment root, and the circuit hash that the transcript mixes.
3. PCS/FRI settings, hash/channel profile, interaction PoW policy, allowed proof shape and byte limits.
4. Typed public ABI and canonical encoding, including lengths, endianness, range checks, and whether values are direct words or a committed digest.
5. Digests of every external AIR evaluator and fixed table used by verification.

Small statements should use direct public words. A large public array can use a cryptographic commitment, but hashing inside the circuit is a real cost and must appear in the cost report. In the current circuit protocol, the eight reserved `u32` output slots are named `output_digest`; cryptographically they are eight verifier-bound words. The first slice uses them directly as four `x` and four `y` values. The prover cannot substitute another public tuple without making verification fail.

The verifier API is `verify(proof_bytes, public_values) -> accepted | error`, with the program key baked into the generated binary. It parses within fixed limits, reconstructs the transcript, verifies commitments and openings, checks component claims and LogUp closure, then binds the statement's public values. It does not trust a topology root, security parameter, or public value supplied by the proof file.

There are two verifier targets. The **native verifier** runs on the host and is mandatory for every build. The **recursive verifier circuit** is optional and is used only when another S31 proof verifies this one. The outermost proof still needs a native verifier. Slice 0 used `verifyProofBytes` to execute the recursive verifier in value mode on the host. The delivered v0.1 verifier instead uses [`src/core/verifier.zig`](../../src/core/verifier.zig) directly and reads a sealed layout and preprocessed root from its embedded key. Agreement with the recursive verifier remains a future recursion gate.

## Compilation and proving architecture

```text
source -> typed SSA circuit -> optimize and partition -> gate AIR + chip AIRs
                                      |                    |
                                      +-> witness AOT       +-> one Stwo transcript
                                      +-> verification key  +-> native verifier
                                      +-> source map        +-> recursive verifier circuit
```

The compiler passes, in order, are: parse and type/shape check; normalize static control flow; prove range and lane independence; fold constants and common subexpressions; choose direct public values or committed values; pack four M31 lanes where profitable; select dedicated gates; estimate padded component cost; extract regular regions into chips; link boundary lookups; lay out and authenticate preprocessed columns; emit witness code, prover adapter, native verifier and cost report. A topology-only build and a witness-value build must produce the same canonical graph and gate lists for every accepted witness. The first slice checks exact gate list equality at runtime.

The initial backend uses the pinned eleven-component circuit proof protocol. This provides correctness and recursion interoperability now. It also has an efficiency floor: all five gate components are padded to at least sixteen rows, and the preprocessed layout always contains 45 columns including range and XOR tables. Those facts are visible in [`finalize.zig`](../../src/frontends/circuit/common/finalize.zig) and [`preprocessed.zig`](../../src/frontends/circuit/common/preprocessed.zig). A small program therefore pays for unused component and table machinery. A **sparse circuit profile** that includes only used components is a later, versioned protocol change. It needs new prover and verifier code, transcript-domain separation, fixed-table authentication, proof-format versioning, and a soundness review before use. Topology/preprocessed commitments should be cached across witnesses regardless of profile.

The chip backend starts with a repeated M31 vector step. It uses the existing typed AIR representation and emits a local witness writer, constraints, and an input/output relation. The circuit linker proves equality of the chip boundary tuple to the circuit tuple using a lookup/permutation argument in the **same** proof. The linker must account for multiplicity, padding, inactive rows, and public exposure. A chip may replace a generic gate region only after a differential proof test and a cost crossover measurement.

Each boundary tuple needs a chip identifier, instance identifier, active flag, typed inputs and typed outputs. Constraints must prove that every active circuit invocation appears exactly once in the chip trace and every active chip row has a matching invocation. The active flag must force padded rows into a canonical inert state. The linker may not infer this from witness ordering: the prover controls witness ordering. The verifier's manifest fixes relation IDs and column order, and the soundness review must cover zero denominators and lookup multiplicities. This is the main new cryptographic work in a hybrid gate/chip backend.

The cost model is calibrated from measurements, not gate count alone. For each candidate lowering it records raw and padded rows per component, base/interaction/preprocessed cells, lookup terms, packed-lane occupancy, hash work, FRI layers and query count, proof bytes, native verification work, peak memory, and cold versus cached preprocessing. It chooses the lower estimated total for the declared batch size and hardware profile. When estimates are close, `s31 tune` can compile and benchmark both alternatives.

## Toolchain and artifacts

| Tool | Required behavior |
| --- | --- |
| `s31 check` | Parse, type and shape check, reject unconstrained hints and value-dependent topology. |
| `s31 build` | Emit canonical graph, witness object, prover, native verifier, verification key, public ABI, source map and cost report atomically. |
| `s31 run` | Evaluate source semantics without proving and show intermediate values by source location. |
| `s31 prove` / `s31 verify` | Produce a versioned proof and verify it with only public values and the sealed key. |
| `s31 inspect` / `s31 explain` | Show per-region lowering, padded components, lookups, fixed tables, source-to-row mapping, and why an optimization was chosen. |
| `s31 profile` / `s31 tune` | Time witness, preprocessing, commitments, composition, FRI, PoW and verification; compare candidate layouts under a reproducible machine profile. |
| `s31 bench` | Run matched Cairo and S31 statements with pinned security parameters, source artifacts, proof/verifier checks, memory and proof-size accounting. |

Build artifacts should be content addressed. A cache key includes canonical graph, compiler/proof-profile version, gate/chip registry, public ABI, and PCS settings. Reusing a preprocessed tree under a different key is forbidden. The verifier build must be independent of prover-only modules and include strict proof length/depth/query limits. A package release gate checks that the generated verifier rejects mutations of public values, topology root, circuit hash, claimed sums, commitments, FRI witnesses and proof bytes.

## Engineering sequence and acceptance gates

**Slice 0: circuit and native-verifier showcase — implemented here.** Parse the normalized DAG, evaluate M31 semantics, lower through the existing circuit builder in value and topology modes, make a real Stwo circuit proof, and verify it with a separately compiled native host binary bound to the embedded program. Compare with an equivalent Cairo executable whose public output contains the same eight values. This slice proves the integration path. Its verifier uses the host execution of the existing in-circuit verifier and recomputes the topology root; it is not the final lean verifier.

**Milestone 1: production language core — partially delivered in v0.1.** Typed arrays and assertions, public/private declarations, deterministic packages, source-node, assertion and public-binding gate spans, and the native core verifier are implemented and covered by acceptance. A human parser or stable binary source IR, broader type system, and more exhaustive mutation tests remain before calling this a production language.

**Milestone 2: optimization and a first chip.** Implement lane packing analysis, cost reports and one specialized repeated-step AIR chip linked into the circuit proof. Acceptance: for a matrix of shapes, gate and chip lowerings produce identical public results and both pass native verification; chip boundaries survive adversarial mutation tests. Promote the chip only where measured end-to-end cost is lower.

**Milestone 3: sparse circuit profile.** Define a new protocol revision and generated component/table registry. Acceptance: identical semantics to the full profile, independent verifier agreement, transcript-domain separation, and a documented soundness argument. No speed claim is made until cold and cached proof timings show a gain.

**Milestone 4: recursion.** Add `verify<Program>` and generate a recursive verifier circuit from the same sealed key. Acceptance: native and recursive verifiers agree on positive and negative corpora, and the outer native verifier binds the entire child-proof chain and its public outputs.

The performance gate is workload specific: compare optimized Cairo, S31 gate lowering, and S31 chip lowering on the same statement, machine, security profile and output encoding. Report p50 and spread across several runs because 26-bit proof-of-work has high variance. Include compilation, cold setup, amortized setup, proving, native verification, proof bytes and peak memory separately. A tenfold advantage on a specified large batch is a research target; a hundredfold advantage is not a design assumption.

The benchmark suite should contain at least: a large independent M31 arithmetic batch (packing and chip crossover), Blake2s/Merkle paths (dedicated-gate crossover), a mixed bounded state machine (irregular-circuit control), and recursion over 2, 8 and 16 child proofs. A release benchmark pins the compiler and adapter versions, captures proof and public-value digests, runs both native verifiers, and reports the full proof tree for recursion. Production parameters require an explicit security analysis of FRI, lookup arguments, commitments, and transcript binding; matching the visible FRI settings alone is not a security equivalence claim.

## First-slice comparison and what it teaches

The committed example computes `y[i] = 7*x[i] + 11` for four `u16` inputs. The Cairo function and the S31 graph both produce `(18, 25, 32, 458756)` for `(1, 2, 3, 65535)`; the public proof words are the four inputs followed by the four results. See the [S31 source](../../src/frontends/s31/examples/affine4.s31.json) and [Cairo function](../../src/frontends/s31/examples/cairo/src/lib.cairo). `scarb execute` reports 128 Cairo VM steps and eight output builtin words. Both the S31 native verifier and this repository's Cairo CPU verifier accepted their respective proofs. The S31 verifier rejected a changed public input and a flipped proof byte.

One M5 Max `ReleaseFast` smoke run, with a separate S31 footprint measurement, used visible FRI settings aligned at 26 PoW bits, blowup 2, last-layer degree bound 1, 70 queries and fold step 1. The [recorded result](measurements/affine4-smoke-2026-10-05.json) is:

| | S31 gate circuit | Cairo executable via this repo's CPU prover |
| --- | ---: | ---: |
| Prover time | 0.574 s after 0.053 s setup | 0.577 s in the product report |
| Total request through verification | 0.809 s | 0.604 s, excluding VM execution |
| Peak process footprint | about 1.01 GB | about 0.68 GB |
| Proof artifact | 799,464 byte circuit binary | 1,902,389 byte JSON; about 681 KB under gzip |
| Padded circuit field-op rows | 320 raw → 512 padded | 128 VM steps, which is a different unit |
| Unused Blake-G component | 0 raw → 16 padded | n/a |

These are **smoke-run observations, not a speedup claim**. The protocols, proof encodings, native verifier implementations, build versions and preprocessing policies still differ, and PoW timing is stochastic. In this tiny example the circuit path does **not** beat the optimized Cairo product on time or memory. That is valuable evidence: the fixed circuit profile and generic output/conversion machinery dominate a four-element calculation. It makes the sparse profile, typed public ABI, chip selection and calibrated cost model concrete engineering requirements rather than optional polish. The benchmark harness must pin the Cairo compiler to the adapter's declared version before any publishable comparison.

The stock Scarb 2.18 `scarb verify` command panicked with `ECDSA segment is not empty` on its own proof in this environment; an [upstream issue](https://github.com/starkware-libs/stwo-cairo/issues/1733) describes the same failure. For this comparison, the Cairo executable was executed by this repository's official-VM adapter and proved with `stwo-cairo-cpu --verify`, which accepted it. The Scarb-produced proof is not used as verified evidence.

## Scaled circuit comparison

The second slice adds a statically unrolled node for four independent M31 recurrences, `x <- x*x + 7 mod (2^31-1)`. The [256 round source](../../src/frontends/s31/examples/square256.s31.json) and [equivalent Cairo function](../../src/frontends/s31/examples/cairo_square/src/lib.cairo) establish the concrete semantics. [`generate_scale.py`](../../src/frontends/s31/generate_scale.py) produces both programs and the expected eight public words for any supported round count. The compiler lowers every round to one four-lane pointwise multiply gate and one four-lane add gate. Cairo uses a `u64` product and two explicit Mersenne folds. Its VM output and both native proof verifiers were checked for every size.

Five process runs per size on an Apple M5 Max, using the same visible FRI settings as the smoke comparison, produced the [full machine-readable record](measurements/square-scale-2026-10-05.json):

| Rounds, four lanes | S31 raw → padded field rows | Cairo VM steps | S31 median prover | Cairo median prover | Cairo/S31 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 256 | 829 → 1,024 | 81,019 | 0.650 s | 0.693 s | 1.07× |
| 1,024 | 2,365 → 4,096 | 323,707 | 0.739 s | 0.699 s | 0.95× |
| 4,096 | 8,509 → 16,384 | 1,294,459 | 0.494 s | 1.108 s | 2.24× |
| 8,192 | 16,701 → 32,768 | 2,588,795 | 0.436 s | 1.698 s | 3.89× |
| 16,384 | 33,085 → 65,536 | 5,177,467 | 0.610 s | 4.100 s | 6.72× |
| 32,768 | 65,853 → 131,072 | 10,354,811 | 0.552 s | 6.755 s | 12.24× |

Circuit rows and Cairo VM steps are different units, so their counts cannot be divided to get a constraint reduction. The deterministic observation is that each additional four-lane round adds two circuit arithmetic rows, while this Cairo implementation adds about 316 VM steps. At 8,192 rounds, one separate S31 run had a 1.026 GB peak physical footprint; the Cairo report's median peak was 3.646 GB. At 32,768 rounds, the corresponding figures were 1.067 GB and 18.947 GB, about 17.8× apart. S31's 799,464 byte binary proof stayed constant across these sizes because the current circuit profile includes fixed XOR lookup columns with up to 2²⁰ rows. Cairo's JSON proof was about 2.41 MB, or 929 KB gzipped, at 32,768 rounds. Those encodings are different; the size figures do not establish a protocol-level compression win.

The S31 prover times are not monotone across these circuit sizes, even though the counts are. The five runs within each size were usually close, and both verifiers accepted the results, but this needs stage profiling before attributing the change to any specific optimization. Cairo's prover automatically selected `official-live-cairo-canonical-small` through 8,192 rounds and `official-live-cairo-canonical` at 16,384 and 32,768 rounds; that profile change contributes to the large-case crossover and is recorded per case. The comparison also spans different proof protocols, compiler versions, verifier implementations and preprocessing policies. Cairo's reported prove time excludes the separately run VM adapter; S31's reported prove time excludes setup and its native verification. The 12.24× result is for this repeated M31 workload and these implementations, **not** a language-wide advantage. A dedicated repeated-step AIR chip joined to the circuit and a sparse arithmetic profile have since been implemented; their current evidence and remaining acceptance gates are in the [MVP roadmap](MVP_ROADMAP.md).

## First-slice commands

From the repository root:

```sh
zig build --build-file src/frontends/s31/build.zig test -Doptimize=ReleaseSafe
zig build --build-file src/frontends/s31/build.zig showcase -Doptimize=ReleaseFast
zig build --build-file src/frontends/s31/build.zig install -Doptimize=ReleaseFast
src/frontends/s31/zig-out/bin/s31-affine4-verifier zig-out/s31/affine4.proof 1 2 3 65535
```

The last command's four inputs are verifier supplied. Changing one causes rejection. The prototype writes proof output under `zig-out/s31`; build caches are ignored by Git.

Run [`compare.sh`](../../src/frontends/s31/compare.sh) to execute both complete showcase paths, check the same eight public values, require both native verifiers to accept, and require the S31 verifier to reject changed public values and modified proof bytes. The script writes its evidence and a `summary.json` under `zig-out/s31/compare.*`.

Run [`scale.sh`](../../src/frontends/s31/scale.sh) for the four default sizes through 8,192 rounds. Pass `16384 32768` to reproduce the two larger cases; their Cairo prover needs substantially more memory. Set `S31_TRIALS` to change the default five trials. The driver regenerates both programs, builds them, checks Cairo execution, proves and verifies each trial, and records JSON summaries under `zig-out/s31/scale/<rounds>/summary.json`.
