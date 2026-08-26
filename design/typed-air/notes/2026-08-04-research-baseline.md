# 2026-08-04 — research baseline

## Question

Is Clement Walter's felt-to-AIR design technically viable, what did the
Stark-V experiment actually establish, and where should `stwo-zig` begin?

## Sources and revisions

- User-supplied design note: “A felt language that compiles to AIR.”
- [Stark-V design on pinned main](https://github.com/ClementWalter/stark-v/blob/d478f783055aa0d73a93768a433a3c6c31c91d1c/docs/felt-air-compiler.md).
- Stark-V pinned main: `d478f783055aa0d73a93768a433a3c6c31c91d1c`.
- Later development branch observed at:
  `0be6d7e0167f4970eb34ed0f94ae96a6311a2161`.
- Pre-revert migrated snapshot:
  [`6301111eb1afc17faac988d5d28b99fe7691deed`](https://github.com/ClementWalter/stark-v/commit/6301111eb1afc17faac988d5d28b99fe7691deed).
- Later opcode migration revert:
  [`3c70b086714043be735f769ed0bbb7189f6b9e86`](https://github.com/ClementWalter/stark-v/commit/3c70b086714043be735f769ed0bbb7189f6b9e86).
- stwo-zig baseline: `385efb9a`.

Primary external precedents reviewed:

- [Zirgen conceptual overview](https://github.com/risc0/zirgen/blob/main/zirgen/docs/02_Conceptual_Overview.md);
- [Circom compiler](https://github.com/iden3/circom);
- [Plonky3 AIR builder](https://github.com/Plonky3/Plonky3/blob/main/air/src/builder.rs);
- [powdr expression and query model](https://docs.powdr.org/pil/expressions.html);
- [AirScript compiler](https://github.com/0xPolygonMiden/air-script); and
- [Cairo AIR components](https://docs.starknet.io/learn/S-two-book/cairo-air/main-components).

## Reproduced experiment

The Stark-V snapshot was checked out in a temporary worktree. The worktree was
removed after the run.

```text
cargo test -p stwo-macros --test air_fns
19 passed; 0 failed

cargo test -p prover --lib
82 passed; 0 failed
```

The test surface included:

- degree materialization and degree bounds;
- Poseidon equivalence and real prove/verify;
- forged-output rejection;
- external relation cancellation;
- hints;
- mini-VM state chaining; and
- end-to-end proofs across migrated opcode families and lookup tables.

## Observations

### The compiler concept is real

The implementation records expressions, tracks degree, materializes derived
columns, emits equality constraints, performs structural reuse, expands static
loops, supports hints, and emits/consumes external relations.

### The optimizer is not yet the prose-level cost model

The inspected implementation uses deterministic local degree splitting and
CSE based on rendered expression identity. It does not yet globally optimize
columns against commitment, evaluation, interaction, or backend costs.

### Opcode migration did not fully unify semantics

At the migrated snapshot, opcode AIR definitions used the felt DSL and
generated fillers. Complex concrete witness algorithms, especially division,
still lived in runner code and manually supplied large argument lists. The
experiment therefore demonstrated AIR/witness plumbing more strongly than one
complete machine-semantic source.

### The later revert is a caution, not a verdict

The later commit reverted 16 opcode AIR migrations and removed their generated
fill/converter plumbing. Its message does not record the reason. Poseidon and
other compiler infrastructure remained. It is not evidence that compiled AIR
is unsound; it is evidence that production opcode ergonomics and ownership
needed further design.

### The Cairo analogy is useful but not literal

Cairo's immutable felt-oriented execution model is a strong authoring
inspiration. Ordinary Cairo programs execute inside a fixed Cairo CPU AIR,
rather than every program literally becoming a new bespoke AIR.

## stwo-zig findings

The repository already has:

1. one generic `Builder(S)` for direct constraints and ordered lookups;
2. a hash-consed symbolic polynomial DAG;
3. production-bound AIR IR v2 export;
4. runtime polynomial-program export for backend acceleration;
5. a specialized Poseidon2 component with 426 degree-reduction temporaries;
6. an owned Poseidon call list for memory/program commitments;
7. parallel main/interaction generation paths; and
8. heterogeneous component quotient scheduling.

The remaining duplication is concentrated in concrete execution and
handwritten witness writers.

The current conformance ledger also documents historical Stark-V
underconstraints. Stark-V is therefore useful for compiler and layout
archaeology, but cannot be imported as a soundness oracle.

## Interpretation

The highest-value project is not a syntax rewrite. It is:

1. reify current generic semantics into a canonical typed IR;
2. add types, hints, effects, degree, layout, and manifests;
3. preserve exact compatibility before optimization;
4. prove the approach on current Poseidon2;
5. migrate an opcode ladder that exercises effects and hints;
6. generalize existing component machinery into a guest precompile ABI; and
7. add separate proofs/recursion only after one-proof relation closure works.

The guaranteed benefits are correctness, reviewability, and development
velocity. Smaller compiled AIR and faster proofs are contingent on measured
layout decisions. The largest potential proving win comes from replacing
hash-heavy native instruction traces with specialized parallel precompile
components.

## What this does not establish

- The Stark-V experiment does not establish universal AIR soundness.
- Passing its tests does not explain the later revert.
- Single-source generation does not prove the shared semantics are correct.
- Function-call relation balance does not make recursive calls well-founded.
- A smaller source program is not necessarily a smaller committed trace.
- Component parallelism does not necessarily reduce total work.
- Separate leaf proofs do not compose without bound relation summaries.

## Resulting decisions and tasks

- ADR-0001: Zig-authored canonical IR.
- ADR-0002: compatibility before optimization.
- ADR-0003: one-proof precompiles before recursion.
- ADR-0004: acyclic function graph in IR v0.
- First implementation task: F-001 in [`TASKS.md`](../TASKS.md).
