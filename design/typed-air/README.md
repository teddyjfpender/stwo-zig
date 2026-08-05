# Typed AIR and precompile architecture

**Status:** active design dossier
**Started:** 2026-08-04
**Development branch:** `feat/typed-air-precompiles`
**Scope:** RISC-V AIR authoring, witness synthesis, typed relations, specialized
precompiles, parallel component proving, and future recursive aggregation

This directory is the control room for developing a typed, single-source AIR
compiler and precompile architecture in `stwo-zig`. It records the intended
system, the standards by which it will be built, the ordered task graph,
validation evidence, performance method, decisions, and chronological notes.

The project is larger than a syntax improvement. Its target is one typed
semantic program that can be interpreted as:

- production constraints;
- ordered LogUp relation events;
- witness synthesis;
- canonical formal AIR IR;
- backend-neutral runtime polynomial programs; and
- eventually, selected concrete machine effects.

That same component vocabulary should make specialized computations such as
Poseidon2 into proof coprocessors: the RISC-V core emits typed calls, a
specialized table proves them, the relation argument binds both sides, and the
prover schedules their work concurrently.

## Authority

These documents are engineering plans, not soundness claims. They MUST NOT
override:

- [the RISC-V verification claim ledger](../../soundness/RISCV_FRONTEND_VERIFICATION_STATUS.md);
- [the AIR IR v2 production binding](../../soundness/AIR_IR_V2_CONTRACT.md);
- [the AIR-to-Sail composition contract](../../soundness/SAIL_AIR_COMPOSITION.md);
- [the universal AIR-to-Sail refinement plan](../../soundness/UNIVERSAL_AIR_SAIL_REFINEMENT.md);
- [the pinned upstream authority ledger](../../conformance/upstream.md); or
- [the RISC-V pull-request proof gate](../../conformance/riscv-pr-proof-gate.md).

Sail remains the RV32IM semantic authority. Stark-V is a design and performance
reference only. A generated evaluator is not evidence of architectural
correctness merely because its witness generator agrees with it.

## Reading order

1. [CHARTER.md](CHARTER.md) — problem, outcome, scope, and success criteria.
2. [CANON.md](CANON.md) — taste, style, and engineering laws.
3. [ARCHITECTURE.md](ARCHITECTURE.md) — current seams and target system.
4. [IR.md](IR.md) — typed intermediate representation and lowering contract.
5. [AUTHORING.md](AUTHORING.md) — executable public surface and lifecycle.
6. [PRECOMPILES.md](PRECOMPILES.md) — component ABI and parallel proving model.
7. [SOUNDNESS.md](SOUNDNESS.md) — threat model and preserved proof obligations.
8. [IMPLEMENTATION.md](IMPLEMENTATION.md) — staged delivery and first pull requests.
9. [TASKS.md](TASKS.md) — dependency-ordered executable work.
10. [VALIDATION.md](VALIDATION.md) — test, formal, and release evidence.
11. [PERFORMANCE.md](PERFORMANCE.md) — measurement and optimization discipline.
12. [PROGRESS.md](PROGRESS.md) — current state, next actions, and chronological log.
13. [decisions/README.md](decisions/README.md) — accepted and proposed decisions.
14. [notes/README.md](notes/README.md) — dated research and implementation notes.
15. [artifacts/README.md](artifacts/README.md) — reviewed deterministic evidence.

## Working rules

1. Every implementation task has an acceptance test before production wiring.
2. Compatibility lowering comes before layout optimization.
3. A duplicate implementation is removed only after its replacement has exact
   equivalence, adversarial, proof, and formal evidence.
4. Layout, relation order, and serialization are deterministic protocol data.
5. Performance claims require verified proofs and reproducible measurements.
6. Every changed correctness claim is reconciled with the soundness ledger.
7. Material design decisions receive an ADR before code makes them expensive.
8. [PROGRESS.md](PROGRESS.md) is updated in the same change that advances a
   milestone; it is not reconstructed later from memory.

## Current starting point

The repository already supplies much of the substrate:

- `air/constraint_program.zig` constructs direct constraints and ordered
  lookup events from one generic `Builder(S)`.
- `air/extract/symbolic.zig` records a hash-consed polynomial DAG.
- `air/extract/runtime_program.zig` exports the production DAG to a
  backend-neutral runtime capability.
- `air/memory_commitment/poseidon2_air.zig` is an existing specialized
  Poseidon2 component with 426 materialization columns.
- `prover/commitment_witness.zig` already builds a Poseidon call list.
- `prover/air/component_parallel.zig` already schedules heterogeneous AIR
  components concurrently.

The isolated kernel now owns typed values, logical degree, hints and proof
paths, ordered provisional effects, static calls, relation schemas, canonical
manifests, semantic identity, and stable diagnostics. Its complete executable
surface is documented in [AUTHORING.md](AUTHORING.md). A lossless shadow bridge
now imports and differentially replays every production family while preserving
independently computed degree. The complete production program boundary also
preserves ordered constraints, selectors, lookup metadata, and batching. A
second pass now models the exact direct and pairs-batched LogUp identities,
boundary terms, and quotient expansion for all 17 families. The versioned
[M2 production report](artifacts/m2-production-shadow-report-v1.md) pins those
counts, dependencies, and final degrees. The `compat-v1` mapping binds every
logical input to the exact preprocessed/main/interaction tree position while
keeping logical and physical names distinct. Direct lowering now reproduces
the independently normalized node DAG and all 545 ordered roots across all 17
families, with randomized replay and failure-path coverage. Ordered lookup
lowering likewise reproduces all 242 events and 155 physical batches while
binding role signs to normalized liveness. Both direct and lookup programs now
export exactly into the existing backend-neutral runtime capability shapes.
The selector-specialized formal path also reproduces AIR IR v2 byte for byte
for every opcode-manifest entry. The next seam packages all-family compatibility
identities and round-trip receipts; this work continues to strengthen and reify
the existing path rather than replace the prover or rewrite all opcodes.
