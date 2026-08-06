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
16. [receipts/README.md](receipts/README.md) — clean-snapshot milestone evidence and open gates.

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
for every opcode-manifest entry. Seventeen canonical `STWAIRC\0` v1 family
manifests now bind the source schedule, semantic identity, exact physical
layout, embedded direct and lookup runtime programs, complete degree records,
hint identities, and exact-checked formal exports. Their
[family-ordered index and binary artifacts](artifacts/README.md) are regenerated
and byte-compared by the package suite, with an explicit fail-closed check and
review-only atomic update command. The command now validates both inputs and
reports the first field-aware divergence with logical/physical names before an
update writes atomically. Typed fixed arrays/maps/folds and the pure width-16
M31 Poseidon2 function have also landed in the isolated authoring kernel. A
generic, versioned degree-three materializer now selects exactly 410 required
cuts plus sixteen outputs, and a separately versioned compatibility adapter
bijectively binds them to all 426 historical lane-major slots in the existing
445-column layout. The authenticated compiler now also evaluates
the full 2,171-instruction closure directly into final bit-reversed storage,
reproduces the existing four Poseidon relation events, two batches, eight
interaction columns, and two claims, and renders a golden 426-record
source-to-storage report. H-007 now exercises those generated artifacts at the
live commitment and claim boundaries of complete CPU and authenticated-AOT
Metal proofs. Both honest backend paths verify; the focused CPU lane rejects
targeted main, interaction, and claim mutations. The path remains test-only and
shadow-only pending an explicit production-authority decision. H-009 now pins
a separately identified, bounded cost-frontier experiment without activating
it. Its complete local neighbourhood is a structural plateau, so H-010 has no
structural winner and required measured representatives before any policy
decision; the completed experiment below selects none. V-006
also pins one backend-neutral semantic/layout/executor/relation identity and
co-attests it beside both verified backend paths; it does not change the
transcript, public statement, proof bytes, or production verifier. The final
[H-009 and V-006 receipts](receipts/README.md) name the immutable evidence and
its limits. This work continues to strengthen and reify the existing path
rather than replace the prover or rewrite all opcodes.

## Completed H-010 experiment

H-010 now has an authenticated, isolated CPU benchmark implementation under
the policy in
[ADR-0022](decisions/0022-authenticated-poseidon-layout-benchmark.md). It
recomputes four deterministic arms from the checked H-009 frontier: the
compatibility seed and the minimum, lower-median, and maximum removed-`ValueId`
representatives. Every arm uses the same retained evaluator, prepared scratch,
and allocation-free row loops; the experiment does not compare a candidate
interpreter with the differently shaped production static evaluator.

Logs 10 and 14 read checked `STWAIRB\0` vectors and independently recorded
Poseidon outputs. Their generated
[readable index](artifacts/h010-poseidon-layout-v1/index-v1.tsv) pins complete
vector identities and boundary rows. Admission requires every expected output,
all 430 direct roots on every timing row, and the complete 426-materialization
and fixed-role mutation matrix to pass. Per-arm trace digests are regression
pins for the candidate layout implementation, not independent correctness
oracles.

The timing boundary contains only prepared main-trace witness execution and
the complete fixed direct-root evaluator. It reports setup, witness, direct,
and normalized process high-water RSS from serial fresh children. It executes
no proof, commitment, LogUp, PCS, verifier, Metal candidate, or production
layout change. Log 18 is generated only as an explicit opt-in resource stress
case and is non-receiptable.

H-010 completed against clean implementation commit
`82bf6b9cd5eb1ab48edd6fb7c0c88a3be687e8c6` and tree
`8cbb9300fa9b820baa079eeb94addf71db97f130`. Two independently
valid and complete default reports are retained locally as ignored evidence:
`v2`, SHA-256
`98abdf472818e21e43ff0e3cc3d509598558a6df6c1c215ea789a997fb5bc25d`,
and `v3-confirm`, SHA-256
`eabeba5d67b26574dbe4246f8924411fe7c1df252452d078688ae6a0bcb5682a`.
Each contains all 112 required fresh sample children with zero failures,
retries, or drops. Candidate-versus-seed directions are small and not
repeatable across reports; q0 and q100 log-14 witness directions flip and
remain within MAD/noise. The result is therefore no meaningful repeatable
layout regression and no selected layout. Proof, Metal-candidate, production,
and promotion claims remain false. The
[H-010 receipt](receipts/h010-authenticated-poseidon-layout-benchmark-v1.json)
records that bounded conclusion without changing authority.
