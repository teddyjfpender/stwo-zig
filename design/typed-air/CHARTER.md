# Project charter

**Status:** proposed implementation charter
**Last updated:** 2026-08-04

## Mission

Build a typed, deterministic AIR authoring and component system in which one
semantic definition drives production constraints, lookup relations, witness
synthesis, formal extraction, and backend programs, while preserving the
repository's Sail authority and proof-system boundaries.

Use that system to make specialized computations first-class proof components
that can be traced and proven alongside the RISC-V core, then prepared for
independent proof aggregation.

## Problem

The current RISC-V frontend has a strong shared source for direct constraints,
lookups, and formal extraction, but it still divides one instruction's meaning
across:

- concrete execution in `runner/execute.zig`;
- row and access construction in `runner/trace.zig`;
- handwritten derived columns in `runner/witness/`;
- generic constraint semantics in `air/semantics/`;
- relation construction in `air/lookups/`;
- layout declarations in `air/trace_columns/`; and
- formal/runtime export in `air/extract/`.

This creates three costs:

1. semantic drift can appear between an honest runner and the AIR;
2. adding or reviewing a component requires coordinated edits across several
   representations; and
3. specialized guest computations cannot yet use a general, typed component
   call ABI even though the prover already supports heterogeneous components.

## Outcomes

The project succeeds when:

1. A canonical typed program is the sole production source for each migrated
   component's constraints and ordered relation events.
2. The same program supplies or validates all derived witness values.
3. The production evaluator and formal exporter continue to consume the same
   exact program.
4. Degree violations, unconstrained hints, malformed relation tuples, unstable
   layouts, and illegal effect order fail before proving.
5. A pure Poseidon2 definition deterministically reproduces a reviewed
   degree-bounded layout and witness.
6. LUI, ADDI, a signed load or JALR, and DIV demonstrate the effect and hint
   model from simple through adversarial cases.
7. A guest-visible Poseidon2 precompile emits calls from the core and proves
   them in the specialized component under one proof transcript.
8. Core and precompile work are scheduled concurrently without changing proof
   meaning or weakening verifier checks.
9. Every performance result reports total work and critical-path time rather
   than moving cost out of the headline.
10. The design leaves a precise relation-summary boundary for future separate
    proofs and two-to-one recursive aggregation.

## Non-goals for the first delivery

- Replacing Sail or the independent architectural oracle.
- Claiming whole-frontend verification or proof-system soundness.
- Migrating all opcode families in one change.
- Introducing recursive functions into the authoring language.
- Building a general-purpose programming language or runtime VM.
- Making Haskell a production build dependency.
- Automatically changing production layout based on local profiling.
- Proving core and precompile relations in unrelated transcripts.
- Recognizing arbitrary guest instruction sequences as precompiles.
- Removing the existing runner before generated behavior has independent
  semantic evidence.

## Product principles

### One meaning, several interpretations

The single source is a typed semantic program, not a generated text file. Every
backend consumes that program or an artifact canonically derived and validated
from it.

### Proof components, not magical acceleration

A precompile is a versioned semantic interface, a witness implementation, an
AIR, and a relation binding. Host acceleration without a constrained proof
component is not a precompile.

### Independent truth remains independent

Shared generation reduces transcription risk but increases correlated-bug
risk. Sail, negative witness mutation, formal replay, and backend
differentials remain separate.

### Protocol changes are explicit

Adding a column, changing event order, batching relations differently, or
moving a call between components changes protocol geometry. Such changes
require a layout manifest, evidence diff, and deliberate version decision.

## Success measures

### Correctness and assurance

- Zero handwritten constraint or relation transcription for migrated
  components.
- Exact production/formal IR identity remains enforced.
- Every hint has a constraint dependency and mutation that rejects a forged
  value.
- Typed relation schemas reject wrong arity, role, domain, access ordinal, and
  liveness at construction time where possible.
- Existing RISC-V soundness and proof gates stay green.

### Engineering

- One small, readable semantic definition per migrated operation.
- Compiler diagnostics identify source construct, inferred degree, gate, and
  materialization path.
- Generated layouts and manifests are stable across clean builds.
- The hot proving path has no per-row allocation or dynamic string dispatch.
- Ownership and lifetime are explicit at every component boundary.

### Performance

- Compatibility-mode migrations introduce no statistically significant
  regression.
- The Poseidon compiler pilot reports columns, total trace cells, constraint
  evaluations, interaction cells, and proof timings against the existing AIR.
- The guest Poseidon precompile reduces verified wall-clock time or total trace
  work on its target workload after including relation and aggregation cost.
- Parallel measurements disclose resource count, peak memory, and total CPU/GPU
  work as well as elapsed time.

## Delivery shape

The work proceeds through independently reviewable vertical slices:

1. IR kernel and validators.
2. Shadow degree and layout analysis of existing production semantics.
3. Exact compatibility lowering.
4. Pure Poseidon2 materialization pilot.
5. Typed machine effects and generated witness slices.
6. Guest precompile relation and one-proof component integration.
7. Parallel scheduling and cost measurement.
8. Broader opcode migration.
9. Separate-proof relation summaries and recursion, only after the preceding
   contracts are stable.
