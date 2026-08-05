# Implementation plan

**Status:** executable delivery plan
**Last updated:** 2026-08-04

## Delivery method

Every phase is a vertical slice with a reversible production boundary:

1. record the baseline;
2. add the new representation in shadow mode;
3. compare exact outputs;
4. add negative evidence;
5. wire one production consumer;
6. measure correctness and performance;
7. remove duplication only after all gates pass.

Large mechanical migrations are deliberately delayed. The compiler earns
authority one component at a time.

## Phase 0 — project contract

**Deliverable:** this dossier, branch, task graph, ADR process, and progress
ledger.

**Exit gate:**

- documents agree with current source and normative soundness contracts;
- initial architectural decisions are recorded;
- first implementation tasks have unambiguous acceptance criteria.

## Phase 1 — IR kernel in isolation

**Status:** complete on `feat/typed-air-precompiles`; no production imports.

Create `src/frontends/riscv/air/lang/` without changing production behavior.

Implement:

- typed IDs and semantic types;
- arena ownership;
- expression nodes and structural interning;
- constraints, hints, effects, and source spans;
- typed relation schema registry;
- structural validator;
- acyclic function graph;
- canonical debug/manifest serialization; and
- unit and negative tests.

The kernel has no dependency on the concrete runner or backend. It may depend
on stable field and frontend types where representation identity requires it.

**Exit gate:**

- malformed IDs, type mismatches, cyclic calls, unbound hints, invalid relation
  roles, duplicate access ordinals, and nondeterministic serialization each
  have focused failing tests;
- allocation ownership passes the package test suite;
- two clean constructions emit byte-identical logical manifests.

## Phase 2 — shadow adapter and degree auditor

**Status:** complete; A-001 through A-005 satisfy the exit gate.

Adapt the existing production `Builder(symbolic.Scalar)` output into the
logical IR or a lossless compatibility view. Do not author opcodes in the new
surface yet.

Implement:

- polynomial DAG import;
- column role and source-name import;
- direct constraint roots;
- ordered lookup-event import;
- active selector and row-mask model;
- complete degree inference;
- relation and interaction degree accounting;
- per-family human and machine-readable reports; and
- deterministic report tests over all 17 families.

This phase should immediately identify the exact degree of every current root
without changing one committed column.

The accepted result is pinned in the machine and human views under
[`artifacts/`](artifacts/README.md). It records 17 independently compiled
families and independently checks the shipped direct and lookup backend bounds.

**Exit gate:**

- concrete replay of imported roots matches production evaluation;
- every family has a report;
- reported direct and lookup counts match current authorities;
- the report explains gates and maximum-degree paths;
- no production trace or proof artifact changes.

## Phase 3 — compatibility lowering

Lower a logical program back into the current `ConstraintProgram` and runtime
polynomial formats.

Start with LUI because it has no source register read and a small effect
surface. Require:

- identical column count, names, and order;
- identical direct expression DAG after canonical normalization;
- identical lookup domains, roles, access ordinals, values, and order;
- identical runtime polynomial roots;
- identical AIR IR v2 output; and
- identical honest and forged-row verdicts.

Then repeat the adapter/lowerer round trip for all existing families while
still using their current authoring source.

**Exit gate:**

- all 17 compatibility manifests are stable;
- AIR IR v2 and runtime exports remain exact;
- package, proof, and formal gates are green.

## Phase 4 — pure Poseidon2 compiler pilot

Author the M31 Poseidon2 permutation as typed pure functions.

Implement:

- static rounds and maps;
- typed state arrays;
- degree-three policy;
- deterministic structural CSE;
- compatibility materialization for the existing 426 temporary columns;
- direct-to-final-storage witness filling; and
- source-span diagnostics through function inlining.

First reproduce the existing 445-column sparse-Merkle component. Only then add
an experimental optimized policy.

**Exit gate:**

- compatibility rows are byte-identical;
- all 426 materialization constraints and final outputs are equivalent;
- lookup and claim sums match;
- real CPU and Metal proofs verify;
- compatibility performance is not meaningfully worse;
- optimized policy, if retained, has a separate manifest and complete cost
  report.

## Phase 5 — typed machine effects

Implement high-level effect constructors backed by current relation schemas:

- `programFetch`;
- `regRead` and `regWrite`;
- `memRead` and `memWrite`;
- `rangeRequest`;
- `stateConsume`, `stateProduce`, and `retire`.

The access-clock API derives strict subclocks and makes illegal order
unrepresentable. It must preserve current x0, alias, clock-gap, state-chain,
and public-boundary behavior.

Migrate the vertical ladder:

1. LUI — fetch, write, retire.
2. ADDI — read, write, alias, carries.
3. signed load — memory, mask, sign hint.
4. JALR — bound target and control flow.
5. DIV — complex hints and exceptional semantics.

The existing concrete executor remains independent throughout.

**Exit gate per opcode:**

- compatibility manifest exact;
- generated witness matches current witness on deterministic and random corpus;
- source/effect event order exact;
- named forgeries remain rejected at the expected stage;
- Sail and Spike behavior unchanged;
- proof and AIR IR gates green.

## Phase 6 — generated witness authority

Once the ladder demonstrates all effect and hint classes:

- write generated witness values directly into preallocated family columns;
- retain current writers as test-only differential oracles;
- add column-by-column mismatch diagnostics;
- run the witness-rigidity fleet; and
- retire old writers one family at a time.

Concrete architectural execution remains separate unless a later ADR changes
that boundary.

**Exit gate:**

- every migrated family has one production witness source;
- no row-loop allocation or string dispatch;
- test inventory and minimum test-count floor are updated;
- production proof corpus and formal regeneration pass.

## Phase 7 — guest Poseidon2 precompile

Before code, accept ADRs for guest ABI, relation schema, component versioning,
and base-RV32IM claim language.

Implement:

- explicit guest invocation;
- typed call buffer;
- separate guest Poseidon relation domain;
- statement-bound call count and component geometry;
- specialized main and interaction traces;
- component registration and verifier construction;
- honest software/precompile output equivalence corpus;
- forged input, output, multiplicity, and padding cases; and
- one-transcript relation closure.

**Exit gate:**

- every guest call is supplied exactly once by multiplicity;
- removing or forging one supplied call fails verification;
- native software and precompile outputs agree;
- CPU and Metal proofs verify independently;
- artifact identity declares the extension and component version.

## Phase 8 — parallel component pipeline

Generalize current parallel composition work into a bounded component task
graph:

- overlap main-trace construction after call buffers freeze;
- overlap component interaction construction after challenges;
- retain canonical commitment and claim order;
- schedule dominant components by measured work;
- expose queue, occupancy, wait, and peak-memory telemetry;
- prohibit nested unbounded pools; and
- preserve deterministic errors and cleanup.

**Exit gate:**

- serial and parallel proofs are byte/protocol equivalent where scheduling is
  not transcript-visible;
- injected worker failures propagate deterministically;
- thread-count sweeps show no race or oversubscription;
- wall time, total work, and memory are reported.

## Phase 9 — broader migration and optimizer

Migrate remaining opcode families in small, reviewable groups. Build an
empirical cost model only after stable manifests and component metrics exist.

The optimizer may propose layouts using:

- main and interaction trace cells;
- constraint evaluation count by degree;
- commitment and LDE cost;
- FRI domain effect;
- reuse count;
- CPU/SIMD and Metal bandwidth;
- device residency; and
- proof critical path.

Accepted optimized layouts are pinned policies. Profile-guided results do not
change production protocols automatically.

## Phase 10 — independent proofs and recursion

This phase is intentionally outside the initial production milestone.

Required sequence:

1. specify transcript-bound relation summaries;
2. prove one leaf exposes its exact summary;
3. prove a recursive verifier checks a core/precompile summary cancellation;
4. reject swapped, omitted, duplicated, and cross-transcript leaves;
5. construct a two-to-one aggregation tree;
6. measure recursion overhead and crossover point; and
7. version final proof/artifact policy.

## First implementation pull requests

### PR 1 — IR kernel

Files:

- new `air/lang/{types,source,ir,builder,validate}.zig`;
- focused test root imports; and
- no production wiring.

Review question: is the logical object sufficient and minimal?

### PR 2 — production adapter and degree report

Files:

- `air/lang/{shadow_import,shadow_program}.zig`;
- `air/lang/{degree,protocol_degree,protocol_report}.zig`;
- byte-pinned report tests over all families.

Review question: does the analyzer describe the complete current program
without changing it?

### PR 3 — compatibility manifest and LUI round trip

Files:

- `air/lang/{layout,manifest,lower_constraint}.zig`;
- LUI exact-diff tests;
- AIR IR/runtime export comparison.

Review question: can the new middle layer be observationally invisible?

### PR 4 — Poseidon2 pure authoring

Files:

- typed Poseidon definition;
- compatibility materializer;
- current-versus-generated trace, AIR, lookup, and proof tests.

Review question: can the compiler reproduce a difficult real layout rather
than a toy circuit?

### PR 5 — typed LUI and ADDI effects

Files:

- typed relation schemas and effect constructors;
- LUI and ADDI component definitions;
- generated witness shadow path.

Review question: do effects preserve every current access and state-chain
invariant?

## Migration checklist

For every component:

1. Freeze current layout and evidence.
2. Import or author logical semantics.
3. Emit a compatibility manifest.
4. Compare every direct root.
5. Compare every relation event.
6. Compare every honest witness column.
7. Run targeted forged witnesses.
8. Prove and independently verify.
9. Regenerate formal artifacts.
10. Benchmark verified production paths.
11. Switch one production consumer.
12. Remove the old implementation only after a clean-tree full gate.
