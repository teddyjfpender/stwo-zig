# Implementation plan

**Status:** executable delivery plan
**Last updated:** 2026-08-05

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

**Status:** implementation complete; A-006 through A-012 are green and V-008
records the clean-snapshot evidence. Release promotion remains blocked by the
broad witness-rigidity and formal generated-artifact gates named in the
[M3 receipt](receipts/m3-compatibility-v1.json).

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

The direct pass now lowers the reachable root closure into an owned, fallible
six-operation program. An independent normalizer establishes exact node and
ordered-root equality for all 17 families; randomized M31 replay, corruption,
malformed-buffer, determinism, and allocation-failure tests provide secondary
evidence. See [ADR-0013](decisions/0013-fallible-normalized-direct-lowering.md).

The ordered lookup pass normalizes already-signed production numerators into
role plus liveness while retaining a structurally bound signed root. It pins
tuple and event order, access ordinals, batch occupancy, and every physical
interaction coordinate. All-family canonical structure and replay agree with
the lookup-only runtime exporter; see
[ADR-0014](decisions/0014-role-normalized-ordered-lookup-lowering.md).

The runtime pass revalidates and mechanically copies the canonical programs
into the prover's owned direct and lookup capability types. Compile-time enum
ABI checks, deterministic tuple tails, all-family structural identity, and both
DIV allocation-failure paths are green; see
[ADR-0015](decisions/0015-validated-canonical-runtime-export.md).

The formal pass applies the explicit selector-to-one policy, replays checked
source-schedule provenance, derives roles and event projections, and delegates
encoding to the existing AIR IR v2 writer. Its output is byte-identical for LUI
and every opcode-manifest entry; see
[ADR-0016](decisions/0016-source-bound-air-ir-v2-compatibility.md).

The all-family receipt pass emits one canonical `STWAIRC\0` version-1 artifact
for each of the 17 production families plus a family-ordered TSV index. Seven
framed sections bind authority revisions, exact physical layout, complete
direct and lookup runtime bodies, event and batch metadata, complete degree
records, hint recipes, and every exact-checked AIR IR v2 export. The package
suite rebuilds and byte-compares all artifacts; a standalone command defaults
to fail-closed check and permits only explicit atomic update. Result/scratch
allocator separation makes every new encoding allocation exhaustively
failure-testable without changing the legacy symbolic builder's panic-on-OOM
contract. See
[ADR-0017](decisions/0017-sectioned-compatibility-manifests.md) and the
[M3 artifact index](artifacts/m3-compat-v1/index-v1.tsv).

The field-aware review pass validates both complete v1 manifests without
allocation, then compares detailed records before their duplicate identity
digests. It reports one stable generated-versus-on-disk path with logical and
physical names where available. Default check fails after rendering it;
explicit update renders the same result before atomic replacement. Malformed
framing, nested runtime programs, sentinel tails, tags, strings, and trailing
bytes fail closed.

**Exit gate:**

- all 17 compatibility manifests are stable;
- AIR IR v2 and runtime exports remain exact;
- package, proof, and formal gates are green.

## Phase 4 — pure Poseidon2 compiler pilot

**Status:** active in the isolated authoring kernel; H-001 through H-006 and
H-008 are complete in shadow mode, while real generated-artifact proof
equivalence remains open.

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

The accepted compatibility path keeps generic compilation and historical
layout separate. The degree-three materializer selects and orders an
authenticated root-closure cut set under an explicit versioned policy. A
second versioned adapter revalidates that plan, reconstructs the canonical
Poseidon semantic schedule, and bijectively assigns it to the 426 frozen
lane-major slots. Its owned binding retains the semantic program, policy,
activation context, and plan identity needed for later witness and constraint
consumers to reauthenticate the result. See
[ADR-0018](decisions/0018-degree-bounded-materialization-and-compatibility-order.md).

The witness compiler authenticates that binding, owns a 2,171-instruction
closure and reusable scratch, and writes the exact 445-column bit-reversed
trace directly into caller-owned final storage without per-row allocation. Its
fallible shape, alias, executable-integrity, and slot checks all precede the
first mutation. The relation plan separately fixes the four current Poseidon
events, two batches, eight interaction columns, and two claims; bulk generation
authenticates once before its allocation-free row kernel. A canonical
37-field diagnostic projection traces all 426 physical slots back through the
generic plan. These boundaries are fixed by
[ADR-0019](decisions/0019-authenticated-witness-and-relation-plans.md) and
remain shadow-only. H-007 has now substituted their authenticated output into
the live main and interaction commitments and into the transcript and component
claim boundaries of complete CPU and Metal proofs. The returned claim is
reconciled after proving, then a fresh unchanged production verifier
specialization verifies the result. That evidence is test-only and does not
itself authorize a production witness change.

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

- `air/lang/{compat_layout,lower_constraint,lower_lookup}.zig`;
- `air/lang/{lower_runtime,lower_air_ir,compat_manifest}.zig`;
- exact all-family runtime and AIR IR export comparisons; and
- 17 byte-pinned family receipts with check/update tooling.

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
