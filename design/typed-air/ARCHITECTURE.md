# Architecture

**Status:** proposed target architecture
**Last updated:** 2026-08-04

## Architectural thesis

The project should add a canonical typed IR between authoring and evaluation.
Zig remains the authoring language. The existing generic semantics become an
input and compatibility backend rather than being discarded.

```text
typed Zig component definitions
              |
              v
      canonical logical IR
  values | constraints | effects
   hints | calls | source spans
              |
              v
 deterministic validation + layout
              |
              v
       lowered component program
       + versioned layout manifest
        /       |       |       \
       v        v       v        v
 production  witness  AIR IR   runtime polynomial
 evaluator   engine   / Lean   CPU / Metal programs
               |       /        /
        +-------+------+--------+
                |
        one transcript-bound proof
```

The logical IR says what a component means. The lowered IR says how that
meaning occupies a particular AIR protocol layout. Keeping those layers
separate permits compatibility layouts, reviewed optimized layouts, and formal
reasoning without making physical columns the source language.

## Existing substrate

| Responsibility | Existing implementation | Intended use |
| --- | --- | --- |
| Shared constraint and lookup source | [`constraint_program.zig`](../../src/frontends/riscv/air/constraint_program.zig) | Compatibility lowering target and source adapter |
| Generic opcode semantics | [`air/semantics/`](../../src/frontends/riscv/air/semantics) | Incremental migration source |
| Symbolic polynomial DAG | [`extract/symbolic.zig`](../../src/frontends/riscv/air/extract/symbolic.zig) | Seed for canonical expression nodes and CSE |
| Formal program projection | [`extract/program.zig`](../../src/frontends/riscv/air/extract/program.zig) | AIR IR v2 boundary to preserve |
| Runtime polynomial export | [`extract/runtime_program.zig`](../../src/frontends/riscv/air/extract/runtime_program.zig) | Backend-neutral lowered-program precedent |
| Concrete execution | [`runner/execute.zig`](../../src/frontends/riscv/runner/execute.zig) | Independent execution path during migration |
| Witness writers | [`runner/witness/`](../../src/frontends/riscv/runner/witness) | Equivalence oracle and retirement target |
| Poseidon2 specialized AIR | [`poseidon2_air.zig`](../../src/frontends/riscv/air/memory_commitment/poseidon2_air.zig) | Pure materialization and component pilot |
| Poseidon call collection | [`commitment_witness.zig`](../../src/frontends/riscv/prover/commitment_witness.zig) | Existing call-list pattern |
| Component scheduling | [`component_parallel.zig`](../../src/prover/air/component_parallel.zig) | Existing heterogeneous quotient parallelism |
| Statement geometry | [`statement_geometry.zig`](../../src/frontends/riscv/prover/statement_geometry.zig) | Protocol layout integration point |
| Component ordering | [`component_order.zig`](../../src/frontends/riscv/air/component_order.zig) | Canonical placement authority |

This baseline changes the project strategy: the first delivery is not a new
language parser or a new prover. It is the missing canonical program between
these working pieces.

## Layer 1: typed authoring

Component authors write ordinary Zig functions against a narrow builder
interface. The surface vocabulary has four categories.

### Values

- field values;
- constrained bits and bounded integers;
- byte and limb arrays;
- architectural words;
- register indexes, addresses, PCs, and clocks;
- selectors; and
- current/next-row views.

Logical values do not imply columns. A value becomes committed only through an
input declaration, explicit output, hint, effect boundary, or materialization
decision.

### Algebra

- field addition, subtraction, multiplication, and negation;
- typed word and limb operations implemented through constrained algebra;
- static selection;
- composition and decomposition;
- assertions; and
- statically bounded maps, folds, and loops.

Data-dependent branching is expressed through constrained selectors. Dynamic
looping is not part of AIR authoring.

### Hints

Hints describe honest witness computation separately from the constraints that
bind their result. A hint handler may use native integer operations and
branching. The logical program records its typed inputs, outputs, recipe
identity, and source span.

### Effects

Effects are typed operations such as:

- program fetch;
- register read and write;
- memory read and write;
- range-table request;
- machine retirement;
- component call; and
- public boundary consumption or production.

An effect records semantic order explicitly. It does not depend on traversal
order through the expression graph.

## Layer 2: canonical logical IR

The authoring builder creates an arena-owned SSA graph. The graph contains:

- typed values and operations;
- zero constraints;
- ordered effects;
- hint recipes;
- static component calls;
- function inputs and outputs;
- row-window references;
- public boundary declarations; and
- source spans.

The IR is immutable after construction. A structural validator establishes
well-formedness before any backend consumes it. See [IR.md](IR.md).

## Layer 3: validation and layout

Validation and layout are deterministic passes:

1. type and reference validation;
2. effect and relation-schema validation;
3. hint dependency and output-use validation;
4. expression-degree analysis;
5. gate, mask, and boundary-degree analysis;
6. structural CSE;
7. policy-directed materialization;
8. physical column allocation;
9. relation batching;
10. layout-manifest construction; and
11. final degree and liveness validation.

The initial `compat-v1` policy maps logical inputs and witnesses onto the
existing physical layouts and rejects any mismatch. It does no opportunistic
optimization.

Its implemented opcode-family mapping is local to one component: tree IDs and
column order are fixed, while statement assembly supplies checked global
offsets. Logical semantic names and physical witness names are retained as
separate fields rather than joined by string equality. The mapping covers the
two preprocessed selectors, every main input, and every batch/coordinate of the
interaction trace.

An optimized policy is a named, versioned protocol choice. It may not depend on
hash-map order, machine characteristics, or a benchmark result discovered
during the current build.

## Layer 4: interpreters and lowerers

### Production constraint evaluator

Evaluates the lowered program over the same QM31/M31 representations used by
the current production path. It must preserve constraint and random-coefficient
order.

### Witness engine

Evaluates pure expressions, invokes registered hint recipes, handles concrete
effects, and writes directly into preallocated column slices. It performs no
per-row allocation.

### Relation engine

Transforms typed effects into ordered relation entries. Relation domains,
roles, arities, access ordinals, and multiplicities come from schemas rather
than call-site conventions.

### Formal exporter

Serializes the exact lowered production program. During compatibility phases it
must reproduce AIR IR v2 exactly. Any future IR version is introduced through a
new normative contract, never an undocumented schema extension.

### Runtime backend exporter

Produces backend-neutral topological polynomial programs for CPU and Metal.
Frontend program identity, column order, and roots remain explicit. Generated
device kernels are derived accelerators, not a second semantic source.

### Concrete machine interpreter

This is deliberately last. During migration, the existing runner remains the
independent concrete implementation checked against Sail. Once typed effects
cover all opcodes, a generated execution interpreter may be introduced and
differentially checked, but Sail remains authoritative.

## Component model

A component package contains:

- a stable component kind and version;
- typed input/output schema;
- logical program;
- accepted layout policies;
- witness and hint handlers;
- relation schemas;
- statement geometry function;
- production evaluator capability;
- verifier component capability; and
- validation and benchmark inventory.

Component calls are static at the schema level and dynamic only in
multiplicity. One call relation can have many rows. Padding rows are inactive
and cannot create calls.

## Precompile placement

The first precompile implementation remains inside one STARK statement:

1. core execution records typed calls;
2. the call list is frozen;
3. main traces for core and specialized components are built concurrently;
4. both commit under the same transcript;
5. relation challenges are drawn;
6. interaction traces are built concurrently;
7. heterogeneous quotient evaluation uses the existing component scheduler;
8. the verifier checks one global relation closure.

Separate proofs and recursion are a later layer. They require a public,
transcript-bound relation summary that both leaf proofs expose and the
recursive verifier compares.

## Proposed source layout

Names remain provisional until the first ADR-backed implementation, but the
responsibilities should be local:

```text
src/frontends/riscv/air/lang/
  types.zig              semantic types and typed values
  source.zig             source spans and stable names
  ir.zig                 logical program and arena ownership
  builder.zig            authoring interface
  validate.zig           structural and effect validation
  degree.zig             logical DAG degree analysis
  protocol_degree.zig    complete current-protocol degree analysis
  protocol_report.zig    deterministic compatibility evidence
  compat_layout.zig      exact local `compat-v1` physical mapping
  layout.zig             policies and physical allocation
  manifest.zig           canonical layout identity
  lower_constraint.zig   current ConstraintProgram compatibility
  lower_runtime.zig      backend-neutral polynomial programs
  witness.zig            row evaluation and hint dispatch
  relations.zig          typed relation schema lowering
```

Precompile-generic orchestration belongs beside current RISC-V proving
orchestration, not inside the language:

```text
src/frontends/riscv/precompiles/
  registry.zig
  call_buffer.zig
  poseidon2.zig
```

The general prover scheduler remains frontend-neutral under `src/prover/`.

## Boundaries that must remain separate

- Sail semantics versus generated AIR semantics.
- Architectural integer values versus field elements.
- Logical values versus physical columns.
- Witness recipes versus constraints.
- Component relations versus host callbacks.
- Protocol-stable layout versus optimizer experiments.
- Single-proof component parallelism versus recursive proof aggregation.
- Correctness tests versus performance benchmarks.
