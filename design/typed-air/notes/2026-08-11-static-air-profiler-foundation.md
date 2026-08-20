# 2026-08-11 — Typed-AIR static profiler foundation

## Status

Implemented and integrated into the typed-AIR public module, the package test
inventory, and a dedicated focused build step. It is not attached to a
production proof or runtime telemetry schema. P-001 itself creates no checked
artifact; P-002 now supplies a separate reviewed all-family projection.

## Decision

Add one deterministic static profile beside the typed AIR IR. The profile
answers structural questions before execution and gives later benchmark and
task telemetry a stable program/layout join key. It does not turn structural
counts into performance claims.

The implementation is
`src/frontends/riscv/air/lang/static_profile.zig`. Its schema is
`stwo.typed-air.static-profile.v1`; its canonical SHA-256 domain is
`stwo-zig/typed-air/static-profile/v1\0`.

## Evidence inspected

### A-005 production-shadow report

A-005 already establishes the useful baseline shape for a structural report:
physical main columns, source and canonical DAG nodes, canonical merges,
direct roots, ordered lookups, batches, interaction coordinates, maximum
logical/protocol degrees, and relation dependencies. It also establishes an
important vocabulary rule: algebraic degree three is not cubic asymptotic
proving complexity.

Two A-005 fields cannot be inferred from a native typed arena alone:

- physical main columns belong to the compatibility/commitment layout; and
- CSE merges require a retained count of source construction attempts.

The new profiler therefore accepts those facts only as explicit context.

### H-009 cost frontier

H-009 separates semantic witness structure from a modeled, globally
hash-consed direct polynomial DAG. Its structural vector includes 426
materializations, 445 candidate main columns, 430 direct roots, 3,460 direct
nodes, operation counts, committed reads, and a modeled streaming peak of 39
nodes.

The distinction matters. The new profile's `expression_dag_*` fields describe
the logical typed IR. They are not aliases for H-009's lowered
`canonical_direct_*` fields. Likewise, H-009's streaming peak is a schedule
property of a particular modeled direct program, not observed resident memory.
No such fields are copied into the static profile.

An optional `degree3_materializer.Plan` may be supplied. The profiler fully
validates it and records only facts owned by that plan: materialization and
output counts, dependency edges, structural-reuse count, and maximum stored
body/constraint degree.

### H-010 retained evaluator

H-010 measures witness generation, direct evaluation, and operating-system
peak RSS for one authenticated retained-scratch evaluator. Those measurements
are runtime properties of a concrete evaluator and workload. They remain in
the H-010 benchmark schema. The static profile can authenticate the program
and layout used by a future H-010-style run, but cannot infer timing, RSS,
scratch residency, or a layout winner.

### C-013 proof benchmark

C-013's child schema records end-to-end execution, proving, encoding,
verification, proof bytes, exact committed cells, and process resource
counters. Its schedule, workload, security profile, source, executable, ELF,
proof, and corpus identities are separately pinned.

The static profile is complementary: a future child report may include its
digest as the AIR/layout identity used by the attempt. It must not replace
C-013's exact statement-derived cell counts or any runtime/resource field.
Static shape does not imply proving speed.

### Stage and task telemetry

`stage_profile` v1 owns hierarchical elapsed seconds. `task_profile` v2 owns
task identities, dependencies, waits, run intervals, byte classes, planned and
completed work, critical path, concurrency, cancellation, and resource
reservation. Backend telemetry separately owns dispatch, fallback, copy,
upload, and cache counters.

Those are observed execution facts. They should join to a static profile by
digest in a future telemetry schema version, not be embedded into or hashed by
the static schema.

## Authority model

```text
validated typed Arena ───────────────┐
                                     ├─ static_profile.collect ─ Profile v1
explicit physical/batching context ──┤                         └─ profile digest
optional validated materialization ──┘

Profile digest ── future join ── stage/task/backend/C-013 observations
```

Intrinsic facts are computed from the arena:

- logical input nodes;
- constraint root references and unique root values;
- repeated references to the same constraint-root value;
- total effects, relation-bound lookup events, and non-lookup effects;
- logical value and constraint degree;
- lookup numerator and relation-denominator degree;
- expression-DAG nodes, operand edges, shared nodes, and maximum fanout; and
- the expression closure reachable from constraint roots/gates and effect
  values/liveness.

Explicit context supplies facts the arena does not own:

- final physical main-column count;
- singleton/pair LogUp batch size and interaction coordinates per batch;
- source expression-node count before canonical interning; and
- an optional authenticated materialization plan.

When batching is supplied, lookup batch count, interaction-column count, and
the maximum degree of the current singleton/pair LogUp recurrence are derived.
Without batching, those fields are `null`, not zero.

## Schema v1

| Field group | Fields | Authority and interpretation |
| --- | --- | --- |
| Identity | `schema_version`, semantic digest format and bytes, profile digest | Program identity comes from the current typed-AIR semantic digest; profile digest also binds explicit context and every static field. |
| Columns | `physical_main_columns`, `logical_input_nodes`, `interaction_columns` | Physical counts are present only when layout context is supplied. Logical input nodes are not relabelled as physical columns. |
| Roots | `constraint_roots`, `unique_constraint_root_values`, `duplicate_constraint_root_references` | A duplicate means another constraint references the same value ID. It does not claim the complete constraints are semantically duplicate because gate, category, and name may differ. |
| Effects/lookups | `effects`, `lookup_events`, `non_lookup_effects` | A lookup is a validated relation-bound effect. Declared order is retained for batching. |
| Batching | batch size, batch count, interaction coordinates per batch | Nullable and explicit. V1 admits only the current singleton/pair recurrence. |
| Degree | logical value/constraint maxima, lookup numerator/denominator maxima, modeled interaction maximum | Logical and protocol layers remain named separately. The interaction maximum exists only with explicit batching. |
| Materialization | count, outputs, dependency edges, reused values, maximum body and equality-constraint degrees | Nullable as one group and emitted only after complete `Plan.validate`. |
| DAG | nodes, operand edges, shared nodes, maximum fanout | Canonical logical expression DAG, not lowered direct algebra and not backend work. Hint/call outputs are DAG leaves, matching current degree/materialization semantics. |
| Closure indicator | reachable and outside-closure node counts | Roots/gates and effect values/liveness are sinks. “Outside” is an audit signal, not deletion authority: function, hint, diagnostic, or future lowering semantics may still name a node. |
| CSE | source nodes and merges | Both are nullable. `cse_merges = source_nodes - canonical_nodes` only when an importer supplies exact source provenance. Native construction attempts are not observable after interning. |

The fixed record contains no borrowed slices and owns no memory. JSON is one
canonical line with fixed key order. TSV has a fixed header and uses the text
`null` for unavailable values. Both encoders validate the record and digest
before emitting their first byte.

## Digest rules

The digest is SHA-256 over:

1. the domain separator and schema version;
2. typed semantic digest format and bytes;
3. every profile field in one fixed order; and
4. an explicit presence byte before every nullable integer.

All integers use fixed-width little-endian encoding. Text rendering, allocator
identity, capacity, addresses, source locations, hash-map order, and runtime
telemetry are excluded. The typed ADDI profile is pinned by focused tests to:

```text
34057a4cdcb0b42caeeec0eadd99cf86309d5eb0405f3fbd3bb0c69829d62fb4
```

Moving the authored source span does not change that profile or digest.

## Complexity and allocation discipline

The base path performs bounded sequential passes:

- the existing validated logical-degree analysis;
- semantic identity computation;
- one forward node pass for input/edge/fanout accounting;
- one reverse topological pass for constraint/effect closure; and
- one ordered effect pass for relation and optional batch-degree accounting.

There is no sorting, hash-map construction, recursion, timing, randomness, or
quadratic duplicate scan in the profiler. One caller-allocator scratch slice
stores reachability, root-seen, and fanout state. Existing degree analysis owns
its explicit temporary arrays. The returned profile is a value and requires no
`deinit`.

Supplying a materialization plan deliberately invokes the existing complete
plan validator before reading its summaries. That validation is cold and can
perform repeated degree/reachability work as defined by the materializer; its
cost must not be conflated with the base linear profile pass or placed in a
prover hot loop.

`Profile.validate`, profile digest recomputation, and JSON/TSV writers allocate
nothing. Focused tests exercise every allocation failure in collection and use
fixed-buffer writers for serialization.

## Claim boundary

Profile v1 does not establish or estimate:

- proving, verification, witness, composition, or commitment time;
- asymptotic proving complexity;
- proof or transcript size;
- trace cells without per-component domain geometry;
- backend scratch, peak RSS, residency, traffic, dispatch, copy, or fallback;
- H-009 lowered direct-node or streaming-live-node counts;
- global optimality or an optimization winner;
- whether a node outside the constraint/effect expression closure is safe to
  delete; or
- CSE savings when source-attempt provenance was not retained.

Any future cost estimate must be a separately versioned projection over this
identity plus explicit geometry. Any runtime result must remain a separately
versioned observation.

## Integration state and remaining seams

This tranche now:

- re-exports `static_profile` from `src/frontends/riscv/air/lang/mod.zig`;
- exposes `test-air-static-profile` through
  `src/frontends/riscv/build.zig` with normal and `-Dcheck-only=true` modes;
- names `air/lang/static_profile_test.zig` in the fail-closed package test
  inventory; and
- raises the package test-count floor by the five newly inventoried tests.

Later consumers can integrate at these explicit seams:

1. At each typed definition adapter, pass the definition's authoritative
   `MAIN_COLUMN_COUNT`, relation batch size, and four QM31 coordinates per
   current interaction column. Do not infer these from input/effect counts.
2. For the A-005 shadow adapter, pass `source_to_value.len` as
   `source_expression_nodes`; this reproduces the provenance needed for CSE
   merges without changing the A-005 artifact schema in place.
3. For Poseidon materialization analysis, pass the authenticated
   `degree3_materializer.Plan`. Keep H-009 lowered-direct costs in its own cost
   record.
4. If runtime correlation is admitted, add `static_profile_schema` and
   `static_profile_sha256` through a new task-profile/benchmark schema version.
   Do not silently extend task-profile v2 or C-013 child v3.
5. A later artifact command may write canonical JSON/TSV and pin bytes under a
   new receipt. This foundation intentionally creates no checked artifact.

## Focused verification

The isolated suite covers:

- exact typed ADDI columns, roots, effects, lookups, batches, and degrees;
- source-location-independent profile identity and a golden digest;
- a synthetic shared DAG with a duplicate root reference, one node outside the
  constraint/effect closure, two materializations, one dependency edge, and
  explicit CSE provenance;
- canonical valid JSON and column-aligned TSV from fixed buffers;
- malformed lookup/source context, structural corruption, digest corruption,
  and pre-emission failure; and
- cleanup under every injected allocation failure.

Acceptance includes the dedicated root in Debug, ReleaseSafe, and ReleaseFast,
the focused package build step in check-only mode, and the package inventory
gate.
