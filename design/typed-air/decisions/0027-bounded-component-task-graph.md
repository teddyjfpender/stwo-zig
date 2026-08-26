# ADR-0027 — Bounded component task graph

**Status:** accepted
**Date:** 2026-08-06

**Classification:** protocol-preserving prover scheduling, ownership, and
measurement boundary

## Context

R-001 requires an executable model of component work before R-002 and R-003
make main- and interaction-trace construction concurrent. The model cannot be
a generic collection of closures over a thread pool. In the current RISC-V
prover, declaration order, transcript order, allocator ownership, and the
lifetime of values borrowed by later stages are already part of the proof
boundary.

[`orchestration.zig`](../../../src/frontends/riscv/prover/orchestration.zig)
runs the following protocol order:

1. derive the memory/program commitment witness and admitted statement;
2. mix the PCS configuration and public statement;
3. generate and commit Tree 0;
4. generate and commit Tree 1;
5. mix the main claim and shard manifest, grind the interaction proof of work,
   and draw all relation challenges;
6. generate the interaction claim and commit Tree 2; and
7. assemble declaration-ordered components and run the generic prover.

Those barriers are real. Tree roots, claims, proof-of-work nonces, and random
coefficients are mixed into one mutable Fiat--Shamir channel. Neither a
per-component transcript nor a completion-order reduction can reproduce that
channel in general.

There are nevertheless substantial independent regions between the barriers:

- [`main_trace.zig`](../../../src/frontends/riscv/prover/main_trace.zig)
  currently overlaps one opcode-generation helper thread with serial
  infrastructure generation. Opcode and infrastructure writes are disjoint,
  but infrastructure is appended through one mutable cursor. The helper may in
  turn use the process-global work pool, so the helper, coordinator, and pool
  are not one enforceable worker budget.
- [`interaction_trace.zig`](../../../src/frontends/riscv/prover/interaction_trace.zig)
  generates opcode shards, program, memory shards, Merkle, Poseidon2, clock,
  and six lookup-table interactions in serial declaration order. Some large
  generators take the whole global pool in turn. Results are appended through
  one mutable cursor even though each result has a statement-derived final
  range and claim slot.
- [`component_parallel.zig`](../../../src/prover/air/component_parallel.zig)
  already contains the right algebraic seed for parallel composition: each
  component receives a disjoint coefficient-power range and accumulator, and
  accumulators merge in protocol order. Its ordinary and
  `pool_exclusive_domain` paths prevent some nested waits, but there is no
  cancellation, task accounting, per-request budget, or shared scheduler with
  trace construction.
- [`task_graph.zig`](../../../src/prover/task_graph.zig) is currently a serial
  executor with 32 slots. It erases a task's cause as `error.TaskFailed`, has no
  cancellation or ownership state, and is smaller than the admitted 256 opcode
  shards, 512 infrastructure descriptors, or 1,024 component handles.
- [`work_pool.zig`](../../../src/prover/work_pool.zig) is a lazily initialized
  process-global pool. `STWO_ZIG_WORKERS` fixes its size only at first use; it
  does not lease a per-request budget or prevent a pool worker from waiting on
  nested work in the same pool.
- [`deferred_commit.zig`](../../../src/prover/pcs/deferred_commit.zig) may spawn
  a dedicated thread for the first tree. This correctly delays the root mix
  until the canonical publication point, but that thread is outside the global
  pool and therefore outside an M7 worker count. Some Merkle paths have similar
  private executors.
- [`proof_workspace.zig`](../../../src/frontends/riscv/prover/proof_workspace.zig)
  deliberately gives statement, opcode columns, retained clock columns, and
  component handles stable addresses. Its ownership notes and fixed-capacity
  tests are the starting point; concurrent work must not reintroduce large
  stack values or movable borrowed storage.
- [`stage_profile.zig`](../../../src/prover_api/stage_profile.zig) is a
  single-stack hierarchical recorder. Concurrent tasks cannot push and pop
  that stack without inventing false parent/child relationships, and it is not
  a thread-safe task recorder.

Commit functions consume their input columns on both success and failure, and
the scheme owns a committed tree afterwards. Tree-1 opcode and clock buffers
remain separately owned until Tree 2 and composition stop borrowing them.
[`commitment_witness.zig`](../../../src/frontends/riscv/prover/commitment_witness.zig)
owns the boundary, program, Merkle-row, and Poseidon-call allocations for the
entire transaction. A cancellation design that detaches a worker or frees one
of these owners before all borrowers join is a use-after-free, not a graceful
abort.

Finally, M7 is governed by the normative
[`m5-m9-protocol-v1.json`](../performance/m5-m9-protocol-v1.json), not by an
informal throughput result. It requires byte-identical protocol artifacts,
bounded task accounting, joined cancellation, no nested oversubscription, and
verified worker-scaling and resource evidence on both required lanes.

## Decision

Introduce one structured, per-proof `ComponentTaskGraph` executed by one
shared `WorkPool` under an explicit `WorkerBudget`. The graph is a prover
execution facility, not proof identity: it may change wall-clock order only
where the current data dependencies permit it. Canonical descriptor order and
the coordinator's transcript order remain the sole source of proof layout and
bytes.

The first implementation replaces the internals of `task_graph.zig`; it does
not add another pool. RISC-V orchestration supplies the plan, fixed result
slots, ownership callbacks, and task metadata. Generic prover composition uses
the same executor through an explicit execution context rather than consulting
`getGlobalPool()`.

### Execution model

One proving request has exactly one coordinator and a configured worker count
`N`:

- `N` is in `1...work_pool.MAX_WORKERS` and includes the coordinator whenever
  the coordinator runs task work;
- the shared pool owns at most `N - 1` active helper threads for that request;
- `N = 1` executes the same plan, task bodies, result slots, assemblers, and
  cleanup path synchronously in canonical task order;
- a native command may map `STWO_ZIG_WORKERS` into `N`, but library code receives
  `N` explicitly and the receipt records both the requested and admitted value;
- concurrent proofs lease workers from the same process-wide capacity. The sum
  of active leases, including their coordinators, may not exceed that capacity;
  and
- failure to admit the requested lease is explicit. A normal prover may choose
  `N = 1`; an M7 capture records `NO_VERDICT` rather than silently relabelling a
  smaller lease as the requested arm.

During migration, the pre-existing opportunistic global-pool entrypoint has no
requested worker count. If its lease is busy before any task starts, it may run
the already-prepared plan with `N = 1` so unrelated concurrent proofs do not
begin failing. That compatibility fallback is recorded as non-admissible for an
M7 scaling capture. The explicit request executor added for promotion retains
the fail-closed lease rule above.

There are three task classes:

| Class | May run with siblings | May submit nested work | May mutate channel or scheme |
| --- | --- | --- | --- |
| `leaf` | yes, subject to worker and byte budgets | no | no |
| `pool_exclusive` | no other task body is active | only through the same leased executor | no |
| `coordinator` | only at its declared barrier | no | yes, where the stage says so |

A leaf receives a serial child execution context. Asking that context for more
than one worker is a deterministic error in safety builds and a serial decline
in production; it never discovers the process-global pool. A
`pool_exclusive` task runs only after every earlier leaf has drained and may use
the complete request lease for an existing row-, FFT-, Merkle-, or
domain-parallel kernel. A worker thread never blocks waiting for tasks queued
behind itself. The coordinator either participates in a work-first parallel
loop or waits from outside the leased helper set.

`component_parallel` keeps its current distinction:

- ordinary heterogeneous components with a prepared, allocation-free domain
  evaluator are leaf tasks with independent coefficient-power ranges and
  accumulators;
- a legacy component without that capability remains a coordinator-run serial
  task until it gains one; it is never made concurrently allocator-unsafe;
- one statically selected dominant component may use the lease while ordinary
  leaves drain only when that implementation is non-blocking under the shared
  executor; and
- components marked `pool_exclusive_domain` execute breadth-first, one at a
  time, in canonical component order after ordinary leaves have drained.

No task may call `std.Thread.spawn`, construct `std.Thread.Pool`, or call
`getGlobalPool()`. The current opcode helper, deferred first-tree worker, and
private Merkle executors must be disabled or converted to executor work when a
`ComponentTaskGraph` context is present. Transitional non-graph callers may
keep their current fallback until their stage migrates, but a mixed graph and
private-thread request is not M7-admissible.

### Capacity and plan construction

Plan construction is serial and fallible. It completes before any task starts
and performs all graph metadata allocation. Each execution epoch allocates one
exact-size `[]TaskSlot`; it never grows, reallocates, or stores task state in a
worker stack frame.

The active epoch is bounded by
`proof_workspace.MAX_COMPONENT_HANDLES` (currently 1,024). This covers the
largest current epoch:

- at most 256 opcode descriptors plus 512 infrastructure descriptors for a
  trace epoch; and
- at most `2 * 256 + 512 = 1,024` prover-component handles for composition.

Opcode row chunks, audit chunks, and coordinator barriers use separate drained
sub-epochs and therefore do not add to the component-slot bound. A plan whose
descriptor-derived count exceeds the bound fails before the channel changes.
All dependency lists are validated for in-range IDs, duplicates, self-edges,
cycles, and forward references. Empty required stages and an unknown admitted
component kind fail closed.

Every task has a stable `TaskKey` formed from:

```text
epoch | stage_rank | component_registry_index | shard_or_chunk_index
```

All fields are fixed-width integers. Names are diagnostic projections of this
key and do not participate in ordering. The planner assigns output ranges and
claim slots from the admitted statement before execution; workers never obtain
an output position from a completion counter.

Ready tasks are ranked from static data only: longest remaining dependency
level first, then descending checked integer work estimate, then ascending
`TaskKey`. Row counts, column counts, final constraint counts, and log sizes may
feed the estimate. Wall-clock observations, allocator addresses, worker IDs,
and prior benchmark results may not. Scheduling is allowed to vary with
completion timing; observable proof data is not.

### Exact stages and dependencies

The graph is divided by transcript barriers. A dependency arrow below means
the consumer cannot be submitted to a worker until every named producer has
published success. Coordinator stages are included because they define when
ownership and transcript state change, even when they do not consume a helper.

#### Admission and Tree 0 / Tree 1 epoch

| Key | Class | Dependencies | Current code seam and output |
| --- | --- | --- | --- |
| `A.derive` | coordinator | none | `commitment_witness.build` plus `statement_geometry.build`; publishes the owned witness and admitted workspace statement before the channel is touched |
| `A.transcript-open` | coordinator | `A.derive` | mixes PCS configuration then public data and initializes the scheme exactly where `proveStages` does today |
| `P.reserve` | coordinator | `A.derive` | allocates declaration-ordered Tree-0 destinations and generator scratch from statement geometry |
| `P.generate` | leaf | `P.reserve` | prepared `preprocessed.generateInto`; publishes declaration-ordered Tree-0 source columns |
| `P.build` | `pool_exclusive` | `P.generate` | prepares/LDEs/hashes Tree 0 without touching the channel or `scheme.trees`; publishes one owned prepared tree |
| `P.publish` | coordinator | `A.transcript-open`, `P.build` | appends Tree 0 and mixes its root exactly once |
| `M.reserve` | coordinator | `A.derive` | computes every Tree-1 column range/log size, allocates final storage and scratch under the byte budget, and initializes empty ownership slots |
| `M.opcode-prepare` | coordinator | `M.reserve` | classifies proof opcodes, fixes chunk/family offsets and placements, and allocates per-chunk lookup counters |
| `M.opcode-fill[k]` | leaf | `M.opcode-prepare` | one disjoint execution-row range from `opcode_trace.generate`; writes final opcode ranges and its private counter set |
| `M.opcode-reduce` | coordinator | all `M.opcode-fill[k]` | checks task errors and geometry, then merges counters by ascending `k`; no completion-order reduction |
| `M.opcode-audit[i]` | leaf | `M.opcode-reduce` | optional non-ReleaseFast direct-semantic audit for admitted opcode descriptor `i`; it never mutates columns |
| `M.program` | leaf | `M.reserve` | `appendProgramColumns` into the program descriptor's preassigned range |
| `M.memory[j]` | leaf | `M.reserve` | `appendMemoryColumns` for memory shard `j`, using the statement's row interval and preassigned column range |
| `M.merkle` | leaf or `pool_exclusive` | `M.reserve` | `appendMerkleColumns` into the Merkle descriptor range; class is fixed from checked geometry |
| `M.poseidon2` | leaf or `pool_exclusive` | `M.reserve` | `appendPoseidonColumns` / `generateMainInto` into the Poseidon descriptor range |
| `M.clock` | leaf | `M.reserve` | `appendClockColumns`; publishes the retained workspace clock columns and their byte-identical committed range |
| `M.lookup-seed` | coordinator | `M.opcode-reduce`, `M.clock` | takes opcode counters, then registers program, memory-boundary, and clock requests from the already-owned witness and clock columns |
| `M.table[t]` | leaf | `M.lookup-seed` | materializes fixed lookup-table multiplicity column `t` into its preassigned registry range |
| `M.seal` | coordinator | every emitted `M.*` producer and enabled audit | verifies every slot was initialized exactly once, applies test mutation/dump hooks in their current position, and captures a diagnostic tree when requested |
| `M.commit-build` | `pool_exclusive` | `M.seal`, `P.publish` | consumes Tree-1 columns and prepares/LDEs/hashes one owned tree without touching the channel or scheme |
| `M.commit-publish` | coordinator | `M.commit-build` | moves the prepared Tree-1 result into the scheme and mixes its root exactly once |
| `R.claim-mix` | coordinator | `M.commit-publish` | mixes the canonical main claim and shard manifest |
| `R.pow` | `pool_exclusive` | `R.claim-mix` | grinds the interaction nonce against the coordinator-supplied transcript state and publishes the nonce only |
| `R.draw` | coordinator | `R.pow` | checks and mixes the nonce, then draws the one shared `Relations` value |

`P.build` and the `M.*` construction tasks may overlap when their admitted byte
reservations fit. `P.publish` remains ahead of `M.commit-build`; this is the structured
equivalent of the current deferred-first-tree optimization. The prepared-tree
result, not a detached thread, carries the pending ownership.

The graph does not make each opcode shard rescan the execution. It preserves
the current single classification and row-range fill: chunk offsets prove that
workers write disjoint physical rows, and private counter sets retain the
current canonical reduction. Infrastructure components use descriptor-indexed
`put`/`reserve` operations instead of `Columns.offset`.

#### Tree 2 epoch

| Key | Class | Dependencies | Current code seam and output |
| --- | --- | --- | --- |
| `I.reserve` | coordinator | `R.draw` | zeroes the boxed interaction claim and allocates every final Tree-2 range and prepared scratch |
| `I.opcode[i]` | leaf or `pool_exclusive` | `I.reserve` | generates descriptor `i` from the retained opcode main columns under the shared relations; publishes its fixed interaction range and `opcode_claims[i]` |
| `I.program` | leaf | `I.reserve` | publishes program interaction columns and the program descriptor's claim slot |
| `I.memory[j]` | leaf | `I.reserve` | publishes memory-shard `j` columns and its infrastructure-indexed claim slot |
| `I.merkle` | leaf or `pool_exclusive` | `I.reserve` | publishes Merkle columns and `merkle_claims[merkle_infra_index]` |
| `I.poseidon2` | leaf or `pool_exclusive` | `I.reserve` | publishes Poseidon2 columns and `poseidon_claims[poseidon_infra_index]` |
| `I.clock` | leaf | `I.reserve` | reads the retained byte-identical clock main columns and publishes clock interaction columns and claim |
| `I.table[t]` | leaf or `pool_exclusive` | `I.reserve` | reads finalized lookup counter `t` and publishes the fixed table range and infrastructure-indexed claim |
| `I.seal` | coordinator | every `I.*` producer | verifies exact range/claim initialization and canonicalizes the complete claim in statement order |
| `I.claim-mix` | coordinator | `I.seal` | mixes the canonical interaction claim exactly once |
| `I.commit-build` | `pool_exclusive` | `I.claim-mix` | consumes Tree-2 columns and prepares/LDEs/hashes one owned tree without touching the channel or scheme |
| `I.commit-publish` | coordinator | `I.commit-build` | moves the prepared Tree-2 result into the scheme and mixes its root exactly once |

All interaction producers receive the same borrowed `Relations` pointer from
`R.draw`. There is no task-local draw, cloned channel, or relation cache keyed
by completion order. The current serial and planned paths use the same
descriptor-indexed generators; only their execution order differs.

An admitted future precompile component is another registry-indexed main and
interaction task with dependencies declared by its reviewed witness and
relation plan. The scheduler does not infer a dependency from a component name
and cannot activate an unregistered kind.

#### Component composition and proof-finalization epoch

| Key | Class | Dependencies | Current code seam and output |
| --- | --- | --- | --- |
| `F.components` | coordinator | `I.commit-publish` | `proof_finalize` constructs stable component values and handles in exact statement order |
| `F.alpha` | coordinator | `F.components` | the generic prover draws the composition coefficient from the post-Tree-2 channel |
| `F.composition-prepare` | coordinator | `F.alpha` | extracts the trace, allocates secure powers and one independent accumulator/scratch plan per component, and assigns coefficient ranges in component order |
| `F.component[i]` | leaf or `pool_exclusive` | `F.composition-prepare` | evaluates component handle `i` into only accumulator `i`; the class follows the reviewed `pool_exclusive_domain` policy |
| `F.composition-merge` | coordinator | every `F.component[i]` | checks errors, merges accumulator 1 through N into accumulator 0 in ascending component order, and finalizes one composition evaluation |
| `F.interpolate-split` | `pool_exclusive` | `F.composition-merge` | current composition interpolation and canonical split |
| `F.composition-build` | `pool_exclusive` | `F.interpolate-split` | commits chunks into one owned prepared commitment in canonical coordinate order without touching the channel |
| `F.composition-publish` | coordinator | `F.composition-build` | moves the prepared commitment into the scheme and mixes its root exactly once |
| `F.oods` | coordinator | `F.composition-publish` | draws the OODS point and constructs declaration-ordered mask points |
| `F.pcs` | coordinator | `F.oods` | runs the existing transcript-ordered PCS pipeline, leasing the request executor only at its declared exclusive kernel barriers |
| `F.constraint-check` | coordinator | `F.pcs` | performs the current OODS composition equality check and publishes the proof only on success |

`F.pcs` is one dependency stage here, not permission to create a private pool.
Its existing FFT, quotient, sampled-value, Merkle, and proof-of-work parallel
kernels receive the request executor or run serially. Later ADRs may expose
more PCS subnodes without changing transcript order or this ownership model.

### Ownership and allocator discipline

Every task slot has one coordinator-owned state machine:

```text
planned -> ready -> running -> succeeded -> moved
                         |-> failed
planned/ready ---------- |-> cancelled
succeeded/failed/cancelled -> released
```

Only the coordinator changes `planned`, `ready`, `moved`, or `released`. A
worker claims `ready -> running` exactly once and publishes exactly one terminal
result with release ordering. The worker owns all task-local scratch until that
publication. On success, the result slot owns the output; on failure, the task
has already released partial local state and publishes no borrowed pointer.
The canonical assembler moves successful outputs once and clears their slots.

Final column storage and task scratch are prepared before worker execution.
Worker hot paths do not call an allocator. Existing generators that allocate
inside `generate` or domain evaluation gain a `prepare`/`runInto` split before
they become leaf tasks. This is required for three reasons:

1. `std.mem.Allocator` does not advertise thread safety;
2. serial preparation makes allocation failure occur before sibling mutation;
   and
3. direct writes avoid multiplying wide traces by the number of active tasks.

The caller allocator remains the sole allocator identity. The graph does not
hide it behind a short-lived thread-safe wrapper whose outputs later escape.
Graph metadata, final buffers, per-task scratch, and cleanup records are
allocated on the coordinator. Allocation and deallocation that must remain
inside an existing backend kernel occur only while that kernel is
`pool_exclusive`, before its row workers start or after they join.

The current ownership transfers remain authoritative:

- `CommitmentWitness` stays owned by `proveStages` until every graph epoch and
  `Engine.prove` borrower has drained;
- opcode and clock retained buffers stay owned by `main_trace.Retained` until
  Tree 2 and composition finish;
- a `Columns` aggregate owns every initialized slot until the call to
  `Engine.commit`; that call consumes all columns on success or error;
- a prepared tree is owned by its task result until `P.publish` or another
  canonical commit publication moves it into `scheme.trees`;
- the scheme is owned by orchestration until it is moved into `Engine.prove`;
  cancellation before that move deinitializes it only after all tasks join; and
- the boxed interaction claim moves to `ProveOutput` only after proof success.

No worker deinitializes workspace, witness, scheme, channel, recorder, or a
sibling result. Coordinator cleanup scans result slots in reverse canonical
order after the executor is drained. This gives one auditable release order and
makes allocation-failure tests independent of completion timing.

### Cancellation and deterministic errors

The graph owns one atomic cancellation flag and one fixed failure slot per
task. The first non-cancellation task failure atomically requests cancellation.
After that request:

- no not-yet-running task starts;
- every planned or ready task becomes `cancelled` exactly once;
- CPU row loops poll at least once per bounded tile, with a maximum tile of
  4,096 rows;
- an already submitted GPU command is awaited and never detached or freed
  while in flight; no later command is submitted;
- running tasks release local scratch or publish their already-complete owned
  result, then terminate; and
- the coordinator joins every helper before inspecting errors or releasing any
  borrowed owner.

Cancellation is not an error cause. Once drained, the coordinator scans failed
slots by ascending `TaskKey` and returns the original error from the first one.
The task that won the cancellation race is recorded separately. Thus
simultaneous failures have a canonical reported cause among the work that
actually ran, while cancellation latency remains observable. Tests that inject
multiple failures use a start barrier so the set of running failures is fixed.

Errors from coordinator stages retain their current exact error. A worker
failure is never collapsed to `error.TaskFailed`. Spawn failure before a task
starts either runs that task synchronously within the same budget or fails
admission before any sibling starts; it does not silently omit the task.

No partial proof output is returned. The caller's channel may have advanced if
a failure occurs after `A.transcript-open`, exactly as it can today; the channel
is caller-owned and documented as consumed by a proving attempt. What is
guaranteed is that a failure before `A.transcript-open` leaves it untouched and
that no worker ever races its state.

### Canonical output

Concurrency is permitted to affect only timestamps and worker assignment. The
following remain byte-exact for every admitted `N`:

- statement and component descriptors;
- Tree-0, Tree-1, Tree-2, and composition column order and values;
- lookup-counter reductions and all relation summaries;
- transcript event sequence, draws, nonces, and roots;
- component handle order and coefficient-power assignment;
- composition accumulator merge order;
- sampled-value, FRI, and query order; and
- serialized proof and protocol artifacts.

Result slots are indexed from the statement and component registry. A task may
finish first and still occupy a later slot. Claims are written only to their
descriptor index, then canonicalized by the existing statement logic. The
channel and scheme are mutated only by coordinator publication stages. Field
addition may be algebraically commutative, but reductions still use the current
serial order so implementation changes cannot hide behind that fact.

### Memory bounds and backpressure

Before an epoch starts, every task declares checked integer values for:

```text
final_output_bytes
exclusive_scratch_bytes
shared_resident_bytes
device_resident_bytes
worker_stack_bytes
```

Final outputs that must coexist for a commitment are allocated once and counted
once as epoch-resident storage. A task reserves only its additional scratch
before becoming ready. The scheduler starts a ready task only when both a
worker lease and its complete byte reservation are available. It may skip to a
smaller ready task using the static ranking, but finite ready work cannot starve:
when no task is running, a task that cannot fit causes
`error.TaskMemoryBudgetExceeded` rather than an over-budget launch.

The byte budget includes padded rows, every final base/interaction coordinate,
temporary coefficient/LDE storage, counter scratch, backend staging, and
configured worker stacks. The generic pool retains its existing 16 MiB default
for kernel classes that have not established a smaller bound. Prepared AIR row
evaluators instead declare the shared 128 KiB
`ROW_EVALUATOR_STACK_BYTES` admission requirement. Promotion requires both a
static audit of every fixed local and focused execution of the production row
loop on a helper configured with exactly that stack. The original 64 KiB
candidate was rejected after the complete package and product binaries crossed
its guard in opcode and generic memory evaluators despite isolated focused
passes. This narrower requirement does not silently resize the generic pool
and may not put `RiscVStatement`, `ProofWorkspace`, or component-capacity
arrays back on a worker frame.

Tree-1 generation writes into the existing backend-shaped arena when available.
The generic path gains equivalent preallocated per-column destinations rather
than allocating one temporary result per concurrent task. Tree-2 gains a
statement-shaped final arena. PCS streaming commitment remains available, but
its preparation/hash stage is exclusive and must declare its actual batch and
high-water reservation. The scheduler never overlaps two wide commitment
preparations merely because their transcript publications are later serialized.

Admission limits are deterministic configuration, not learned from the run.
Peak RSS remains an operating-system measurement under the performance
protocol; a byte reservation is not relabelled as measured RSS.

### Serial differential and rollback

`N = 1` is the normative candidate serial mode. It executes the graph without a
pool, using the same prepared destinations and canonical assemblers as `N > 1`.
During migration, the current non-graph path remains behind one explicit
rollback option. It is test authority, not an alternative production identity.

For every migrated epoch, tests compare:

1. predecessor serial path versus graph `N = 1`;
2. graph `N = 1` versus each supported `N > 1`;
3. CPU-native versus Metal-hybrid functional artifacts where both lanes are
   admitted; and
4. successful, allocation-failure, injected-task-failure, mutation, and
   cancellation paths.

The differential covers statement bytes, geometry, complete column digests,
canonical relation claim, transcript event trace, proof bytes, verifier result,
and allocator leak accounting. It also asserts that every borrowed owner
outlives the last task that can read it. The old path may be deleted only after
all three graph epochs have passed the M7 exact gates and the rollback period
has closed explicitly.

### Telemetry

The existing hierarchical `stage_profile.Recorder` remains coordinator-only.
It records wall-clock envelopes and serial transcript stages. Parallel work
uses a separate, flat `TaskProfile`; workers write only their preassigned event
slot, so there is no shared append and no false nesting.

Each task event records at least:

- `TaskKey`, stable stage ID, component kind/index, shard/chunk index, and task
  class;
- dependency keys and whether the task is M7 parallel-eligible;
- submitted, ready, start, cancellation-request, and finish monotonic integer
  nanoseconds where applicable;
- configured worker count, worker slot, queue-wait nanoseconds, run
  nanoseconds, and coordinator/helper classification;
- final-output and reserved scratch bytes, resource-wait nanoseconds, and
  device bytes where applicable;
- terminal status, exact error name, cancellation winner/reason, and cleanup
  completion; and
- static work estimate and completed rows/tiles.

The request summary records:

- requested/admitted workers, pool capacity, worker-stack bytes, and
  `peak_active_workers`;
- `submitted`, `completed`, `failed`, and `cancelled`, with the required equality
  `submitted = completed + failed + cancelled`;
- duplicate-start and duplicate-finish counters, both required to be zero;
- useful task work, critical-path duration computed from the declared DAG,
  queue/resource wait, worker utilization, cancellation latency, and peak
  reserved bytes;
- scheduler kind and steal count. The initial central ready queue declares
  `central_queue_no_steal` and reports an exact zero rather than inventing a
  work-stealing metric; and
- per-component work and the complete flat event list in canonical `TaskKey`
  order, independent of completion order.

For the one-worker M7 arm, `parallelizable_fraction p` is computed exactly as
the protocol defines it: the sum of run durations for tasks marked
parallel-eligible whose dependencies were satisfied, divided by one-worker
verified-request duration. Receipt construction uses raw integer nanoseconds;
floating-point presentation is not the authority. A qualifying workload has
`p >= 0.40` and at least 500,000,000 eligible nanoseconds. At least two M7
workloads must qualify.

### M7 promotion gates

This ADR does not replace or narrow the normative protocol. Production
activation requires all of its M7 rules, including:

- the corpus `multi_shard_addi`, `memcpy_loop`,
  `balanced_core_and_poseidon2`, and `poseidon2_dominant`;
- worker counts 1, 2, 4, and `min(8, physical_cores)` on a host with at least
  four physical cores;
- candidate one-worker proof bytes, statement, transcript, relation summaries,
  and geometry exactly equal to the protocol-preserving predecessor;
- byte-identical proof and protocol artifacts for every candidate worker count;
- `peak_active_workers <= configured_workers`;
- submitted-task accounting closes exactly, no task starts or completes twice,
  the first fatal failure cancels and joins every sibling, nested work creates
  no pool and exceeds no global bound, and task events express overlap without
  false hierarchy;
- candidate one-worker versus predecessor one-worker satisfies every universal
  budget;
- for every qualifying workload at the largest worker count, verified-request
  speed lower CI is at least
  `max(1.05, 0.70 / ((1 - p) + p / N))`;
- the CPU-native primary target `multi_shard_addi`, four workers over one worker
  on the same candidate, has verified-request speed lower CI at least
  `max(1.05, 0.70 * Amdahl ideal)`;
- largest-worker process CPU, retired instructions, and GPU command work over
  candidate one worker have upper CI at most 1.15, and peak RSS has upper CI at
  most 1.25; and
- both `cpu-native` and `metal-hybrid` pass independently, with the required
  Metal runtime identity, resident dispatch count, and zero fallback evidence.

The 1.15 total-work and 1.25 RSS limits replace the corresponding universal
caps only for candidate N-worker versus candidate one-worker scaling. They do
not excuse a regression against the predecessor. Proof verification,
fresh-child sampling, A/A calibration, and every other universal budget remain
as specified by the protocol.

## First implementation slice

The first code slice is deliberately below the transcript and frontend layers:

1. replace the serial 32-slot executor in `src/prover/task_graph.zig` with the
   exact-size bounded state machine, explicit `WorkerBudget`, cancellation,
   deterministic error scan, byte reservations, and flat task telemetry;
2. add budgeted submission to `src/prover/work_pool.zig` without changing its
   process-global ownership;
3. add an optional prepared-domain capability to `ComponentProver`: its
   coordinator `prepare` owns every fallible allocation and its leaf `run`
   receives fixed scratch, an accumulator, and a cancellation token;
   components without the capability remain serial;
4. migrate `component_parallel.compute` to that executor. Keep its existing
   serial preparation of secure powers and per-component accumulators, run
   prepared ordinary components as leaves, run `pool_exclusive_domain`
   components in canonical breadth-first phases, and retain the current ordered
   merge; and
5. pass the execution context through `Engine.prove` for one RISC-V proof while
   leaving Tree 0, Tree 1, and Tree 2 on their current serial orchestration.

That slice exercises the hardest scheduler invariants with the smallest
protocol surface: fixed coefficient ownership, heterogeneous component sizes,
exclusive row-parallel components, deterministic merge, cancellation, and
proof-byte differential. Its tests must include N=1/2/4, two simultaneous
failures behind a start barrier, cancellation of queued and running siblings,
allocation failure before launch, byte-budget backpressure, and nested-submit
rejection. Only after it is green does R-002 replace `OpcodeGeneration` and the
Tree-1 append cursor with the main-trace epoch above. R-003 then adopts the
Tree-2 epoch, R-004 removes remaining nested/global pool discovery, and R-005
wires the task profile into performance receipts.

## Consequences

The proof protocol remains unchanged, but the scheduling boundary becomes
explicit and testable. Main, interaction, and composition work can use the
same finite hardware budget without completion order leaking into columns,
claims, reductions, or the transcript. A single-worker run becomes a real
differential of the parallel machinery instead of a separate implementation.

The design adds preparation APIs and result-slot state. That is deliberate
complexity: it converts allocator failure, cancellation, and ownership transfer
from conventions spread across helper threads into one structured transaction.
Direct-to-final generation should also reduce temporary memory and make Metal
arena adoption easier.

Some current opportunistic overlap will be temporarily disabled as stages
migrate. In particular, a graph request cannot also use the dedicated deferred
commit thread or hidden Merkle pools. Performance is recovered through the
shared executor only after exact output, cleanup, and resource accounting are
proven.

The worker-count limit is now a property that can be audited, not an intention.
The price is that every internally parallel kernel must accept an execution
context or explicitly run serially. This is necessary for M7 and also gives M9
recursive proving a usable global budget instead of multiplying pools at every
tree level.

## Rejected alternatives

### Keep the opcode helper and add more dedicated threads

Rejected because dedicated threads compose by addition. They cannot enforce
the M7 worker count once opcode generation, deferred commits, interactions,
composition, FFTs, Merkle hashing, and recursive proving overlap.

### Create one pool per component or stage

Rejected because pool multiplication oversubscribes both cores and worker
stacks, makes cancellation non-structural, and violates the exact M7 nested-work
gate.

### Submit one task per row

Rejected because task count and queue memory would scale with witness rows.
Rows are processed in bounded chunks inside a protocol-capacity component task;
the graph itself is bounded by admitted descriptors and component handles.

### Let workers append columns and claims under a mutex

Rejected because a mutex prevents memory corruption but makes completion order
the layout authority. Preassigned descriptor ranges are simpler and preserve
the current protocol order without synchronization on the hot path.

### Give every task a cloned transcript and merge digests

Rejected because Fiat--Shamir is a sequential cryptographic transcript, not a
mergeable log. Only channel-independent construction may run ahead of a
barrier; root and claim publication remains singular and ordered.

### Return the first error observed in wall-clock time

Rejected because worker timing would change the public failure. Cancellation
may be requested by the first observed failure, but the returned cause is
selected from drained failure slots in canonical task order.

### Detach or abandon workers after cancellation

Rejected because workers borrow the witness, workspace, relations, trace
arenas, and scheme-owned buffers. Every sibling must terminate and join before
any of those owners can be released.

### Share the existing hierarchical stage recorder across workers

Rejected because concurrent siblings do not have one stack nesting. A flat,
preassigned task timeline records real overlap; coordinator stage envelopes
remain hierarchical.

### Adapt concurrency from timings observed during the same capture

Rejected because it introduces post-selection and makes the plan depend on
noisy measurements. Task class, work estimate, byte reservation, worker count,
and primary performance target are frozen before candidate execution.

## Revisit when

Revisit the fixed task-slot bound if statement admission raises
`MAX_COMPONENTS`, `MAX_INFRA_COMPONENTS`, or `MAX_COMPONENT_HANDLES`. Revisit
the single device-serial resource only after a backend exposes independently
owned command queues, deterministic publication, bounded device memory, and a
failure model that survives concurrent commands. Revisit central ready-queue
scheduling if measured contention is material and a work-stealing executor can
preserve the same task-accounting schema and global lease.

Do not revisit transcript barriers, descriptor-indexed output, joined
cancellation, or one shared worker budget merely because a backend offers more
threads. Those are correctness and ownership boundaries. A protocol-changing
component registry, distributed prover, or recursive multi-proof scheduler
requires its own decision and must compose with this budget rather than bypass
it.
