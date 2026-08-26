# Precompile and parallel component design

**Status:** proposed staged design
**Last updated:** 2026-08-04

## Definition

A precompile is a specialized proof component implementing a versioned,
deterministic function or effect that the core machine invokes through a typed
relation.

It consists of:

1. guest-visible invocation semantics;
2. an honest host implementation that produces outputs;
3. a typed call schema;
4. a call buffer with canonical multiplicities;
5. a specialized witness and AIR;
6. relation closure tying calls to supplied rows;
7. statement and transcript identity; and
8. verifier support.

Host code that computes a value without items 3–8 is an oracle, not a
precompile.

## Existing proof-component seam

The sparse-Merkle path already demonstrates most internal mechanics:

- [`commitment_witness.zig`](../../src/frontends/riscv/prover/commitment_witness.zig)
  collects ordered Poseidon2 calls;
- [`poseidon2_air.zig`](../../src/frontends/riscv/air/memory_commitment/poseidon2_air.zig)
  creates a specialized 445-column table;
- [`main_trace.zig`](../../src/frontends/riscv/prover/main_trace.zig) places
  it in the main commitment;
- [`interaction_trace.zig`](../../src/frontends/riscv/prover/interaction_trace.zig)
  constructs its relation columns, with parallel paths;
- [`component_order.zig`](../../src/frontends/riscv/air/component_order.zig)
  fixes component placement; and
- [`component_parallel.zig`](../../src/prover/air/component_parallel.zig)
  evaluates heterogeneous component quotients concurrently.

The first guest precompile should reuse and generalize this seam. It should not
replace the existing Merkle component or conflate its relation domain with
guest calls.

## Call ABI

A call schema contains:

```text
precompile domain and version
operation selector or mode
typed inputs
typed outputs
activation multiplicity
optional execution ordinal
```

For a deterministic pure function, the relation tuple can be the domain,
version, inputs, and outputs. A unique call ID is unnecessary for mathematical
soundness when multiplicities are correct, but an execution ordinal may be
useful for diagnostics and public accounting. It must not be added to the
proof tuple unless the protocol needs it.

The core consumes or requests the tuple. The precompile table supplies it.
Repeated identical calls are represented by a bounded integral multiplicity or
repeated rows according to one reviewed policy.

## Guest invocation boundary

The first implementation should use an explicit, versioned zkVM ABI:

- a reserved host-call surface, custom instruction, or clearly identified
  runtime entry point;
- deterministic input/output memory layout;
- explicit failure behavior;
- profile admission and program-commitment binding; and
- Sail/refinement treatment appropriate to an extension outside base RV32IM.

It should not recognize an arbitrary sequence of ordinary RV32IM instructions
and silently replace it with a precompile. Verified trace compression of native
code is a separate and substantially harder project.

The base RV32IM claim must remain precise: a precompile invocation is a
documented zkVM extension, not relabelled Sail behavior.

## Execution and witness flow

1. The runner encounters an admitted precompile invocation.
2. It validates input placement and reads typed inputs.
3. The host implementation computes outputs so execution can continue.
4. The runner records one canonical call in an owned buffer.
5. The core trace records the invocation and its architectural effects.
6. After execution, the call buffer is frozen and sorted only if the protocol
   specifies canonical sorting.
7. The specialized witness engine fills one or more precompile tables.
8. Core and precompile relation events close under shared challenges.

The honest host result and specialized witness may share an implementation for
efficiency, but mutation tests treat every output as prover-controlled.

## One-proof parallelism

The initial topology is one proof and one transcript:

```text
execution
   |
   +-- core rows -----------+
   +-- precompile calls ----+--> parallel main-trace construction
                            |
                       commit main trees
                            |
                  draw shared relation challenges
                            |
              parallel interaction-trace construction
                            |
              parallel component quotient evaluation
                            |
                       one PCS/FRI proof
```

This gives useful concurrency without solving cross-proof relation binding.
Current prover infrastructure already parallelizes component quotient
evaluation; the new scheduler should expose main-trace and interaction tasks at
the same component granularity.

Parallel work is bounded by the existing work pool. No component creates its
own unbounded threads. Dominant components may subdivide disjoint row ranges;
small components run as leaf tasks.

## Separate proofs and recursion

True independent core and precompile proofs require more than verifying each
one's local LogUp sum. The leaves must expose compatible,
transcript-bound relation summaries.

A future relation summary should bind at least:

- relation schema and version;
- challenge derivation context;
- claimed source/sink accumulator;
- multiplicity and source bounds;
- component statement digest; and
- public call commitment where needed.

A recursive aggregator then verifies both proofs and equality/cancellation of
the relevant summaries. Two-to-one aggregation can combine leaves into a tree,
but recursion is not allowed to obscure a missing cross-proof binding.

## Poseidon2 pilot

Poseidon2 is the first target because:

- a reviewed field implementation already exists;
- its existing AIR contains 426 manually materialized temporaries, an ideal
  compiler equivalence target;
- it has clear deterministic inputs and outputs;
- interaction and parallel code already exist; and
- hash-heavy guest workloads provide meaningful performance evidence.

The pilot has two distinct stages.

### Compiler stage

Express the permutation as pure typed functions and regenerate the existing
Merkle Poseidon layout under `compat-v1`. Require exact row, constraint,
relation, proof, and formal/runtime-program equivalence.

An optimized layout is a later policy and is benchmarked separately.

### Guest-precompile stage

Add an explicitly versioned guest call relation that reuses the mathematical
permutation while preserving a separate semantic domain from Merkle hashing.
Prove ordinary software and precompile executions produce the same advertised
output on a pinned corpus, while being honest that the precompile is a zkVM
profile extension.

## Failure and padding policy

- Invalid invocation data rejects before architectural state mutation.
- A host failure does not produce an active call row.
- Padding has zero liveness and cannot balance a real call.
- Unused output lanes are constrained to their canonical values.
- Unsupported modes reject; they do not fall through to a weaker relation.
- Call counts and component geometry are statement-bound.
- Relation-source coefficients remain below the applicable M31 bounds.
- Empty call tables have one canonical representation.

## Performance hypotheses

The precompile wins when specialized trace cells plus interaction overhead are
substantially less than the native instruction trace it replaces.

Expected wall-clock shape with adequate resources:

```text
serial:    core proof work + hash proof work
parallel:  max(core proof work, hash proof work) + linking overhead
```

Actual measurements must also report total CPU/GPU work and peak memory. A
smaller elapsed time caused solely by using twice the hardware is useful but
must be labelled accurately.

## Open design questions

1. Which guest ABI best preserves the repository's Sail-authoritative base
   profile?
2. Does the first call table retain duplicates or aggregate multiplicities?
3. Can the current Poseidon relation schema be parameterized safely, or should
   guest calls use a distinct schema?
4. Which main-trace stages can begin before execution completes, and which need
   the frozen statement geometry?
5. What relation summary is sufficient for later independent proofs?
6. Is recursive aggregation built over M31-native verification or another
   field/curve boundary?
7. How are precompile versions admitted into artifact and verifier policy?

Answers require ADRs before production implementation.
