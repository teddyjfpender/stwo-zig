---
name: cuda-performance-design
description: Design generic, process-resident CUDA proving architectures from ProofProgram and CudaPlan evidence. Use for runtime ownership, arenas, caching, streams, graphs, AOT modules, pass reduction, proof concurrency, and frontend/backend boundaries.
---

# Design high-performance CUDA provers

Optimize complete verified proofs across structural classes. Preserve
`conformance/2026-07-24-cuda-system-architecture-goal.md` and apply
`../cuda-profiling/SKILL.md` before changing architecture.

## Required design brief

```text
program families and target GPUs:
correctness and final oracle:
measurement boundary and current profile:
ProofProgram nodes and transcript barriers:
resource lifetime/alias table:
accounted peak and in-flight multiplier:
module and plan cache identity:
stream/event dependency graph:
graph-capture regions and parameter updates:
global-memory passes and bytes by stage:
host/device transfer and synchronization plan:
failure/unwind ownership:
predicted structural-class effects:
validation and ABBA plan:
```

## Priority order

1. Preserve proof semantics and exact production admission.
2. Remove request-time context, module, plan, allocation, and compilation work.
3. Remove intermediate transfers and host synchronization.
4. Reduce global-memory passes, temporary materialization, and launch count.
5. Introduce evidence-derived overlap and stable graph regions.
6. Tune dominant kernels for access, instruction, register, and occupancy limits.
7. Admit concurrent proofs only after a single proof's saturation is measured.

## Runtime ownership

`CudaRuntime` is the only owner of device-global state. It contains no AIR name.
It retains authenticated modules, device identity, pools, immutable tables,
prepared plans, streams, events, and graph executables. Frontends emit
`ProofProgram`; the CUDA compiler produces `CudaPlan`; proof sessions borrow
bounded resources.

For each resource record:

- byte size and alignment;
- persistent, shape-local, request-local, or terminal-host lifetime;
- producer and last consumer;
- mutability and alias eligibility;
- owning runtime/session and error-unwind path;
- stream and last-use event;
- cache key and eviction rule.

No cache may prolong a proof-owned resource accidentally. No eviction may free
a live resource.

## Scheduling

Start with the dependency DAG:

- transcript absorbs and challenge derivations are hard barriers;
- independent component trace/commit work may use lane streams;
- quotient chunks and Merkle subtrees may overlap only without hidden shared
  scratch or bandwidth saturation;
- FRI rounds remain sequential while work within one round may parallelize;
- the coordination stream owns terminal assembly and one proof readback.

Use an event edge for a real cross-stream dependency. Do not insert a
device-wide synchronization for convenience. Compare one-stream and scheduled
paths byte-for-byte and under Nsight Systems.

## CUDA Graphs

Graphs cache stable launch topology, not compilation or proof semantics.

Capture a region only when:

- topology and arena addresses are stable;
- request variation is expressible as validated parameter updates;
- transcript-dependent host work does not bisect the region;
- instantiate/update cost is outside or smaller than the warm request;
- a direct-execution differential path remains available.

Bind graph cache identity to the complete `CudaPlan`. Record instantiate,
update, launch, miss, and fallback counters. A graph update failure fails closed
in production; it does not silently enter a direct or JIT path.

## AOT and research compilation

Production loads authenticated per-SM cubins. Exact device support is required.
PTX is a labelled compatibility mode. NVRTC is permitted only outside proving
requests for research and onboarding, followed by parity, identity generation,
review, and AOT promotion.

The cache key includes GPU SM, driver/runtime compatibility, toolkit, host
toolchain, module digest, program digest, protocol, geometry, and schedule
version. Module load count should approach one per process, not one per proof.

## Pass reduction

For each dominant stage write a pass ledger:

```text
pass | input bytes | output bytes | reread bytes | temporary bytes
     | launches | barriers | retained consumer
```

Prefer eliminating a materialized intermediate or complete global-memory pass
over shaving instructions from a bandwidth-bound kernel. Fusion is accepted
only when reduced traffic outweighs register growth, spills, occupancy loss,
and lost overlap. Retain before/after Nsight counters.

## Memory and concurrency

Account:

- persistent runtime/module/table bytes;
- cached shape/graph bytes;
- one proof's live arena high-water mark;
- staging and terminal host buffers;
- allocator reservation;
- concurrent-session multiplier.

Admission uses checked arithmetic and device capacity policy. One proof may
already saturate DRAM or compute. Concurrent sessions are a throughput feature,
not an automatic latency feature, and require queue, tail-latency, fairness,
and out-of-memory evidence.

## Broad-system acceptance

Evaluate latency, narrow/deep, wide/non-target, hash-heavy, lookup-heavy,
irregular, VM, extreme, and sustained classes. Use equal class weights. A large
wide-Fibonacci win cannot compensate for a proof-family regression. Minimum
system acceptance is 1.3x; 2x is the objective.
