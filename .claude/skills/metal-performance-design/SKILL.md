---
name: metal-performance-design
description: Design and review high-performance Metal compute, render, and hybrid architectures for Apple GPUs. Use when writing or reviewing Metal host code or MSL; choosing storage modes, resource lifetimes, synchronization, command-buffer structure, bindings, pipeline compilation, threadgroup/SIMD-group algorithms, render-pass attachments, tile-memory techniques, or GPU-driven execution; removing allocation, dispatch, or CPU-GPU wait overhead; or turning Metal profiling evidence into an implementation plan. Use metal-profiling for measurement and this skill for architecture and code changes.
---

# Design high-performance Metal systems

Optimize measured end-to-end throughput and latency on the target Apple GPU,
not Metal folklore. Before recommending or implementing a design, read
[common-patterns.md](references/common-patterns.md) completely. For a
render-only or hybrid workload, also read
[render-patterns.md](references/render-patterns.md) completely. Do not load the
render reference for compute-only work unless the design introduces a render
pass.

If the change invents or replaces an algorithm rather than mapping an existing
one to Metal, apply `../match-algorithmic-problems/SKILL.md` first. Evaluate
Metal Performance Shaders, Metal Performance Primitives, and established
libraries before hand-writing a generic primitive.

## Classify the workload first

- **Compute-only:** analyze resource residency, dispatch epochs, memory traffic,
  thread execution, and readback boundaries. Do not apply render-pass TBDR rules
  to ordinary compute dispatches.
- **Render-only:** additionally analyze attachment lifetime, load/store actions,
  tile memory, overdraw, and CPU draw encoding.
- **Hybrid:** draw dependencies across compute and render passes; preserve useful
  overlap and avoid system-memory round trips between stages.

Record the device family, OS and SDK floor, Metal language/version, required
fallback, and runtime feature checks. Never infer tile size, SIMD width,
argument-buffer tier, or advanced features from an “M-series” or “A-series” name.

## Use this default priority order

Override the order only with measurements:

1. Preserve identical work, outputs, ordering, and production admission.
2. Remove CPU-GPU round trips, hot-path compilation/allocation, and unnecessary
   completion boundaries.
3. Reduce command buffers, dispatches/passes, and system-memory bytes moved.
4. Reduce measured CPU binding and state-encoding work.
5. Tune shader access, SIMD-group/threadgroup cooperation, and occupancy.
6. Add feature-gated tile or GPU-driven techniques when simpler changes cannot
   remove the bottleneck.

## Produce a design brief

Write this before changing architecture:

```text
Workload and target devices:
Unit of work and equivalence oracle:
Measurement boundary, build mode, and run conditions:
Measured bottleneck and evidence:
Required features and fallbacks:
Resource lifetime/storage table:
Peak working set and in-flight multiplier:
CPU-GPU and pass dependency graph:
Command-buffer and in-flight ownership plan:
Binding and pipeline-compilation plan:
Shader/threadgroup plan:
Render-pass/tile plan (if applicable):
Work/byte/dispatch or attachment-traffic budget:
Expected counter or trace changes:
Correctness, ABI, and synchronization proof:
Before/after validation plan:
```

Treat each optimization as a hypothesis. Predict the counter, dispatch count,
bandwidth, CPU encode time, GPU time, or wait interval that should move.

## 1. Establish the baseline and target

Use `metal-profiling` to separate CPU encoding, queue starvation, command-buffer
or wait overhead, GPU execution, bandwidth, and occupancy. Capture the target
device and feature support with the evidence. Do not redesign a kernel when the
trace says synchronization or submission economics dominate.

Define one unit of completed work and an equivalence oracle before timing. Use
optimized production-like builds for performance verdicts. Use validation,
capture, replay, and counters for diagnosis, then confirm the result without
their instrumentation overhead and across the normal overlap schedule.

## 2. Build the resource plan

Inventory each large or hot resource: size, producer, consumer, CPU/GPU access,
mutability, lifetime, aliasing, and reuse interval. Select `shared`, `private`,
or a compatibility mode from the access table in the common reference. Select
`memoryless` only from the render reference. UMA alone is not a storage-mode
decision.

Budget persistent resources, peak transient aliases, staging, archives, and all
in-flight copies. Compare the peak against the target device's working-set
guidance and record allocation telemetry; unified memory pressure harms the CPU
and GPU together.

Move device, queue, library, pipeline, heap/arena, buffer, texture, and reusable
plan construction outside hot loops. Prefer persistent arenas or bounded pools
to per-dispatch allocation. Define every CPU-to-MSL layout as an ABI and verify
size, alignment, and important offsets instead of relying on type-name similarity.

## 3. Prove ownership and scheduling

Draw the pass/dispatch dependency graph and annotate every CPU/GPU ownership
transition. Choose command-buffer boundaries, barriers/events, readbacks, and
in-flight resource slots from that graph. State why each blocking wait exists.

Maximize useful GPU work per submission and completion boundary without hiding
latency, breaking error propagation, or exhausting memory. Treat three in-flight
slots as a display-loop convention, not a compute constant. Before replacing a
`waitUntilCompleted`, prove how resource reuse, returned results, and failures
remain ordered. Retain every resource and host-side owner through its last GPU
use. Recycle in-flight slots even when a command buffer fails, surface the
failure, and keep completion handlers bounded.

## 4. Choose binding and compilation strategy

Estimate and measure CPU binding cost. Keep direct bindings for a small stable
interface; adopt argument buffers for large, reused, dynamically indexed, or
GPU-driven resource groups only with explicit tier, mutability, residency, and
usage handling.

Create known pipeline variants outside latency-sensitive work. Specify AOT,
binary-archive, or newer compilation behavior together with device compatibility,
cache identity, miss/rebuild handling, and fallback. Reorder render state only
when profiling justifies it and semantic draw ordering remains intact.

## 5. Design the shader around the limiting resource

State the expected limiter before editing MSL. Write a per-unit budget for bytes
read/written, arithmetic work, dispatches, and barriers; compare it with measured
bandwidth and execution time. Minimize system-memory passes and redundant loads
first. Evaluate fusion against register pressure, occupancy, and lost
concurrency. Choose threadgroup shapes from pipeline properties and sweeps, not
a fixed width. Treat occupancy as evidence, not an objective by itself.

Use SIMD-group operations only for communication within one SIMD group. Use
threadgroup memory and the required synchronization for wider reuse. Include
divergence, atomics, access coalescing, dependency chains, register use, spills,
and threadgroup-memory pressure in the measurement plan. Treat compiler math
modes, reduced precision, and reassociation as correctness changes, not free
performance switches; require an explicit numerical contract before using them.

## 6. Add the render/TBDR branch only when applicable

For each attachment, record first use, last use, whether prior contents matter,
and whether later work consumes it. Derive load/store/resolve actions and
memoryless eligibility from that dataflow and the render reference. Evaluate
pass merging, programmable blending, imageblocks, tile shaders, and persistent
threadgroup memory only with feature checks, ordering proof, and a finite
tile-memory budget. Treat hardware tile dimensions as opaque.

## 7. Justify GPU-driven execution

Distinguish a GPU-written indirect argument buffer from an indirect command
buffer containing commands and state. Compare direct CPU encoding with the full
GPU-driven cost: culling, compaction, reset, residency, empty commands,
synchronization, and fallback. Adopt it only when it removes a measured round
trip or encoding bottleneck at sufficient scale.

## Preserve stwo-zig's production contracts

- Keep production on authenticated AOT metallibs; do not introduce source JIT
  into an admitted path.
- Reuse the resident arena, prepared plans, persistent sessions, and archive
  identity/telemetry instead of creating parallel lifetime systems.
- Treat existing completion waits as possible API or readback boundaries.
  Measure the wait and enlarge the dispatch epoch before deleting synchronization.
- Keep proof outputs and transcript-visible behavior bit-exact. Validate every
  shader or schedule change against the CPU/reference path.
- Skip TBDR render advice for the current compute-only prover unless a render
  pass is actually introduced.

## Exercise the large scored regime

The Metal board's `xlarge` and `huge` classes are wide Fibonacci traces at
log18 × 100 and log20 × 100. They use the manifest's explicit `large` resource
profile and bounded sampling, and they are first-class suite coordinates rather
than diagnostics. Validate architecture changes there as well as on
small/wide/deep; the large regime is where residency, submission economics,
bandwidth, and threadgroup reuse become visible.

ClementWalter/stwo#6 provides public, bit-identical-certified hypotheses worth
measuring here: threadgroup-tiled FFT stages and single-submission GPU commit
chains, alongside batched constraint evaluation. Predict global-memory passes,
command buffers, dispatches, waits, and peak in-flight bytes before porting a
technique. Keep it only when Metal traces and complete-proof ABBA evidence match
that prediction and the Rust Stwo oracle accepts identical proof bytes.

## Verify and retain evidence

Run Metal API validation and shader warnings, correctness/parity tests, ABI
checks, and resource-lifetime stress tests. Profile before and after on target
devices with GPU time, bandwidth, occupancy, threadgroup sweeps, CPU encoding,
dispatch counts, waits, and Metal System Trace as applicable. Measure warm and
cold compilation behavior separately, plus sustained steady state under matched
thermal and power conditions. Use capture/replay for attribution and an
uninstrumented paired run for the verdict. Reject improvements that change the
work, reduce correctness coverage, move work outside the timed interval, or win
only on one transient sample. Preserve the design brief and evidence with the
PR or design note.
