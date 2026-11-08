# Apple GPU Metal core patterns

Use this reference for compute, render, and hybrid workloads. Treat it as a
decision table, not a list of unconditional rules. It was checked against Apple
documentation on 2026-07-18. Recheck the current Metal feature tables and target
SDK before relying on feature availability.

## Contents

- [Resource storage and UMA](#resource-storage-and-uma)
- [Feature gating and deployment](#feature-gating-and-deployment)
- [CPU-GPU ownership and synchronization](#cpu-gpu-ownership-and-synchronization)
- [Binding, pipelines, and persistent state](#binding-pipelines-and-persistent-state)
- [Shader execution, data layout, and numerical contracts](#shader-execution-data-layout-and-numerical-contracts)
- [Indirect execution](#indirect-execution)
- [Measurement integrity](#measurement-integrity)
- [Guardrails against overgeneralization](#guardrails-against-overgeneralization)
- [Primary Apple sources](#primary-apple-sources)

## Resource storage and UMA

Choose storage mode from ownership, not from the assumption that all unified
memory has identical performance:

| Access and lifetime | Preferred design | Important condition |
| --- | --- | --- |
| CPU writes/reads and GPU consumes/produces | `shared` | Enforce CPU/GPU ownership; avoid cache-thrashing access from both processors |
| GPU-only intermediate or long-lived data | `private` | Populate by GPU or blit; include upload cost in end-to-end measurement |
| Intel/external discrete Mac compatibility | default or `managed` as required | Managed resources require explicit synchronization; do not make this the Apple-GPU path |

On Apple GPUs, `shared` means CPU and GPU can address the same system-memory
allocation. It avoids a discrete upload copy but still consumes system bandwidth
and requires correct ordering. `private` remains useful because GPU-only access
permits Metal to optimize the resource. Allocate long-lived resources once and
reuse them; use heaps or arenas when they improve aliasing, residency, or
allocation overhead and the lifetime proof is explicit.

Count the full peak: persistent resources, heap slack, transient overlap,
staging, in-flight rings, and compilation/archive state. Compare device
`currentAllocatedSize` with `recommendedMaxWorkingSetSize` where available.
Treat the latter as guidance, not an allocation entitlement. Set texture usage
flags narrowly enough for Metal to optimize access and verify the effect with
bandwidth and resource-allocation tooling.

## Feature gating and deployment

Make capability checks part of the design rather than cleanup after coding:

| Decision | Runtime/build evidence |
| --- | --- |
| Apple GPU family features | `supportsFamily` plus the current Metal feature tables |
| Argument-buffer design | `argumentBuffersSupport`, tier limits, and shader interface reflection |
| Threadgroup shape | Pipeline `threadExecutionWidth`, `maxTotalThreadsPerThreadgroup`, and device/threadgroup-memory limits |
| Memory budget | Device `currentAllocatedSize`, `recommendedMaxWorkingSetSize`, and measured peak lifetime |
| Tile/imageblock/ICB feature | OS/API availability plus the exact GPU-family capability |
| Archive or compilation path | Deployment target, device compatibility, cache identity, and tested miss fallback |

Compile and test a fallback for every optional feature required on supported
devices. Log the selected feature path in benchmark evidence so a fast result
cannot be attributed to the wrong implementation.

## CPU-GPU ownership and synchronization

Use a FIFO ring when the CPU updates data while earlier GPU work is in flight.
Tie slot reuse to command completion. The familiar depth of three comes from a
render loop whose drawable limit is commonly three; it is a starting point, not
a universal compute constant. Too few slots serialize processors; too many add
memory and latency.

Finish CPU writes before committing work that reads them. Do not overwrite a
slot until its consuming command buffer completes. Prefer completion handlers or
shared events for asynchronous notification. Use GPU fences, barriers, or events
for real resource hazards, not as general “make this safe” decoration.

Retain buffers, textures, argument-buffer dependencies, and their host-side
owners until the last consuming command completes. If the command-buffer or
resource configuration disables automatic retention or hazard tracking, require
an explicit lifetime and hazard proof plus stress tests. Use completion handlers
as short ownership notifications: release the ring slot on both success and
failure, record command-buffer status/errors, and move substantial recovery or
follow-on work elsewhere. Otherwise an error path can deadlock the producer or
silently recycle invalid results.

`waitUntilCompleted` blocks the calling thread. Avoid it between small dispatches
in a throughput path. It remains valid at a synchronous API boundary, required
readback, initialization probe, correctness test, or profiling interval. The
first optimization is often to encode a larger dependency-preserving epoch into
one command buffer and wait once.

## Binding, pipelines, and persistent state

Create devices, queues, buffers, textures, libraries, pipeline states, samplers,
and depth/stencil state early and reuse them. Keep resource and PSO construction
out of render/compute hot loops.

Direct bindings are appropriate for a small fixed interface. Argument buffers
reduce CPU binding overhead for large resource groups, stable groups reused
across calls, dynamic indexing, and GPU-driven pipelines. They introduce tier,
mutability, layout, and explicit residency obligations. Declare referenced
resources with `useResource` or `useHeap`; declare writable heap members with the
correct resource usage rather than relying on a read-only heap declaration.

Binary archives associate pipeline descriptors with compiled shader code and
can reduce or avoid device-time compilation. Treat them as versioned,
GPU-specific cache/build artifacts with miss, invalidation, and rebuild paths.
They do not justify compiling PSOs in a latency-sensitive loop or assuming every
pipeline creation is free. Newer Metal versions add compilation and harvesting
workflows; select them from the deployment target instead of mixing APIs blindly.

Sort rendering by pipeline/material only when state encoding is a measured CPU
cost and the reorder preserves semantic draw order. Metal state changes are not
automatically the dominant cost.

## Shader execution, data layout, and numerical contracts

Query pipeline/device properties and check GPU family support. Do not hard-code
SIMD width from a chip generation. SIMD-group operations exchange or reduce data
within one SIMD group and can avoid threadgroup-memory traffic for that scope.
They do not communicate across SIMD groups. Use threadgroup memory and the
required barriers for cross-group reuse; include its occupancy and cache cost.

Start with contiguous/coalesced access, fewer system-memory passes, sufficient
grids, and threadgroup dimensions related to `threadExecutionWidth`. Sweep real
dimensions. Check divergence, register pressure, spills, atomics, threadgroup
memory, cache behavior, and arithmetic dependency chains with counters rather
than source inspection alone.

Do not maximize occupancy blindly. Low occupancy can reflect a small grid or
short shader, while high occupancy can still thrash caches or execute excessive
work. Correlate occupancy with limiters, elapsed GPU time, and useful work.

Host and MSL structs form an ABI. Use the Metal Shading Language specification
for size/alignment rules, keep definitions shared when practical, and assert
`sizeof`, alignment, and important offsets on the host. Three-component vectors,
arrays, matrices, packed types, and language-specific SIMD wrappers are common
layout traps. `float4` or `simd_float4` is not a universal optimization; use it
when the ABI and access pattern call for a four-lane, 16-byte-aligned value.

Define the numerical contract before enabling fast math, reduced precision,
reassociation, approximate functions, or mixed-precision accumulation. These
options can change results and reproducibility. Validate them against stated
error bounds and adversarial inputs; preserve bit-exact integer, proof, hash,
and transcript-visible behavior when the workload requires it.

## Indirect execution

Keep these distinct:

- **Indirect arguments:** a GPU-written `MTLBuffer` with a fixed draw/dispatch
  argument layout, consumed by one indirect draw or dispatch API.
- **Indirect command buffer (ICB):** a collection of render or compute commands
  and permitted state, encoded on the CPU or GPU and executed later.

Use GPU-driven culling/compaction plus ICBs when CPU visibility readback and draw
encoding are measured bottlenecks at sufficient scale. Include command reset,
compaction, residency, empty slots, synchronization, and feature fallback in the
design. For a small stable command stream, direct CPU encoding may remain faster.

## Measurement integrity

Use two measurement modes:

- **Attribution:** enable API/shader validation, captures, replay, counters, and
  System Trace as needed to locate the cause.
- **Verdict:** run an optimized production-like build without capture or
  validation overhead, with identical completed work and correctness checks.

GPU counter replay may serialize passes that normally overlap; use it to explain
individual passes, not as the sole end-to-end concurrency result. Metal capture
also adds measurable CPU overhead. Use System Trace to confirm scheduling and an
uninstrumented run to confirm headline latency/throughput.

Separate cold compilation/startup, warm-cache latency, and sustained steady
state. Match device, OS, build, workload, background load, power source, and
thermal state. Interleave baseline and candidate when possible. Report medians
and dispersion or confidence intervals, not the fastest sample. Confirm that
resource creation, preprocessing, compilation, synchronization, and readback
remain inside the measurement boundary appropriate to the claimed result.

## Guardrails against overgeneralization

- Do not translate “UMA” into “make every resource shared.”
- Do not translate “bindless” into “every workload needs argument buffers.”
- Do not translate “triple buffering” into a fixed depth for batch compute.
- Do not translate “avoid waits” into returning before required results exist.
- Do not disable retention or hazard tracking without proving both obligations.
- Do not call binary archives an unconditional no-cost PSO cache.
- Do not confuse GPU-generated indirect arguments with GPU-encoded ICB commands.
- Do not treat SIMD-group operations as cross-threadgroup communication.
- Do not maximize occupancy without correlating it to time and limiter counters.
- Do not treat a relaxed numerical contract as a performance-only change.
- Do not use capture/replay timing as the sole end-to-end performance verdict.
- Do not optimize a kernel after traces show submission or synchronization is
  the dominant end-to-end cost.

## Primary Apple sources

- [Choosing a resource storage mode for Apple GPUs](https://developer.apple.com/documentation/metal/choosing-a-resource-storage-mode-for-apple-gpus)
- [Setting resource storage modes](https://developer.apple.com/documentation/metal/setting-resource-storage-modes)
- [Synchronizing CPU and GPU work](https://developer.apple.com/documentation/metal/synchronizing-cpu-and-gpu-work)
- [Persistent Metal objects](https://developer.apple.com/library/archive/documentation/3DDrawing/Conceptual/MTLBestPracticesGuide/PersistentObjects.html)
- [Improving CPU performance with argument buffers](https://developer.apple.com/documentation/metal/improving-cpu-performance-by-using-argument-buffers)
- [Tracking argument-buffer resource residency](https://developer.apple.com/documentation/metal/tracking-the-resource-residency-of-argument-buffers)
- [Metal feature set tables](https://developer.apple.com/metal/capabilities/)
- [Metal binary archives](https://developer.apple.com/documentation/metal/metal-binary-archives)
- [Encoding indirect command buffers on the GPU](https://developer.apple.com/documentation/metal/encoding-indirect-command-buffers-on-the-gpu)
- [Resource synchronization](https://developer.apple.com/documentation/metal/resource-synchronization)
- [Recommended maximum working-set size](https://developer.apple.com/documentation/metal/mtldevice/recommendedmaxworkingsetsize)
- [Measuring GPU memory bandwidth](https://developer.apple.com/documentation/xcode/measuring-the-gpus-use-of-memory-bandwidth)
- [Reducing shader bottlenecks](https://developer.apple.com/documentation/xcode/reducing-shader-bottlenecks)
- [SIMD-group operations on A14](https://developer.apple.com/videos/play/tech-talks/10858/)
- [Analyzing Metal performance and thermal state](https://developer.apple.com/documentation/xcode/analyzing-the-performance-of-your-metal-app/)
- [Apple GPU counter statistics](https://developer.apple.com/documentation/xcode/analyzing-apple-gpu-performance-using-counter-statistics)
- [Metal capture overhead](https://developer.apple.com/documentation/xcode/capturing-a-metal-workload-programmatically)
- [Optimizing GPU performance with Xcode](https://developer.apple.com/documentation/xcode/optimizing-gpu-performance/)
- [Metal Performance Primitives Programming Guide](https://developer.apple.com/download/files/Metal-Performance-Primitives-Programming-Guide.pdf)
- [Metal Shading Language Specification](https://developer.apple.com/metal/Metal-Shading-Language-Specification.pdf)
