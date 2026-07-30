# Task 01: CUDA Persistent Runtime

Status: process runtime, retained plan cache, and bounded FIFO service
implemented; locked-host mixed-family evidence pending

## Objective

Move CUDA context, modules, reusable allocations, events, tables, and compiled
shape plans outside the proving request.

## Deliverables

- One `CudaRuntime` owner per visible GPU/process.
- Device and authenticated module identity frozen at initialization.
- Persistent memory/event pools with bounded high-water telemetry.
- Bounded caches for modules, twiddles, domains, immutable tables, prepared
  plans, and graph executables.
- Proof sessions borrow resources and return them after the terminal event.
- Repeated same-shape requests reuse modules and compiled plans.
- Mixed-shape requests use keyed hits/misses without stale resource aliasing.
- Failure and teardown release all live bytes exactly once.
- A backend-neutral process service enforces one active proof, bounded queued
  inputs, FIFO publication, and explicit busy/capacity/poison outcomes.
- Fatal or uncertain request failure aborts the runtime and requires an
  explicit new-runtime generation before service reset.

## Gates

- No context, module load, compilation, or toolkit discovery in a warm request.
- AOT loads equal one per process; repeat launches become cache hits.
- Prepared-plan reuse count equals proof count.
- Allocation failure at every acquisition point unwinds safely.
- Device error in every asynchronous stage surfaces at the terminal boundary.
- Plan/cache eviction cannot invalidate a live session.
- A repeated proof loop retains exact bytes and zero final pool usage.
- Cold, first, and steady timings are reported separately.

## Exit Evidence

- Same-shape and randomized mixed-shape stress tests.
- Runtime/cache ownership table and bounded-memory calculation.
- Nsight Systems proof that module loads and hot allocations left warm requests.
- Steady-request delta versus the pre-runtime baseline.
