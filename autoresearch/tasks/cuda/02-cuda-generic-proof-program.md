# Task 02: Generic ProofProgram And CudaPlan

Status: wide-Fibonacci first emitter implemented; generic AIR coverage pending

## Objective

Ensure frontends describe proof semantics once and never implement separate
CUDA provers.

## Deliverables

- Immutable backend-neutral `ProofProgram` with identity, geometry, constraints,
  commitments, transcript barriers, quotient, FRI, buffers, lifetimes, and DAG.
- Validation for overflow, identity, buffer lifetime, challenge order, and DAG
  topology.
- Stable complete-program digest.
- `CudaPlan` compiler for arena layout, aliases, schedule, streams, graphs,
  variants, work estimates, and peak accounted memory.
- Cache key binds program, protocol, geometry, SM/device, toolchain, kernel
  pack, and schedule schema.
- Native wide Fibonacci emits the program and executes only the compiled plan.
- Runtime contains no wide-Fibonacci or frontend identity.

## Gates

- Program digest changes when any semantic or scheduling authority changes.
- Invalid graphs, lifetimes, sizes, and challenge dependencies fail closed.
- Arena clone/instantiation does not mutate the cached plan.
- Old and generic paths produce exact intermediate values and proof bytes.
- Pinned Rust Stwo accepts every retained vector.
- Non-target widths 37, 73, and 128 use structural admission, not benchmark IDs.
- Source conformance enforces frontend/backend layering.

## Exit Evidence

- Program/plan unit tests and mutation tests.
- Wide-Fibonacci CPU/CUDA byte equality over logs and non-target widths.
- Plan digest/cache-key records in structural benchmark output.
- Design note for the next Native AIR emitter proving the interface is generic.
