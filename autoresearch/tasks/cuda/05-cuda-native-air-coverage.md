# Task 05: Native AIR Coverage

Status: in progress; Poseidon is release-gated as the hash-heavy family

## Objective

Prove the CUDA architecture is generic by routing all six Native AIR families
through `ProofProgram` and the same runtime/compiler.

## Required Families

1. wide Fibonacci;
2. Blake;
3. Poseidon;
4. Plonk with LogUp;
5. state machine / irregular multi-component trace;
6. XOR / lookup-table structure.

## Deliverables

- One frontend emitter per family.
- Shared primitives remain in the generic CUDA backend.
- AIR-specific AOT kernels live in authenticated program packs.
- Hash work, lookup work, and nonuniform component geometry are represented in
  the generic program rather than hidden driver calls.
- Structural controller enables hash-heavy, lookup-heavy, and irregular rows.

## Current Activation

- Poseidon uses the real 1,264-column M31 permutation trace and constant-QM31
  AIR, not the seeded Blake trace recipe.
- The Native CUDA CLI, structural benchmark, and staged autoresearch group
  admit Poseidon at `log_n_instances` 10 and 13.
- The device release lane requires exact Native CPU/CUDA bytes, independent
  Zig and pinned Rust verification, authenticated SM89 AOT witness/constraint
  activation, graph/direct proof equality, zero fallback, and one terminal
  D2H.
- The aggregate CUDA autoresearch group remains disabled and
  non-promotion-eligible until all six families satisfy this task.

## Gates

- Exact CPU/CUDA canonical proof bytes for every scored shape.
- Independent Zig verification and pinned Rust Stwo verification.
- Transcript and challenge parity.
- Controlled mutation rejection for each statement.
- Zero fallback/JIT and one terminal D2H.
- Forced accelerated-path tests at target and non-target shapes.
- Full lifecycle/stage/resource telemetry.
- No AIR adds a second CUDA runtime, arena system, scheduler, or transcript.

## Exit Evidence

- Coverage matrix with each family, shapes, program/module digest, proof digest,
  oracle receipt, and stage profile.
- Structural ABBA across latency, deep, wide, hash, lookup, irregular, and
  extreme classes.
- Source-conformance report showing clean frontend/backend boundaries.
