# Task 05: Native AIR Coverage

Status: blocked; only wide Fibonacci is release-ready

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

## Current Audit

The executable authority is
`conformance/cuda-native-activation-state-v1.json`, validated by
`python3 scripts/cuda_activation.py`. Structural benchmark admission does not
mean that an AIR family is complete.

Source paths in that authority document the audited implementation state; path
existence alone is not release evidence. A proof, Rust-oracle, fallback, or
telemetry gate may transition to true only with a reviewed immutable receipt
and a gate that parses and cross-checks the relevant receipt fields.

- Poseidon uses the real 1,264-column M31 permutation trace and constant-QM31
  composition, not the Poseidon AIR constraints.
- Blake uses a seeded-xorshift structural trace and constant-QM31 composition.
- Plonk has the four preprocessed and four main columns, but zero interaction
  columns and no LogUp composition.
- The CPU oracle path now has the exact pinned-Stwo three-constraint Plonk AIR,
  two secure LogUp columns, claimed sum, independent Zig verification, and
  controlled statement mutation rejection. Pinned-Rust acceptance and the
  resident CUDA interaction/constraint path remain required; the provisional
  CUDA `plonk` route does not inherit readiness from the CPU implementation.
- State machine has its affine trace and proof route, but its constraint kernel
  is still the claimed-sum ABI placeholder.
- XOR has its real three-column trace, but zero interaction columns and no
  lookup relation in composition.
- The Native CUDA CLI, structural benchmark, and staged autoresearch group
  may admit these rows for profiling. They remain provisional until the
  per-family activation authority is green.
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
