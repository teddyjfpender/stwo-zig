# Task 00: CUDA Measurement Contract

Status: implemented first slice; profiler evidence and locked-host freeze pending

## Objective

Make every CUDA optimization attributable and every performance claim
reproducible before changing more kernels.

## Deliverables

- Product schema separates runtime initialization, shape preparation, resident
  proof, terminal decode, independent verification, verified request, teardown,
  and total time.
- CUDA events cover ingress, trace generation, trace commitment, constraints,
  OODS, quotient, FRI, PoW, decommitment, and proof assembly.
- NVTX ranges use the same stable stage identities.
- `stwo-prof cuda caps`, `systems`, `compute`, and `report` fail clearly when a
  required NVIDIA tool is absent.
- Structural controller covers cold, first, warm, steady, and paired ABBA runs.
- Reports retain source/binary/module/toolchain/protocol/statement/device
  identity, proof identity, transfers, launches, synchronizations, memory,
  fallback, and AOT telemetry.
- Equal structural-class portfolio scoring and per-row regression ceilings are
  encoded.

## Gates

- Contract tests reject missing/extra fields, invalid durations, noncontiguous
  repetition, fallback, JIT miss, proof drift, device drift, and lifecycle
  inconsistency.
- Stage totals equal the final device interval.
- Device time does not exceed resident wall time.
- Exactly one terminal D2H and zero intermediate readbacks.
- Instrumented profiles are labelled diagnostic and excluded from verdicts.
- Real CUDA smoke validates the schema on an authenticated AOT product.

## Exit Evidence

- Unit and integration test output.
- One retained Nsight Systems capture and summarized launch-gap/overlap table.
- One retained Nsight Compute capture for each dominant kernel family.
- One uninstrumented immutable baseline over active structural workloads.
- Machine-readable explanation for every currently unavailable class.
