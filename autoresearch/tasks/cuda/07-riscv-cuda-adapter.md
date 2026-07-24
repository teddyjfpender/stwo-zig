# Task 07: RISC-V CUDA Adapter

Status: pending Native CUDA activation

## Objective

Emit the release-gated Stark-V-compatible RISC-V statement as generic
`ProofProgram` and prove it through the existing CUDA runtime/compiler.

## Deliverables

- RISC-V components encode ALU, branches, memory, public I/O, interaction
  claims, SHA, and Keccak without frontend-specific CUDA scheduling.
- Immutable program/ROM tables use runtime caches where statement identity
  permits.
- Component geometry preserves cross-shard LogUp and public I/O semantics.
- CUDA program packs are authenticated and per-SM.
- VM structural rows cover the manifest RISC-V workload portfolios.

## Gates

- Existing RISC-V CPU proof and release gates remain green.
- CUDA/Zig CPU proof bytes and transcript state are exact where supported.
- Pinned Stark-V is the final RISC-V oracle.
- Known upstream signed `MULH`/`MULHSU` behavior remains documented; parity is
  not misrepresented as repaired semantics.
- Multi-shard, memory, public I/O, SHA, and Keccak mutation tests reject.
- Zero fallback/JIT and complete stage/resource telemetry.
- No CUDA path weakens the RISC-V release receipt or workload registry.

## Exit Evidence

- Per-portfolio correctness receipts and stage profiles.
- CPU/CUDA same-host comparison for latency and throughput.
- Sustained mixed-program queue diagnostic.
- Separate RISC-V CUDA board activation proposal after A/A calibration.
