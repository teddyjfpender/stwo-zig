# Task 06: CUDA Autoresearch Activation

Status: blocked on Tasks 03-05 and locked-host calibration

## Objective

Enable `core_cuda` only when the search and judge cannot accept a faster but
incorrect, hybrid, narrow, or cross-machine result.

## Deliverables

- CUDA runner/parser integrated with `stwo-perf`.
- Board-owned workload registry and equal structural-class scoring.
- CUDA editable paths isolated from locked benchmark/oracle contracts.
- Immutable locked-host identity and CUDA A/A calibration.
- Candidate/predecessor ABBA, CI, regression, resource, and mechanism gates.
- Correctness receipt binds Rust oracle, proof, program, protocol, product,
  module, toolchain, device, and benchmark identities.
- Feed, ledger epoch, task prompt, and website schema expose the board.
- Governance activation receipt changes `enabled` and `promotion_eligible`.

## Activation Gates

- `python3 scripts/cuda_activation.py` passes against the manifest-pinned
  activation state, and reports `ready=true` with six of six families.
- All six Native AIR families pass Task 05.
- Exact CPU/CUDA bytes and pinned Rust verification.
- Zero fallback, exact AOT, complete stage telemetry.
- No required structural class is missing.
- A/A dispersion and anchor are frozen on the designated CUDA host.
- At least one candidate-only dry run and one predecessor A/B rehearsal pass.
- Mutation and anti-forgery tests fail as expected.
- Every harness and full-repository gate passes.

Passing booleans and repository paths are not evidence. The activation
authority parses each positive global receipt and rejects schema, candidate
identity, oracle, residency, AOT, schedule, or confidence-interval drift:

| Gate | Required parsed receipt |
| --- | --- |
| Structural coverage | `stwo-zig-cuda-structural-screen-receipt-v1` with `activation_eligible=true`, no blocked class, and exact oracle/residency invariants |
| Sustained calibration | `stwo-zig-cuda-sustained-judge-v1` |
| Locked judge host | `stwo-zig-cuda-judge-host-authority-v1` |
| Locked-host A/A | `stwo-zig-cuda-aa-calibration-v1` |
| Candidate dry run | source-bound clean strict-AOT structural-screen receipt with every artifact accepted by pinned Rust |
| Predecessor rehearsal | `native_cuda_structural_verdict_v1` with at least seven paired counterbalanced A-B-B-A rounds |
| Mutation/anti-forgery | `stwo-zig-cuda-anti-forgery-v1` |
| Full repository | `stwo-zig-cuda-release-gates-v1` |

Every release receipt must bind the candidate commit and binary digest. A
future state edit cannot activate a gate by pointing at source code, prose, or
an unrelated JSON document.

## Exit Evidence

- Reviewed immutable calibration package.
- Manifest and epoch digests.
- First neutral A/A verdict.
- First end-to-end claimed submission rehearsal.
- Only then: reviewed activation commit.
