# Session 02: exact-frontier local objective screen

## Run design

The current-frontier candidate
`97cd41882ff7afa772be82c888b75597418092e4` was paired against
`cfd47be98a10598b90a898e787e5cd1c674b09e7` for 20 S3 rounds on
`core_cpu/small/time` with pinned Zig 0.15.2. The scored objective,
correctness checks, proof-byte comparison, resource vectors, and pinned Rust
oracle remained active. Automatic guards were disabled only to avoid the
separately diagnosed generic-runner wall-budget defect, so this run is
advisory rather than qualification evidence.

The first attempt failed closed before timing because post-build load1 was
`8.28`, above the 10-core quiet-host threshold `7.50`. After the host cooled,
the entire paired run was restarted; no samples from the rejected admission
were reused.

## Result and interpretation

The accepted screen completed with `R = 0.991108`, workload CI
`[0.963037, 1.025516]`, and portfolio CI `[0.963264, 1.026027]`.
All five local gates passed, the Rust oracle verified the workload, and every
cross-arm proof digest was identical. The harness classified the candidate as
confirmed-neutral.

The fresh whole-proof result supersedes the older micro-measurement for
prioritization. Reusing the tower slice is correct, but its current
small-class contribution is too small to distinguish from whole-proof noise.

## Evidence boundary

No attestation or qualification receipt was generated, and no improvement is
claimed. The failed high-load attempt remains an admission failure, not a
performance result.
