# Session 02: exact-frontier local objective screen

## Run design

The current-frontier candidate
`2a74f0a152c6b43fc6873ccc45ee185195cc50ae` was paired against
`cfd47be98a10598b90a898e787e5cd1c674b09e7` for 20 S3 rounds on
`core_cpu/small/time` with pinned Zig 0.15.2. The scored objective,
correctness checks, proof-byte comparison, resource vectors, and pinned Rust
oracle remained active. Automatic guards were disabled only to avoid the
separately diagnosed generic-runner wall-budget defect, so this run is
advisory rather than qualification evidence.

## Result and interpretation

The screen completed with `R = 1.001324`, workload CI
`[0.980883, 1.021910]`, and portfolio CI `[0.980664, 1.022294]`.
All five local gates passed, the Rust oracle verified the workload, and every
cross-arm proof digest was identical. The harness classified the candidate as
confirmed-neutral.

This falsifies the hypothesis that shared forward twiddle loads create a
material whole-proof gain for the current small workload on this host. The
kernel may still reduce repeated loads internally, but any effect is below
whole-proof noise or offset by the extra batch-loop structure.

## Evidence boundary

No attestation or qualification receipt was generated, and no improvement is
claimed. The neutral result is retained because rejected mechanisms are part
of the research record and should not be silently recycled as winners.
