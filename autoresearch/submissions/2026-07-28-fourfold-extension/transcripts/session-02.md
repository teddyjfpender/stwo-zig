# Session 02: exact-frontier local objective screen

## Run design

The current-frontier candidate
`f3d814b087abe7585930bc334f89cfb37bd6a7c9` was paired against
`cfd47be98a10598b90a898e787e5cd1c674b09e7` for 20 S3 rounds on
`core_cpu/small/time` with pinned Zig 0.15.2. The scored objective,
correctness checks, proof-byte comparison, resource vectors, and pinned Rust
oracle remained active. Automatic guards were disabled only to avoid the
separately diagnosed generic-runner wall-budget defect, so this run is
advisory rather than qualification evidence.

## Result and interpretation

The screen completed with `R = 0.975219`, workload CI
`[0.962150, 0.989141]`, and portfolio CI `[0.962243, 0.989400]`.
All five local gates passed, the Rust oracle verified the workload, and every
cross-arm proof digest was identical.

The interval lies below parity, which supports the mechanism's direction, but
the promotion rule requires the full objective CI below
`1 - theta = 0.962692`. The observed upper bound is well above that bar. The
harness therefore correctly reports neither significant nor neutral. This is
a directional, non-promotable result.

## Evidence boundary

No attestation or qualification receipt was generated, and no improvement is
claimed. A central judged run could record the result, but it must independently
execute the full guard portfolio and apply the same significance rule.
