# Session 03: exact-frontier local objective screen

## Why this run was performed

The hosted diagnostic proved that the setup repair reaches benchmarking, then
failed because the unchanged predecessor consumed almost all of the shared
300-second guard wall budget. That failure left the PoW mechanism without a
fresh current-frontier measurement. A same-host objective screen could not
replace fork qualification, but it could test whether the candidate still
deserved priority while the workflow policy remained under review.

The run therefore used the exact canonical predecessor
`cfd47be98a10598b90a898e787e5cd1c674b09e7`, immutable candidate
`6efb93d539498178fe2fb67ead0788bb884a6bcb`, pinned Zig 0.15.2,
`core_cpu/small/time`, S3, and 20 preregistered paired rounds. Automatic
regression guards were disabled explicitly because their generic-runner budget
is the diagnosed infrastructure defect; the scored objective, correctness
checks, proof-byte comparison, resource vectors, and pinned Rust oracle
remained active.

## Result and interpretation

The screen completed with `R = 0.956784`, workload CI
`[0.922230, 0.979032]`, and portfolio CI `[0.921421, 0.980501]`.
All five local gates passed. The Rust oracle verified the workload, every
cross-arm proof digest was identical, peak RSS ratio was `0.962034`, and
energy ratio was `0.928132`.

The configured threshold was `theta = 0.037308`. Although the point estimate
is faster than `1 - theta`, the full CI is not below that boundary. The
harness therefore reports `significant: false`. The correct status is a
promising but non-promotable advisory result, not a claimed win.

## Evidence boundary

The verdict is hash-bound to the exact source commits and retained as local
screening evidence. It contains no GitHub artifact attestation and ran without
the complete guard portfolio. It is not a fork qualification receipt, remote
submission ID, central judgment, or research-record promotion.
