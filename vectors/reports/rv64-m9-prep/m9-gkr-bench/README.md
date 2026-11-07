# m9-gkr-bench (WIP, stopped at owner handoff 2026-11-07)

Standalone fused projected outer-GKR benchmark (`src/backends/cuda/native/rv64/bench/`, driver `scripts/rv64_m9/gkr_bench_pod.sh`).
The stream was stopped mid-optimisation; there is no final kill/schedule verdict yet.

Only measurement taken [M dev-5090, RTX 5090 dev pod, CUDA events, 1 rep]: class leaf_d2 (137,363,456 facts, 26 layers), route B,
104.61 ms = **0.762 ns/fact**, workspace 4.42 GB = **32.15 B/fact**, transcript log stable across reps. Raw line in
`bench-leaf_d2-dev5090.txt` (ncu counters are not permitted on RunPod, ERR_NVGPUCTRPERM).

Gate (from codex/rv64-m9-outer-gkr review): kill outer GKR above 0.45 ns/fact, schedule at <= 0.3 ns/fact incl. MAIN projection.
At 0.76 ns/fact the lever is still a net loss (break-even 0.55-0.68 ns/fact). Next: the 2^23 fold class (257.9 M facts), layer fusion,
fewer passes, chunked frontier; parity vs CPU GKR (cpu_ref was not run).
