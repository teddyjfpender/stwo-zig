# Canonical Metal parent worker sweep — 2026-09-24

The previous canonical parent fixture hard-coded two proving workers. It now
accepts a qualification-only `STWO_RISCV_PARENT_BENCH_WORKERS` override, defaulting
to two, rejects zero/oversubscription, and prints/asserts the actual pool size.
Production workers continue to receive counts from their caller's admitted policy.
No cryptographic settings, AIRs, kernels, or production defaults changed.

One frozen ReleaseFast executable, authenticated core bundle, M5 Max, q70/PoW26
child and parent, 24 GiB tracked worker allocation cap. Serial mirrored order:
**2, 4, 8, 16, 16, 8, 4, 2**, two processes per count. Compilation excluded.

| Parent workers | Complete fixture median (s) | Parent stage sum median (s) | Main setup median (s) |
|---|---:|---:|---:|
| 2 | 21.607 | 8.741 | 1.615 |
| 4 | 19.172 | 6.507 | 0.811 |
| 8 | 18.427 | 5.781 | 0.443 |
| 16 | 20.318 | 7.516 | 0.301 |

**There is substantial temporal drift.** At eight workers, parent stages were
4.513 then 7.049 s; at two, 7.295 then 10.187 s. Core time roughly doubled in
several later runs. The experiment does not identify the cause and cannot establish
a stable percentage speedup. All samples are retained; none are discarded.
Eight workers performed best in this sweep and are a candidate for pipeline
qualification, not an autotuned production default. Sixteen were slower than eight.
CPU main setup scaled consistently; total runtime did not scale monotonically.

The eight runs preserve identical proof bytes and independent canonical verification,
worker rekey/fixed-plan reuse, output lifetime, and transcript replay. Parent SHA-256:
`87eacb69ec7dcf9d5aad70f4f36ff5ac8839bf78366fb11e7ac20da38755ce7b`.
Parent/child artifact sizes: 857,591 / 483,375 bytes. Peak physical footprint remains
about 27.76 GB and tracked worker peak about 11.99 GB across counts.
`parent.log` records the default two-worker qualification: 7/7 tests pass.

This is a complete single-parent fixture including child proving, preparation,
verification and teardown. It is not full-tree throughput, production root latency,
or an ordinary CSP result. The full objective remains open.

`measure.py` reproduces the eight serial frozen-binary runs. `binary.json` pins the
executable; `core` contains its authenticated bundle. `candidate-source` is the
exact qualification helper for this sweep (before the subsequent pipeline adapter
made its count reader public). `control-source` records the original helper.
Raw logs and individual profiles are in `results.json`; `summary.json` contains
all aggregates. The worktree is dirty; HEAD alone does not reproduce this binary.
