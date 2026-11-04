# RV64 M6 stream `capture`, iteration 1 (2026-11-05)

Branch `codex/rv64-m6-capture` from `95d40063d`. Code commit `554dd90dd`. CPU-only capture diagnostic
(`rv64-capture-bench CONFIG - 0 RESOURCES`, same route/allocator/pool/JSON as `gkr capture`), inflight 4, 8 segment workers.
**No run was quiet**: 1-minute load 11–52 (other M6 streams share the 40.8-CPU quota); every row records it.
Compare interleaved pairs. Single observations or medians [M]; nothing extrapolated. Design: `design/riscv-proving-stack/rv64-m6-capture.md`.

| block | binary | runs | capture s (median) | runs (load) | byte-identical |
|---|---|---:|---:|---|---|
| 24628607 | base-i4 | 5 | 2.984 | 2.63 (15), 3.67 (48), 4.25 (48), 2.91 (33), 2.98 (30) | yes |
| 24628607 | v1off-i4 | 1 | 2.664 | 2.66 (12) | yes |
| 24628607 | v1-i4 | 1 | 2.445 | 2.44 (13) | yes |
| 24628607 | v2-i4 | 3 | 2.173 | 2.17 (26), 2.16 (48), 2.59 (47) | yes |
| 24628607 | v3-i4 | 1 | 2.944 | 2.94 (28) | yes |
| 24628607 | v3np-i4 | 1 | 3.007 | 3.01 (28) | yes |
| 24628607 | v4-i4 | 2 | 2.385 | 2.61 (33), 2.16 (28) | yes |
| 24628607 | v1t28-i8 | 1 | 2.054 | 2.05 (15) | yes |
| 26235156 | base-i4 | 5 | 2.691 | 2.29 (17), 2.69 (52), 2.79 (47), 2.74 (36), 2.55 (31) | yes |
| 26235156 | v1off-i4 | 1 | 2.317 | 2.32 (11) | yes |
| 26235156 | v1-i4 | 1 | 1.778 | 1.78 (12) | yes |
| 26235156 | v2-i4 | 3 | 2.166 | 2.08 (27), 2.17 (49), 2.38 (47) | yes |
| 26235156 | v4-i4 | 2 | 1.898 | 1.85 (34), 1.94 (30) | yes |

`base` = M5 reference code (95d40063d + the bench tool). `v1off` = v1 binary with STWO_RV64_TRACED_ENGINE=0 STWO_RV64_CAPTURE_ASYNC_START=0.
`v1` traced engine + hashmap cells + async boot; `v2` + page-blocked CellMap + critical batch 0; `v3` + opt-in tape populate
(on/np=off); `v4` = `554dd90dd` (populate off by default, slab blocks, direct-mapped page cache, walk split instrumentation).

## Walk (24628607) [M]

| | M5 reference walk (base) | traced engine (v3np = v4 code) |
|---|---:|---:|
| steps retired by the fast traced path | 0 | 26,747,155 / 26,894,777 (99.45%) |
| reference steps (services, traps, page fills) | 26.9 M | 147,622 (1.7 µs each, 0.25 s summed) |
| summed traced walk | 3.26 s | 1.46 s |
| fast path cost | — | 45 ns/step (31 ns with tape pre-population, but see below) |
| walk per worker | 7.2–7.3 MIPS | 14.7–16.2 MIPS |
| batch walk max | 0.78 s | 0.33–0.35 s |

Opt-in `STWO_RV64_TAPE_POPULATE=1` (MADV_POPULATE_WRITE on a helper) cuts the fast path to 31 ns/step but 7 concurrent populates
contend on the address space: reference steps 0.25 → 1.90 s summed, first pass 126 → 52 MIPS, walk max 0.35 → 0.79 s. NET LOSS, off.
The remaining fast-path cost (45 ns/step against ≈8 ns/step for the untraced first pass) is dominated by first-touch faults on the
200 MB fresh tape per batch (48 B/step) under a shared, throttled CPU quota; no profiler is available on the pod (perf_event_paranoid 4).

## What bounds capture now (24628607, v4) [M]

init (image 0.27–0.34 + program 0.11 + compact 0.08 s; walk boot 0.29–0.36 s now runs beside it) → batch 0 ready ≈0.1 s after init
→ batch 0 admission + CPU capture 0.45–0.65 s → segment-0 ledger 0.17–0.25 s → segments 1..6 ledgers → finish 0.12 s.
Gate (capture ≤ 1.0 s on 607): **NOT MET** on the CPU bench (2.16–2.61 s under load 28–33).

## Tests (pod, ReleaseSafe)

See `raw/tests-*.log` once copied; `test-riscv64-execution` ran 151/152 on the pre-fix tree (the one failure was the new
stale-cell unit test's own expectation, fixed in `554dd90dd`); the 800-program traced differential and every boundary-capture test passed.

## Files

- `<block>-capture-m6.json`: every run (stats, segment-ready timeline, walk split, digests), grouped medians.
- `raw/`: per-run records (`cap-<block>-<tag>.json`), `cap.py`, `build.sh`, `tests.sh`, `gpubuild.sh`.
- `../../progress/capture.jsonl`: one row per run (milestone M6).
