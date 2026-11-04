# RV64 M6 stream `capture`, iteration 1 (2026-11-05)

Branch `codex/rv64-m6-capture` from `95d40063d`. Code commits `554dd90dd` (engine, v4) and the v5 commit (parallel boundaries). CPU-only capture diagnostic
(`rv64-capture-bench CONFIG - 0 RESOURCES`, same route/allocator/pool/JSON as `gkr capture`), inflight 4, 8 segment workers.
**No run was quiet**: 1-minute load 11–52 (other M6 streams share the 40.8-CPU quota); every row records it.
Compare interleaved pairs. Single observations or medians [M]; nothing extrapolated. Design: `design/riscv-proving-stack/rv64-m6-capture.md`.

| block | binary | runs | capture s (median) | runs (load) | byte-identical |
|---|---|---:|---:|---|---|
| 24628607 | base-i4 | 7 | 2.909 | 2.63 (15), 3.67 (48), 4.25 (48), 2.91 (33), 2.98 (30), 2.44 (10), 2.65 (10) | yes |
| 24628607 | v1off-i4 | 1 | 2.664 | 2.66 (12) | yes |
| 24628607 | v1-i4 | 1 | 2.445 | 2.44 (13) | yes |
| 24628607 | v2-i4 | 3 | 2.173 | 2.17 (26), 2.16 (48), 2.59 (47) | yes |
| 24628607 | v3-i4 | 1 | 2.944 | 2.94 (28) | yes |
| 24628607 | v3np-i4 | 1 | 3.007 | 3.01 (28) | yes |
| 24628607 | v4-i4 | 8 | 2.198 | 2.61 (33), 2.16 (28), 1.99 (10), 2.06 (18), 2.06 (20), 2.24 (16), 2.66 (21), 2.52 (18) | yes |
| 24628607 | v5-i4 | 2 | 2.256 | 2.36 (17), 2.15 (20) | yes |
| 24628607 | v5pb0-i4 | 2 | 2.253 | 2.41 (19), 2.10 (19) | yes |
| 26235156 | base-i4 | 7 | 2.547 | 2.29 (17), 2.69 (52), 2.79 (47), 2.74 (36), 2.55 (31), 2.30 (11), 2.24 (17) | yes |
| 26235156 | v1off-i4 | 1 | 2.317 | 2.32 (11) | yes |
| 26235156 | v1-i4 | 1 | 1.778 | 1.78 (12) | yes |
| 26235156 | v2-i4 | 3 | 2.166 | 2.08 (27), 2.17 (49), 2.38 (47) | yes |
| 26235156 | v4-i4 | 6 | 1.822 | 1.85 (34), 1.94 (30), 1.74 (11), 1.73 (18), 1.98 (20), 1.79 (19) | yes |
| 26235156 | v5-i4 | 2 | 1.835 | 1.98 (21), 1.69 (19) | yes |
| 26235156 | v5pb0-i4 | 2 | 1.769 | 1.80 (21), 1.74 (20) | yes |

`base` = M5 reference code (95d40063d + the bench tool). `v1off` = v1 binary with STWO_RV64_TRACED_ENGINE=0 STWO_RV64_CAPTURE_ASYNC_START=0.
`v1` traced engine + hashmap cells + async boot; `v2` + page-blocked CellMap + critical batch 0; `v3` + opt-in tape populate
(on/np=off); `v4` = `554dd90dd` (populate off by default, slab blocks, direct-mapped page cache, walk split instrumentation);
`v5` = v4 + parallel boundary sort/lookup in `Ordered.finish` (`v5pb0` = same binary, `STWO_RV64_CAPTURE_PARALLEL_BOUNDARIES=0`).

Quieter pairs (load 10–17, interleaved): 607 base 2.44/2.65 → v4 1.99/2.06 s; 156 base 2.30/2.24 → v4 1.74/1.73 s.

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

## Sweeps that did not move capture (v4 binary, env only) [M, 607, load 9–20]

| knob | values | capture s |
|---|---|---|
| `STWO_RV64_CPU_CAPTURE_THREADS` × inflight | 8/16/24 × 4/8, two rounds | 1.94–2.26, no ordering beyond noise |
| `STWO_RV64_CAPTURE_JOB_NICE=10` | vs default, interleaved ×2 | 1.99/2.02 vs 2.06/2.24 |

## v5: parallel boundary cells (`Ordered.finish`) [M]

`ledger_finish` 0.094–0.108 → 0.049–0.071 s (8 chunk sorts + pairwise merges; addresses are unique so the order equals pdq's;
unit test "parallel boundary sort equals the serial sort"). End-to-end inside noise (607 v5 2.36/2.15 vs flag-off 2.41/2.10).

## Ledger profile (607, v4, `STWO_RV64_CAPTURE_LEDGER_PROFILE=1`, load 47, one run) [M]

| shard | total ms | LS records | LS+dispatch ms | first touch | sponge | bulk |
|---:|---:|---:|---:|---|---|---|
| 0 | 224.5 | 1,542,861 | 39.2 | 726,594 / 67.7 ms | 3,680 / 97.3 ms | 3,088 / 86.0 ms |
| 1 | 58.1 | 1,538,383 | 32.8 | 78,386 / 4.5 ms | 1 | 2,285 / 22.7 ms |
| 2–6 | 24.5–47.9 | 0.8–1.59 M | 14.9–36.3 | ≤70k | ≤2,173 / 6.6 ms | ≤8,414 / 9.2 ms |

Next leap for capture (not done here): a two-phase, address-sharded ledger. Phase 1 per segment in the parallel job threads
(segment-local predecessor chains for LS records AND service words, first-touch image states, local earliest error); phase 2 serial
over each segment's unique first-touched addresses only (patch predecessors, merge exit states, report the earliest error in global
record order). It needs the services collector (`services/collector.zig` `one`) restructured onto a segment-local ledger view; it is
the only way left inside capture's files to take the ≈0.5 s serial chain out of the critical path.

## Production (switched on): resident GPU service, both dev blocks [M]

`scripts/rv64_m4_resident.py daemon 26235156 24628607 --repeat 1 --store none --receive {first|none}`, M5 default producer env,
M5 integrate CUDA library (`0caf0144…`, CUDA sources unchanged), driver built from `554dd90dd` (`e8ca32a5…`). The traced engine,
async boot and critical first batch are DEFAULT ON in this driver (no env needed). `--store none` because the store key includes the
driver hash and /workspace had 1–2 GB free (a fresh store is ≈6.4 GB): setup is therefore cold (9–11 s) in every run below,
identically for the M5 driver, so compare capture and the other stages, not request wall against the warm M5 receipt.

| run | driver | load | 156 capture | 607 capture | 607 request | 607 native | 607 recursion | proofs vs M3/M5 | receiver |
|---|---|---:|---:|---:|---:|---:|---:|---|---|
| c3-m5base | M5 37f94901 | 28 | 2.383 | 2.930 | 40.97 | 7.27 | 19.71 | identical (native bins, bundle, tree, every recursive proof) | not run |
| c2-on | M6 e8ca32a5 | 38 | 1.719 | 2.234 | 39.62 | 7.17 | 19.16 | identical (native bins, bundle, tree, every recursive proof) | accepted 2/2 (separate receiver process, M5 receiver) |
| c3-on | M6 e8ca32a5 | 21 | 1.754 | 2.095 | 39.57 | 6.83 | 19.60 | identical (native bins, bundle, tree, every recursive proof) | not run |

Capture stage (production): **607 2.93 → 2.10–2.23 s (−24..−28%), 156 2.38 → 1.72–1.75 s (−27%)** at load 21–38 [M].
Root hashes `2feed86a…` (607) and `b424203b…` (156) equal the M3/M5 receipts; every native bin, bundle and recursive proof hash matches.

## Tests (pod, ReleaseSafe; logs in `raw/tests/`)

| suite | result |
|---|---|
| `test-riscv64-execution` (incl. 800-program traced-vs-reference differential, stale-cell stop test, boundary-capture tests now in this root) | **pass** (`tests-v4.log`) |
| `test-riscv64-capture-prefetch` filter "boundary sort" (new collector test) | **pass** |
| `test-riscv64-capture-prefetch` filters "walks" / "on-disk" | 2/2 and 3/3 pass, then a `munmap` `unreachable` abort inside the durable on-disk collector (`Collect.runWithOptions`) in "segment walks equal the serial walk" and "in-process handoff capture equals the on-disk packet capture" |
| same two filters on the **untouched base tree** `95d40063d` | **identical aborts at the same two tests** (`t6-*-base.log`): pre-existing on this pod (M4/M5 recorded the same fsync/munmap class), not caused by this stream |

So the fixture-level serial-vs-segments parity test cannot run to completion here on either tree; byte identity is carried by the
800-program differential test, the dev-block `captured_values_sha256` on every CPU run (66 runs) and the full proof-hash parity of the
production runs.

## Files

- `<block>-capture-m6.json`: every run (stats, segment-ready timeline, walk split, digests), grouped medians.
- `raw/`: per-run records (`cap-<block>-<tag>.json`), `cap.py`, `build.sh`, `tests.sh`, `gpubuild.sh`.
- `../../progress/capture.jsonl`: one row per run (milestone M6).
