# RV64 M8 optimisation stream T1-capture-parallel, round 1 (2026-11-07)

Branch `codex/rv64-m8-opt-T1-capture-parallel`, cut from `codex/rv64-m7-integrate` @ `c72b51646`. Guest capture is the CPU stage on the
request critical path. Default stage 1 waits for all of it; the GPU-native path waits for each segment's ledger.

All numbers are [M] from `rv64-capture-bench CFG - 0 RES` (the same capture route, allocator and JSON as production), on pod
`rv64-resident-2x5090` with 48 vCPU under a shared 40.8-CPU cgroup quota. Other streams were running, so the 1-minute load was 11–40
(recorded on every row). Comparisons are between interleaved rows only. Rows are the `*.jsonl` files here, one JSON summary per run;
the raw JSON per run is under `/workspace/m3/runs/m8-opt-T1-capture-parallel/cap/`.

## What changed (every change is default off; outputs are byte-identical)

| flag | effect |
|---|---|
| `STWO_RV64_M8_CAPTURE_LOCAL_LEDGER=1` | **Two-phase ledger.** Phase 1 runs in each segment's capture job thread: the services ledger `one()` runs on a segment-local table. A word the segment reads before writing it becomes a placeholder `{value from the first-pass starting checkpoint, image rights, epoch 0, tick = first-touch ordinal + 1}`. Phase 2 runs on the ordered thread over the segment's first-touched words only. Pass A (read-only) checks value and rights against the global ledger. Pass B writes the exit states, appending new INITIAL cells in serial order. Then every placeholder clock in the shard is patched to the real predecessor clock (comptime reflection over every `State` field). Segment 0 is adopted whole: it is the serial code on the empty ledger. Any mismatch or error falls back to the serial `append` for that segment from the untouched global ledger, so outputs **and errors** are the serial ones. |
| `STWO_RV64_M8_CAPTURE_INFLIGHT=N` (1..16), `STWO_RV64_M8_CAPTURE_WORKERS=N` (1..32) | Override the in-process capture window (production resources: 4) and the segment replay workers (8). |

The validators only order a predecessor clock against the current call (epoch ≥ 1). Placeholder epoch 0 and any real earlier epoch
pass them alike, so phase 1 accepts exactly what serial accepts, given the phase-2 value/rights check.

Segments are still released in order through `Capture.Ready` (`call`/`native_segment`), now as soon as the short phase 2 ends. The
`Capture.Ready` / `CaptureSink` API is unchanged. Segments retain their starting checkpoint (`Segments.retain_starts`) until phase 1
ends.

Report-only additions: `direct_capture.{local_ledgers, local_fallbacks, local_ledger_ns, local_touched, local_merge_ns, local_patch_ns,
job_admit_ns, job_capture_ns, job_narrow_ns, job_seal_ns, job_events_ns}`. `rv64-capture-bench` now also prints `advice_all_sha256`
over every advice family. `captured_values_sha256` skips sha256/arith256/curves/bulk/sponge.

## Parity [M]

`captured_values_sha256` **and** `advice_all_sha256` are identical with the flag off and on, at every inflight/worker setting, on all
three blocks, with 0 fallbacks in every run (97 runs):

| block | captured_values_sha256 | advice_all_sha256 |
|---|---|---|
| 26235156 | `c9f3d40fa8c9e3b7…` | `a811f4e03417eca0…` |
| 24628607 | `e5f5e7606c584ca6…` | `9707f65176276948…` |
| 26235159 | `a80fddbfb4e3ec74…` | `f411dd853332bfff…` |

Unit tests (`services/collector.zig`, run via `collector_test.zig`) cover the placeholder patch over every State-bearing field
(events, keccak, bulk words, sponge words, padding untouched) and starting-image reads (in-page, page-crossing, absent page).
`test-riscv64-word16-combined-services`: 81/81 passed, then `wire_test` "Combined compact transport … read allocation failure"
aborted with signal 6. The **untouched base tree aborts identically** (2/2 passed, then the same abort), so the abort is pre-existing
(the M6 munmap abort class).

## Capture time [M] (`image_and_import_ns`, seconds)

| block | production (inflight 4, serial ledger) | inflight 16, serial | inflight 16 + local ledger | Δ |
|---|---|---|---|---|
| 26235159 (49 segments) | 8.53 (8.66, 8.53, 8.48) | 6.11 (6.57, 6.11, 6.09) | **5.76** (5.76, 5.71, 6.06) | **−2.77 s (−32%)** |
| 24628607 (7) | 1.90 (1.84, 1.90, 1.92) | 1.93 | **1.83** (1.83, 1.73, 1.88) | −0.07 s (noise-level) |
| 26235156 (5) | 1.62 (1.62, 1.70, 1.60) | 1.60 | 1.64 (1.56, 1.64, 1.70) | 0 |

These are 3-rep medians from `ab3.jsonl`. With the local ledger the serial ledger on 26235159 drops from 2.7–3.2 s to 0.57–0.79 s
(phase 2: merge 0.26 s over 4.71 M first-touched words, plus patch 0.32 s). On 24628607 it drops from 0.37–0.45 s to 0.06–0.09 s.

Sweeps on 26235159 (`sweep1.jsonl`, `sw5.jsonl`, `sw6.jsonl`):
- Serial ledger: inflight 4 → 8 → 16 gives 8.45/8.82 → 6.99/7.29 → 6.37/6.18.
- Workers 8 → 16 → 24 at inflight 16 gives 6.37/6.18 → 6.27/6.39 → 7.07. Replay is not the bound (summed walk 10.9–13.9 s over 8 workers).
- Local ledger: inflight 8, 12, 16, 24 and 32 give 6.87/6.92, 6.10/6.26, 5.85/5.75, 6.30/5.88 and 6.32/6.19. The 24 and 32 rows used a probe build with the cap raised; that change was not kept.
- Local ledger with 4 helper threads instead of 8: 5.95/5.89. With 4 workers: 6.36/6.71.
- **Local ledger at inflight 4 is slower (9.07 vs 8.53).** Phase 1 lengthens jobs that are already the bottleneck. Use the pair `LOCAL_LEDGER=1` + `INFLIGHT=16`.

## What bounds capture now [M, 26235159, inflight 16 + local ledger]

The capture jobs are the bound: the consumer's `join_wait` is 2.8–3.1 s. Summed job time is 47 s:

| part of the jobs | summed time |
|---|---|
| narrow capture (`Prepared.captureForCombinedServices`) | 37–42 s |
| phase 1 | 5–5.8 s |
| LS event prefault | 2.8 s |
| admission | 3.3 s |

The same narrow work sums to **22.0 s at inflight 4 but 38.7 s at inflight 16**. That is CPU contention under the shared quota, not
more work, so capture is CPU-throughput-bound here.

Event-array reuse ("pre-faulted tape arenas", plan item 4) could save at most the 2.3–2.8 s of summed prefault (~5% of job CPU).
It is not done in this round. Next lever (round 2, outside this stream's claimed files): the narrow capture itself,
`word16_execution/{cpu_source,prepared}.zig`, about 107 ns/step uncontended vs 53 ns/step for the traced replay walk.

## Against the plan's estimates

- [E] 26235159 8.3 → ~3.0 s: **reached 5.76 s [M]**. The ledger is off the serial path. The bound is now narrow-capture CPU under a shared quota.
- [E] 24628607 1.85 → ~1.1 s: **not reached (1.83 s [M])**. 7 segments: segment 0 is ready at 1.09–1.14 s. Segments 1–6 capture concurrently and are CPU-bound until 1.7 s.
- Request-level: for 24628607 the default path cannot gain more than about 0.07 s from this (capture is flat), so a canonical 3+3 would sit inside noise [D]. 26235159 is outside the canonical runner's block set (dev blocks only).

## Gate

rv64_gate default: **blocked, not run.** Attempt `gate-1` built and passed unit-zig and unit-python, then `small-block-proof` failed
with `GpuPcsInitializationFailed`. Both GPUs had only 1.5 GB free: orphan pid 3302210 (`m8-native-hybrid` combined-serve, idle >3 h)
holds 30.1 GB on each GPU. This stream does not own it and did not touch it. `t1gates.sh` (tmux `t1cap-gates`) runs `gate-2`
(default) and `gate-3` (`--env STWO_RV64_M8_CAPTURE_LOCAL_LEDGER=1 --env STWO_RV64_M8_CAPTURE_INFLIGHT=16`) by itself once both
GPUs are below 2 GB.
