# sched M6 — streaming native->recursion handoff (2026-11-05)

Branch `codex/rv64-m6-sched` (from 95d40063d). Scheduling only: proof bytes unchanged. Every run below is
byte-identical to the M5 default receipts on both dev blocks (harness `parity_vs_m3.byte_identical`, all 22 / 34 proofs,
roots `b424203b...` 156 and the 607 root of accepted-v7). Fresh-receiver acceptance (separate CPU-only, cache-disabled
process): `r2-s1` 26235156 accepted (43.4 s), 24628607 accepted (64.1 s); `r6-a22` (final binary, 613b4c6da tree) 26235156
accepted (45.6 s), 24628607 accepted (68.7 s).

All timings are single observations [M] on the shared pod; the 1-min load average (column `load`) was 12-52 during
every run except `base-m5` (4.1) — other M6 streams were building. They are NOT quiet-host quotable; read them as A/B pairs.

## What is switched on (default in the production prover)
- `STWO_RV64_RECURSION_STREAM=1` (default; `=0` = M5 handoff): recursion starts at the native stage-one barrier.
  Each native worker's final stage-two proof opens its leaf for host prep (graph, PP, host plan) while native stage two
  still runs on both GPUs; device recursion starts right after native produce returns and the terminal check passes
  (native publication / verification continue on the host, overlapped). Root metadata check starts at native end.
- Hook: `services/gkr_local/coordinator.zig` `Options.stream` (sealed / cpu_done / truth_done / abort), default null.
- Leaf prep during native is limited to `STWO_RV64_RECURSION_STREAM_PREP` (default 4) host workers.
- Device order: `STWO_RV64_RECURSION_SCHED=m5` (default). `critical` (deepest-first) is opt-in: measured slower on 607
  (19.4 s recursion vs 18.7): deferred folds keep authority slots, the 17-slot admission then starves leaves.

## Results (request s, 26235156 / 24628607)
| run | config | load | request | native | fold tail after last leaf | recursion overlapped with native | RSS GiB | byte-identical |
|---|---|---:|---|---|---|---|---:|---|
| base-m5 | M5 binaries, M5 default | 4.1 | 20.02 / 27.96 | 4.70 / 5.75 | 5.26 / 5.52 | 0 / 0 | 31.8 | yes |
| r1-m5 | sched build, M5 order, no stream (fresh store) | 15.8 | 22.08 / 28.61 | 4.74 / 6.67 | 6.93 / 5.79 | 0 / 0 | 30.6 | yes |
| r1-crit | critical order, no stream | 12.9 | 19.71 / 28.67 | 4.48 / 6.44 | 4.24 / 5.02 | 0 / 0 | 31.3 | yes |
| r1-stream | critical order + stream | 19.1 | 18.06 / 27.20 | 4.89 / 6.70 | 3.48 / 5.18 | 3.24 / 4.26 | 31.3 | yes |
| r2-m5s | no stream | 15.6 | 20.09 / 27.89 | 4.83 / 6.54 | 4.74 / 4.97 | 0 / 0 | 31.3 | yes |
| **r2-s1** | **default (stream)** | 12.5 | **18.78 / 25.48** | 5.04 / 6.83 | 4.65 / 4.91 | 3.13 / 4.40 | 31.4 | yes + receiver |
| r3-m5s | no stream | 52.4 | 23.77 / 28.43 | 5.02 / 6.53 | 7.12 / 5.91 | 0 / 0 | 30.6 | yes |
| r3-s1 | default (stream) | 31.8 | 22.50 / 28.43 | 5.91 / 6.95 | 5.15 / 5.72 | 3.59 / 4.13 | 31.2 | yes |
| r3-pa3 | stream, PREP_AHEAD=3 | 39.3 | 20.16 / 28.22 | 5.01 / 6.94 | 4.50 / 5.12 | 3.00 / 4.19 | **26.5** | yes |
| r3-sp8 | stream, STREAM_PREP=8 | 39.9 | 19.38 / 25.87 | 5.03 / 6.56 | 4.29 / 4.91 | 3.00 / 3.89 | 31.3 | yes |
| r4-s1-0 | default (stream) | 15.7 | 19.26 / 25.91 | 5.20 / 6.63 | 4.50 / 5.36 | 3.16 / 4.04 | 31.3 | yes |
| r4-m5s-1 | no stream | 24.6 | 21.79 / 32.92 | 4.93 / 7.01 | 4.86 / 5.59 | 0 / 0 | 31.2 | yes |
| r4-s1-2 | default (stream) | 31.3 | 19.03 / 26.92 | 4.94 / 6.74 | 4.69 / 5.38 | 3.05 / 3.94 | 31.3 | yes |
| r4-m5s-3 | no stream | 48.2 | 22.05 / 33.27 | 4.98 / 6.72 | 5.02 / 7.25 | 0 / 0 | 31.3 | yes |
| r4-s1-4 | default (stream) | 47.0 | 21.84 / 27.87 | 5.57 / 6.68 | 5.43 / 4.44 | 3.46 / 3.93 | 31.4 | yes |
| r4-m5s-5 | no stream | 35.3 | 23.93 / 31.59 | 5.33 / 7.22 | 5.23 / 4.84 | 0 / 0 | 31.4 | yes |
| r4-sp8-6 | stream, STREAM_PREP=8 | 33.2 | 22.63 / 29.60 | 5.32 / 7.63 | 6.25 / 5.55 | 3.10 / 4.61 | 31.3 | yes |
| r5-s1-0 | default (stream), RSS sampled | 30.7 | 21.86 / 26.90 | 5.62 / 7.14 | 5.48 / 4.40 | 3.07 / 4.47 | 31.2 | yes |
| r5-pa3-1 | stream, PREP_AHEAD=3, RSS sampled | 35.7 | 21.67 / 34.02 | 5.57 / 8.47 | 4.77 / 5.97 | 3.31 / 5.54 | 26.6 | yes |
| r6-a22 | default (stream) + DEVICE_ARENA=22G | see json | 22.57 / 29.72 | 5.85 / 6.82 | 5.31 / 5.86 | 3.72 / 3.97 | 31.3 | yes + receiver |

r4 is a strict alternation (s1, m5s, s1, m5s, s1, m5s) on one binary and one store, so it is the cleanest A/B we have
under the shared load: 24628607 stream median 26.92 s vs no-stream 32.93 s (-6.0 s); 26235156 19.26 vs 22.05 s (-2.8 s) [D from M].
All stream runs (r2-r4, 5 obs.): 24628607 median 26.92 s, best 25.48; no-stream (r2-r4, 6 obs.) median 30.0 s; the M5 binaries
measured 27.96 s on a quiet host (base-m5). Under CPU contention the M5 handoff loses more, because its 1.5 s leaf-prep head
and the native publication sit on the critical path; the streamed path does both while native still runs. The gain is the leaf-prep head (1.5 s of idle
GPUs at recursion start in M5) plus native publication/verify moved off the device path.

## Measured negatives / kills
- 2 concurrent outer proofs per GPU (`STWO_RV64_RECURSION_LANES_PER_DEVICE=2`, two outer contexts per device, separate
  helper pools): both blocks FAIL on the first request (`CudaTraceCommitFailed`, then `ImmutableSetupStillBorrowed`,
  arena overrun 3.49 GB at 23.6 GB live). The per-device trace-commit/immutable-setup state and the 2 GiB immutable budget
  are single-proof today (enqueue/arena files). Hook stays OFF (default 1); simulator [E]: 607 recursion 15.7 -> 13.0 s at a
  1.3x per-proof slowdown, if it fit.
- Critical-path device order: see above (kept opt-in).

## Gate status (honest)
- byte identity both dev blocks: MET; fresh receiver: MET (r2-s1).
- request 24628607 <= 12 s: NOT met by sched alone (25.5-25.9 s).
- recursion GPU busy >= 70%: NOT met; lane device-stage occupancy 0.62-0.73 is an upper bound; kernel busy was 39.8% (M5 nsys).
  The remaining recursion wall is device-stage bound (half of each device stage is host/sync time: enqueue stream) plus a
  ~5 s serial fold tail (5 fold latencies of ~1.05 s on the binary carry; topology frozen for byte identity).
- tail after the last leaf: measured every run (4.3-5.9 s on 607).
- service RSS <= 20 GiB: NOT met (31.2-31.4 GiB peak). RSS sampled every 0.2 s (rss-r5-*.txt, /proc VmRSS/RssAnon/RssFile):
  the service FLOOR between requests is already 18.4-20.4 GiB (anon 16.5-18.4 + 1.86 file); each request adds 7-11 GiB at the
  native->recursion transition (prepped leaves + bundle + overlapped native verify). PREP_AHEAD=3 cuts the peak to 26.5-26.6 GiB
  (-4.7 GiB, 2 obs.) but its 607 time is inconclusive under load (28.22 in r3 vs 34.02 in r5, where the device stages
  themselves ran 28% slower: 34.3 vs 26.8 GPU-stage-s); kept opt-in. The floor (class preload 4.2 GB on disk, CUDA eager module
  load ~5.5 GiB per M4 measure, native/session caches) must shrink before <= 20 GiB is reachable.
- device peak <= 28 GB: MET with the M5 opt-in carve: r6-a22 (stream + STWO_RV64_DEVICE_ARENA=22G) 27.81 GB on both GPUs,
  byte-identical, receivers accepted. Default auto arena stays 31.5 GB (arena default is not this stream's call in M6 yet).
