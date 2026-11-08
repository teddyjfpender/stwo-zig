# RV64 M4 integrate summary (2026-11-04)

Branch `codex/rv64-m4-integrate` (source `cbe06a3f3`), fast-forwarded into `codex/rv64-cuda-ethereum` (PR #314).
Hardware: 2x RTX 5090 on the shared pod. Binaries: driver `a9acb639`, CUDA library `5886e2a5`, receiver `1af34c0b`
(`integrate/build.json`). The catalogue drift gate passed on catalogues-v3 (6/6 families byte-equal to regeneration).

**Labels:**
- **[M]** measured, a single observation with its receipt in `integrate/`.
- **[D]** derived from measured numbers.
- **[E]** estimated.

**Load:** the pod's 1-minute load was 6.7–26 during the gate. The protocol's quiet bar is 8, and only the seed run started under it (6.7). No number here is a median.

## What was merged

| stream | head | effect on the request path |
|---|---|---|
| measure | `6f398efa0` | receipt v2, counter shim, progress ledger (tools only) |
| arena | `d3835ed12` | VMM static device arena, opt-in `STWO_RV64_DEVICE_ARENA=1` (**on in every gate run**) |
| kernels | `c8f9ee76b` | 2-pass NTT/LDE, eager SoA Blake leaf states, row-major DEEP, LogUp generate (kernel GPU-s 29.9 → 19.4) |
| resident | `0fee57fe7` | `combined-serve` resident service, ArtifactStore, reused setup validations, catalogue drift gate |
| capture | `ed09c445c` | paged radix ledger table, events prepared off the ledger thread |
| profiles | `6fb652849` | M5 binding note (review 1), M7 profile note, negative corpus v2, candidate profiles that cannot be selected |
| diet | `abf1c48cf` | prototypes and tests only (fused Blake2s AIR, outer-GKR cost test); not referenced by production |

- **Not merged:** `codex/rv64-m4-recsize-port` (`d4cdf05fa`). It is a proof-format change (k-ary folds and the m3 profile), it edits canon-vk files, and its GPU byte-parity has not been run. It goes to M5/M7.
- **Conflicts:** the only text conflict was the generated `PROGRESS.md`, which was regenerated. `rv64_m3_pod.py` auto-merged the measure, kernels and resident hooks, and each flag was kept.
- **Integration fixes made here:**
  1. The harness catalogue gate now uses this stream's freshly built generator tools. Before, it read `build/m4-resident/tools`.
  2. `rv64_progress.py` now normalises legacy rows when it reads them: 70 early hand-written rows use alias keys, per-GPU dicts, or the 0.04 GiB RSS of the nsys wrapper. History on disk is not rewritten, and new rows must still use schema keys.

## Headline [M]

Configuration: the resident service, the ArtifactStore reused, `--warm` boot, arena on, and the M3 scale environment (`NARROW_RUNS`, `GPU_CPU_REPLAY`, `CORE_SINGLE_STREAM`). Results come from `integrate/daemon-g3-warmboot.json`.

| block | M3 request | **M4 1st / 2nd request** | vs M3 | capture | setup | native | recursion | receiver |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| 26235156 | 34.28 | **19.52 / 20.06 s** | **1.76x** | 2.32 | 0.137 | 4.77 | 12.16 | accepted (41.2 s) |
| 24628607 | 51.11 | **28.46 / 29.21 s** | **1.80x** | 2.80 | 0.148 | 5.86 | 19.47 | accepted (61.4 s) |

- **Byte-identical to M3:** every proof in every gate run matches the M3 integrate scale receipts. That covers native bins, the bundle, every leaf, fold and root, and the tree.
  - 12 of 12 service requests are identical.
  - The one-shot runs are identical too: 37/37 hashes on 26235156, 55/55 on 24628607 and 97/97 on the scale probe.
- **Fresh receivers accepted 7 of 7 roots.** Each receiver was a separate CPU-only process with the ArtifactStore directory renamed away and the setup cache, class store and fold class cache disabled.
- **Service start:** 12.36 s, reported separately and never counted in a request. It covers 683 EAGER library loads, the warm pre-boot and the class preload. Service stop took 1.7 s.

### Per column, 24628607 (M4 row = warm-boot 1st request)

| column | M3 [M] | plan M4 target [E] | **M4 [M]** | factor vs M3 |
|---|---:|---:|---:|---:|
| request | 51.11 s | 33–36 | **28.46 s** | 1.80x (plan target beaten) |
| capture | 3.28 s | 1.5 | 2.80 s | 1.17x (**gate missed**) |
| setup | 12.55 s | ≤1 | **0.148 s** warm boot; 0.563 s cold service | 85x / 22x |
| native prove | 7.83 s | 7 | 5.86 s | 1.34x |
| recursion | 27.28 s | 22 | **19.47 s** | 1.40x |
| verifier | 77.3 s | 77 | 61.4 s | no code change; the difference is load (kernels-adv measured M3 vs branch at 61.7 vs 61.6 s at the same load) |
| RSS | 25.0 GiB | 15–18 | 22.9 GiB one-shot (20.2 private); 27.45 GiB whole service | 1.09x (**gate missed**) |
| GPU0 peak | 33.65 GB | ≤28 | 31.50 GB (auto carve) | **gate missed** |
| proof | 706,424 B | 708 KB | 706,424 B | unchanged (no format change) |

### Other configurations [M]

| receipt | config | 26235156 req (setup) | 24628607 req (setup) | notes |
|---|---|---:|---:|---|
| `daemon-g1-seed` | empty store, so setup is cold in the request | 26.99 (4.74) | **36.30 (5.62)** | load 6.7, the only quiet start. Recursion 14.92 / 20.53 |
| `daemon-g2-coldservice` | store reused, lazy load (no `--warm`) | 19.63 / 20.43 (0.54 / 0.13) | 30.21 / 32.13 (0.56 / 0.17) | 2nd vs 1st: +4.1% / +6.3% |
| `daemon-g3-warmboot` | headline | 19.52 / 20.06 | 28.46 / 29.21 | 2nd vs 1st: +2.8% / +2.6% |
| `daemon-g4-nsys` | `--warm`, under nsys | 19.41 | 32.20 | counters only; timings under nsys are not quoted |
| `*-g5-counters` | one-shot `combined-batch` under the counter shim, no store | 46.85 | 69.79 | shim interposition slows syncs; counters only |

## M4 exit gate (plan §5)

| gate | result | evidence |
|---|---|---|
| cold-service setup ≤ 1.0 s | **met**: 0.54 s (156), 0.56 s (607); 0.137 / 0.148 s with `--warm` | g2, g3 |
| 2nd request = 1st ± 10% | **met**: +2.8% / +2.6% (warm), +4.1% / +6.3% (cold service) | g2, g3 |
| `cuLibraryLoadData` per request ≤ 20 | **met: 0 per request.** All 683 loads happen at service start | g4 per-request nsys window |
| pool mallocs in steady state ≈ 0 | **met: 0** (arena on). M3 had 14,670 on 607 | g5 shim and g4 nsys window |
| pageable copies = 0 | **not met**: 19,613 copies, 71.1 GB H2D per 607 request (M3: 19,705 / 73.0 GB). Pinned staging was measured slower by arena; producers need pinned ingress (M6 native-stream) | g5 |
| request-attributable RSS −30% | **not met**: one-shot peak 22.9 GiB vs 25.0 (−8%), private at peak 20.2 GiB | g5 smaps |
| GPU0 peak ≤ 28 GB | **not met**: 31.50 GB with the auto carve. The arena sweep's feasible minimum is 28.88 GB (23 GiB cap) → **the plan's M4 kill rule fires** | g3, arena README |
| capture on 607 ≤ 1.5 s | **not met**: 2.80–3.28 s quiet-ish; up to 6.0 s under compaction stalls (below) | g3, capture-ab |
| byte-identical proofs | **met** on all 15 producer runs | all |
| fresh receiver accepts, store deleted | **met** 7/7 (6 service requests + scale probe) | g1, g3, g6 |

Per-request CUDA counts for 24628607 (shim on the one-shot path, then the nsys window in the service):

| | M3 [M] | M4 [M] |
|---|---:|---:|
| syncs | 55,396 | 57,816 / 57,958 |
| launches | 228,174 | 222,913 / 222,905 |
| pool mallocs | 14,670 | 0 / 0 |
| library loads | 683 | 683 one-shot / **0 in the service** |
| pageable copies | 19,705 | 19,613 |

**Syncs and launches did not change.** M4 did not touch the enqueue path; that is M6's job (gates: ≤10 syncs and ≤500 launches per node).

GPU busy in the service (nsys, 607 request window):
- Kernels total 8.99 + 10.42 GPU-s. Over the request that is 30% busy on average.
- In the recursion window, kernels are 7.13 + 7.78 = **14.9 GPU-s, 38% busy**. M3 was 25.1 GPU-s at 49% / 43%.
- **Recursion is now host-bound:** the GPU floor at perfect overlap is about 7.5 s against a 19.5 s recursion wall [D].

## Scale probe: 24697070 (57.8 M instr), one cold one-shot run [M]

| | request | capture | setup | native | recursion | fold tail | receiver | RSS |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| M3 | 86.37 | 5.74 | 23.35 | 14.40 | 42.54 | — | 142.4 s | 26.4 GiB |
| M4 (no store, so setup is cold) | 82.65 | **12.12** | 23.40 | 13.16 | **33.56** | 6.81 | accepted, 114.9 s | 24.7 GiB |

- **Proofs:** 97/97 hashes byte-identical to M3, and the fresh receiver accepted the root (31 leaves, 30 folds).
- **Recursion** is −21%.
- **Capture regressed** from 5.74 to 12.12 s [M], a single observation at load 14–19.

### Capture regression investigation

I ran a CPU-only A/B on 607 (`integrate/capture-ab/`), comparing the capture stream's base and v3 binaries, interleaved, 2 runs each. For each run I recorded the change in `/proc/vmstat` `compact_stall`.

| run | compaction stalls | v3 capture (last inputs) | base capture |
|---|---:|---:|---:|
| first run of each binary | 935 (v3) / 680 (base) | 5.69 s | 3.21 s |
| second run of each binary | ≈0 | **2.71 s** | 2.95 s |

What this shows:
- THP is `defrag=madvise` on this host, and 45.7 k of 47.7 k compaction stalls since boot failed.
- v3 advises `MADV_HUGEPAGE` on its prefaulted per-segment event arrays (about 123 MB each).
- Under host memory fragmentation, that advice pulls synchronous direct compaction into capture.

This is a **[D] hypothesis, not proven**. The scale probe has more segments (14 against 7), so it would have more exposure. The fix belongs to the capture stream: drop `MADV_HUGEPAGE`, or gate it on `defrag`, and keep only the off-thread prefault.

## Kill and re-plan triggers (plan §5, §7)

1. **The M4.0 recursion-kernel trigger (> 20 GPU-s) was hit at M3 (25.1). After the kernels stream it is no longer hit:** 14.9 GPU-s in the recursion window, 19.4 GPU-s for the whole process.
   - The M6 recursion gate of ≤ 8 s still sits barely above the 7.5 s two-GPU floor [D].
   - So the L4 cell diet stays pulled forward to run in parallel with M5 and M6: outer-GKR and blake-gadget prototypes from M5 start. Diet measured the tree factors as GKR ×0.62, fused Blake ×0.61–0.69 and combined ×0.39–0.44 [D].
2. **The M4 kill fires on device memory.** The preset sweep cannot bring GPU0 below 28 GB (minimum feasible 28.88 GB). Per the plan, **M6 concurrency is cut to 2 nodes per GPU, and the recursion target moves to the "realistic" band.**
   - The listed diet items would free about 5.7 GB [E]: direct el-2 extension for the 18.44 GB rl+2 composition role (−3.69 GB) and bounding the 12.5 KB-stack kernel (−2 GB of local memory).
   - Those items could re-open 3 nodes per GPU.
3. **RSS is reducible, not driver-pinned.**
   - 8.9 GiB at the peak is recursion prep for nodes prepared ahead (measure).
   - About 5.5 GiB is CUDA EAGER image load. In the service this is paid once at start, but it is still resident.
   - The RAM target stays. The levers are M5 (graph, PP and plan built once per image in the store) and M6 (hint tape).

## Reproduce

```sh
# pod, after podsync to /workspace/m3/src/m4-integrate
flock -w 3600 /workspace/m3/locks/build.1.lock python3 scripts/rv64_m3_pod.py build --stream m4-integrate --jobs 24
bash vectors/reports/rv64-m4-20261104/integrate/gate.sh            # seed cold warm nsys counters scale
python3 /workspace/m3/runs/m4-integrate/perreq.py <g4 run dir>      # = integrate/nsys_per_request.py
# laptop
python3 vectors/reports/rv64-m4-20261104/integrate/make_summary.py  # summary.json (+ --ledger once)
python3 scripts/rv64_progress.py render
```

The ArtifactStore for this driver lives at `/root/m4-store/codex-rv64-m4-resident/` on the overlay disk. `/workspace/m3/store/codex-rv64-m4-resident` is a symlink to it, because `/workspace` was 90% full. The old `6ce263f1…` namespace (driver `d6af8aae`) was pruned.
