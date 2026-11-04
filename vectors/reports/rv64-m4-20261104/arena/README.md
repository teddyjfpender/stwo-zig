# Stream arena (M4 L1): VMM static device arena, pinned staging, preset sweep

Branch `codex/rv64-m4-arena` (from `bcd401ce4`). Pod: 2x RTX 5090 (33.68 GB each), shared with the other M4
streams; the 1-minute load average was 28-65 during every run below (protocol asks for <8; **no quiet host
was available**). So every timing is **[M] single observation on a loaded host**; the stable evidence is in
the counters (API calls, driver ms, bytes), which do not depend on load.

Driver `b28544a1` (M3 integrate, unchanged; no Zig change in this stream). Library: this tree (`context.cu`
plus two new headers), catalogues-v3, built with infra's object store (2 TUs recompiled, ~130 s).
Env for every run: the M3 scale-up config (`NARROW_RUNS=1 GPU_CPU_REPLAY=1 CORE_SINGLE_STREAM=1`).

## What it is

`STWO_RV64_DEVICE_ARENA=1|auto|<bytes>` (default **off**, so other streams are unaffected until integrate flips it):

1. **Physical memory is carved once per device** at the first allocation: `cudaDeviceSetLimit(StackSize, 12544)`
   first (the stack-admission worst kernel, so kernel local memory is reserved up front and the driver never
   grows it into a full device), then `(free - 2 GiB)` as 814 x 32 MiB `cuMemCreate` chunks, all mapped
   contiguously into a 4x virtual reservation (`premap`, 76-85 ms per device).
2. **Placement is virtual.** Allocations >= 4 MiB take the free window with the most already-mapped slots
   (a fully mapped window costs no driver call). Freed ranges stay mapped and coalesce. When the live set
   fragments the mapped window, free mapped chunks elsewhere are unmapped and remapped behind the new range
   ("steal"). **Physical fragmentation is impossible at 32 MiB granularity**; a request fails only when live
   bytes + request > carve.
3. Allocations < 4 MiB come from a permanently mapped 512 MiB slab (deterministic offset allocator,
   `device_arena.h`, host-unit-tested).
4. **Overrun returns `cudaErrorMemoryAllocation`; there is never a pool or `cudaMalloc` fallback.** The
   caller's existing recovery (PCS idle-cache eviction, then retry) is unchanged.
5. **Cross-stream reuse safety.** Contexts used to own private pools, so a range was only reused by the
   stream that freed it. The arena is shared by every context of a device. Multi-lane contexts already join
   all lanes before a free. A single-lane free records an event; any later reuse by another stream waits on
   it. Measured: `fence_records = 0` (every free in this workload is joined).
6. `pool_current` / `pool_split` report arena live bytes and the carve, so the PCS physical admission and the
   `GPU_DEVICE_PEAK` lines keep working.

`STWO_RV64_PINNED_STAGING=1` (default **off**): pinned 4 x 16 MiB bounce rings per stream for every pageable
`memcpy_{h2d,d2h}_async`, with the exact blocking contract of a pageable copy. **Measured as a net loss**, see
below.

### Why VMM and not a contiguous slab (measured, not assumed)

The first implementation (a1) was a contiguous `cudaMalloc` slab with a best-fit / size-class allocator. On
26235156 it **failed**: an 18.44 GB composition-arena request (the rl+2 role) found only a 13.1 GB hole with
4.38 GB live after idle eviction (`GPU_ARENA_OVERRUN ... largest_free_bytes=13114284032 free_extents=4`). The
pool path survives this only because the driver remaps physical pages. VMM gives the same immunity, but with a
static physical carve and no driver allocation. The design then iterated on driver cost (all byte-identical):

| lib | design | map ms (dev0) | unmap ms (dev0) | map misses / steals | 156 request | load |
|---|---|---:|---:|---:|---:|---:|
| a3 | VMM, map on alloc / unmap on free | 4,521 | 2,345 | every alloc | 42.57 | 47.0 |
| a4 | + retained-mapping cache | 3,520 | 1,300 | 521 misses | 38.12 | 30.8 |
| a5 | coalescing mapped VA + steal | 1,523 | 546 | 587 / 502 | 38.19 | 34.4 |
| a6 | + max-mapped-window placement | 283 | 158 | 92 / 25 | 34.97 | 50.5 |
| a7 | + premap whole carve at init | 408-470* | 240-288* | 32-35 / 32-35 | 35.96 | 57.6 |

\* a7 figures are from 24628607 (larger block); on 607, a6 was 749-1,134 ms of mapping.

## Results [M]

See `*.json` here for the receipts and `vectors/reports/progress/arena.jsonl` for the progress rows.

### 24628607 (2 GPUs)

| run | request | capture | setup | native | recursion | pool mallocs | pool trims | pool OOM recov. | pageable copies | parity vs M3 | receiver | load1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---:|
| control (arena off, lib a5) | 53.87 | 3.60 | 13.59 | 7.91 | 28.54 | **14,619** | 8 | 4 | 19,659 | identical | (not run) | 33.1 |
| a5 arena | 55.30 | 3.52 | 13.44 | 7.88 | 30.09 | 0 | 0 | 0 | 19,705 | identical | (not run) | 40.3 |
| a6 arena | 52.80 | 3.30 | 13.23 | 7.95 | 28.09 | 0 | 0 | 0 | 19,705 | identical | (not run) | 28.6 |
| **a7 arena** | **51.93** | 3.35 | 13.04 | 7.84 | **27.51** | **0** | **0** | **0** | 19,751 | **identical** | **accepted** (69.4 s) | 64.5 |

M3 baseline (`rv64-m3-20261104/integrate/scale/24628607.json`, quiet-ish host): 51.11 s. **Parity** here means
byte identity against that M3 receipt: native bins, bundle, recursive tree and every one of the 33 recursive
proofs. Root proof 706,424 B.

### 26235156 (2 GPUs)

| run | request | capture | setup | native | recursion | pool mallocs | pool trims | pageable copies | parity vs M3 | load1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|
| control (arena off, lib a3) | 35.92 | 2.83 | 8.86 | 5.27 | 18.83 | **9,501** | 12 (6 OOM recov.) | 12,296 | identical | 39.5 |
| a4 arena + **pinned staging** | 40.71 | 2.80 | 9.27 | 5.86 | 22.57 | 0 | 0 | **0** | identical | 40.0 |
| a4 arena, staging off | 38.12 | 2.66 | 8.90 | 5.35 | 20.99 | 0 | 0 | 12,250 | identical | 30.8 |
| a6 arena | **34.97** | 2.80 | 9.38 | 5.14 | **17.51** | 0 | 0 | 12,250 | identical | 50.5 |
| **a7 arena** (bench) | 35.96 | 3.04 | 9.74 | 5.26 | 17.71 | **0** | **0** | 12,250 | **identical**, receiver **accepted** (45.2 s) | 57.6 |

M3 baseline: 34.28 s.

### Device memory [M]

Physical budget per 5090 (from `GPU_ARENA_INIT`): 33.68 GB total; **1.18 GB** context + 686 eager modules;
**3.01 GB** kernel local memory for the 12,544 B/thread stack worst kernel (`secp witness<Add>`);
2 GiB reserve; arena carve 27.31 GB.

- **Live high-water inside the arena: 26.4-26.8 GB per device on both blocks with the auto carve; 23.6-24.1
  GB under the 23 GiB cap.** That includes the PCS idle
  cache, which grows to fill whatever the device offers. The 33.65 GB NVML "peak" of the pool path was
  reservation, not need.
- Overruns at the carve ceiling are absorbed by the existing PCS idle-cache eviction (11-14 per device on
  607), exactly as pool OOMs were before (4 recovered pool OOMs plus trims). Proofs stay identical.
- Whole-device footprint = arena physical high-water + outside (context/modules + local memory):
  **31.50 GB** with the auto carve (vs 33.65 GB NVML-sampled on the pool path), **28.88 GB** with a 23 GiB cap.
  (An earlier print counted the 512 MiB slab twice; the rows/receipt post-processing and the code are fixed.)

### Cap sweep: the binding request [M]

`scripts/rv64_m4_arena_sweep.py` (presets `presets-v1.json`; gate = byte identity vs M3 plus native slowdown
<= 15%) on 26235156, result `26235156-sweep-v1.json`, plus one 23 GiB probe:

| arena cap | device total | result | request | native | recursion | load1 |
|---|---:|---|---:|---:|---:|---:|
| auto (27.31 GB) | 31.50 GB | identical | 34.76 | 5.06 | — | 74.4 |
| **23 GiB (24.70 GB)** | **28.88 GB** | **identical**, 17 recovered overruns | **34.16** | 5.17 | 17.41 | 34.9 |
| 22 GiB (23.62 GB) | 27.81 GB | **fails**: `CudaAllocationFailed` | — | — | — | 61.3 |
| 18 GiB, 18 GiB + idle cache 0 | ≤ 23.5 GB | fail (same request) | — | — | — | — |

The binding request is a single **18.44 GB composition arena** (rl+2 role: 3,516 columns at `eval_log` 20,
= 14.75 GB of evaluations + 3.69 GB of staged coefficients). It fails while **4.32 GB of leases** must stay
live; the idle PCS cache was already evicted to 0. A request can only succeed when
live + 18.44 GB <= carve, so presets alone cannot go below about 28.9 GB per device.
**The M4 GPU0 ≤ 28 GB gate is therefore not met by presets.** The plan's kill rule applies to "presets
only". There are two concrete, separately measurable diet items, not done here:

1. **Direct extension for degree el-2 columns** in `resident_composition.zig`. The staged-coefficient
   copy (3.69 GB) disappears, as M3's change 4 did for el-1 columns (16.84 → 11.24 GB). This needs
   `stwo_lde_n2b_columns_on` to accept a compact el-2 source (a kernel change outside the AOT catalogues).
   Expected device total about 25.2 GB [E].
2. **Local-memory diet:** the 12,544 B/thread stack worst kernel reserves 3.01 GB per GPU. Bounding it at
   4 KB frees about 2 GB [E]. Together with item 1 that gives about 23 GB, inside the ≤24 GB target [E].

## Gates (plan M4) — status

| gate | status |
|---|---|
| `cudaMallocFromPoolAsync` in steady state ≈ 0 | **met**: 0 (was 14,619 on 607 / 9,501 on 156); trims 0; pool OOM recoveries 0 |
| pageable copies 0 | **not met by default.** The pinned bounce reaches 0 but costs +2.6 s on 156: 47.8 GB of H2D become single-thread memcpys. Needs pinned *source* buffers in the producers (capture/witness streams) or a parallel memcpy |
| proofs byte-identical | **met** on both dev blocks (all native, bundle, tree and recursive proofs vs the M3 receipts) |
| fresh receiver accepts | **met** on both dev blocks (a7 bench: 607 69.4 s, 156 45.2 s receiver wall) |
| device peak counters per stage | `GPU_ARENA_INIT/HW/OVERRUN/SUMMARY` + arena-backed `GPU_DEVICE_PEAK pool_used_bytes`; see the receipts |
| GPU0 peak <= 28 GB | **not met: 28.88 GB** is the minimum feasible hard cap (23 GiB arena), byte-identical with no slowdown. 22 GiB fails on the 18.44 GB composition request; see the sweep section for the two diet items |
| measured request delta | 607: 53.87 → 51.93 s; 156: 35.92 → 34.97 (a6) / 35.96 (a7) s. **[M] single observations on a host at load 28-65; within noise**, not claimed as a speedup. The robust deltas are the counters above and the driver ms in each receipt |

## Integration notes

- Hooks are in `context.cu`, which the plan assigns to the resident stream: about 70 lines, all `#if
  STWO_DEVICE_ARENA_HOOK`, default off. Merge order: resident, then arena (or cherry-pick the hunks).
- **Kernel local memory costs 3.01 GB per GPU** because of one 12.5 KB-stack kernel. Cutting the worst
  stack to 4 KB would free about 2 GB per GPU. That is kernels-stream work; it should become part of the
  stack admission.
- Pinned staging stays opt-in. The win needs pinned source buffers in capture/witness ingress, which belong
  to other streams.
- Pod disk was 100% full at 13:06; this stream keeps one 2 GB library copy plus the `base/` binaries.
