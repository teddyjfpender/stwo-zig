# bench15-1: the 15-block M3 basket on codex/rv64-m8-gpu (2026-11-07)

**Setup**
- Source: `22214984e` (bench script fixes are in `3e380e3ed` and `a36cb6aea`).
- Runtime: the source-built opt-combined image `25d0e62f`, so the default-on T5/T7/T8/T9 kernels are active.
- Preset: the frozen `baseline` arm (auto arena) plus `--coalesce-truth-families`. Security profile `d2_native_b4_q54_p20_fold4`.
- Arms, interleaved:
  - `default`: the integrate head kernels, no M8 job flags;
  - `gpu-native`: `STWO_RV64_M8_JOBS=1` + `STWO_RV64_M8_GPU_NATIVE=1` + jobs addon `d8692f82`.
- Each arm gets 3 headline services per block, each with a cold and a warm request, under the quiet gate (all 8/8 accepted).
- After timing: byte parity, and fresh CPU receivers on the reference service. One Nsight-profiled warm service per arm gives kernel GPU-s.
- Machine-readable receipt: `summary.json`. Labels: [M] measured, [D] derived.

**Timing boundary (Ethproofs).** Proving time is the service request wall. It runs from the input bytes through capture (witness generation), native and recursion to the root. It excludes fetch and submit. Request time is the client latency through the spool.

## Result: default proves 6/15 blocks; GPU-native proves 0/15

| block | seg | M3 s [M] | M7 s [M] | default warm proving s | warm request s | cold s | warm / M3 [D] | capture | native window | recursion after native | kernel GPU-s | GPU busy kernel / any [D] | gpu-native |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 26235156 | 4 | 34.3 | 10.5 | **9.55** | 9.55 | 23.01 | 0.279 | 1.73 | 2.84 | 4.84 | 6.56 | 34% / 39% | FAIL install |
| 24647140 | 6 | 48.2 | – | **11.46** | 11.46 | 29.51 | 0.238 | 1.99 | 3.83 | 5.38 | 8.47 | 37% / 43% | FAIL install |
| 24628607 | 7 | 51.1 | 12.9 | **11.77** | 11.78 | 29.01 | 0.230 | 2.10 | 3.81 | 5.69 | 8.43 | 36% / 42% | FAIL install |
| 25229957 | 7 | 53.8 | – | **12.51** | 12.52 | 30.54 | 0.233 | 2.14 | 4.05 | 6.18 | 9.12 | 37% / 43% | FAIL install |
| 24628608 | 10 | 60.3 | – | **17.03** | 17.04 | 39.34 | 0.282 | 2.88 | 6.87 | 7.27 | 11.72 | 34% / 40% | FAIL install |
| 24626900 | 12 | 68.3 | – | FAIL `OneTruthPerFamilySourceCapacity` | | | | | | | | | not run |
| 24697073 | 15 | 84.6 | – | FAIL `OneTruthPerFamilySourceCapacity` | | | | | | | | | not run |
| 24697070 | 14 | 86.4 | 69.9 cold | **25.14** | 25.15 | 56.02 | 0.291 | 3.74 | 11.19 | 10.06 | 18.39 | 36% / 42% | FAIL install |
| 26235168 | 28 | 145.4 | – | FAIL `OneTruthPerFamilySourceCapacity` | | | | | | | | | not run |
| 25229955 | 30 | 147.7 | – | FAIL `OneTruthPerFamilySourceCapacity` | | | | | | | | | not run |
| 25229951 | 40 | 179.0 | – | FAIL `OneTruthPerFamilySourceCapacity` | | | | | | | | | not run |
| 24628590 | 38 | 186.0 | – | FAIL `V3TruthShapeExceeded` | | | | | | | | | not run |
| 24628595 | 42 | 213.3 | – | FAIL `V3TruthShapeExceeded` | | | | | | | | | not run |
| 24628611 | 45 | 234.3 | – | FAIL `V3TruthShapeExceeded` | | | | | | | | | not run |
| 26235159 | 49 | 250.5 | – | FAIL `V3TruthShapeExceeded` | | | | | | | | | not run |

**Per-row values**
- Warm and cold values are medians of 3 headline services [M]. The stage columns are warm, in seconds [M]. Setup is 0.11–0.21 s and the tail is 0.03–0.07 s.
- GPU busy is the CUPTI kernel union, or the kernel+copy union, divided by 2 GPUs × the profiled warm window [D].
- Launches and syncs per node come from Nsight counts / nodes [D]: 2392/122 on 26235156, 2765/136 on 24628607, 3292/158 on 24697070.

**Peak memory**
- The sampled device peak is 31.6–31.7 GB on every block [M]. That is the auto arena reservation (vmm maps its full capacity), not live use.
- The default arm has no job-arena receipts, so per-node peak is unavailable.

**Totals (default, the 6 proved blocks)**
- Warm proving sum: 87.46 s vs 334.04 s for M3 on the same blocks (0.262×) [D].
- Cold sum: 207.43 s (0.621×) [D].
- Kernel GPU-s sum: 62.68 [M].
- p50 / p90 / max (nearest rank, n = 6):
  - warm proving 11.77 / 25.14 / 25.14 s;
  - cold 29.51 / 56.02 / 56.02 s;
  - warm request 11.78 / 25.15 / 25.15 s;
  - per-block warm / M3 0.238 / 0.291 / 0.291.
- No 15-block total exists, because 9 blocks fail.

**Against M7 [M vs M]**
- 24628607 warm: 12.9 → 11.77 s (−8.8 %).
- 26235156 warm: 10.5 → 9.55 s (−9.0 %).
- 24697070 cold: 69.9 → 56.0 s (−19.8 %).

**Correctness [M]**
- Every request on every proved block is byte-identical to the block reference: 8/8 per block, including the profiled service.
- On 26235156 and 24628607 every request is also byte-identical to the frozen D2 golden.
- Fresh CPU receivers: 2/2 accepted per block, 30–76 s each.

## Failures

- **The default arm fails deterministically on 9/15 blocks.** The frozen D2 coalesced-truth profile refuses them at plan time: in the cold request of the first service, after capture. Nothing OOMs, and no GPU memory is left behind.
  - `OneTruthPerFamilySourceCapacity` (`ethereum/plan.zig` `oneTruthPerFamily`, through `coalesceTruthFamilies`) on 24626900, 24697073, 26235168, 25229955 and 25229951. A coalesced non-Keccak family exceeds its roster MAX_LOG: sha256 13, arith256 16, curves 16.
  - `V3TruthShapeExceeded` (`truth_v3_catalog.zig:139` / `truth_v3_role.zig:75`) on the 4 largest blocks: 24628590, 24628595, 24628611 and 26235159.
  - It depends on the block, not on its size: 24697070 (14 segments) proves, but 24626900 (12) does not.
  - Running each failed block as its own one-block invocation kept the stop-on-failure rule per block and still mapped the whole basket.
  - Fixing this is a proof-profile decision (split rosters / larger truth geometry for big blocks), not a speed item. Until then the D2 profile cannot run the basket.
- **GPU-native fails on every block it ran on** (6/6): `error: GpuNativeNativeShapeHookMissing` at install, so the service never becomes READY. It fails closed, as designed, with no fallback. The remaining work is the shape/pack hooks listed in `gpu-integrate/integrate-2.json`.

## Gates and landing

| gate | block | env | runtime | result |
|---|---|---|---|---|
| gate-11 | 26235156 | default | opt-combined 25d0e62f | **PASS** (32 artifacts byte-identical to D2, 2/2 receivers, corpus) |
| gate-12 | 24628607 | default | opt-combined 25d0e62f | **PASS** (39 artifacts byte-identical to D2, 2/2 receivers, corpus) |
| gate-14 | 26235156 | JOBS=1 + JOBS_LIBRARY | opt-combined | FAIL `MissingM8OuterFsLibrary` |
| gate-15 | 26235156 | JOBS=1 + addon + outer-fs + pinned 2365587456 | opt-combined | FAIL `CudaEnqueueFailed` (arena live high water 26.45 / 27.28 GB on device 0) |
| gate-16 | 26235156 | as gate-15 | frozen a25 | FAIL `DeviceScopeReleaseFailed` → `GpuPcsFailed` |

**Not landed.** The protocol requires the `STWO_RV64_M8_JOBS=1` gate for a job-path landing, and it fails, as does the GPU-native arm. `codex/rv64-m8-gpu` stays off `codex/rv64-m7-integrate`. The GPU-native flag stays default-off, and no flip is proposed: it proved 0/15 blocks.

## Pod receipts

- Run directory: `/workspace/m3/runs/m8-gpu/bench15-1/` (`config.json`, `blocks/*.json`, `logs/`).
- Services: `/workspace/m3/runs/m8-gpu/daemon-*-bench15-1-*`. Proofs and Nsight files are pruned; `producer.stderr` is gzipped.
- Assets: `assets-22214984e.json`. Driver `b5868c74`, receiver `d8a831b6`, library `25d0e62f`, addon `d8692f82`, outer-fs `166556d1`.
- Gate receipts: `/workspace/m3/runs/m8-gpu/gate-{11,12,14,15,16}/gate.json`. Their SHA-256 values are in `summary.json`.
