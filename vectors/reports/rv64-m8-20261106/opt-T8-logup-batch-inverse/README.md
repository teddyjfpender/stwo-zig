# T8 LogUp batch inverse (M8 optimisation round 2)

Branch `codex/rv64-m8-opt-T8-logup-batch-inverse`. Labels: [M] measured, [D] derived from measured values, [E] estimate.

Files: `src/backends/cuda/native/rv64/{global.cu,binding.cu}` (binding.cu: `stwo_rv64_prefix_scan_on` and its scan kernels only), new `rv64/logup_t8.h`, new `tests/cuda/rv64/t8_logup_parity_bench.cu`.
`circuit_interaction.cu` was claimed but **not changed**: `circuit_outer::cumulative` already runs at about 1.37 TB/s [D: 832 B/row x 2^22 rows in 2.55 ms, M7-P1 trace], and its traffic is the minimum the entry point's contract allows.

## Switch
`STWO_RV64_M8_LOGUP_BLOCK_INVERSE`: unset/`0` = original kernels (default), `1` = T8 kernels, anything else = the entry points return `cudaErrorInvalidValue`.
The extern entry points, struct ABI and status bits are unchanged. The default path and the GPU-native path both reach T8 through `stwo_rv64_global_pairs_on`, `stwo_rv64_prefix_scan_on` and `stwo_rv64_global_contributions_scan_v1_on`.

## What changed
- **Inverse + contribution.** The original kernel spends 13 OM31 multiplications per row (52 M31 muls each) on a warp prefix/suffix scan, plus a lane-0 inversion. That is about 690 M31 muls per row-pair, so the kernel is compute bound: 11.4 ms at 2^22 x 13 pairs, about 610 GB/s [M, M7-P1 trace].
  - T8 inverts each row by norm descent (OM31 -> QM31 -> CM31 -> M31) and batches the M31 inversions over K = 2 rows per thread (Montgomery). That is about 150 M31 muls per row-pair.
  - This follows Airbender's `batch_inv_registers`, which uses per-thread register batches and no warp scan. The difference is that T8 batches at the base field, because an OM31 Montgomery step (3 OM31 muls) costs more than a whole norm descent.
- **Row sum fused** from 2^18 rows (>= 1024 blocks of 256 rows): one 1-D pass over all pairs keeps the row sums in registers, so contributions are not re-read. Below 2^18, a 2-D grid (pairs on y) plus the original `global_row_sum`.
- **Prefix scan level 0** for row_log >= 15. Viewed as 64 x n/64, the circle-order plane holds each logical 128-chunk in exactly two columns: brev(c) for the even logicals and n/64-1-brev(c) for the odd logicals.
  - A block owns columns [r0, r0+32) plus their mirror, which is 32 whole chunks, so every global access is a 128-byte row.
  - Two passes run: chunk sums, then the local scan plus carry plus centring. They replace `scan_chunks` + `scan_carries` at level 0 with the same launch count.
  - Upper levels, `scan_claim` and the scratch contents are unchanged.
- **Outputs are bit-identical** because inverses and n·inv are unique canonical elements and modular sums are order independent. Invalid rows use the same substitution (d = 1, n = 0) and the same status bits 2/4/8.
- **Counter note.** With the flag on, the fused path issues one launch fewer than `resident.zig` records (`2 + plan.dispatches(true)`). This affects the launch counter only.

## Kernel parity [M]
`kernel-parity.jsonl`: **208/208 cases bit-identical**, mode 0 vs mode 1, through the same launcher. Every word of every buffer the launcher may write is compared: pair planes including stride padding, the row-sum plane, scan scratch, claim and status.
- Pairs: log 4..19 x {1, 2, 3, 13} pairs x pad {0, 7}, plus {50, 143} pairs at logs 10/14/16, plus 640 pairs at 2^12. Non-canonical words and zero denominators were injected (status 6 in both modes), plus clean cases (status 0).
- Scan: log 4..21 x center {0, 1} x pad {0, 5}, with non-canonical injection (status 2/8/10).
- Logs 20+ at 13 pairs could not be allocated: an orphan process (pid 3302210) holds 30.1 GB on each GPU.

## CUDA-event microbenchmark [M]
`kernel-bench.jsonl`: the whole `global_pairs` launcher (inverse + row sum + centred prefix scan). Input is refilled untimed before every timed call; 9 reps after 1 warm-up, old/new interleaved, RTX 5090. Spreads are within ±1% of the median.

| rows x pairs | old ms | T8 ms | speedup |
|---|---|---|---|
| 2^23 x 2 | 7.288 | 2.282 | 3.19x |
| 2^22 x 2 | 3.702 | 1.155 | 3.21x |
| 2^20 x 13 | 3.483 | 1.390 | 2.51x |
| 2^20 x 8 | 2.285 | 0.884 | 2.58x |
| 2^20 x 6 | 1.802 | 0.679 | 2.65x |
| 2^20 x 3 | 1.073 | 0.358 | 3.00x |
| 2^19 x 6 | 0.915 | 0.346 | 2.65x |
| 2^17 x 143 | 4.321 | 2.006 | 2.15x |
| 2^16 x 50 | 0.784 | 0.331 | 2.37x |
| 2^14 x 13 | 0.066 | 0.029 | 2.30x |

`scan-bench.jsonl` (prefix scan alone, centred): 2^15 0.0238 -> 0.0195 ms, 2^18 0.107 -> 0.023, 2^20 0.355 -> 0.042, 2^22 1.671 -> 0.281, 2^23 3.306 -> 0.563 (2^12 not tiled: 0.0099 vs 0.0104, noise).

Tuning A/Bs (`tuning/`, also quoted next to each constant): rows per thread K = 1/2/4, the fused-grid threshold (256 / 1024 / 4096 / never) and the scan tile threshold (2^12..2^17).

## Request-level projection [D]/[E]
- **Measured LogUp kernels.** On the M7-P1 24628607 warm trace [M], `global_inverse_contribute` + `global_row_sum` + `scan_chunks` + `scan_carries` = 0.388 + 0.043 + 0.065 + 0.066 = 0.562 GPU-s.
- **Kernel-level saving [D].** The microbenchmark speedups (2.2–3.2x launcher; the scan 6–8.5x from 2^20) give about -0.33 to -0.38 GPU-s.
- **Large shapes [D].** The 2^22 x 13 and 2^23 x 13 shapes (0.24 GPU-s of the total) are projected linearly from 2^20 x 13: 14.4 -> ~5.6 ms per call.
- **Request time [E].** About -0.10 to -0.15 s, mostly in recursion INTER-witness. This is pending the canonical 3+3 below.

## Request level
Pending: `/workspace/m3/runs/m8-opt-T8-logup-batch-inverse/pipe1.sh` (tmux `t8-pipe1`, status `pipe1.status`) waits for both GPUs to drop below 2 GB and for 4 GB of free disk. Then it:
1. links the image: `build/m8-opt-T8-logup-batch-inverse/image`, the frozen `m7-combined-residency` link with rv64 global/binding/circuit_interaction rebuilt, plus the 4 objects whose original build dirs are gone, as T2/T4 did;
2. gates flag-off and flag-on on 26235156 and 24628607;
3. runs the canonical 3+3 on 24628607 on one image: baseline = flag 0, fullstack = flag 1, and only the flag differs (`ab-preset.json`).

The 1.98 GB `.so` was deleted after the first link because the pod disk reached 100% (345 MB free) while the GPUs were blocked.
