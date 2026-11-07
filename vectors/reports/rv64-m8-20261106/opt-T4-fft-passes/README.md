# T4 FFT passes (M8 optimisation round 1)

Branch `codex/rv64-m8-opt-T4-fft-passes`. Files: `src/backends/cuda/native/transform/{b2n_fused.cuh,b2n_retained.cu,n2b_smem.cuh,n2b.cu}`
plus new `wide_tile.cuh`, `fft_small.cuh`, `bench/fft_passes_bench.cu`. C entry points, twiddle layout and the old kernels are unchanged;
`lde.cu`, `composition_split.cu` and `pcs_enqueue.cu` are not touched. lde.cu picks up the n2b changes through `n2b_wide_supported`.

## What changed
- **B2N logs 19–24: 2 HBM passes instead of 3.** `b2n_wide_contiguous` applies stages 1..13 to an 8192-word tile (5+5+3 register phases joined by padded shared memory).
  `b2n_wide_strided<High,LaneLog>` applies stages 14..log_n to a tile of 2^LaneLog contiguous words x 2^High high points, with 2^13 values per tile.
  It also applies the 2^-log_n scale and writes the plain, Duplicate (retained 2N) or CompactDepth layout. This is the mirror image of the n2b wide pair, in the same style as the
  Airbender/sppark multi-stage register kernels.
- **N2B/LDE log 20: 2 passes instead of 3** (`STWO_N2B_WIDE_MIN_LOG` 21 -> 20). It uses a new wide-row strided kernel `n2b_wide_strided_rows`, which also takes heights 8–9 (logs 21–22).
- **log_n <= 12: one shared-memory pass** (`fft_small_columns`, radix-4 per barrier, several columns per CTA) instead of one launch per stage. This covers b2n compact/retained and n2b; the LDE staging kernel in lde.cu remains.
- Kill switches (default on): `STWO_RV64_M8_B2N_WIDE=0`, `STWO_RV64_M8_FFT_SMALL=0`, `STWO_RV64_M8_N2B_WIDE_MIN_LOG=21`, `STWO_RV64_M8_N2B_WIDE_ROWS=0`.
  All four together restore the previous kernel set on the same image.

## Kernel parity [M]
`kernel-parity-2.jsonl`: **252/252 cases bit-identical**, old schedule vs new. This covers log_n 4..24, 1 column and many columns (odd counts for partial CTAs),
and every entry point: b2n compact, b2n exact alias, b2n to_retained, n2b, LDE, and LDE before circle. Random columns, twiddles and coefficient log sizes (zero extension and clamped) were used.

## CUDA-event microbenchmark [M]
`kernel-bench-2.jsonl`: 256 MiB of input per call, 9 reps interleaved old/new, median [min, max] ms, RTX 5090.

| log | b2n compact old -> new | b2n retained | n2b | LDE |
|---|---|---|---|---|
| 10 | 3.533 -> 0.371 | 3.779 -> 0.569 | 3.534 -> 0.369 | 3.857 -> 0.696 |
| 12 | 4.215 -> 0.424 | 4.473 -> 0.573 | 4.213 -> 0.401 | 4.557 -> 0.746 |
| 13–18 | unchanged (2 passes) | unchanged | unchanged | unchanged |
| 19 | 1.053 -> 0.709 | 1.270 -> 0.911 | 0.707 = | 0.614 = |
| 20 | 1.057 -> 0.707 | 1.288 -> 0.920 | 1.053 -> 0.698 | 0.969 -> 0.619 |
| 21 | 1.061 -> 0.709 | 1.288 -> 0.936 | 0.715 -> 0.705 | 0.627 -> 0.633 |
| 22 | 1.075 -> 0.733 | 1.302 -> 0.950 | 0.733 -> 0.719 | 0.645 -> 0.643 |
| 23 | 1.153 -> 0.793 | 1.374 -> 0.993 | 0.758 -> 0.760 | 0.686 -> 0.682 |
| 24 | 1.163 -> 0.920 | 1.395 -> 1.216 | 0.891 = | 0.748 = |

Spreads are within ±2% of the median. Every new 2-pass call at logs 19–22 runs at about 0.70 ms, the 2-pass floor (about 1.5 TB/s per pass [D]).
Logs 23–24 drop toward 0.79/0.92 ms because of twiddle traffic at 4–8 columns per call [D]: the 13 low stages read about 1.5 words of twiddles per tile word, and that cost is amortised over the columns.
Tuning A/Bs (strided tile 2^12/2^13/2^14, wide rows on heights 6–11) are in `kernel-bench-t12/t13.jsonl` and in the comments next to the constants.

## Image
`/workspace/m3/build/m8-opt-T4-fft-passes/image/` is the frozen `m7-combined-residency` link with `transform-{lde,n2b,b2n_retained}` recompiled from this tree.
It also recompiles the four objects whose original build dirs are gone (`rv64/pcs_native`, `runtime/context`, `rv64/fused_blake2s`, `rv64/circuit_fill_chain`), from unchanged sources, as T2 did.
Runtime JSON: `image/runtime.json`.

## Request level
**Pending: GPU blocked.** The orphan `m8-native-hybrid` combined-serve (pid 3302210, PPID 1) holds 30.1 GB on each GPU. gate-1 failed at
`GpuPcsInitializationFailed` with 1.5 GB free, before any proof. The build, the Zig unit tests and the Python unit tests had passed.
tmux `t4-pipe1` (`/workspace/m3/runs/m8-opt-T4-fft-passes/pipe1.sh`, status in `pipe1.status`) starts by itself once both GPUs are below 2 GB.
It runs the default gate on 26235156 and 24628607, then the canonical 3+3 on 24628607 with `ab-preset.json`. In that A/B, baseline = the four kill switches (old kernels) and fullstack = new kernels, on the same image.
Both arms use the canonical fullstack environment with its fixed 22G arena, so the runner's fullstack-only guard cannot change arena sizing.
[E] On a warm 24628607 request: -0.25 to -0.35 GPU-s in the FFT family, which is about -0.1 s of request time.

## Review (2026-11-07): coverage, DRY, bench fix
Kernel logic re-derived by hand: every phase map is a bijection over (thread, k) -> tile word, so each shared word is written before it is read; each
phase reads and writes only its own set, and the sets are split by `__syncthreads`. CTAs own disjoint global words, so the exact alias is safe. Twiddle
indices stay below 2^(log_n-1). Strided grids put columns on y, which is safe because callers chunk at 65535.
- **Parity gaps closed:** `kMinLogN` = 3 (fft_small is enabled there) was untested, every stride was dense (== n), and the `launch_b2n_wide`
  CompactDepth 1/2 variants offered to composition_split had no test at all. `kernel-parity-review.jsonl` now covers **552/552 cases bit-identical [M]**:
  log 3..24, 1 and many columns, pad 0 and pad 7 (an odd stride, so every column but the first is misaligned), and 24 CompactDepth cases
  (log 19..24, checked against the chunk-major relayout of the plain output).
- **Bench bug:** `log_sizes` was a fixed 65536-word buffer, so any bench shape with more than 65536 columns (log <= 9 at 256 MiB) overran it
  (`invalid argument`). It is now sized per column count. With the fix, log 3 runs [M]: b2n 12.22 -> 1.08 ms, n2b 12.33 -> 1.22 ms, LDE 16.54 -> 5.47 ms.
- **DRY:** `n2b_wide_pad` (== `wide_tile_pad`), `kB2nWideValues` (== `kWideValues`, now in wide_tile.cuh) and three copies of the >48 KiB
  `cudaFuncSetAttribute` block (now `wide_allow_shared_bytes`) are deduplicated. `b2n_wide_contiguous<Unused>` becomes `<LowBits = 13>`, with
  a static_assert and a comment explaining the -rdc merge.
- **Device code unchanged:** `sass-diff-review.txt` shows all 63 common kernels with identical SASS [M], and the 6 renamed kernels are identical too.
  The renames are the template argument and the TU-hashed static names. The new-only kernels are the bench's CompactDepth instantiations.
  `kernel-bench-review.jsonl` (CUDA events, 9 reps, median) reproduces the earlier numbers within 1% [M].
- Open, not changed: the four kill switches are **default on**, while PROTOCOL-M8 says that new flags land default off. T3 does the same. The
  integrator should confirm this is intended for kernel-only, bit-identical streams. Request-level A/B is still pending (orphan GPU holder).
